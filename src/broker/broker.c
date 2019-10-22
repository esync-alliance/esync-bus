
#include "broker.h"
#include "lib/common.h"
#include "lib/debug.h"
#include "lib/poll_help.h"

#include <libxl4bus/low_level.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>

#include "utlist.h"

static void * run_conn(void *);
static void signal_f(int);
static void process_bcc(int);

int debug = 0;
UT_array dm_clients;
hash_list_t * ci_by_group = 0;
hash_list_t * ci_by_x5t = 0;
conn_info_t * connections;
int poll_fd;
xl4bus_identity_t broker_identity;

#ifndef MSG_TRUNC
#define MSG_TRUNC 0
#endif

broker_context_t broker_context = {
        .stream_timeout_ms = 10000,
};


static struct {
    time_t second;
    int in;
    int out;
} perf = {
        .second = 0
};

#if !XL4_HAVE_EPOLL
typedef struct pf_poll {
    int fd;
    void* data_ptr;
    short events;
    short revents;
} pf_poll_t;

typedef struct poll_list {
    pf_poll_t * polls;
    int polls_len;
} poll_list_t;

static poll_list_t polist = { .polls = 0, .polls_len = 0};

static int pf_poll(pf_poll_t * polls, int polls_len, int timeout);

#endif


void add_to_str_array(char *** array, char * str) {

    if (!*array) {
        *array = f_malloc(sizeof(void*) * 2);
        *array[0] = f_strdup(str);
    } else {

    }

}

static size_t str_array_len(char ** array) {

    char ** i;
    for (i = array; *i; i++);
    return (size_t)(i - array);

}

void load_pem_array(char ** file_list, xl4bus_asn1_t ***asn_list, char const * f_type) {

    size_t cnt = str_array_len(file_list) + 1;
    *asn_list = f_malloc(cnt * sizeof(void*));
    int i = 0, j = 0;
    for (;i<cnt; i++) {
        if (!file_list[i]) {
            (*asn_list)[j] = 0;
            break;
        }
        if (!((*asn_list)[j] = load_pem(file_list[i]))) {
            ERR("Problem loading %s file %s", f_type, file_list[i]);
        }
        free(file_list[i]);
        j++;

    }

}

void send_presence(json_object * connected, json_object * disconnected, conn_info_t * except) {

    json_object *body = json_object_new_object();
    if (connected) {
        json_object_object_add(body, "connected", connected);
    }
    if (disconnected) {
        json_object_object_add(body, "disconnected", disconnected);
    }

    conn_info_t * ci;
    conn_info_t * aux;

    DBG("Broadcasting presence change %s", json_object_get_string(body));

    DL_FOREACH_SAFE(connections, ci, aux) {
        if (ci == except) { continue; }
        uint16_t stream_id;
        if (xl4bus_get_next_outgoing_stream(ci->conn, &stream_id)) {
            continue;
        }
        send_json_message(ci, "xl4bus.presence", json_object_get(body), stream_id, 0, 1);
    }

    json_object_put(body);

}

void count(int in, int out) {

    if (!broker_context.perf_enabled) { return; }

    clockid_t clk =
#ifdef CLOCK_MONOTONIC_COARSE
            CLOCK_MONOTONIC_COARSE
#elif defined(CLOCK_MONOTONIC_RAW)
    CLOCK_MONOTONIC_RAW
#else
    CLOCK_MONOTONIC
#endif
    ;

    struct timespec ts;

    clock_gettime(clk, &ts);
    if (perf.second != ts.tv_sec) {
        if (perf.second) {
            conn_info_t * ci;
            int stream_count = 0;
            DL_FOREACH(connections, ci) {
                if (ci->conn) {
                    stream_count += ci->conn->stream_count;
                }
            }
            MSG_OUT("E872 %d IN %d OUT %d streams\n", perf.in, perf.out, stream_count);
        }
        perf.in = 0;
        perf.out = 0;
        perf.second = ts.tv_sec;
    }

    perf.in += in;
    perf.out += out;

}

static void signal_f(int s) {

    ERR("Killed with %d", s);
    exit(3);

}

int start_broker() {

    xl4bus_ll_cfg_t ll_cfg;

    // in case we are under gprof
    signal(SIGINT, signal_f);

    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    if (debug) {
        ll_cfg.debug_f = print_out;
#if XL4BUS_ANDROID
        ll_cfg.debug_no_time = 1;
#endif
    }

    if (broker_context.demo_pki && (broker_context.key_path || broker_context.ca_list || broker_context.cert_path)) {
        FATAL("Demo PKI label can not be used with X.509 identity parameters");
    }

    if (xl4bus_init_ll(&ll_cfg)) {
        FATAL("failed to initialize xl4bus");
    }

    broker_context.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (broker_context.fd < 0) {
        perror("socket");
        return 1;
    }
#if 1
    /* set tcp_nodelay improves xl4bus performance from 40mS delivery to ~ 500uS */
    int opt=1;
    setsockopt(broker_context.fd, IPPROTO_TCP, TCP_NODELAY,  (void*)&opt, sizeof(int));
#endif

    memset(&broker_context.b_addr, 0, sizeof(broker_context.b_addr));
    broker_context.b_addr.sin_family = AF_INET;
    broker_context.b_addr.sin_port = htons(9133);
    broker_context.b_addr.sin_addr.s_addr = INADDR_ANY;

    memset(&broker_identity, 0, sizeof(broker_identity));

    if (broker_context.demo_pki) {
        load_test_x509_creds(&broker_identity, broker_context.demo_pki, broker_context.argv0);
        free(broker_context.demo_pki);
    } else {

        broker_identity.type = XL4BIT_X509;

        if (broker_context.key_path) {
            if (!(broker_identity.x509.private_key = load_pem(broker_context.key_path))) {
                ERR("Key file %s could not be loaded", broker_context.key_path);
            }
            free(broker_context.key_path);
        } else {
            ERR("No key file specified");
        }

        if (broker_context.ca_list) {
            load_pem_array(broker_context.ca_list, &broker_identity.x509.trust, "trust");
            free(broker_context.ca_list);
        } else {
            ERR("No trust anchors specified");
        }

        if (broker_context.cert_path) {
            load_pem_array(broker_context.cert_path, &broker_identity.x509.chain, "certificate");
            free(broker_context.cert_path);
        } else {
            ERR("No certificate/certificate chain specified");
        }

        if (broker_context.key_password) {
            broker_identity.x509.custom = broker_context.key_password;
            broker_identity.x509.password = simple_password_input;
        } else if (broker_context.key_path) {
            // $TODO: Using console_password_input ATM is a bad idea
            // because it will ask the password every time it's needed.
            broker_identity.x509.password = console_password_input;
            broker_identity.x509.custom = f_strdup(broker_context.key_path);
        }

    }

    if (init_x509_values() != E_XL4BUS_OK) {
        FATAL("Failed to initialize X.509 values");
    }

    int reuse = 1;
    if (setsockopt(broker_context.fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        ERR_SYS("setsockopt(SO_REUSEADDR)");
    }

    utarray_init(&dm_clients, &ut_ptr_icd);

    if (bind(broker_context.fd, (struct sockaddr*)&broker_context.b_addr, sizeof(broker_context.b_addr))) {
        FATAL_SYS("Can't bind listening socket");
    }

    if (listen(broker_context.fd, 5)) {
        FATAL_SYS("Can't set up TCP listen queue");
    }

    if (set_nonblocking(broker_context.fd)) {
        FATAL_SYS("Can't set non-blocking socket mode");
    }

    broker_context.main_pit.type = PIT_INCOMING;
    broker_context.main_pit.fd = broker_context.fd;

#if XL4_HAVE_EPOLL
    poll_fd = epoll_create1(0);
    if (poll_fd < 0) {
        FATAL_SYS("Can't create epoll socket");
    }

    struct epoll_event ev;
    ev.events = POLLIN;
    ev.data.ptr = &broker_context.main_pit;

    if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, broker_context.fd, &ev)) {
        FATAL_SYS("epoll_ctl() failed");
    }

#else
    if (set_poll(&broker_context.main_pit, fd, XL4BUS_POLL_READ)) {
        perror("set_poll");
        return 1;
    }
#endif

    if (broker_context.use_bcc) {

        if (!broker_context.bcc_path) {
            broker_context.bcc_path = f_strdup("/var/run/xl4broker");
        }

        struct sockaddr_un bcc_addr = {AF_UNIX};
        strncpy(bcc_addr.sun_path, broker_context.bcc_path, sizeof(bcc_addr.sun_path)-1);
        broker_context.bcc_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

        if (broker_context.bcc_fd < 0) {
            FATAL_SYS("Can not create BCC socket");
        }

        if (setsockopt(broker_context.bcc_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
            ERR_SYS("setsockopt(SO_REUSEADDR)");
        }

        if (bind(broker_context.bcc_fd, (struct sockaddr*)&bcc_addr, sizeof(bcc_addr))) {
            FATAL_SYS("Can't bind BCC socket");
        }

        if (set_nonblocking(broker_context.bcc_fd)) {
            FATAL_SYS("Can't set non-blocking socket mode");
        }

        broker_context.bcc_pit.type = PIT_BCC;
        broker_context.bcc_pit.fd = broker_context.bcc_fd;

#if XL4_HAVE_EPOLL

        memset(&ev, 0, sizeof(struct epoll_event));
        ev.events = POLLIN;
        ev.data.ptr = &broker_context.bcc_pit;

        if (epoll_ctl(poll_fd, EPOLL_CTL_ADD, broker_context.bcc_fd, &ev)) {
            FATAL_SYS("epoll_ctl() failed");
        }

#else
        if (set_poll(&broker_context.bcc_pit, fd, XL4BUS_POLL_READ)) {
        perror("set_poll");
        return 1;
    }
#endif


    }

}

int cycle_broker(int in_timeout) {

    broker_context.timeout = pick_timeout(broker_context.timeout, in_timeout);
    if (broker_context.max_ev < 1) { broker_context.max_ev = 1; }

#if XL4_HAVE_EPOLL

    struct epoll_event rev[broker_context.max_ev];
    uint64_t before = 0;

    if (broker_context.timeout >= 0) {
        before = msvalue();
    }
    int ec = epoll_wait(poll_fd, rev, broker_context.max_ev, broker_context.timeout);
    if (broker_context.timeout >= 0) {
        before = msvalue() - before;
        if (broker_context.timeout > before) {
            broker_context.timeout -= before;
        } else {
            broker_context.timeout = 0;
        }
    }
    if (ec < 0) {
        if (errno == EINTR) { return 0; }
        FATAL_SYS("epoll_wait() failed");
    }

    if (ec == broker_context.max_ev) { broker_context.max_ev++; }

    for (int i=0; i<ec; i++) {

        poll_info_t * pit = rev[i].data.ptr;
        if (pit->type == PIT_INCOMING) {

            if (rev[i].events & POLLERR) {
                get_socket_error(pit->fd);
                FATAL_SYS("Connection socket error");
            }

            if (rev[i].events & POLLIN) {

                socklen_t b_addr_len = sizeof(broker_context.b_addr);
                int fd2 = accept(broker_context.fd, (struct sockaddr*)&broker_context.b_addr, &b_addr_len);
                if (fd2 < 0) {
                    FATAL_SYS("accept() failed");
                }

                xl4bus_connection_t * conn = f_malloc(sizeof(xl4bus_connection_t));
                conn_info_t * ci = f_malloc(sizeof(conn_info_t));

                conn->on_message = brk_on_message;
                conn->on_sent_message = on_sent_message;
                conn->fd = fd2;
                conn->set_poll = set_poll;
                conn->stream_timeout_ms = broker_context.stream_timeout_ms;
                conn->on_stream_closure = on_stream_close;

                memcpy(&conn->identity, &broker_identity, sizeof(broker_identity));

                conn->custom = ci;
                ci->conn = conn;
                ci->pit.ci = ci;
                ci->pit.type = PIT_XL4;
                ci->pit.fd = fd2;

                // DBG("Created connection %p/%p fd %d", ci, ci->conn, fd2);

                int err = xl4bus_init_connection(conn);

                if (err == E_XL4BUS_OK) {

                    conn->on_shutdown = on_connection_shutdown;

                    DL_APPEND(connections, ci);

                    // send initial message - alg-supported
                    // https://gitlab.excelfore.com/schema/json/xl4bus/alg-supported.json
                    json_object *aux;
                    json_object *body = json_object_new_object();

                    json_object_object_add(body, "signature", aux = json_object_new_array());
                    json_object_array_add(aux, json_object_new_string("RS256"));
                    json_object_object_add(body, "encryption-key", aux = json_object_new_array());
                    json_object_array_add(aux, json_object_new_string("RSA-OAEP"));
                    json_object_object_add(body, "encryption-alg", aux = json_object_new_array());
                    json_object_array_add(aux, json_object_new_string("A128CBC-HS256"));
                    json_object_object_add(body, "protocol-version", json_object_new_int(2));

                    uint16_t stream_id;
                    err = xl4bus_get_next_outgoing_stream(ci->conn, &stream_id) ||
                          send_json_message(ci, "xl4bus.alg-supported", body, stream_id, 0, 0);
                    broker_context.timeout = pick_timeout(broker_context.timeout, ci->ll_poll_timeout);
                    // DBG("timeout adjusted to %d (new conn %p)", timeout, ci);

                    if (err == E_XL4BUS_OK) {
                        int s_err;
                        if ((s_err = xl4bus_process_connection(conn, -1, 0)) == E_XL4BUS_OK) {
                        } else {
                            DBG("xl4bus process (initial) returned %d", s_err);
                        }
                    }

                } else {
                    free(ci);
                    free(conn);
                }

            }

        } else if (pit->type == PIT_XL4) {

            conn_info_t *ci = pit->ci;
            int flags = 0;
            if (rev[i].events & POLLIN) {
                flags |= XL4BUS_POLL_READ;
            }
            if (rev[i].events & POLLOUT) {
                flags |= XL4BUS_POLL_WRITE;
            }
            if (rev[i].events & (POLLERR | POLLNVAL | POLLHUP)) {
                flags |= XL4BUS_POLL_ERR;
            }

            int s_err;
            if ((s_err = xl4bus_process_connection(ci->conn, pit->fd, flags)) == E_XL4BUS_OK) {
                broker_context.timeout = pick_timeout(broker_context.timeout, ci->ll_poll_timeout);
                // DBG("timeout adjusted to %d (exist conn %p)", timeout, ci);
            } else {
                DBG("xl4bus process (fd up route) returned %d", s_err);
            }

        } else if (pit->type == PIT_BCC) {

            if (rev[i].events & POLLIN) {

                process_bcc(pit->fd);

            } else if (rev[i].events & POLLOUT) {
                // this is not possible...
                FATAL("Write even on BCC socket?");
            } else {
                // this must be an error event, let's just clear it...
                get_socket_error(pit->fd);
                ERR_SYS("BCC socket %d error", pit->fd);
            }

        } else {
            DBG("PIT type %d?", pit->type);
            return 1;
        }

    }

#else

    uint64_t before = 0;

    if (timeout >= 0) {
        before = msvalue();
    }
    int res = pf_poll(polist.polls, polist.polls_len, timeout);

    if (timeout >= 0) {
        before = msvalue() - before;
        if (timeout > before) {
            timeout -= before;
        } else {
            timeout = 0;
        }
    }
    if (res < 0) {
        if (errno == EINTR) { continue; }
        FATAL_SYS("pf_poll() failed");
    }

    for (int i=0; i<polist.polls_len; i++) {
        pf_poll_t * pp = polist.polls + i;
        if (pp->revents) {
            poll_info_t * pit = pp->data_ptr;

            if (pit->type == PIT_INCOMING) {

                if (pp->events & POLLERR) {
                    get_socket_error(pit->fd);
                    FATAL_SYS("Connection socket error");
                }

                if (pp->events & POLLIN) {

                    socklen_t b_addr_len = sizeof(b_addr);
                    int fd2 = accept(fd, (struct sockaddr*)&b_addr, &b_addr_len);
                    if (fd2 < 0) {
                        FATAL_SYS("accept() failed");
                    }

                    xl4bus_connection_t * conn = f_malloc(sizeof(xl4bus_connection_t));
                    conn_info_t * ci = f_malloc(sizeof(conn_info_t));

                    conn->on_message = brk_on_message;
                    conn->on_sent_message = on_sent_message;
                    conn->fd = fd2;
                    conn->set_poll = set_poll;
                    conn->stream_timeout_ms = stream_timeout_ms;
                    conn->on_stream_closure = on_stream_close;

                    memcpy(&conn->identity, &broker_identity, sizeof(broker_identity));

                    conn->custom = ci;
                    ci->conn = conn;
                    ci->pit.ci = ci;
                    ci->pit.type = PIT_XL4;
                    ci->pit.fd = fd2;

                    // DBG("Created connection %p/%p fd %d", ci, ci->conn, fd2);

                    int err = xl4bus_init_connection(conn);

                    if (err == E_XL4BUS_OK) {

                        conn->on_shutdown = on_connection_shutdown;

                        DL_APPEND(connections, ci);

                        // send initial message - alg-supported
                        // https://gitlab.excelfore.com/schema/json/xl4bus/alg-supported.json
                        json_object *aux;
                        json_object *body = json_object_new_object();

                        json_object_object_add(body, "signature", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("RS256"));
                        json_object_object_add(body, "encryption-key", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("RSA-OAEP"));
                        json_object_object_add(body, "encryption-alg", aux = json_object_new_array());
                        json_object_array_add(aux, json_object_new_string("A128CBC-HS256"));

                        uint16_t stream_id;
                        err = xl4bus_get_next_outgoing_stream(ci->conn, &stream_id) ||
                              send_json_message(ci, "xl4bus.alg-supported", body, stream_id, 0, 0);
                        timeout = pick_timeout(timeout, ci->ll_poll_timeout);
                        // DBG("timeout adjusted to %d (new conn %p)", timeout, ci);

                        if (err == E_XL4BUS_OK) {
                            int s_err;
                            if ((s_err = xl4bus_process_connection(conn, -1, 0)) == E_XL4BUS_OK) {
                            } else {
                                DBG("xl4bus process (initial) returned %d", s_err);
                            }
                        }

                    } else {
                        free(ci);
                        free(conn);
                    }

                }

            } else if (pit->type == PIT_XL4) {

                conn_info_t * ci = pit->ci;
                int flags = 0;
                if (pp->events & POLLIN) {
                    flags |= XL4BUS_POLL_READ;
                }
                if (pp->events & POLLOUT) {
                    flags |= XL4BUS_POLL_WRITE;
                }
                if (pp->events & (POLLERR|POLLNVAL|POLLHUP)) {
                    flags |= XL4BUS_POLL_ERR;
                }

                int s_err;
                if ((s_err = xl4bus_process_connection(ci->conn, pit->fd, flags)) == E_XL4BUS_OK) {
                    timeout = pick_timeout(timeout, ci->ll_poll_timeout);
                    // DBG("timeout adjusted to %d (exist conn %p)", timeout, ci);
                } else {
                    DBG("xl4bus process (fd up route) returned %d", s_err);
                }

            } else {
                DBG("PIT type %d?", pit->type);
                return 1;
            }
        }
    }
#endif

    if (broker_context.quit) {
        return 0;
    }

    if (!broker_context.timeout) {

        broker_context.timeout = -1;

        conn_info_t * aux;
        conn_info_t * ci;

        DL_FOREACH_SAFE(connections, ci, aux) {
            int s_err;
            ci->ll_poll_timeout = -1;
            if ((s_err = xl4bus_process_connection(ci->conn, -1, 0)) == E_XL4BUS_OK) {
                broker_context.timeout = pick_timeout(broker_context.timeout, ci->ll_poll_timeout);
                // DBG("timeout adjusted to %d (exist conn %p), timeout route", timeout, ci);
            } else {
                DBG("xl4bus process (timeout route) returned %d", s_err);
            }
        }

    }

    return 0;

}

#if !XL4_HAVE_EPOLL
int set_poll(xl4bus_connection_t * conn, int fd, int flg) {

    conn_info_t * ci = NULL;

    if (conn) {
        ci = conn->custom;
    }

    if (fd == XL4BUS_POLL_TIMEOUT_MS) {
        if(ci) {
            ci->ll_poll_timeout = pick_timeout(ci->ll_poll_timeout, flg);
        }
        return E_XL4BUS_OK;
    }

    uint32_t need_flg = 0;

    if (flg & XL4BUS_POLL_WRITE) {
        need_flg |= POLLOUT;
    }
    if (flg & XL4BUS_POLL_READ) {
        need_flg |= POLLIN;
    }

    if ((!ci) || ((ci) && (ci->poll_modes != need_flg))) {

        int rc = 0;

        if (need_flg) {
            pf_poll_t * found = 0;
            for (int i=0; i<polist.polls_len; i++) {
                pf_poll_t * poll = polist.polls + i;
                if(ci) {
                    if(poll->fd == conn->fd) {
                        found = poll;
                        break;
                    }
                } else {
                    if(poll->fd == fd) {
                        found = poll;
                        break;
                    }
                }
            }
            if (!found) {
                void * v = realloc(polist.polls, (polist.polls_len + 1) * sizeof(pf_poll_t));
                if (!v) {
                    return E_XL4BUS_MEMORY;
                }
                polist.polls = v;
                found = polist.polls + polist.polls_len++;
                if(ci) {
                    found->fd = conn->fd;
                    found->data_ptr = &ci->pit;
                } else {
                    found->fd = fd;
                    found->data_ptr = &main_pit;
                }
            }
            found->events = (short)need_flg;
        } else {
            if ((ci) && (ci->poll_modes)) {
                for (int i=0; i<polist.polls_len; i++) {
                    if (polist.polls[i].fd == conn->fd) {
                        polist.polls[i].fd = -1;
                        break;
                    }
                }
            } else {
                rc = 0;
            }
        }

        if (rc) {
            return E_XL4BUS_SYS;
        }

        if(ci) {
            ci->poll_modes = need_flg;
        }
    }

    return E_XL4BUS_OK;
}

int pf_poll(pf_poll_t * polls, int polls_len, int timeout) {

    struct rlimit rlim;

    getrlimit(RLIMIT_NOFILE, &rlim);

    if (polls_len < 0 || polls_len > rlim.rlim_cur) {
        errno = EINVAL;
        return -1;
    }

    struct pollfd s_poll[polls_len];

    for (int i=0; i<polls_len; i++) {

        s_poll[i].events = 0;
        polls[i].revents = 0;

        if ((s_poll[i].fd = polls[i].fd) < 0) {
            // DBG("pf_poll: skipping negative fd");
            continue;
        }

        short ine = polls[i].events;
        if (ine & XL4BUS_POLL_WRITE) {
            s_poll[i].events |= POLLOUT;
        }
        if (ine & XL4BUS_POLL_READ) {
            s_poll[i].events |= POLLIN;
        }

        // DBG("pf_poll : %d: %x->%x", s_poll[i].fd, polls[i].events, s_poll[i].events);

    }

    int ec = poll(s_poll, (nfds_t) polls_len, timeout);
    if (ec <= 0) { return ec; }

    // DBG("pf_poll: %d descriptors, %d timeout, returned %d", polls_len, timeout, ec);

    for (int i=0; i<polls_len; i++) {
        if (s_poll[i].fd < 0) { continue; }
        short ine = s_poll[i].revents;
        if (ine & POLLOUT) {
            polls[i].revents |= XL4BUS_POLL_WRITE;
        }
        if (ine & POLLIN) {
            polls[i].revents |= XL4BUS_POLL_READ;
        }
        if (ine & (POLLERR|POLLHUP|POLLNVAL)) {
            polls[i].revents |= XL4BUS_POLL_ERR;
        }
        // DBG("pf_poll: %x->%x for %d", ine, polls[i].revents, s_poll[i].fd);
    }

    return ec;
}
#endif

void process_bcc(int sock) {

    broker_control_command_t cmd = {0};

    do {

        ssize_t rc = recv(sock, &cmd, sizeof(cmd), MSG_TRUNC);
        if (rc == -1) {
            if (errno != EAGAIN || errno != EWOULDBLOCK) {
                ERR_SYS("Reading from BCC socket %d", sock);
            }
            break;
        }

        if (rc > sizeof(cmd) || rc < sizeof(broker_control_command_mandatory_t)) {
            ERR("BCC message size %zd invalid", rc);
            break;
        }

        if (cmd.hdr.magic != BCC_MAGIC) {
            ERR("BCC magic %" PRIx32 "invalid", cmd.hdr.magic);
            break;
        }

        switch (cmd.hdr.cmd) {
            case BCC_QUIT:
                MSG("Received QUIT command over BCC");
                broker_context.quit = 1;
                break;
            default:
                ERR("Unknown BCC command %" PRId32, cmd.hdr.cmd);
                break;
        }

    } while (0);

}