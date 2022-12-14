
#include "broker.h"
#include "config.h"
#include "lib/common.h"
#include "lib/debug.h"
#include "basics.h"
#include "client_message.h"
#include "lib/xl4_epoll.h"

#include <libxl4bus/low_level.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>

#include <mbedtls/x509_crt.h>

#include "fragments/linux_if_bind.h"

#include "utlist.h"

static void * run_conn(void *);
static void signal_f(int);
static void process_bcc(broker_context_t * broker_context, int);
static void free_str_array(char *** array);

int debug = 0;

#ifndef MSG_TRUNC
#define MSG_TRUNC 0
#endif

static struct {
    time_t second;
    int in;
    int out;
} perf = {
        .second = 0
};

void free_str_array(char *** array) {

    if (!array) { return; }
    for (int i = 0; (*array)[i]; i++) {
        free((*array)[i]);
    }
    free(*array);
    *array = 0;

}

void add_to_str_array(char *** array, char const * str) {

    if (!*array) {

        *array = f_malloc(sizeof(void*) * 2);
        (*array)[0] = f_strdup(str);

    } else {

        int i = 0;
        for (; (*array)[i]; i++) {};
        // "i" points to terminating 0 now
        *array = f_realloc(*array, sizeof(void*)*(i+2));
        (*array)[i] = f_strdup(str);
        (*array)[i+1] = 0;

    }

}

static size_t str_array_len(char ** array) {

    char ** i;
    for (i = array; *i; i++) {};
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
        // free(file_list[i]);
        j++;

    }

}

void init_broker_context(broker_context_t * c) {
    memset(c, 0, sizeof(broker_context_t));
    c->stream_timeout_ms = 10000;
    c->init_ll = 1;
    c->fd = -1;
    c->bcc_fd = -1;
    c->poll_fd = -1;
}

void release_broker_context(broker_context_t * c) {
    Z(free, c->key_path);
    free_str_array(&c->cert_path);
    free_str_array(&c->ca_list);
    Z(free, c->demo_pki);
    Z(free, c->key_password);
    close(c->fd);
    c->fd = -1;
    close(c->poll_fd);
    c->poll_fd = -1;

    if (c->use_bcc) {
        close(c->bcc_fd);
        c->bcc_fd = -1;
        unlink(c->bcc_path);
    }

    Z(free, c->bcc_path);
    Z(free, c->net_if);

    xl4bus_release_cache(c->g_cache);
    Z(free, c->g_cache);
    release_identity(&c->broker_identity);
    Z(cjose_jwk_release, c->private_key);
    mbedtls_x509_crt_free(&c->trust);
    mbedtls_x509_crl_free(&c->crl);
    Z(json_object_put, c->my_x5c);

    // memset(c, 0, sizeof(broker_context_t));
}

void send_presence(broker_context_t * bc, json_object * connected, json_object * disconnected, conn_info_t * except) {

    // we can't get the context from 'except', because it can be 0

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

    DL_FOREACH_SAFE(bc->connections, ci, aux) {
        if (ci == except || !ci->registered) { continue; }
        uint16_t stream_id;
        if (xl4bus_get_next_outgoing_stream(ci->conn, &stream_id)) {
            continue;
        }
        send_json_message(ci, MSG_TYPE_PRESENCE, json_object_get(body), stream_id, 0, 1);
    }

    json_object_put(body);

}

void count(broker_context_t * bc, int in, int out) {

    if (!bc->perf_enabled) { return; }

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
            DL_FOREACH(bc->connections, ci) {
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

int start_broker(broker_context_t * bc) {

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

    if (bc->demo_pki && (bc->key_path || bc->ca_list || bc->cert_path)) {
        FATAL("Demo PKI label can not be used with X.509 identity parameters");
    }

    if (bc->init_ll && xl4bus_init_ll(&ll_cfg)) {
        FATAL("failed to initialize xl4bus");
    }

    bc->g_cache = f_malloc(xl4bus_get_cache_size());

    bc->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (bc->fd < 0) {
        perror("socket");
        return 1;
    }
#if 1
    /* set tcp_nodelay improves xl4bus performance from 40mS delivery to ~ 500uS */
    int opt=1;
    setsockopt(bc->fd, IPPROTO_TCP, TCP_NODELAY,  (void*)&opt, sizeof(int));
#endif

    int port = bc->port;
    MSG("Will bind to port %d", port);

    memset(&bc->broker_identity, 0, sizeof(bc->broker_identity));

    if (bc->demo_pki) {
        load_test_x509_creds(&bc->broker_identity, bc->demo_pki, bc->argv0);
        free(bc->demo_pki);
    } else {

        bc->broker_identity.type = XL4BIT_X509;

        if (bc->key_password) {
            bc->broker_identity.x509.custom = bc->key_password;
            bc->broker_identity.x509.password = simple_password_input;
        } else if (bc->key_path) {
            // $TODO: Using console_password_input ATM is a bad idea
            // because it will ask the password every time it's needed.
            bc->broker_identity.x509.password = console_password_input;
            bc->broker_identity.x509.custom = f_strdup(bc->key_path);
        }

        if (bc->key_path) {
            if (!(bc->broker_identity.x509.private_key = load_pem(bc->key_path))) {
                ERR("Key file %s could not be loaded", bc->key_path);
            }
        } else {
            ERR("No key file specified");
        }

        if (bc->ca_list) {
            load_pem_array(bc->ca_list, &bc->broker_identity.x509.trust, "trust");
        } else {
            ERR("No trust anchors specified");
        }

        if (bc->cert_path) {
            load_pem_array(bc->cert_path, &bc->broker_identity.x509.chain, "certificate");
        } else {
            ERR("No certificate/certificate chain specified");
        }

    }

    if (init_x509_values(bc) != E_XL4BUS_OK) {
        FATAL("Failed to initialize X.509 values");
    }

    int reuse = 1;
    if (setsockopt(bc->fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        ERR_SYS("setsockopt(SO_REUSEADDR)");
    }

    utarray_init(&bc->dm_clients, &ut_ptr_icd);

    if (if_bind(bc->fd, bc->net_if, AF_INET, htons(bc->port))) {
        FATAL_SYS("Can't bind listening socket");
    } else {
        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        if (getsockname(bc->fd, (struct sockaddr *)&sin, &len) == -1) {
            ERR_SYS("Can't get port number from broker listen socket");
        } else {
            MSG("Bound to port %d", ntohs(sin.sin_port));
        }

    }

    if (listen(bc->fd, 5)) {
        FATAL_SYS("Can't set up TCP listen queue");
    }

    if (set_nonblocking(bc->fd)) {
        FATAL_SYS("Can't set non-blocking socket mode");
    }

    bc->main_pit.type = PIT_INCOMING;
    bc->main_pit.fd = bc->fd;

    bc->poll_fd = epoll_create1(0);
    if (bc->poll_fd < 0) {
        FATAL_SYS("Can't create epoll socket");
    }

    struct epoll_event ev = {0};
    ev.events = POLLIN;
    ev.data.ptr = &bc->main_pit;

    if (epoll_ctl(bc->poll_fd, EPOLL_CTL_ADD, bc->fd, &ev)) {
        FATAL_SYS("epoll_ctl() failed");
    }

    if (bc->use_bcc) {

        if (!bc->bcc_path) {
            bc->bcc_path = f_strdup("/var/run/xl4broker");
        }

        struct sockaddr_un bcc_addr = {AF_UNIX};
        strncpy(bcc_addr.sun_path, bc->bcc_path, sizeof(bcc_addr.sun_path) - 1);
        bc->bcc_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

        if (bc->bcc_fd < 0) {
            FATAL_SYS("Can not create BCC socket");
        }

        if (setsockopt(bc->bcc_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
            ERR_SYS("setsockopt(SO_REUSEADDR)");
        }

        if (bind(bc->bcc_fd, (struct sockaddr*)&bcc_addr, sizeof(bcc_addr))) {
            FATAL_SYS("Can't bind BCC socket");
        }

        if (set_nonblocking(bc->bcc_fd)) {
            FATAL_SYS("Can't set non-blocking socket mode");
        }

        bc->bcc_pit.type = PIT_BCC;
        bc->bcc_pit.fd = bc->bcc_fd;


        memset(&ev, 0, sizeof(struct epoll_event));
        ev.events = POLLIN;
        ev.data.ptr = &bc->bcc_pit;

        if (epoll_ctl(bc->poll_fd, EPOLL_CTL_ADD, bc->bcc_fd, &ev)) {
            FATAL_SYS("epoll_ctl() failed");
        }

    }

    return 0;

}

int cycle_broker(broker_context_t * bc, int in_timeout) {

    bc->timeout = pick_timeout(bc->timeout, in_timeout);
    if (bc->max_ev < 1) { bc->max_ev = 1; }

    struct epoll_event rev[bc->max_ev];
    uint64_t before = 0;

    if (bc->timeout >= 0) {
        before = msvalue();
    }
    int ec = epoll_wait(bc->poll_fd, rev, bc->max_ev, bc->timeout);
    if (bc->timeout >= 0) {
        before = msvalue() - before;
        if (bc->timeout > before) {
            bc->timeout -= before;
        } else {
            bc->timeout = 0;
        }
    }
    if (ec < 0) {
        if (errno == EINTR) { return 0; }
        FATAL_SYS("epoll_wait() failed");
    }

    if (ec == bc->max_ev) { bc->max_ev++; }

    for (int i=0; i<ec; i++) {

        brk_poll_info_t * pit = rev[i].data.ptr;
        if (pit->type == PIT_INCOMING) {

            if (rev[i].events & POLLERR) {
                get_socket_error(pit->fd);
                FATAL_SYS("Connection socket error");
            }

            if (rev[i].events & POLLIN) {

                int fd2 = accept(bc->fd, 0, 0);
                if (fd2 < 0) {
                    FATAL_SYS("accept() failed");
                }

                xl4bus_connection_t * conn = f_malloc(sizeof(xl4bus_connection_t));
                conn_info_t * ci = f_malloc(sizeof(conn_info_t));

                conn->on_message = brk_on_message;
                conn->on_sent_message = on_sent_message;
                conn->fd = fd2;
                conn->set_poll = set_poll;
                conn->stream_timeout_ms = bc->stream_timeout_ms;
                conn->on_stream_closure = on_stream_close;

                memcpy(&conn->identity, &bc->broker_identity, sizeof(bc->broker_identity));

                conn->custom = ci;
                conn->cache = bc->g_cache;
                ci->conn = conn;
                ci->pit.ci = ci;
                ci->pit.type = PIT_XL4;
                ci->pit.fd = fd2;
                ci->ctx = bc;

                // DBG("Created connection %p/%p fd %d", ci, ci->conn, fd2);

                int err = xl4bus_init_connection(conn);

                if (err == E_XL4BUS_OK) {

                    conn->on_shutdown = on_connection_shutdown;

                    DL_APPEND(bc->connections, ci);

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
                          send_json_message(ci, MSG_TYPE_ALG_SUPPORTED, body, stream_id, 0, 0);
                    bc->timeout = pick_timeout(bc->timeout, ci->ll_poll_timeout);
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
                bc->timeout = pick_timeout(bc->timeout, ci->ll_poll_timeout);
                // DBG("timeout adjusted to %d (exist conn %p)", timeout, ci);
            } else {
                DBG("xl4bus process (fd up route) returned %d", s_err);
            }

        } else if (pit->type == PIT_BCC) {

            if (rev[i].events & POLLIN) {

                process_bcc(bc, pit->fd);

            } else if (rev[i].events & POLLOUT) {
                // this is not possible...
                FATAL("Write event on BCC socket?");
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

    if (bc->quit) {

        // make sure we don't accept new connections.
        epoll_ctl(bc->poll_fd, EPOLL_CTL_DEL, bc->fd, (void*)1);

        conn_info_t * ci;
        conn_info_t * aux;

        DL_FOREACH_SAFE(bc->connections, ci, aux) {
            xl4bus_shutdown_connection(ci->conn);
        }

    }

    if (!bc->timeout) {

        bc->timeout = -1;

        conn_info_t * aux;
        conn_info_t * ci;

        DL_FOREACH_SAFE(bc->connections, ci, aux) {
            int s_err;
            ci->ll_poll_timeout = -1;
            if ((s_err = xl4bus_process_connection(ci->conn, -1, 0)) == E_XL4BUS_OK) {
                bc->timeout = pick_timeout(bc->timeout, ci->ll_poll_timeout);
                // DBG("timeout adjusted to %d (exist conn %p), timeout route", timeout, ci);
            } else {
                DBG("xl4bus process (timeout route) returned %d", s_err);
            }
        }

    }

    return 0;

}

void process_bcc(broker_context_t * broker_context, int sock) {

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
                broker_context->quit = 1;
                break;
            default:
                ERR("Unknown BCC command %" PRId32, cmd.hdr.cmd);
                break;
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

}
