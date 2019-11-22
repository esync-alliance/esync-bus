
#include "tests.h"
#include "full-test.h"
#include <libxl4bus/high_level.h>
#include <lib/debug.h>
#include "broker/broker.h"
#include "utlist.h"
#include "basics.h"
#include "cases.h"

#include <sys/un.h>
#include <pthread.h>

typedef struct test_case {
    UT_hash_handle hh;
    char * name;
} test_case_t;

static void * broker_runner(void *);
static void submit_event(test_event_t ** event_queue, test_event_t * event);
static int test_expect(int timeout_ms, test_event_t ** queue, test_event_t ** event,
        test_event_type_t first, va_list other);
static void timespec_add_ms(struct timespec * ts, int ms);
static void release_handler(struct xl4bus_client *);
static void version(FILE *);
static void help(void);
static void exclude_test(const char *);
static void end_loud_mode(const char *);
static int ignore_failure(const char *);
static void check_loud_mode(const char *);
static int should_run_test_case(const char *);
static void delivered_handler(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok);
static void incoming_handler(struct xl4bus_client * clt, xl4bus_message_t * msg);
static void status_handler(struct xl4bus_client * clt, xl4bus_client_condition_t status);
static char * set_client_thread_name(test_client_t * clt);

FILE * output_log = 0;
char const * test_name = 0;

static pthread_mutex_t broker_start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t broker_start_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

static int run_individually = 0;
static test_case_t * test_cases = 0;
static test_case_t * loud_tests = 0;
static test_case_t * ignored_tests = 0;
static test_case_t * excluded_cases = 0;
static test_case_t * was_excluded = 0;
static int test_skip_count = 0;
static int through_count;
static pthread_key_t thread_name_key;
static xl4bus_ll_cfg_t ll_cfg = {
        .realloc = realloc,
        .malloc = malloc,
        .free = free,
        .debug_f = full_test_print_out
};

void help() {

    printf(""
"Options:\n"
" -h          show this help\n"
" -d          turn on debug output\n"
"");

}

static __attribute__((constructor)) void my_init() {

    if (xl4bus_init_ll(&ll_cfg)) {
        abort();
    }
    pthread_key_create(&thread_name_key, free);
    pthread_setspecific(thread_name_key, f_strdup("main"));

}

void version(FILE * to) {

    if (!to) { to = stderr; }
    char now[25];
    str_output_time(now);
    char const * full_version = xl4bus_version();
    fprintf(to, "unit_test libxl4bus %s, time: %s\n", full_version, now);

}

int main(int argc, char ** argv) {

    char * output_file_log = 0;

    int ret = 0;
    int c;
    int t_count = 0;
    int f_count = 0;
    int i_count = 0;

    if (isatty(0)) {
        printf("Use -h for brief help\n");
    }

    while ((c = getopt(argc, argv, "hdt:T:Q:I:O:")) != -1) {

#pragma clang diagnostic push
#pragma ide diagnostic ignored "missing_default_case"
        switch (c) {
            case 'h':
                version(0);
                help();
                return 1;
            case 'd':
                debug = 1;
                break;
            case 't':
            {
                test_case_t * tc = f_malloc(sizeof(test_case_t));
                tc->name = f_strdup(optarg);
                run_individually = 1;
                HASH_ADD_KEYPTR(hh, test_cases, tc->name, strlen(tc->name), tc);
            }
                break;
            case 'T':
            {
                exclude_test(optarg);
            }
                break;
            case 'Q':
            {
                test_case_t * tc = f_malloc(sizeof(test_case_t));
                tc->name = f_strdup(optarg);
                HASH_ADD_KEYPTR(hh, loud_tests, tc->name, strlen(tc->name), tc);
            }
            case 'I':
            {
                test_case_t * tc = f_malloc(sizeof(test_case_t));
                tc->name = f_strdup(optarg);
                HASH_ADD_KEYPTR(hh, ignored_tests, tc->name, strlen(tc->name), tc);
            }
                break;
            case 'O':
                if (output_file_log) {
                    TEST_ERR("Multiple log files are not supported");
                    return 1;
                }
                output_file_log = f_strdup(optarg);
                break;
            default:
                version(0);
                TEST_ERR("Option errors\n");
                return 1;
                break;
        }
    }

#pragma clang diagnostic pop

    version(0);

    if (test_cases && excluded_cases) {
        TEST_ERR("-t option can not be used with -T");
        return 1;
    }

#define CASE(n) do { \
    if (should_run_test_case(#n)) { \
        test_name = #n; \
        check_loud_mode(#n); \
        if (n()) { \
            if (ignore_failure(#n)) {\
                i_count ++; \
            } else {\
                f_count ++; \
                ret = 1; \
            } \
        } \
        t_count++; \
        end_loud_mode(#n); \
    } else { \
        test_skip_count++; \
    } \
} while(0)

    // before we are going to start any operations, let's close "all" file
    // descriptors. We going to leave out 0,1,2, as we might need them. But
    // we need to close anything else that parent might have passed down to us.
    // we can't do it later, because we must ensure no file descriptor is
    // leaked, and we won't know which ones are parent's or ours past this
    // point. There is a better way of determining currently open file
    // descriptors (like reading /proc/<x>/fd), but brute force here is easy
    // and effective.

    for (int i=3; i<=255; i++) { close(i); }

    if (output_file_log) {
        output_log = fopen(output_file_log, "w");
        if (!output_log) {
            TEST_ERR("Failed to create log file %s: %s",
                    optarg, strerror(errno));
            return 1;
        }
        version(output_log);
    }

    CASE(hello_world);

    test_case_t * tc, * aux;
    HASH_ITER(hh, test_cases, tc, aux) {
        TEST_ERR("Unknown test case %s", tc->name);
    }
    HASH_ITER(hh, excluded_cases, tc, aux) {
        TEST_ERR("Unknown test case specified for exclusion: %s", tc->name);
    }
    // int has_been_excluded = HASH_COUNT(was_excluded);
    HASH_ITER(hh, was_excluded, tc, aux) {
        TEST_ERR("Excluded %s", tc->name);
        HASH_DEL(was_excluded, tc);
        free(tc->name);
        free(tc);
    }

    if (!t_count) {
        fprintf(stderr, "NO TESTS ARE BEING RAN, FAILING\n");
        ret = 1;
    }

    if (!ret) {
        fprintf(stderr, "UNIT TEST SUCCESSFUL (%d tests, %d excluded, %d ignored)!\n",
                t_count, test_skip_count, i_count);
    } else {
        fprintf(stderr, "UNIT TEST FAILED (%d failed out of %d, %d excluded, %d ignored)!!!\n",
                f_count, t_count, test_skip_count, i_count);
    }

    // close standard file descriptors, otherwise valgrind will throw an
    // error due to leaked FDs.
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    // return ret;
    // _exit(ret); /* this breaks gcov! */
    return ret;

}

int full_test_client_start(test_client_t * clt, test_broker_t * brk, int wait_on_latch) {

    int err /*= E_XL4BUS_OK*/;
    char * url = 0;
    test_event_t * event = 0;

    do {

        BOLT_IF(!brk->port, E_XL4BUS_ARG, "");
        url = f_asprintf("tcp://localhost:%d", brk->port);

        if (!clt->name) {
            clt->name = f_asprintf("%s:%s:%d", test_name, clt->label, through_count++);
        }

        clt->bus_client.mt_support = 1;
        clt->bus_client.use_internal_thread = 1;
        clt->bus_client.on_release = release_handler;
        clt->bus_client.on_delivered = delivered_handler;
        clt->bus_client.on_message = incoming_handler;
        clt->bus_client.on_status = status_handler;

        BOLT_IF(load_simple_x509_creds(&clt->bus_client.identity,
                f_asprintf("./testdata/pki/%s/private.pem", clt->label),
                f_asprintf("./testdata/pki/%s/cert.pem", clt->label),
                f_strdup("./testdata/pki/ca/ca.pem"), 0), E_XL4BUS_INTERNAL, "");

        BOLT_SUB(xl4bus_init_client(&clt->bus_client, url));
        clt->started = 1;

        if (wait_on_latch) {
            BOLT_SUB(full_test_client_expect_single(0, clt, &event, TET_CLT_RUNNING));
        }

        TEST_DBG("client %s started", clt->name);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    free(url);
    full_test_free_event(event);

    return err;

}

void full_test_client_stop(test_client_t * clt) {
    if (!clt->started) { return; }
    xl4bus_stop_client(&clt->bus_client);
    full_test_client_expect(0, clt, 0, TET_CLT_QUIT, TET_NONE);
}

int full_test_broker_start(test_broker_t * brk) {

    int err = E_XL4BUS_OK;
    int locked = 0;

    do {

        broker_context.init_ll = 0;
        broker_context.key_path = f_strdup("./testdata/pki/broker/private.pem");
        add_to_str_array(&broker_context.cert_path, "./testdata/pki/broker/cert.pem");
        add_to_str_array(&broker_context.ca_list, "./testdata/pki/ca/ca.pem");

        if (!brk->name) {
            brk->name = f_asprintf("%s:%d", test_name, through_count++);
        }

        BOLT_DIR(pthread_mutex_lock(&broker_start_lock), "");
        locked = 1;
        pthread_t broker_thread;
        BOLT_DIR(pthread_create(&broker_thread, 0, broker_runner, brk), "");
        BOLT_DIR(pthread_cond_wait(&broker_start_cond, &broker_start_lock), "");
        if (!brk->started) {
            err = brk->start_err;
        }
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (locked) {
        pthread_mutex_unlock(&broker_start_lock);
    }

    return err;

}

void full_test_broker_stop(test_broker_t * brk) {

    if (!brk->started) { return; }

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        FATAL_SYS("socket failed");
    }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, broker_context.bcc_path, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un))) {
        FATAL_SYS("connecting to BCC failed");
    }

    broker_control_command_t cmd = {
            .hdr = {
                    .magic = BCC_MAGIC,
                    .cmd = BCC_QUIT
            }
    };

    if (send(fd, &cmd, sizeof(cmd), 0) != sizeof(cmd)) {
        FATAL_SYS("problem sending BCC message");
    }

    full_test_broker_expect(0, brk, 0, TET_BRK_QUIT, TET_NONE);

}

static void * broker_runner(void * arg) {

    test_broker_t * broker = arg;

    int err = E_XL4BUS_OK;
    int locked = 0;

    pthread_setspecific(thread_name_key, f_asprintf("brk %s", broker->name));

    do {

        BOLT_DIR(pthread_mutex_lock(&broker_start_lock), "");
        locked = 1;
        BOLT_DIR(pthread_cond_broadcast(&broker_start_cond), "");

        broker_context.use_bcc = 1;
        broker_context.bcc_path = f_asprintf("/tmp/test-xl4bus-broker%d", getpid());
        broker_context.key_path = f_strdup("./testdata/pki/broker/private.pem");
        add_to_str_array(&broker_context.cert_path, "./testdata/pki/broker/cert.pem");
        add_to_str_array(&broker_context.ca_list, "./testdata/pki/ca/ca.pem");

        BOLT_IF(start_broker(), E_XL4BUS_INTERNAL, "");

        struct sockaddr_in sin;
        socklen_t len = sizeof(sin);
        if (getsockname(broker_context.fd, (struct sockaddr *)&sin, &len) == -1) {
            FATAL_SYS("Can't get port number from broker listen socket");
        } else {
            broker->port = ntohs(sin.sin_port);
        }

        // OK, we started successfully, release the start lock.

        broker->started = 1;
        BOLT_DIR(pthread_mutex_unlock(&broker_start_lock), "");
        locked = 0;

        while (1) {
            int cycle_err = cycle_broker(-1);
            if (cycle_err) {
                test_event_t * event = f_malloc(sizeof(test_event_t));
                event->type = TET_BRK_FAILED;
                submit_event(&broker->events, event);
                err = E_XL4BUS_INTERNAL;
                break;
            }
            if (broker_context.quit) {
                test_event_t * event = f_malloc(sizeof(test_event_t));
                event->type = TET_BRK_QUIT;
                submit_event(&broker->events, event);
                break;
            }
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (locked) {
        pthread_mutex_unlock(&broker_start_lock);
    }

    broker->start_err = err;
    return 0;

}

void submit_event(test_event_t ** event_queue, test_event_t * event) {

    DBG("Submitting event %d to %p", event->type, event_queue);

    if (pthread_mutex_lock(&queue_lock)) {
        FATAL_SYS("locking queue lock");
    }

    DL_APPEND(*event_queue, event);
    if (pthread_cond_broadcast(&queue_cond)) {
        FATAL_SYS("Failing to broadcast queue update");
    }

    if (pthread_mutex_unlock(&queue_lock)) {
        FATAL_SYS("Failed to unlock queue lock");
    }

}

int full_test_client_expect(int timeout_ms, test_client_t * clt, test_event_t ** event, test_event_type_t first, ...) {

    va_list v;
    va_start(v, first);
    int res = test_expect(timeout_ms, &clt->events, event, first, v);
    va_end(v);
    return res;
}

int full_test_client_expect_single(int timeout_ms, test_client_t * clt, test_event_t ** event, test_event_type_t first) {
    return full_test_client_expect(timeout_ms, clt, event, first, TET_NONE, TET_NONE);
}

int full_test_broker_expect(int timeout_ms, test_broker_t * brk, test_event_t ** event, test_event_type_t first, ...) {

    va_list v;
    va_start(v, first);
    int res = test_expect(timeout_ms, &brk->events, event, first, v);
    va_end(v);
    return res;

}

static int test_expect(int timeout_ms, test_event_t ** queue, test_event_t ** event,
        test_event_type_t first, va_list other) {

    va_list use_other;
    va_copy(use_other, other);

    test_event_type_t * success = 0;
    test_event_type_t * failure = 0;
    int success_count = 0;
    int failure_count = 0;

    test_event_type_t ** target = &success;
    int * target_count = &success_count;

    int in_success = 1;
    int is_first = 1;

    while (1) {

        test_event_type_t consider;
        if (is_first) {
            consider = first;
            is_first = 0;
        } else {
            consider = va_arg(use_other, int);
        }

        if (consider == TET_NONE) {
            if (in_success) {
                in_success = 0;
                target = &failure;
                target_count = &failure_count;
            } else {
                break;
            }
        }

        *target = realloc(*target, (*target_count+1) * sizeof(test_event_type_t));
        *target[*target_count] = consider;
        (*target_count)++;

    }

    int err = E_XL4BUS_OK;
    int locked = 0;

    if (event) { *event = 0; }

    do {

        BOLT_IF(!success_count && !failure_count, E_XL4BUS_ARG, "");

        struct timespec ts;

        if (timeout_ms <= 0) {
            timeout_ms = 10 * MILLIS_PER_SEC;
        }

        BOLT_SYS(clock_gettime(CLOCK_REALTIME, &ts), "");
        timespec_add_ms(&ts, timeout_ms);

        BOLT_DIR(pthread_mutex_lock(&queue_lock), "");
        locked = 1;

        int found = 0;

        while (1) {

            while (*queue) {

                test_event_t *head = *queue;

                for (int i=0; i<success_count; i++) {
                    if (head->type == success[i]) {
                        found = 1;
                        break;
                    }
                }

                if (!found) {

                    // certain events are automatically considered
                    // bad, because if the application waited for something
                    // else, but those came instead, there won't be anything else.

                    if (head->type == TET_BRK_FAILED || head->type == TET_CLT_QUIT || head->type == TET_BRK_QUIT) {
                        TEST_ERR("failing on negative event %d", head->type);
                        found = 1;
                        err = E_XL4BUS_DATA;
                        break;
                    }

                    for (int i = 0; i < failure_count; i++) {
                        if (head->type == failure[i]) {
                            TEST_ERR("failing on negative event %d", head->type);
                            found = 1;
                            err = E_XL4BUS_DATA;
                            break;
                        }
                    }

                }

                DL_DELETE(*queue, head);
                if (found && err == E_XL4BUS_OK) {
                    if (event) {
                        *event = head;
                    } else {
                        full_test_free_event(head);
                    }
                    break;
                } else {
                    full_test_free_event(head);
                }

            }

            if (found) {
                break;
            }

            // OK, queue is empty.
            // TEST_MSG("Waiting for event...");
            int rc = pthread_cond_timedwait(&queue_cond, &queue_lock, &ts);
            if (rc) {
                if (rc == ETIMEDOUT) {
                    err = E_XL4BUS_FULL; // $TODO: this really should be timeout...
                    break;
                }
                FATAL_DIR(rc, "error waiting for the condition?");
            }
            continue;
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (locked) {
        pthread_mutex_unlock(&queue_lock);
    }

    return err;

}

void timespec_add_ms(struct timespec * ts, int ms) {

    ts->tv_sec += ms / MILLIS_PER_SEC;
    ts->tv_nsec += ms % MILLIS_PER_SEC;
    if (ts->tv_nsec >= NANOS_PER_SEC) {
        ts->tv_nsec -= NANOS_PER_SEC;
        ts->tv_sec++;
    }

}

void full_test_free_event(test_event_t * evt) {

    if (!evt) { return; }

    if (evt->msg) {
        xl4bus_free_address(evt->msg->address, 1);
        free((void*)evt->msg->content_type);
        free((void*)evt->msg->data);
        free(evt->msg);
    }

    free(evt);

}

char * set_client_thread_name(test_client_t * clt) {

    char * used =  f_asprintf("clt %s", clt->name);
    pthread_setspecific(thread_name_key, used);
    return used;

}

void full_test_print_out(char const * s) {

    char const * thread = pthread_getspecific(thread_name_key);
    if (!thread) { thread = "?"; }
    char * msg = f_asprintf("[%s] %s", thread, s);

    fprintf(stderr, "%s\n", msg);
    if (output_log) {
        fprintf(output_log, "%s\n", msg);
    }

    free(msg);

}

void status_handler(struct xl4bus_client * clt, xl4bus_client_condition_t status) {

    test_client_t * t_clt = (test_client_t*)clt;
    char const * name = pthread_getspecific(thread_name_key);
    if (!name) {
        set_client_thread_name(t_clt);
    }

    if (status == XL4BCC_RUNNING) {
        test_event_t * evt = f_malloc(sizeof(test_event_t));
        evt->type = TET_CLT_RUNNING;
        submit_event(&t_clt->events, evt);
    }

}


void incoming_handler(struct xl4bus_client * clt, xl4bus_message_t * msg) {

    test_client_t * t_clt = (test_client_t*)clt;
    test_event_t * evt = f_malloc(sizeof(test_event_t));
    evt->type = TET_CLT_MSG_RECEIVE;
    evt->msg = f_malloc(sizeof(xl4bus_message_t));
    evt->msg->data = f_malloc(evt->msg->data_len = msg->data_len);
    memcpy((void*)evt->msg->data, msg->data, msg->data_len);
    xl4bus_copy_address(msg->address, 1, &evt->msg->address);
    evt->msg->content_type = f_strdup(msg->content_type);
    submit_event(&t_clt->events, evt);

}

void delivered_handler(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok) {

    test_client_t * t_clt = (test_client_t*)clt;
    test_event_t * evt = f_malloc(sizeof(test_event_t));
    evt->type = ok ? TET_MSG_ACK_OK : TET_MSG_ACK_FAIL;
    evt->msg = msg;
    submit_event(&t_clt->events, evt);

}


void release_handler(struct xl4bus_client * clt) {

    test_client_t * test = (test_client_t *) clt;

    test_event_t * event = f_malloc(sizeof(test_event_t));
    event->type = TET_CLT_QUIT;

    submit_event(&test->events, event);

}

void exclude_test(const char * test) {

    test_case_t * tc;
    HASH_FIND_STR(test_cases, test, tc);

    // don't exclude a test that is specified in the list of test cases
    // explicitly.

    if (tc) { return; }

    tc = f_malloc(sizeof(test_case_t));
    tc->name = f_strdup(test);
    HASH_ADD_KEYPTR(hh, excluded_cases, tc->name, strlen(tc->name), tc);
    TEST_MSG("Will exclude test %s", test);

}

int ignore_failure(const char * name) {

    test_case_t * tc;
    HASH_FIND_STR(ignored_tests, name, tc);
    if (tc) {
        TEST_MSG(">>> FAILURE of %s IS IGNORED", name);
        return 1;
    }

    return 0;

}

void check_loud_mode(const char * name) {

    test_case_t * tc;
    HASH_FIND_STR(loud_tests, name, tc);
    if (tc) {
        TEST_MSG(">>> OUTPUT OF TEST %s", name);
        // dmclient_set_quiet(1);
    }


}

int should_run_test_case(char const * name) {

    if (run_individually) {

        test_case_t * tc;
        HASH_FIND_STR(test_cases, name, tc);
        if (tc) {
            HASH_DEL(test_cases, tc);
            free(tc->name);
            free(tc);
            return 1;
        }

        return 0;

    }

    test_case_t * tc;
    HASH_FIND_STR(excluded_cases, name, tc);
    if (tc) {
        HASH_DEL(excluded_cases, tc);
        HASH_ADD_KEYPTR(hh, was_excluded, tc->name, strlen(tc->name), tc);
        return 0;
    }

    return 1;

}

void end_loud_mode(const char * name) {
#if 0 // this needs to be fixed for xl4bus
    if (set_dmclient_quiet && !dmclient_is_quiet()) {
        dmclient_set_quiet(1);
        TEST_MSG("<<< END OF OUTPUT OF TEST %s", name);
    }
#endif
}

int full_test_send_message(test_client_t * from, test_client_t * to, char * str) {

    xl4bus_message_t * msg = 0;

    int err = E_XL4BUS_OK;

    char * old_name = pthread_getspecific(thread_name_key);
    char * new_name = set_client_thread_name(from);

    do {

        msg = f_malloc(sizeof(xl4bus_message_t));
        BOLT_SUB(xl4bus_get_identity_addresses(&to->bus_client.identity, &msg->address));
        msg->data = str;
        msg->data_len = strlen(str);
        str = 0; // consume
        BOLT_SUB(xl4bus_send_message2(&from->bus_client, msg, 0, 1));

    } while (0);

    if (err != E_XL4BUS_OK) {
        xl4bus_free_address(msg->address, 1);
        free((void*)msg->data);
        free(msg);
    }

    pthread_setspecific(thread_name_key, old_name);
    free(new_name);

    free(str);

    return err;

}
