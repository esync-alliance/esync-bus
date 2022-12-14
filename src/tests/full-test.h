
#ifndef _TEST_FULL_TEST_H_
#define _TEST_FULL_TEST_H_

#ifdef WITH_UNIT_TEST

#include <libxl4bus/high_level.h>
#include "broker/broker.h"

#define PRINT_LN(to_prt, s, fm, a...) do { \
    char now__[25]; \
    str_output_time(now__); \
    char * str = f_asprintf(s " %s%s:%s:%d" fm "\n", now__, __func__, chop_path(__FILE__), __LINE__, ## a); \
    if (to_prt) { \
        fprintf(stderr, "%s", str); \
    } \
    if (output_log) { \
        fprintf(output_log, "%s", str); \
    } \
    free(str); \
} while (0)

#define TEST_DO(a, b) TEST_DO2(a, b, 0)

#define TEST_ERR(s, a...) PRINT_LN(1, "ERR", " " s, ## a)
#define TEST_MSG(s, a...) PRINT_LN(1, "MSG", " " s, ## a)
#define TEST_DBG(s, a...) PRINT_LN(show_debug, "DBG", " " s, ## a)
#define TEST_SUB(a) { err = (a); if (err != E_XL4BUS_OK) { BOLT_SAY(err, "FAIL - " #a); } else { TEST_MSG("OK - " #a); }} do{}while(0)
#define TEST_IF(a) BOLT_IF(a, E_XL4BUS_INTERNAL, "FAIL - " #a)
// { if ((a) != E_XL4BUS_OK) { BOLT_SAY(err, "FAIL - " #a); } else { TEST_MSG("OK - " #a); }} do{}while(0)

typedef enum test_event_type {
    TET_NONE = 0,
    TET_CLT_MSG_RECEIVE,
    TET_BRK_QUIT,
    TET_BRK_FAILED,
    TET_CLT_QUIT,
    TET_CLT_PAUSED, // reception paused
    TET_CLT_UNPAUSED, // reception unpaused
    TET_CLT_DISCONNECTED, // connection to broker lost
    TET_CLT_DNS_FAILED, // resolving broker host name failed
    TET_CLT_CONN_FAILED, // connection to broker failed
    TET_MSG_ACK_OK,
    TET_MSG_ACK_FAIL,
    TET_CLT_RUNNING,
    TET_TEST = 50000, // test can use this as a base value.
} test_event_type_t;

typedef struct test_event {

    struct test_event * next;
    struct test_event * prev;
    test_event_type_t type;
    xl4bus_message_t * msg;

} test_event_t;

typedef struct test_client {

    xl4bus_client_t bus_client; // must be first!
    test_event_t * events;
    int started;
    char * label;
    char * name;
    pthread_t client_thread;
    char * query;

} test_client_t;

typedef struct test_broker {

    int port;
    int start_err;
    int started;
    test_event_t * events;
    char * name;
    broker_context_t context;
    pthread_t thread;
    char * host;
    char * net_if;

} test_broker_t;

/**
 * Starts a test client.
 * @param wait_for_latch if `!0`, then waits until connection to the broker is considered established.
 * @return
 */
int full_test_client_start(test_client_t *, test_broker_t *, int wait_for_latch);
void full_test_client_stop(test_client_t *, int release);
int full_test_broker_start(test_broker_t *);
int full_test_broker_stop(test_broker_t *, int release);
void full_test_free_event(test_event_t *);
int full_test_client_pause_receive(test_client_t *, int pause);

int full_test_client_expect(int timeout_ms, test_client_t *, test_event_t ** event, test_event_type_t first, ...);
int full_test_client_expect_single(int timeout_ms, test_client_t *, test_event_t ** event, test_event_type_t first);
int full_test_broker_expect(int timeout_ms, test_broker_t *, test_event_t ** event, test_event_type_t first, ...);
void full_test_print_out(char const * msg);
void full_test_print_out_d(int, int, char const * msg);
int full_test_send_message(test_client_t * from, test_client_t * to, char * str);
int full_test_send_message2(test_client_t * from, xl4bus_address_t * to, char * str);
extern char const * test_name;
int full_test_if_bus_message(const xl4bus_ll_message_t *, char const *);
void full_test_submit_event(test_event_t ** event_queue, test_event_type_t type, ...);

#define TEST_CHR_EQUAL(chr1, chr2) BOLT_IF(z_strcmp(chr1, chr2), E_XL4BUS_INTERNAL, "String %s was expected to be equal to %s", chr2, chr1)
#define TEST_CHR_N_EQUAL(chr1, chr2, len) BOLT_IF(z_strncmp(chr1, chr2, len), E_XL4BUS_INTERNAL, "String %.*s was expected to be equal to %.*s", len, chr2, len, chr1)
#define TEST_INT_EQUAL(int1, int2) BOLT_IF(int1 != int2, E_XL4BUS_INTERNAL, "Value %d was expected to be equal to %d", int2, int1)
#define TEST_MEM_EQUAL(addr1, addr2, len) BOLT_IF(memcmp(addr1, addr2, len), E_XL4BUS_INTERNAL, "Memory at %p did not match memory at %p for %zu", addr1, addr2, len)

extern FILE * output_log;
extern int show_debug;

#endif

#endif
