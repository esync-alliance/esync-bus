
#ifndef _TEST_FULL_TEST_H_
#define _TEST_FULL_TEST_H_

#ifdef WITH_UNIT_TEST

#include <libxl4bus/high_level.h>

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
#define TEST_DBG(s, a...) do { PRINT_LN(!dmclient_is_quiet(), "DBG", " " s, ## a); } while (0)


typedef enum test_event_type {
    TET_NONE = 0,
    TET_CLT_MSG_RECEIVE,
    TET_BRK_QUIT,
    TET_BRK_FAILED,
    TET_CLIENT_QUIT
} test_event_type_t;

typedef struct test_event {

    struct test_event * next;
    struct test_event * prev;
    test_event_type_t type;

} test_event_t;

typedef struct test_client {

    xl4bus_client_t bus_client; // must be first!
    test_event_t * events;
    int started;

} test_client_t;

typedef struct test_broker {

    int port;
    int start_err;
    int started;
    test_event_t * events;

} test_broker_t;

int full_test_client_start(test_client_t *, test_broker_t *);
void full_test_client_stop(test_client_t *);
int full_test_broker_start(test_broker_t *);
void full_test_broker_stop(test_broker_t *);
void free_test_event(test_event_t *);

int full_test_client_expect(int timeout_ms, test_client_t *, test_event_t ** event, test_event_type_t first, ...);
int full_test_broker_expect(int timeout_ms, test_broker_t *, test_event_t ** event, test_event_type_t first, ...);

extern FILE * output_log;

#endif

#endif
