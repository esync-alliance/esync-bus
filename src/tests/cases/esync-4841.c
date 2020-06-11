
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include "bus-test-support.h"
#include "embedded/embedded_test_functions.h"
#include <libxl4bus/low_level.h>

typedef int (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_ll_message_t *);

xl4bus_client_t * rcv_client;

static int intercept_ll(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {
    if (!esync_4841_intercept(conn, msg, rcv_client)) {
        return xl4bus_process_ll_message(conn, msg);
    }
}

int esync_4841() {

    int err = E_XL4BUS_OK;


    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_broker_t broker = {0};


    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));

        rcv_client = &client2.bus_client;
        test_message_interceptor = intercept_ll;

        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("boo")));
        test_event_t * event;

        // client 2 should die because of our intercept.
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_DISCONNECTED));
        full_test_free_event(event);

        // the beef - no incompletely received mints must be left over
        BOLT_SUB(esync_4841_check_mints(&client2.bus_client));

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);


    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}