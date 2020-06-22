#include <bus-test-support.h>
#include <lib/common.h>
#include <basics.h>
#include "embedded/embedded_test_functions.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"

#define TET_INCOMING_CORRUPTED (TET_TEST+1)
#define TET_CT_CORRUPTED (TET_TEST+2)

int multi_dest_mem_leak() {

    // this all here is just to make sure it doesn't leak, as
    // quite some memory leakage was found with clients that receive
    // messages with multiple keys.

    int err = E_XL4BUS_OK;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_client_t client3 = {0, .label = f_strdup("ua-rom")};
    test_broker_t broker = { 0};

    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));
        BOLT_SUB(full_test_client_start(&client3, &broker, 1));

        xl4bus_address_t * addr = 0;
        xl4bus_chain_address(&addr, XL4BAT_GROUP, "grp1", 1);
        xl4bus_chain_address(&addr, XL4BAT_GROUP, "grp2", 1);

        BOLT_SUB(full_test_send_message2(&client3, addr, f_strdup("boo")));

        xl4bus_free_address(addr, 1);

        test_event_t * event;
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "boo", 3);
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "boo", 3);
        full_test_free_event(event);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_client_stop(&client3, 1);
    full_test_broker_stop(&broker, 1);

    return err;


}

static test_client_t * rcv_client;

static int intercept_ll(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg) {

    int rc = E_XL4BUS_INTERNAL;

    int was_incoming_corrupted = esync_4843_corrupted_incoming;
    int was_details_corrupted = esync_4843_corrupted_cert_details;

    if (!esync_4843_corrupt(conn, msg, &rcv_client->bus_client)) {
        rc = xl4bus_process_ll_message(conn, msg);
    }

    if (!was_incoming_corrupted && esync_4843_corrupted_incoming) {
        full_test_submit_event(&rcv_client->events, TET_INCOMING_CORRUPTED);
    }
    if (!was_details_corrupted && esync_4843_corrupted_cert_details) {
        full_test_submit_event(&rcv_client->events, TET_CT_CORRUPTED);
    }

    return rc;

}

int disconnect_on_malformed() {

    int err = E_XL4BUS_OK;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_broker_t broker = {0};

    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));

        rcv_client = &client2;
        test_message_interceptor = intercept_ll;

        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("will fail")));

        test_event_t * event;
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_INCOMING_CORRUPTED));
        full_test_free_event(event);

        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("will fail too")));

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CT_CORRUPTED));
        full_test_free_event(event);

        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("ok")));

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_ERR("msg rcv: %.*s", (int)event->msg->data_len, event->msg->data);
        TEST_CHR_N_EQUAL(event->msg->data, "ok", 2);
        full_test_free_event(event);

        TEST_INT_EQUAL(esync_4843_corrupted_incoming, 1);
        TEST_INT_EQUAL(esync_4843_corrupted_cert_details, 1);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    Z(free, esync_4843_copy_message);

    return err;

}

int esync_4843() {

    int err = E_XL4BUS_OK;

    do {
        BOLT_SUB(multi_dest_mem_leak());
        BOLT_SUB(disconnect_on_malformed());
    } while (0);

    return err;

}