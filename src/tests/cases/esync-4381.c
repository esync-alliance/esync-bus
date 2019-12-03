
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>

int esync_4381() {

    int err = E_XL4BUS_OK;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_client_t client3 = {0, .label = f_strdup("ua-rom")};
    test_client_t client4 = {0, .label = f_strdup("ua-tbox")};
    test_broker_t broker = { 0};

    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));
        BOLT_SUB(full_test_client_start(&client3, &broker, 1));
        BOLT_SUB(full_test_client_start(&client4, &broker, 1));
        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("boo")));
        test_event_t * event;
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "boo", 3);
        full_test_free_event(event);
        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_send_message(&client4, &client3, f_strdup("kangaroo")));
        BOLT_SUB(full_test_client_expect_single(0, &client3, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "kangaroo", 3);
        full_test_free_event(event);
        BOLT_SUB(full_test_client_expect_single(0, &client4, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_client_stop(&client3, 1);
    full_test_client_stop(&client4, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}