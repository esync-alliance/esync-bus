
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>

static int key_used_twice() {

    int err /*= E_XL4BUS_OK */;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_broker_t broker = { 0};

    do {

        test_event_t * event;

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));

        BOLT_SUB(full_test_client_pause_receive(&client1, 1));

        BOLT_SUB(full_test_send_message(&client2, &client1, f_strdup("boo")));
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_send_message(&client2, &client1, f_strdup("far")));
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_pause_receive(&client1, 0));

        test_event_t * event1;
        test_event_t * event2;
        BOLT_SUB(full_test_client_expect_single(0, &client1, &event1, TET_CLT_MSG_RECEIVE));
        BOLT_SUB(full_test_client_expect_single(0, &client1, &event2, TET_CLT_MSG_RECEIVE));

        // the condition is complicated because realistically there is no expectation that messages come
        // in any specific order.
        if ((strncmp(event1->msg->data, "boo", 3) || strncmp(event2->msg->data, "far", 3)) &&
                (strncmp(event1->msg->data, "far", 3) || strncmp(event2->msg->data, "boo", 3))) {

            BOLT_SAY(E_XL4BUS_INTERNAL, "Expected messages boo and far, but got: %.3s and %.3s",
                    event1->msg->data, event2->msg->data);

        }

        full_test_free_event(event1);
        full_test_free_event(event2);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}

static int stream_reused() {

    int err /*= E_XL4BUS_OK */;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_broker_t broker = { 0};

    do {

        test_event_t * event;

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));

        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("boo")));
        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "boo", 3);
        full_test_free_event(event);

        BOLT_SUB(full_test_broker_stop(&broker, 0));

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_CLT_DISCONNECTED));
        full_test_free_event(event);
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_DISCONNECTED));
        full_test_free_event(event);

        BOLT_SUB(full_test_broker_start(&broker));

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_CLT_RUNNING));
        full_test_free_event(event);
        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_RUNNING));
        full_test_free_event(event);

        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup("boo")));
        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "boo", 3);
        full_test_free_event(event);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}

int esync_4413() {

    int err /*= E_XL4BUS_OK*/;

    do {

        TEST_SUB(stream_reused());
        TEST_SUB(key_used_twice());

    } while (0);

    return err;

}