
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>
#include "bus-test-support.h"
#include "basics.h"

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

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}

test_client_t stream_reused_client1 = {0};


static int stream_reused_message_handler(xl4bus_client_t * clt, xl4bus_ll_message_t * msg,
        struct decrypt_and_verify_data * dav, json_object * root, char const * type, int * need_reconnect) {

    test_client_t * t_clt = (test_client_t*)clt;

    if (t_clt == &stream_reused_client1) {

        if (!z_strcmp(type, MSG_TYPE_REQ_KEY)) {
            // instead of responding to the key request, unblock the main test thread to proceed with
            // further testing.
            full_test_submit_event(&t_clt->events, TET_TEST);
            return E_XL4BUS_OK;
        }

    }

    return xl4bus_process_client_message(clt, msg, dav, root, type, need_reconnect);

}

static int stream_reused() {

    int err /*= E_XL4BUS_OK */;

    stream_reused_client1.label = f_strdup("client-grp1");
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_client_t client3 = {0, .label = f_strdup("client-grp1")};
    test_broker_t broker = { 0};

    do {

        test_event_t * event;

        TEST_SUB(full_test_broker_start(&broker));
        TEST_SUB(full_test_client_start(&stream_reused_client1, &broker, 1));
        TEST_SUB(full_test_client_start(&client2, &broker, 1));

        // enter meddling mode
        test_control_message_interceptor = stream_reused_message_handler;

        TEST_SUB(full_test_send_message(&stream_reused_client1, &client2, f_strdup("boo")));
        TEST_SUB(full_test_client_expect_single(0, &stream_reused_client1, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        TEST_SUB(full_test_client_expect_single(0, &stream_reused_client1, &event, TET_TEST));
        full_test_free_event(event);

        full_test_client_stop(&stream_reused_client1, 1);
        TEST_SUB(full_test_broker_stop(&broker, 0));

        TEST_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_DISCONNECTED));
        full_test_free_event(event);

        TEST_SUB(full_test_broker_start(&broker));

        TEST_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_RUNNING));
        full_test_free_event(event);

        TEST_SUB(full_test_client_start(&client3, &broker, 1));

        TEST_SUB(full_test_send_message(&client3, &client2, f_strdup("boo")));
        TEST_SUB(full_test_client_expect_single(0, &client3, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        TEST_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, "boo", 3);
        full_test_free_event(event);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    full_test_client_stop(&stream_reused_client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_client_stop(&client3, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}

int esync_4413() {

    int err /*= E_XL4BUS_OK*/;

    do {

        TEST_SUB(key_used_twice());
        TEST_SUB(stream_reused());

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;

}