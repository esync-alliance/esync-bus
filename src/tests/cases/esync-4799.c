
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>

#define MSG1 "туда"
#define MSG2 "сюда"
#define DMC_OID "1.3.6.1.4.1.45473.5.1"

static unsigned char b_a[4] = {
        0x0C, 0x02, 0x2F, 0x61
};

static unsigned char b_b[4] = {
        0x0C, 0x02, 0x2F, 0x62
};

static int test_sender_data(xl4bus_sender_data_t const * sender_data, size_t sender_data_count) {

    int err = E_XL4BUS_OK;

    do {

        TEST_INT_EQUAL(2, sender_data_count);
        TEST_CHR_EQUAL(sender_data[0].oid, DMC_OID);
        TEST_INT_EQUAL(sizeof(b_a), sender_data[0].data_size);
        TEST_MEM_EQUAL(b_a, sender_data[0].data, sizeof(b_a));
        TEST_CHR_EQUAL(sender_data[1].oid, DMC_OID);
        TEST_INT_EQUAL(sizeof(b_b), sender_data[1].data_size);
        TEST_MEM_EQUAL(b_b, sender_data[1].data, sizeof(b_b));

    } while (0);

    return err;

}

int esync_4799() {

    int err = E_XL4BUS_OK;

    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_client_t client2 = {0, .label = f_strdup("client-grp2")};
    test_broker_t broker = { 0};

    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker, 1));
        BOLT_SUB(full_test_client_start(&client2, &broker, 1));
        BOLT_SUB(full_test_send_message(&client1, &client2, f_strdup(MSG1)));
        test_event_t * event;

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, MSG1, strlen(MSG1));

        BOLT_SUB(test_sender_data(event->msg->sender_data, event->msg->sender_data_count));

        full_test_free_event(event);

        BOLT_SUB(full_test_send_message(&client2, &client1, f_strdup(MSG2)));

        BOLT_SUB(full_test_client_expect_single(0, &client2, &event, TET_MSG_ACK_OK));
        full_test_free_event(event);

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_CLT_MSG_RECEIVE));
        TEST_CHR_N_EQUAL(event->msg->data, MSG2, strlen(MSG2));
        TEST_INT_EQUAL(0, event->msg->sender_data_count);
        full_test_free_event(event);

        xl4bus_sender_data_t * data;
        size_t data_count;

        BOLT_SUB(xl4bus_get_identity_data(&client1.bus_client.identity, 0, &data, &data_count));
        BOLT_SUB(test_sender_data(data, data_count));

        xl4bus_sender_data_t * data2;
        BOLT_SUB(xl4bus_copy_sender_data(data, data_count, &data2));
        BOLT_SUB(test_sender_data(data2, data_count));

        /*
        TEST_INT_EQUAL(2, data_count);
        TEST_INT_EQUAL(sizeof(b_a), data[0].data_size);
        TEST_MEM_EQUAL(b_a, data[0].data, sizeof(b_a));
        TEST_INT_EQUAL(sizeof(b_b), data[1].data_size);
        TET_MEM_EQUAL(b_b, data[1].data, sizeof(b_b));
         */

        xl4bus_free_sender_data(data, data_count);
        xl4bus_free_sender_data(data2, data_count);

        // make sure we handle 0s well:
        xl4bus_copy_sender_data(0, 0, &data2);

        BOLT_SUB(xl4bus_get_identity_data(&client2.bus_client.identity, 0, &data, &data_count));
        TEST_INT_EQUAL(0, 0);

    } while (0);

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}