
#include <libxl4bus/low_level.h>
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/common.h"
#include "lib/debug.h"

int esync_4417() {

    int err/* = E_XL4BUS_OK*/;

    test_client_t client1 = {0, .label = f_strdup("ua-and-group")};
    test_client_t client2 = {0, .label = f_strdup("client-grp1")};
    test_broker_t broker = {0};

    do {

        TEST_SUB(full_test_broker_start(&broker));
        TEST_SUB(full_test_client_start(&client1, &broker, 1));
        TEST_SUB(full_test_client_start(&client2, &broker, 1));

        TEST_SUB(full_test_send_message(&client1, &client2, f_strdup("boo")));
        test_event_t * event;
        TEST_SUB(full_test_client_expect_single(0, &client2, &event, TET_CLT_MSG_RECEIVE));

        TEST_SUB(xl4bus_require_group("group", event->msg->source_address));
        TEST_SUB(xl4bus_require_update_agent("/UA", event->msg->source_address));
        TEST_SUB(xl4bus_require_group("grp1", event->msg->address));

        TEST_IF(event->msg->source_address->next->next);

        full_test_free_event(event);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    full_test_client_stop(&client1, 1);
    full_test_client_stop(&client2, 1);
    full_test_broker_stop(&broker, 1);

    return err;

}
