
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>

int esync_5093() {

    int err = E_XL4BUS_OK;

    xl4bus_client_t no_client = {0};
    // make sure this doesn't SIGSEGV
    xl4bus_stop_client(&no_client);


    test_client_t client1 = {0, .label = f_strdup("client-grp1")};
    test_broker_t broker = { 0};

    do {

        test_event_t * event;

        BOLT_SUB(full_test_broker_start(&broker));

        free(broker.host);
        broker.host = f_strdup("non.existing.domain.name.i.hope.ever.is.noneexistingdomain");

        BOLT_SUB(full_test_client_start(&client1, &broker, 0));
        // send message to nowhere

        BOLT_SUB(full_test_client_expect_single(0, &client1, &event, TET_CLT_DNS_FAILED));
        full_test_free_event(event);

        full_test_client_stop(&client1, 1);
        full_test_broker_stop(&broker, 1);


    } while (0);

    return err;

}
