
#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "lib/debug.h"
#include <libxl4bus/low_level.h>

int hello_world() {

    int err = E_XL4BUS_OK;

    test_client_t client1 = {0};
    test_client_t client2 = {0};
    test_broker_t broker = { 0};

    do {

        BOLT_SUB(full_test_broker_start(&broker));
        BOLT_SUB(full_test_client_start(&client1, &broker));
        BOLT_SUB(full_test_client_start(&client2, &broker));

    } while (0);

    full_test_client_stop(&client1);
    full_test_client_stop(&client2);
    full_test_broker_stop(&broker);

    return err;

}