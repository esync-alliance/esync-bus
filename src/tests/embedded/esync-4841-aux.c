
#include <debug.h>
#include "internal.h"
#include "embedded_test_functions.h"
#include "embedded_test_exposure.h"

int esync_4841_intercept(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, xl4bus_client_t * for_client) {

    xl4bus_client_t * clt = conn->custom;

    if (clt != for_client) {
        return 0;
    }

    client_internal_t * i_clt = clt->_private;

    // we want to prevent the client to receive cert-details message. We return 1 (error) that will collapse
    // the connection and leave an internal message object in an unhandled state.

    if (i_clt->state == CS_RUNNING) {

        message_internal_t *mint = 0;
        HASH_FIND(hh, i_clt->stream_hash, &msg->stream_id, 2, mint);
        // here we are cheating a little bit, and just tanking any message that has a mint.
        if (mint) { return 1; }
    }

    return 0;

}

int esync_4841_check_mints(xl4bus_client_t * clt) {

    client_internal_t * i_clt = clt->_private;
    int err = E_XL4BUS_OK;

    message_internal_t * mint;

    do {

#if XL4_SUPPORT_THREADS
        BOLT_SYS(pf_lock(&i_clt->hash_lock), "");
#endif
        DL_FOREACH(i_clt->message_list, mint) {
            BOLT_IF(e_test_is_mint_incoming(mint), E_XL4BUS_INTERNAL, "no incoming messages allowed");
        }

#if XL4_SUPPORT_THREADS
        pf_unlock(&i_clt->hash_lock);
#endif

    } while (0);

    return err;

}