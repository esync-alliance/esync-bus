
#include <misc.h>
#include <basics.h>
#include "debug.h"
#include "internal.h"
#include "embedded_test_functions.h"
#include "renamed_json.h"

int esync_4843_corrupted_incoming = 0;
int esync_4843_corrupted_cert_details = 0;
void * esync_4843_copy_message = 0;

int esync_4843_corrupt(xl4bus_connection_t * conn, xl4bus_ll_message_t * msg, xl4bus_client_t * for_client) {

    xl4bus_client_t * clt = conn->custom;

    DBG("Considering: %.*s, %s", (int)msg->data_len, msg->data, msg->bus_data);

    if (clt != for_client) {
        return 0;
    }

    client_internal_t * i_clt = clt->_private;

    if (i_clt->state == CS_RUNNING) {

        message_internal_t *mint = 0;
        HASH_FIND(hh, i_clt->stream_hash, &msg->stream_id, 2, mint);

        if (!mint && !esync_4843_corrupted_incoming) {

            char * s = f_asprintf("%.*s", (int)msg->data_len, msg->data);
            json_object * obj = json_tokener_parse(s);
            uint8_t * kid_bin = 0;
            char * kid_out_str = 0;
            char const * kid_str;

            if (obj && !xl4json_get_pointer(obj, "/header/kid", json_type_string, &kid_str)) {

                size_t kid_bin_len;

                if (cjose_base64url_decode(kid_str, strlen(kid_str), &kid_bin, &kid_bin_len, 0)
                        && kid_bin_len >= conn->my_x5t_bin.len * 2
                        && !memcmp(kid_bin + conn->my_x5t_bin.len, conn->my_x5t_bin.data, conn->my_x5t_bin.len)) {

                    // OK, mess with the KID then

                    kid_bin[conn->my_x5t_bin.len]++; // this makes it not ours.

                    size_t kid_out_str_len;

                    if (cjose_base64url_encode(kid_bin, kid_bin_len, &kid_out_str, &kid_out_str_len, 0)) {

                        DBG("Will corrupt %s", json_object_get_string(obj));

                        if (!json_pointer_set(&obj, "/header/kid",
                                json_object_new_string_len(kid_out_str, kid_out_str_len))) {

                            esync_4843_corrupted_incoming ++;
                            // free((void*)msg->data); // we can't free that, because it's referenced by some other
                            // object that is cleaned up separately. So we have to just allocate the memory, which
                            // means we also have to clean it up later.
                            msg->data = esync_4843_copy_message = f_strdup(json_object_get_string(obj));
                            msg->data_len = strlen(msg->data) + 1;

                            DBG("Corrupted: %.*s", (int)msg->data_len, msg->data);

                        }

                    }

                }

                free(kid_out_str);
                free(kid_bin);
                json_object_put(obj);
                free(s);

            }

        } else if (mint && !esync_4843_corrupted_cert_details && !z_strcmp(msg->content_type, FCT_BUS_MESSAGE)) {

            char * s = f_asprintf("%.*s", (int)msg->data_len, msg->data);
            json_object * obj = json_tokener_parse(s);
            char const * type;

            if (obj && !xl4json_get_pointer(obj, "/type", json_type_string, &type) && !z_strcmp(type, MSG_TYPE_CERT_DETAILS)) {

                // OK, we want to corrupt that. It's enough to just both the content-type, though.
                msg->content_type = FCT_APPLICATION_OCTET_STREAM;
                esync_4843_corrupted_cert_details = 1;
            }

            json_object_put(obj);
            free(s);

        }

    }

    return 0;

}
