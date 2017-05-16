
#include <config.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"

int validate_jws(void * bin, size_t jws_len, int ct, uint16_t * stream_id) {

    if (ct != CT_JOSE_COMPACT) {
        // cjose library only supports compact!
        return E_XL4BUS_DATA;
    }

    cjose_err c_err;

    cjose_jws_t * jws = 0;
    json_object * hdr = 0;
    int err;

    do {

        jws = cjose_jws_import(bin, jws_len, &c_err);
        err = cjose_to_err(&c_err);

        if (err != E_XL4BUS_OK) { break; }

        // $TODO: call jws_validate

        cjose_header_t * p_headers = cjose_jws_get_protected(jws);
        const char * hdr_str = cjose_header_get(p_headers, "x-xl4bus", &c_err);
        err = cjose_to_err(&c_err);

        if (err != E_XL4BUS_OK) { break; }

        hdr = json_tokener_parse(hdr_str);
        if (!hdr || !json_object_is_type(hdr, json_type_object)) {
            err = E_XL4BUS_DATA;
            break;
        }

        // $TODO: check nonce/timestamp

        if (stream_id) {

            json_object * j;
            if (!json_object_object_get_ex(hdr, "stream-id", &j) ||
                    !json_object_is_type(j, json_type_int)) {
                err = E_XL4BUS_DATA;
                break;
            }

            int val = json_object_get_int(j);
            if (val & 0xffff) {
                err = E_XL4BUS_DATA;
                break;
            }

            *stream_id = (uint16_t)val;

        }


    } while(0);

    cjose_jws_release(jws);
    json_object_put(hdr);

    return err;

}

int sign_jws(const void * data, size_t data_len, int pad, int offset, char ** jws_data, size_t * jws_len) {

    cjose_err err;
    cjose_jws_t * jws = 0;
    int res; // = E_XL4BUS_OK;
    do {

        jws = cjose_jws_sign(0, 0, data, data_len, &err);
        if ((res = cjose_to_err(&err)) != E_XL4BUS_OK) {
            break;
        }

        const char * jws_export;

        cjose_jws_export(jws, &jws_export, &err);
        res = cjose_to_err(&err);

        if (res != E_XL4BUS_OK) { break; }

        size_t l = strlen(jws_export) + 1;
        if (!(* jws_data = f_malloc(l+pad))) {
            res = E_XL4BUS_MEMORY;
            break;
        }

        memcpy((*jws_data)+offset, jws_export, l);
        *jws_len = l;

    } while (0);

    cjose_jws_release(jws);

    return res;

}
