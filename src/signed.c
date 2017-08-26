
#include <config.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"

int validate_jws(void * bin, size_t jws_len, int ct, uint16_t * stream_id, mbedtls_x509_crt * trust,
        mbedtls_x509_crl * crl, cjose_jws_t ** exp_jws) {

    if (ct != CT_JOSE_COMPACT) {
        // cjose library only supports compact!
        DBG("Can't validate unknown content type %d", ct);
        return E_XL4BUS_DATA;
    }

    cjose_err c_err;

    cjose_jws_t *jws = 0;
    json_object *hdr = 0;
    int err = E_XL4BUS_OK;
    char * x5c = 0;
    const char * x5t = 0;

    do {

        BOLT_IF(((char*)bin)[--jws_len], E_XL4BUS_DATA, "Compact serialization is not ASCISZ");

        // DBG("Verifying serialized JWS (len %d, strlen %d) %s", jws_len, strlen(bin), bin);

        BOLT_CJOSE(jws = cjose_jws_import(bin, jws_len, &c_err));

        cjose_header_t *p_headers = cjose_jws_get_protected(jws);
        const char *hdr_str;

        // is there an x5c entry?
        BOLT_CJOSE(x5c = cjose_header_get_raw(p_headers, "x5c", &c_err));

        if (x5c) {
            BOLT_SUB(accept_x5c(x5c, i_conn, &x5t));
        } else {
            BOLT_CJOSE(x5t = cjose_header_get(p_headers, "x5t#S256", &c_err));
        }

        BOLT_CJOSE(hdr_str = cjose_header_get(p_headers, "x-xl4bus", &c_err));

        hdr = json_tokener_parse(hdr_str);
        if (!hdr || !json_object_is_type(hdr, json_type_object)) {
            BOLT_SAY(E_XL4BUS_DATA, "No x-xl4bus property in the header");
        }

        // $TODO: use proper key!
        BOLT_IF(!cjose_jws_verify(jws, test_jwk_pub, &c_err), E_XL4BUS_DATA, "Failed JWS verify");

        // $TODO: check nonce/timestamp

        if (stream_id) {

            json_object *j;
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

            *stream_id = (uint16_t) val;

        }

    } while (0);

    cfg.free(x5c);

    json_object_put(hdr);

    if ((err == E_XL4BUS_OK) && exp_jws) {
        *exp_jws = jws;
    } else {
        cjose_jws_release(jws);
    }

    return err;

}

int sign_jws(cjose_jwk_t * key, const char * x5, int is_full_x5, const void *data, size_t data_len,
        char const * ct, int pad, int offset, char **jws_data, size_t *jws_len) {

    cjose_err c_err;
    cjose_jws_t *jws = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;

    do {

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, "RS256", &c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        if (is_full_x5) {
            BOLT_CJOSE(cjose_header_set_raw(j_hdr, "x5c", x5, &c_err));
        } else {
            BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", x5, &c_err));
        }

        json_object * obj = json_object_new_object();

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(obj), &c_err));

        BOLT_CJOSE(jws = cjose_jws_sign(key, j_hdr, data, data_len, &c_err));

        const char *jws_export;

        BOLT_CJOSE(cjose_jws_export(jws, &jws_export, &c_err));

        size_t l = strlen(jws_export) + 1;
        if (!(*jws_data = f_malloc(l + pad))) {
            err = E_XL4BUS_MEMORY;
            break;
        }

        // DBG("Serialized JWS(%d bytes) %s, ", l-1, jws_export);

        memcpy((*jws_data) + offset, jws_export, *jws_len = l);

    } while (0);

    cjose_jws_release(jws);
    cjose_header_release(j_hdr);

    return err;

}

int encrypt_jwe(cjose_jwk_t * key, const void *data, size_t data_len,
        char const * ct, int pad, int offset, char **jws_data, size_t *jws_len) {

    cjose_err c_err;
    cjose_jwe_t *jwe = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;

    do {

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256CBC_HS512, &c_err));
        // x5t#S256 must be in the key.
        // BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", x5t, &c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        json_object * obj = json_object_new_object();

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(obj), &c_err));

        // $TODO: use proper key

        BOLT_CJOSE(jwe = cjose_jwe_encrypt(key, j_hdr, data, data_len, &c_err));

        const char *jwe_export;

        BOLT_CJOSE(jwe_export = cjose_jwe_export(jwe, &c_err));

        size_t l = strlen(jwe_export) + 1;
        if (!(*jws_data = f_malloc(l + pad))) {
            err = E_XL4BUS_MEMORY;
            break;
        }

        // DBG("Serialized JWS(%d bytes) %s, ", l-1, jws_export);

        memcpy((*jws_data) + offset, jwe_export, *jws_len = l);

    } while (0);

    cjose_jwe_release(jwe);
    cjose_header_release(j_hdr);

    return err;

}
