
#include <config.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"

int validate_jws(void * bin, size_t bin_len, int ct, xl4bus_connection_t * conn,
        cjose_jws_t ** exp_jws, json_object ** bus_object) {

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
    json_object * x5c_json = 0;
    char * x5t = 0;
    cjose_jwk_t * key = 0;
    connection_internal_t * i_conn = conn->_private;

    do {

        BOLT_IF(((char*)bin)[--bin_len], E_XL4BUS_DATA, "Compact serialization is not ASCISZ");

        // DBG("Verifying serialized JWS (len %d, strlen %d) %s", bin_len, strlen(bin), bin);

        BOLT_CJOSE(jws = cjose_jws_import(bin, bin_len, &c_err));

        cjose_header_t *p_headers = cjose_jws_get_protected(jws);
        const char *hdr_str;

        // is there an x5c entry?
        BOLT_CJOSE(x5c = cjose_header_get_raw(p_headers, "x5c", &c_err));

        if (x5c) {

            BOLT_IF((!(x5c_json = json_tokener_parse(x5c)) ||
                     !json_object_is_type(x5c_json, json_type_array)),
                    E_XL4BUS_DATA, "x5c attribute is not a json array");

            BOLT_SUB(accept_x5c(x5c_json, conn, &x5t, 0));
        } else {
            BOLT_CJOSE(x5t = f_strdup(cjose_header_get(p_headers, "x5t#S256", &c_err)));
        }

        key = find_key_by_x5t(x5t);
        BOLT_IF(!key, E_XL4BUS_SYS, "Could not find JWK for tag %s", NULL_STR(x5t));

        if (conn->remote_x5t) {
            BOLT_IF(strcmp(conn->remote_x5t, x5t), E_XL4BUS_DATA,
                    "Connection set with tag %s, received tag %s", x5t, conn->remote_x5t);
        }

        BOLT_CJOSE(hdr_str = cjose_header_get(p_headers, "x-xl4bus", &c_err));

        hdr = json_tokener_parse(hdr_str);
        if (!hdr || !json_object_is_type(hdr, json_type_object)) {
            BOLT_SAY(E_XL4BUS_DATA, "No x-xl4bus property in the header");
        }

        BOLT_IF(!cjose_jws_verify(jws, key, &c_err), E_XL4BUS_DATA, "Failed JWS verify");

        if (!conn->remote_x5t) {
            conn->remote_x5t = x5t;
            x5t = 0;
            cjose_jwk_release(i_conn->remote_key);
            i_conn->remote_key = key;
            key = 0;
        }

        // $TODO: check nonce/timestamp

    } while (0);

    cfg.free(x5c);
    cfg.free(x5t);
    cjose_jwk_release(key);
    json_object_put(x5c_json);

    if (err == E_XL4BUS_OK) {
        if (exp_jws) {
            *exp_jws = jws;
            jws = 0;
        }
        if (bus_object) {
            *bus_object = hdr;
            hdr = 0;
        }
    }

    json_object_put(hdr);
    cjose_jws_release(jws);

    return err;

}

int sign_jws(cjose_jwk_t * key, const char * x5, int is_full_x5, json_object * bus_object, const void *data, size_t data_len,
        char const * ct, int pad, int offset, char **jws_data, size_t *jws_len) {

    cjose_err c_err;
    cjose_jws_t *jws = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;

    do {

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, "RS256", &c_err));

        // this is for https://tools.ietf.org/html/rfc7515#section-4.1.10,
        // application/ can be omitted if there are no other slashes.
        if (!strncmp(ct, "application/", 12) && !strchr(ct+12, '/')) {
            ct += 12;
        }

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        if (is_full_x5) {
            BOLT_CJOSE(cjose_header_set_raw(j_hdr, "x5c", x5, &c_err));
        } else {
            BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", x5, &c_err));
        }

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(bus_object), &c_err));

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

int encrypt_jwe(cjose_jwk_t * key, const char * x5t, const void * data, size_t data_len,
                char const * ct, int pad, int offset, char ** jwe_data, size_t * jwe_len) {

    cjose_err c_err;
    cjose_jwe_t *jwe = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;

    do {

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256CBC_HS512, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", x5t, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        json_object * obj = json_object_new_object();

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(obj), &c_err));

        // $TODO: use proper key

        BOLT_CJOSE(jwe = cjose_jwe_encrypt(key, j_hdr, data, data_len, &c_err));

        const char *jwe_export;

        BOLT_CJOSE(jwe_export = cjose_jwe_export(jwe, &c_err));

        size_t l = strlen(jwe_export) + 1;
        if (!(*jwe_data = f_malloc(l + pad))) {
            err = E_XL4BUS_MEMORY;
            break;
        }

        // DBG("Encrypted JWE(%d bytes) %s, ", l-1, jwe_export);

        memcpy((*jwe_data) + offset, jwe_export, *jwe_len = l);

    } while (0);

    cjose_jwe_release(jwe);
    cjose_header_release(j_hdr);

    return err;

}

int decrypt_jwe(void * bin, size_t bin_len, int ct, char * x5t, cjose_jwk_t * key,
        void ** decrypted, size_t * decrypted_len, char ** decrypted_ct) {

    if (ct != CT_JOSE_COMPACT) {
        // cjose library only supports compact!
        DBG("Can't decrypt unknown content type %d", ct);
        return E_XL4BUS_DATA;
    }

    cjose_err c_err;

    cjose_jwe_t *jwe = 0;
    int err = E_XL4BUS_OK;
    *decrypted = 0;

    do {

        BOLT_IF(((char*)bin)[--bin_len], E_XL4BUS_DATA, "Compact serialization is not ASCISZ");

        // DBG("Verifying serialized JWS (len %d, strlen %d) %s", bin_len, strlen(bin), bin);

        BOLT_CJOSE(jwe = cjose_jwe_import(bin, bin_len, &c_err));

        cjose_header_t *p_headers = cjose_jwe_get_protected(jwe);

        char const * x5t_in;

        // is there an x5c entry?
        BOLT_CJOSE(x5t_in = cjose_header_get(p_headers, "x5t#S256", &c_err));

        BOLT_IF(strcmp(x5t_in, x5t) != 0, E_XL4BUS_DATA, "Incoming tag %s, my tag %s", x5t_in, x5t);

        BOLT_CJOSE(*decrypted = cjose_jwe_decrypt(jwe, key, decrypted_len, &c_err));

        if (decrypted_ct) {

            BOLT_CJOSE(*decrypted_ct = (char*)cjose_header_get(p_headers, CJOSE_HDR_CTY, &c_err));

            // NOTE: we have to parse the mime type value, plus expand the mime type if shortened as
            // specified in https://tools.ietf.org/html/rfc7515#section-4.1.10
            {
                BOLT_MEM(*decrypted_ct = f_strdup(*decrypted_ct));
                char * aux = strchr(*decrypted_ct, ';');
                if (aux) { *aux = 0; }
                aux = strchr(*decrypted_ct, '/');
                if (!aux) {
                    BOLT_MEM(aux = f_asprintf("application/%s", *decrypted_ct));
                    cfg.free(*decrypted_ct);
                    *decrypted_ct = aux;
                }
            }

        }

    } while (0);

    cjose_jwe_release(jwe);

    if (err) {
        cfg.free(*decrypted);
        *decrypted = 0;
        if (decrypted_ct) {
            cfg.free(*decrypted_ct);
        }
    }

    return err;

}
