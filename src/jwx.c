
#include <config.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"

int sign_jws(cjose_jwk_t * key, char const * x5t, json_object * x5c, json_object * bus_object, const void * data, size_t data_len, char const * ct,
        int pad, int offset, char ** jws_data, size_t * jws_len) {

    cjose_err c_err;
    cjose_jws_t *jws = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;
    char * base64 = 0;

#if XL4_DISABLE_JWS
    json_object * trust = 0;
#endif

    do {

        // we need to add nonce and timestamp into the object, since that's common
        // for all outgoing messages.

        size_t base64_len;
        unsigned char rand[64];
        pf_random(rand, 64);
        BOLT_CJOSE(cjose_base64_encode(rand, 64, &base64, &base64_len, &c_err));
        json_object * val;
        BOLT_MEM(val = json_object_new_string_len(base64, (int)base64_len));
        json_object_object_add(bus_object, "nonce", val);
        BOLT_MEM(val = json_object_new_int64((int64_t)pf_sec_time()));
        json_object_object_add(bus_object, "timestamp", val);

        cfg.free(base64);
        base64 = 0;

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, "RS256", &c_err));

        ct = deflate_content_type(ct);

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        if (x5c) {
            BOLT_CJOSE(cjose_header_set_raw(j_hdr, "x5c", json_object_get_string(x5c), &c_err));
        } else if (x5t) {
            BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", x5t, &c_err));
        }

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(bus_object), &c_err));

        BOLT_CJOSE(jws = cjose_jws_sign(key, j_hdr, data, data_len, &c_err));

        const char *jws_export;

        BOLT_CJOSE(cjose_jws_export(jws, &jws_export, &c_err));

        size_t l = strlen(jws_export) + 1;
        BOLT_MALLOC(*jws_data, l + pad);
        memcpy((*jws_data) + offset, jws_export, *jws_len = l);

    } while (0);

    cjose_jws_release(jws);
    cjose_header_release(j_hdr);

#if XL4_DISABLE_JWS
    json_object_put(trust);
    cfg.free(base64);
#endif

    return err;

}

int encrypt_jwe(cjose_jwk_t * key, const char * x5t, json_object * bus_object, const void * data, size_t data_len,
                char const * ct, int pad, int offset, char ** jwe_data, size_t * jwe_len) {

    cjose_err c_err;
    cjose_jwe_t *jwe = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;
    char * jwe_export = 0;
    cjose_jwk_t * used_key = 0;

    do {

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(used_key = cjose_jwk_retain(key, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RSA_OAEP, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", x5t, &c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256CBC_HS512, &c_err));
        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, deflate_content_type(ct), &c_err));

        if (bus_object) {
            BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(bus_object), &c_err));
        }

        BOLT_CJOSE(jwe = cjose_jwe_encrypt(used_key, j_hdr, data, data_len, &c_err));

        BOLT_CJOSE(jwe_export = cjose_jwe_export(jwe, &c_err));

        size_t l = strlen(jwe_export) + 1;
        BOLT_MALLOC(*jwe_data, l + pad);

        // DBG("Encrypted JWE(%d bytes) %s, ", l-1, jwe_export);

        memcpy((*jwe_data) + offset, jwe_export, *jwe_len = l);

    } while (0);

    cjose_jwe_release(jwe);
    cjose_header_release(j_hdr);
    cjose_jwk_release(used_key);
    free(jwe_export);

    return err;

}

int decrypt_and_verify(decrypt_and_verify_data_t * dav) {

    cjose_err c_err;

    cjose_jwe_t *jwe = 0;
    int err = E_XL4BUS_OK;
    cjose_jwk_t * used_key = 0;
    int is_symmetric = 0;
    xl4bus_identity_t * full_id = 0;
    char * x5c = 0;
    json_object * x5c_json = 0;

    do {

        // try to decrypt

        do {

            BOLT_IF(dav->in_ct != CT_JOSE_COMPACT && dav->in_ct != CT_JOSE_JSON, E_XL4BUS_DATA,
                    "Can't decrypt unknown content type %d", dav->in_ct);

            char const * bin = dav->in_data;
            size_t bin_len = dav->in_data_len;

            BOLT_IF(!bin_len || bin[--bin_len], E_XL4BUS_DATA, "Serialization is not ASCIIZ");

            if (dav->in_ct == CT_JOSE_COMPACT) {
                BOLT_CJOSE(jwe = cjose_jwe_import(bin, bin_len, &c_err));
            } else {
                BOLT_CJOSE(jwe = cjose_jwe_import_json(bin, bin_len, &c_err));
            }

            cjose_header_t *p_headers = cjose_jwe_get_protected(jwe);

            char const * alg;
            BOLT_CJOSE(alg = cjose_header_get(p_headers, CJOSE_HDR_ALG, &c_err));

            cjose_key_locator key_locator;
            void * key_locator_data = 0;

            if (!z_strcmp(alg, CJOSE_HDR_ALG_RSA_OAEP)) {

                if ((key_locator = dav->asymmetric_key_locator)) {

                    key_locator_data = dav->asymmetric_locator_data;

                } else {
                    BOLT_IF(!dav->symmetric_key, E_XL4BUS_ARG, "Incoming message uses asymmetric encryption, but no asymmetric key is available");
                    BOLT_CJOSE(used_key = cjose_jwk_retain(dav->symmetric_key, &c_err));

                    char const * x5t_in;
                    BOLT_CJOSE(x5t_in = cjose_header_get(p_headers, "x5t#S256", &c_err));
                    BOLT_IF(strcmp(x5t_in, dav->remote_x5t) != 0, E_XL4BUS_DATA, "Incoming tag %s, expected tag %s", x5t_in, dav->remote_x5t);
                }

            } else if (!z_strcmp(alg, CJOSE_HDR_ALG_A128KW) || !z_strcmp(alg, CJOSE_HDR_ALG_A192KW) || !z_strcmp(alg, CJOSE_HDR_ALG_A256KW)) {

                char const * enc;
                BOLT_CJOSE(enc = cjose_header_get(p_headers, CJOSE_HDR_ENC, &c_err));

                if (z_strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) &&
                    z_strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) &&
                    z_strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512)) {
                    BOLT_SAY(E_XL4BUS_DATA, "Unsupported JWE encryption algorithm %s", enc);
                }

                if ((key_locator = dav->symmetric_key_locator)) {

                    key_locator_data = dav->asymmetric_locator_data;

                } else {

                    BOLT_IF(!dav->symmetric_key, E_XL4BUS_ARG, "Incoming message uses symmetric encryption, but no symmetric key is available");
                    BOLT_CJOSE(used_key = cjose_jwk_retain(dav->symmetric_key, &c_err));

                }

                is_symmetric = 1;

            } else {
                BOLT_SAY(E_XL4BUS_DATA, "Unsupported JWE algorithm %s", alg);
            }

            if (key_locator) {

                BOLT_CJOSE( dav->x_data = cjose_jwe_decrypt_multi(jwe, key_locator, key_locator_data, &dav->out_data_len, &c_err));

            } else {

                BOLT_CJOSE( dav->x_data = cjose_jwe_decrypt(jwe, used_key, &dav->out_data_len, &c_err));

            }

            char const * content_type;
            BOLT_CJOSE(content_type = (char*)cjose_header_get(p_headers, CJOSE_HDR_CTY, &c_err));
            BOLT_MEM(dav->x_content_type = inflate_content_type(content_type));

            dav->was_encrypted = 1;
            dav->out_data = dav->x_data;
            dav->out_ct = dav->x_content_type;
            if (is_symmetric) {
                dav->was_verified = 1;
                dav->was_symmetric = 1;
            }

        } while (0);

        if (err) {

            // decryption failed.
            Z_FREE(dav->x_data);
            Z_FREE(dav->x_content_type);

            is_symmetric = 0;

            if (err == E_XL4BUS_MEMORY) { break; }

            dav->out_data = dav->in_data;
            dav->out_data_len = dav->in_data_len;
            dav->out_ct = str_content_type(dav->in_ct);

            err = E_XL4BUS_OK;

        }

        do {

            if (is_symmetric) {
                // if JWE used symmetric key, validation has already been done.
                break;
            }

            // we want to reuse the key variable for verification here
            Z(cjose_jwk_release, used_key);

            BOLT_IF(z_strcmp(FCT_JOSE_COMPACT, dav->out_ct), E_XL4BUS_DATA,
                    "Can not use content type %s for JWS", dav->out_ct);

            char const * bin = dav->out_data;
            size_t bin_len = dav->out_data_len;

            BOLT_IF(!bin_len || ((char*)bin)[--bin_len], E_XL4BUS_DATA, "Validated message is not ASCIIZ");

            BOLT_CJOSE(dav->x_jws = cjose_jws_import(bin, bin_len, &c_err));

            cjose_header_t * p_headers = cjose_jws_get_protected(dav->x_jws);

            char const * alg;
            BOLT_CJOSE(alg = cjose_header_get(p_headers, CJOSE_HDR_ALG, &c_err));

            if (!z_strcmp(alg, CJOSE_HDR_ALG_HS256) || !z_strcmp(alg, CJOSE_HDR_ALG_HS384) ||
                    !z_strcmp(alg, CJOSE_HDR_ALG_HS512)) {

                BOLT_IF(!dav->symmetric_key, E_XL4BUS_DATA,
                        "Message signed with symmetric key, but no symmetric key is available");

                used_key = cjose_jwk_retain(dav->symmetric_key, &c_err);
                is_symmetric = 1;

            } else if (!z_strcmp(alg, CJOSE_HDR_ALG_RS256) || !z_strcmp(alg, CJOSE_HDR_ALG_RS384) ||
                    !z_strcmp(alg, CJOSE_HDR_ALG_RS512)) {

                // is there an x5c entry?
                BOLT_CJOSE(x5c = cjose_header_get_raw(p_headers, "x5c", &c_err));

                remote_info_t * rmi;

                if (x5c) {

                    BOLT_MALLOC(full_id, sizeof(xl4bus_identity_t));

                    BOLT_IF((!(x5c_json = json_tokener_parse(x5c)) ||
                             !json_object_is_type(x5c_json, json_type_array)),
                            E_XL4BUS_DATA, "x5c attribute is not a json array");

                    full_id->type = XL4BIT_X509;
                    size_t cert_count = json_object_array_length(x5c_json);
                    BOLT_MALLOC(full_id->x509.chain, sizeof(void*) * cert_count);
                    for (size_t i = 0; i < cert_count; i++) {
                        json_object * item = json_object_array_get_idx(x5c_json, i);
                        size_t base64_len = json_object_get_string_len(item);
                        BOLT_IF(!base64_len, E_XL4BUS_DATA, "Empty certificate in chain");
                        char const * base64 = json_object_get_string(item);
                        BOLT_MALLOC(full_id->x509.chain[i], sizeof(xl4bus_asn1_t));
                        BOLT_CJOSE(cjose_base64_decode(base64, base64_len,
                                &full_id->x509.chain[i]->buf.data, &full_id->x509.chain[i]->buf.len, &c_err));
                    }

                    BOLT_NEST();
                    BOLT_SUB(accept_x5c(x5c_json, dav->my_x5t, dav->trust, dav->crl, &dav->ku_flags, &rmi));


                } else {

                    const char * x5t;
                    BOLT_CJOSE(x5t = cjose_header_get(p_headers, "x5t#S256", &c_err));
                    // BOLT_IF(!(remote_info = find_by_x5t(x5t)), E_XL4BUS_SYS, "Could not find JWK for tag %s", NULL_STR(x5t));
                    rmi = find_by_x5t(x5t);

                    if (!rmi) {
                        dav->missing_x5t = f_strdup(x5t);
                        BOLT_SAY(E_XL4BUS_DATA, "No remote info for tag %s", x5t);
                    }

                }

                BOLT_CJOSE(used_key = cjose_jwk_retain(rmi->key, &c_err));

            } else {
                BOLT_SAY(E_XL4BUS_DATA, "Unsupported algorithm for verification : %s", alg);
            }

            BOLT_IF(!cjose_jws_verify(dav->x_jws, used_key, &c_err), E_XL4BUS_DATA, "Failed JWS verify");

            const char * aux;
            BOLT_CJOSE(aux = cjose_header_get(p_headers, CJOSE_HDR_CTY, &c_err));

            uint8_t * pt;
            size_t pt_len;

            BOLT_CJOSE(cjose_jws_get_plaintext(dav->x_jws, &pt, &pt_len, &c_err));

            // past that point, the only acceptable errors are memory related.

            Z_FREE(dav->x_content_type);
            Z_FREE(dav->x_data);
            BOLT_MEM(dav->x_content_type = inflate_content_type(aux));

            dav->out_ct = dav->x_content_type;
            dav->was_verified = 1;
            if (is_symmetric) {
                dav->was_symmetric = 1;
            }
            dav->out_data = pt;
            dav->out_data_len = pt_len;

        } while (0);

        if (err) {
            Z(cjose_jws_release, dav->x_jws);
            if (err == E_XL4BUS_MEMORY) { break; }
            err = E_XL4BUS_OK;
        }

    } while (0);

    cjose_jwe_release(jwe);
    cjose_jwk_release(used_key);
    free(x5c);
    free(x5c_json);

    if (err) {
        clean_decrypt_and_verify(dav);
    }

    return err;


}

int decrypt_jwe(void * bin, size_t bin_len, int ct, char * x5t, cjose_jwk_t * a_key, cjose_jwk_t * s_key,
        int * is_verified, void ** decrypted, size_t * decrypted_len, char ** decrypted_ct) {

    if (ct != CT_JOSE_COMPACT) {
        // we only support compact in this function.
        DBG("Can't decrypt unknown content type %d", ct);
        return E_XL4BUS_DATA;
    }

    cjose_err c_err;

    cjose_jwe_t *jwe = 0;
    int err = E_XL4BUS_OK;
    *decrypted = 0;
    cjose_jwk_t * used_key = 0;
    int is_symmetric = 0;

    do {

        BOLT_IF(!bin_len || ((char*)bin)[--bin_len], E_XL4BUS_DATA, "Compact serialization is not ASCIIZ");

        BOLT_CJOSE(jwe = cjose_jwe_import(bin, bin_len, &c_err));

        cjose_header_t *p_headers = cjose_jwe_get_protected(jwe);

        char const * alg;
        BOLT_CJOSE(alg = cjose_header_get(p_headers, CJOSE_HDR_ALG, &c_err));

        if (!z_strcmp(alg, CJOSE_HDR_ALG_RSA_OAEP)) {

            BOLT_IF(!a_key, E_XL4BUS_ARG, "Incoming message uses asymmetric encryption, but no asymmetric key is available");
            BOLT_CJOSE(used_key = cjose_jwk_retain(a_key, &c_err));

            char const * x5t_in;
            // is there an x5c entry?
            BOLT_CJOSE(x5t_in = cjose_header_get(p_headers, "x5t#S256", &c_err));
            BOLT_IF(strcmp(x5t_in, x5t) != 0, E_XL4BUS_DATA, "Incoming tag %s, my tag %s", x5t_in, x5t);

        } else if (!z_strcmp(alg, CJOSE_HDR_ALG_A128KW) || !z_strcmp(alg, CJOSE_HDR_ALG_A192KW) || !z_strcmp(alg, CJOSE_HDR_ALG_A256KW)) {

            BOLT_IF(!a_key, E_XL4BUS_ARG, "Incoming message uses symmetric encryption, but no symmetric key is available");
            BOLT_CJOSE(used_key = cjose_jwk_retain(s_key, &c_err));

            char const * enc;
            BOLT_CJOSE(enc = cjose_header_get(p_headers, CJOSE_HDR_ENC, &c_err));

            if (z_strcmp(enc, CJOSE_HDR_ENC_A128CBC_HS256) &&
                    z_strcmp(enc, CJOSE_HDR_ENC_A192CBC_HS384) &&
                    z_strcmp(enc, CJOSE_HDR_ENC_A256CBC_HS512)) {
                BOLT_SAY(E_XL4BUS_DATA, "Unsupported JWE encryption algorithm %s", enc);
            }

            is_symmetric = 1;

        } else {
            BOLT_SAY(E_XL4BUS_DATA, "Unsupported JWE algorithm %s", alg);
        }

        BOLT_CJOSE(*decrypted = cjose_jwe_decrypt(jwe, used_key, decrypted_len, &c_err));

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
    cjose_jwk_release(used_key);

    if (err) {
        cfg.free(*decrypted);
        *decrypted = 0;
        if (decrypted_ct) {
            cfg.free(*decrypted_ct);
        }
    }

    if (!err) {
        if (is_symmetric && is_verified) {
            *is_verified = 1;
        }
    }

    return err;

}

int xl4bus_set_remote_identity(xl4bus_connection_t * conn, xl4bus_identity_t * identity) {

    int err = E_XL4BUS_OK;
    json_object * x5c = 0;
    json_object * x5c_item = 0;
    connection_internal_t * i_conn = conn->_private;
    remote_info_t * remote_info = 0;
    char * x5c_str = 0;
    xl4bus_address_t * remote_address = 0;
    char * x5t = 0;
    cjose_err c_err;

    do {

        BOLT_IF(identity->type != XL4BIT_X509, E_XL4BUS_ARG, "Only X.509 identities are supported");

        // accept_x5c wants JSON. It's easier to make json out of provided
        // asn.1, than create an alternative version of accept_x5c.

        BOLT_MEM(x5c = json_object_new_array());

        int i = 0;
        for (xl4bus_asn1_t ** one = identity->x509.chain; *one; one++, i++) {
            BOLT_SUB(asn1_to_json(*one, &x5c_item));
            BOLT_MEM(!json_object_array_add(x5c, x5c_item));
            x5c_item = 0;
        }

        BOLT_NEST();

        BOLT_SUB(accept_x5c(x5c, conn->my_x5t, &i_conn->trust, &i_conn->crl, &i_conn->ku_flags, &remote_info));
        BOLT_MEM(x5c_str = f_strdup(json_object_get_string(x5c)));
        BOLT_SUB(xl4bus_copy_address(remote_info->addresses, 1, &remote_address));
        BOLT_MEM(x5t = f_strdup(remote_info->x5t));

        cjose_jwk_t * key;
        BOLT_CJOSE(key = cjose_jwk_retain(remote_info->key, &c_err));

        // OK, we found everything we needed to find, we can release existing remotes, and replace.
        // no errors should be possible to happen below this line

        cfg.free(conn->remote_x5t);
        cfg.free(conn->remote_x5c);
        cjose_jwk_release(i_conn->remote_key);
        xl4bus_free_address(conn->remote_address_list, 1);

        conn->remote_x5c = x5c_str;
        conn->remote_x5t = x5t;
        i_conn->remote_key = key;
        conn->remote_address_list = remote_address;

        remote_address = 0;
        x5t = 0;
        x5c_str = 0;

    } while(0);

    json_object_put(x5c_item);
    json_object_put(x5c);
    cfg.free(x5t);
    release_remote_info(remote_info);
    cfg.free(x5c_str);
    xl4bus_free_address(remote_address, 1);

    return err;

}

void clean_decrypt_and_verify(decrypt_and_verify_data_t * dav) {

    json_object_put(dav->bus_object);
    cfg.free(dav->missing_x5t);
    cfg.free(dav->x_data);
    cfg.free(dav->x_content_type);
    cjose_jws_release(dav->x_jws);

    memset(dav, 0, sizeof(decrypt_and_verify_data_t));

}

int xl4bus_set_session_key(xl4bus_connection_t * conn, xl4bus_key_t * key) {

    int err = E_XL4BUS_OK;
    cjose_err c_err;
    cjose_jwk_t * jwk = 0;

    do {

        BOLT_IF(key->type != XL4KT_AES_256, E_XL4BUS_ARG, "Unknown key type %d", key->type);
        BOLT_CJOSE(jwk = cjose_jwk_create_oct_spec(key->aes_256, 256/8, &c_err));

        connection_internal_t * i_conn = conn->_private;
        Z(cjose_jwk_release, i_conn->session_key);
        BOLT_CJOSE(i_conn->session_key = cjose_jwk_retain(jwk, &c_err));

    } while (0);

    cjose_jwk_release(jwk);

    return err;

}
