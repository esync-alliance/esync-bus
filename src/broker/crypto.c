
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <libxl4bus/high_level.h>
#include "lib/common.h"
#include "lib/debug.h"
#include "broker.h"

static mbedtls_x509_crt trust;
static mbedtls_x509_crl crl;
static remote_info_t * tag_cache = 0;
static const mbedtls_md_info_t * hash_sha256;
static json_object * my_x5c;
static char * my_x5t;
static cjose_jwk_t * private_key;

int validate_jws(int trusted, void const * data, size_t data_len, validated_object_t * vo) {

    cjose_err c_err;

    cjose_jws_t *jws = 0;
    json_object *hdr = 0;
    int err = E_XL4BUS_OK;
    char *x5c = 0;
    json_object *x5c_json = 0;
    remote_info_t *remote_info = 0;
    char *content_type = 0;

#if XL4_DISABLE_JWS
    json_object *trust = 0;
#endif

    do {

        BOLT_IF(!data_len || ((char *) data)[--data_len], E_XL4BUS_DATA, "Data is not ASCIIZ");

#if XL4_DISABLE_JWS

        if (trusted) {

            BOLT_IF(!(trust = json_tokener_parse(data)),
                    E_XL4BUS_DATA, "Incoming trust message doesn't parse");

            // is there an x5c entry?
            if (json_object_object_get_ex(trust, "x5c", &x5c_json)) {
                x5c_json = json_object_get(x5c_json);
                BOLT_SUB(accept_x5c(x5c_json, &remote_info));
            } else {
                json_object *x5t_json;
                const char *x5t = "<unspecified>";
                if (json_object_object_get_ex(trust, "x5t#S256", &x5t_json)) {
                    x5t = json_object_get_string(x5t_json);
                    remote_info = find_by_x5t(x5t);
                }
                if (!remote_info) {
                    BOLT_SAY(E_XL4BUS_DATA, "No remote info for tag %s", x5t);
                }
            }

            if (!json_object_object_get_ex(trust, "x-xl4bus", &hdr) ||
                !json_object_is_type(hdr = json_object_get(hdr), json_type_object)) {
                BOLT_SAY(E_XL4BUS_DATA, "No x-xl4bus object property in the header");
            }

            json_object *j_aux;
            if (!json_object_object_get_ex(trust, "content-type", &j_aux)) {
                BOLT_MEM(content_type = f_strdup("application/octet-stream"));
            } else {
                BOLT_MEM(content_type = f_strdup(json_object_get_string(j_aux)));
            }

            const char *in_data;
            if (!json_object_object_get_ex(trust, "data", &j_aux)) {
                in_data = "";
            } else {
                in_data = json_object_get_string(j_aux);
            }

            BOLT_CJOSE(cjose_base64_decode(in_data, strlen(in_data), &vo->data, &vo->data_len, &c_err));
            vo->data_copy = 1;

            break;


        }

#endif

        BOLT_CJOSE(jws = cjose_jws_import(data, data_len, &c_err));

        cjose_header_t *p_headers = cjose_jws_get_protected(jws);
        const char *hdr_str;

        // is there an x5c entry?
        BOLT_CJOSE(x5c = cjose_header_get_raw(p_headers, "x5c", &c_err));

        if (x5c) {

            BOLT_IF((!(x5c_json = json_tokener_parse(x5c)) ||
                     !json_object_is_type(x5c_json, json_type_array)),
                    E_XL4BUS_DATA, "x5c attribute is not a json array");

            BOLT_SUB(accept_x5c(x5c_json, &remote_info));

        } else {
            const char *x5t;
            BOLT_CJOSE(x5t = cjose_header_get(p_headers, "x5t#S256", &c_err));
            BOLT_IF(!(remote_info = find_by_x5t(x5t)), E_XL4BUS_SYS, "Could not find JWK for tag %s", NULL_STR(x5t));
        }

        BOLT_CJOSE(hdr_str = cjose_header_get(p_headers, "x-xl4bus", &c_err));

        const char *aux;
        BOLT_CJOSE(aux = cjose_header_get(p_headers, CJOSE_HDR_CTY, &c_err));
        BOLT_MEM(content_type = inflate_content_type(aux));

        hdr = json_tokener_parse(hdr_str);
        if (!hdr || !json_object_is_type(hdr, json_type_object)) {
            BOLT_SAY(E_XL4BUS_DATA, "No x-xl4bus property in the header");
        }

        BOLT_IF(!cjose_jws_verify(jws, remote_info->key, &c_err), E_XL4BUS_DATA, "Failed JWS verify");

        // $TODO: check nonce/timestamp!

        BOLT_CJOSE(cjose_jws_get_plaintext(jws, &vo->data, &vo->data_len, &c_err));

    } while (0);

    // free stuff that we used temporary

    free(x5c);

#if XL4_DISABLE_JWS
    json_object_put(trust);
#endif

    if (err == E_XL4BUS_OK) {

        vo->exp_jws = jws;
        vo->bus_object = hdr;
        vo->x5c = x5c_json;
        vo->remote_info = remote_info;
        vo->content_type = content_type;

    } else {

        cjose_jws_release(jws);
        json_object_put(hdr);
        json_object_put(x5c_json);
        free(content_type);

    }

    return err;

}


int accept_x5c(json_object * x5c, remote_info_t ** rmi) {

    int err = E_XL4BUS_OK;
    remote_info_t * entry = 0;
    uint8_t * der = 0;
    cjose_jwk_rsa_keyspec rsa_ks;
    mbedtls_x509_crt crt;

    memset(&rsa_ks, 0, sizeof(cjose_jwk_rsa_keyspec));
    mbedtls_x509_crt_init(&crt);

    if (rmi) { *rmi = 0; }

    do {

        cjose_err c_err;
        int l;

        int is_array = json_object_is_type(x5c, json_type_array);
        if (!is_array && !json_object_is_type(x5c, json_type_string)) {
            BOLT_SAY(E_XL4BUS_DATA, "x5c json is neither an array, nor a string");
        }

        if (is_array) {
            BOLT_IF((l = json_object_array_length(x5c)) <= 0, E_XL4BUS_DATA, "x5c array is empty");
        } else {
            l = 1;
        }

        BOLT_MEM(entry = f_malloc(sizeof(remote_info_t)));

        mbedtls_x509_crt_init(&crt);

        for (int i=0; i<l; i++) {
            const char * str;

            if (is_array) {
                str = json_object_get_string(json_object_array_get_idx(x5c, i));
            } else {
                str = json_object_get_string(x5c);
            }

            size_t chars = strlen(str);

            size_t der_len;
            BOLT_CJOSE(cjose_base64_decode(str, chars, &der, &der_len, &c_err));

            BOLT_MTLS(mbedtls_x509_crt_parse_der(&crt, der, der_len));
            if (!i) {

                BOLT_MEM(entry->x5t = make_cert_hash(der, der_len));

            }
        }
        BOLT_SUB(err);

        uint32_t flags;
        BOLT_MTLS(mbedtls_x509_crt_verify(&crt, &trust, &crl, 0, &flags, 0, 0));

        BOLT_IF(!mbedtls_pk_can_do(&crt.pk, MBEDTLS_PK_RSA), E_XL4BUS_ARG, "Only RSA certs are supported");
        mbedtls_rsa_context * prk_rsa = mbedtls_pk_rsa(crt.pk);

        // for public key, we only have N and E
        BOLT_SUB(mpi2jwk(&prk_rsa->E, &rsa_ks.e, &rsa_ks.elen));
        BOLT_SUB(mpi2jwk(&prk_rsa->N, &rsa_ks.n, &rsa_ks.nlen));

        BOLT_CJOSE(entry->key = cjose_jwk_create_RSA_spec(&rsa_ks, &c_err));

        const char * eku_oid = "1.3.6.1.4.1.45473.3.1";
        if (!mbedtls_x509_crt_check_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) &&
            !mbedtls_x509_crt_check_extended_key_usage(&crt, eku_oid, strlen(eku_oid))) {
            // HAVE SIGNING FLAG
        }

        eku_oid = "1.3.6.1.4.1.45473.3.2";
        if (!mbedtls_x509_crt_check_key_usage(&crt, MBEDTLS_X509_KU_KEY_ENCIPHERMENT) &&
            !mbedtls_x509_crt_check_extended_key_usage(&crt, eku_oid, strlen(eku_oid))) {
            // HAVE ENCRYPTING FLAG
        }

        {

            mbedtls_asn1_sequence seq;
            seq.next = 0;

            unsigned char * start = crt.v3_ext.p;
            unsigned char * end = start + crt.v3_ext.len;
            xl4bus_address_t * bus_address = 0;
            char * x_oid = 0;

            if (!mbedtls_asn1_get_sequence_of(&start, end, &seq, MBEDTLS_ASN1_SEQUENCE|MBEDTLS_ASN1_CONSTRUCTED)) {

                // each sequence element is sequence of:
                //    Extension  ::=  SEQUENCE  {
                //      extnID      OBJECT IDENTIFIER,
                //      critical    BOOLEAN DEFAULT FALSE,
                //      extnValue   OCTET STRING
                //      -- contains the DER encoding of an ASN.1 value
                //      -- corresponding to the extension type identified
                //      -- by extnID
                //    }

                for (mbedtls_asn1_sequence * cur_seq = &seq; cur_seq; cur_seq = cur_seq->next) {

                    start = cur_seq->buf.p;
                    end = start + cur_seq->buf.len;

                    // because we asked to unwrap sequence of sequences,
                    // the inner sequence is already unpacked into the corresponding
                    // mbedtls_asn1_buf, so we can start plucking sub-sequence items.

                    // next must be OID
                    mbedtls_asn1_buf oid;
                    if (get_oid(&start, end, &oid)) {
                        continue;
                    }

                    free(x_oid);
                    x_oid = make_chr_oid(&oid);
                    // DBG("extension oid %s", NULL_STR(x_oid));

                    int is_xl4bus_addr =  !z_strcmp(x_oid, "1.3.6.1.4.1.45473.1.6");
                    int is_xl4bus_group = !z_strcmp(x_oid, "1.3.6.1.4.1.45473.1.7");

                    // NOTE: we don't expect critical value because we always issue our certs
                    // marking out extensions as not critical, which is default, and therefore
                    // not included in DER. We can't mark is as critical, because any other verification
                    // will have to reject it.

                    if (is_xl4bus_group) {

                        size_t inner_len;

                        if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_OCTET_STRING)) {
                            DBG("xl4group attr : not octet string");
                            continue;
                        }
                        end = start + inner_len;

                        // the extracted octet string should contain SET of UTF8String
                        if (mbedtls_asn1_get_tag(&start, end, &inner_len,
                                MBEDTLS_ASN1_SET|MBEDTLS_ASN1_CONSTRUCTED)) {
                            DBG("Group list is not a constructed set");
                            continue;
                        }

                        end = start + inner_len;

                        while (start < end) {

                            if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_UTF8_STRING)) {
                                DBG("Group element is not utf-8 string");
                                break;
                            }

                            free(bus_address);
                            bus_address = f_malloc(sizeof(xl4bus_address_t));
                            bus_address->type = XL4BAT_GROUP;
                            BOLT_MEM(bus_address->group = f_strndup((char*)start, inner_len));
                            bus_address->next = entry->addresses;
                            entry->addresses = bus_address;

                            DBG("Identity has group %s", bus_address->group);

                            bus_address = 0;

                            start += inner_len;

                        }

                    }

                    if (is_xl4bus_addr) {

                        size_t inner_len;

                        if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_OCTET_STRING)) {
                            DBG("Addr attribute is not octet string");
                            continue;
                        }
                        end = start + inner_len;

                        // the extracted octet string should contain Xl4-Bus-Addresses

                        mbedtls_asn1_sequence addr;
                        addr.next = 0;

                        if (!mbedtls_asn1_get_sequence_of(&start, end, &addr,
                                MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)) {

                            for (mbedtls_asn1_sequence *p_addr = &addr; p_addr; p_addr = p_addr->next) {

                                // ok, address contains of an OID, followed by a parameter.

                                start = p_addr->buf.p;
                                end = start + p_addr->buf.len;

                                if (get_oid(&start, end, &oid)) {
                                    DBG("Address doesn't start with an OID");
                                    continue;
                                }

                                free(x_oid);
                                x_oid = make_chr_oid(&oid);
                                // DBG("extension oid %s", NULL_STR(x_oid));

                                free(bus_address);
                                bus_address = f_malloc(sizeof(xl4bus_address_t));
                                int bus_address_ok = 0;

                                if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.1")) {
                                    bus_address->type = XL4BAT_SPECIAL;
                                    bus_address->special = XL4BAS_DM_BROKER;
                                    bus_address_ok = 1;

                                    DBG("Identity is BROKER");

                                } else if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.2")) {
                                    bus_address->type = XL4BAT_SPECIAL;
                                    bus_address->special = XL4BAS_DM_CLIENT;
                                    bus_address_ok = 1;

                                    DBG("Identity is DM_CLIENT");

                                } else if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.3")) {
                                    bus_address->type = XL4BAT_UPDATE_AGENT;
                                    if (!mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_UTF8_STRING)) {
                                        // $TODO: validate utf-8
                                        BOLT_MEM(bus_address->update_agent = f_strndup((char*)start, inner_len));
                                        bus_address_ok = 1;

                                        DBG("Identity is UA %s", bus_address->update_agent);

                                    } else {
                                        DBG("Address value part is not utf8 string");
                                    }
                                } else {
                                    DBG("Unknown address OID %s", x_oid);
                                }

                                if (bus_address_ok) {
                                    bus_address->next = entry->addresses;
                                    entry->addresses = bus_address;
                                    bus_address = 0;
                                }

                            }

                        } else {
                            DBG("address is not a sequence of constructed sequences");
                        }

                        for (mbedtls_asn1_sequence *f_seq = addr.next; f_seq;) {
                            void *ptr = f_seq;
                            f_seq = f_seq->next;
                            free(ptr);
                        }

                        BOLT_NEST();

                    }

                }

            }

            for (mbedtls_asn1_sequence * f_seq = seq.next; f_seq; ) {
                void * ptr = f_seq;
                f_seq = f_seq->next;
                free(ptr);
            }

            free(x_oid);
            free(bus_address);

        }

        BOLT_NEST();

        remote_info_t * old;
        HASH_FIND_STR(tag_cache, entry->x5t, old);
        if (old) {
            HASH_DEL(tag_cache, old);
            free_remote_info(old);
        }

        HASH_ADD_KEYPTR(hh, tag_cache, entry->x5t, strlen(entry->x5t), entry);

        if (rmi) {
            *rmi = entry;
        }

    } while (0);

    free(der);
    clean_keyspec(&rsa_ks);
    mbedtls_x509_crt_free(&crt);

    if (err != E_XL4BUS_OK) {
        free_remote_info(entry);
    }

    return err;

}

remote_info_t * find_by_x5t(const char * x5t) {

    remote_info_t * entry;
    if (!x5t) { return 0; }
    HASH_FIND_STR(tag_cache, x5t, entry);
    return entry;

}


char * make_cert_hash(void * der, size_t der_len) {

    int err = E_XL4BUS_OK;
    mbedtls_md_context_t mdc;
    char * x5t = 0;
    cjose_err c_err;

    mbedtls_md_init(&mdc);

    do {

        // the top cert is the reference point.
        size_t hash_len = mbedtls_md_get_size(hash_sha256);
        uint8_t hash_val[hash_len];
        size_t out_len;

        // calculate sha-256 of the entire DER
        BOLT_MTLS(mbedtls_md_setup(&mdc, hash_sha256, 0));
        BOLT_MTLS(mbedtls_md_starts(&mdc));
        BOLT_MTLS(mbedtls_md_update(&mdc, der, der_len));
        BOLT_MTLS(mbedtls_md_finish(&mdc, hash_val));

        BOLT_CJOSE(cjose_base64url_encode(hash_val, hash_len, &x5t, &out_len, &c_err));

    } while(0);

    mbedtls_md_free(&mdc);

    return x5t;

}

int mpi2jwk(mbedtls_mpi * mpi, uint8_t ** dst , size_t * dst_len) {

    *dst = 0;
    *dst_len = mpi->n * sizeof(mbedtls_mpi_uint) + 1;

    while (1) {

        void * aux = realloc(*dst, *dst_len);
        if (!aux) {
            free(*dst);
            *dst = 0;
            return E_XL4BUS_MEMORY;
        }

        *dst = aux;

        if (mbedtls_mpi_write_binary(mpi, *dst, *dst_len) == MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL) {
            DBG("MPI %p, size %d failed to fit into %d raw", mpi, mpi->n, *dst_len);
            *dst_len += 20;
            continue;
        }

        return 0;

    }

}

int get_oid(unsigned char **p, unsigned char *end, mbedtls_asn1_buf *oid) {

    int ret;

    if ((ret = mbedtls_asn1_get_tag(p, end, &oid->len, MBEDTLS_ASN1_OID)) != 0) {
        return (ret);
    }

    oid->p = *p;
    *p += oid->len;
    oid->tag = MBEDTLS_ASN1_OID;

    return 0;

}

char * make_chr_oid(mbedtls_asn1_buf * buf) {

    // this is an approximation.
    size_t len = buf->len * 4;

    if (!len) { return 0; }

    while (1) {

        char * chr = f_malloc(len);
        if (!chr) { return 0; }
        int ret = mbedtls_oid_get_numeric_string(chr, len-1, buf);
        if (ret >= 0) { return chr; }
        free(chr);
        if (ret == MBEDTLS_ERR_OID_BUF_TOO_SMALL) {
            // $TODO: this can lead to DoS if there is a bug in mbedtls
            len *= 2;
        } else {
            return 0;
        }

    }

}

void clean_keyspec(cjose_jwk_rsa_keyspec * ks) {

    free(ks->e);
    free(ks->n);
    free(ks->d);
    free(ks->p);
    free(ks->q);
    free(ks->dp);
    free(ks->dq);
    free(ks->qi);

}

int sign_jws(conn_info_t * ci, json_object * bus_object, const void *data, size_t data_len, char const * ct, const void **jws_data, size_t *jws_len) {

    cjose_err c_err;
    cjose_jws_t *jws = 0;
    cjose_header_t *j_hdr = 0;
    int err = E_XL4BUS_OK;

#if XL4_DISABLE_JWS
    json_object * trust = 0;
    char * base64 = 0;
#endif

    do {

#if XL4_DISABLE_JWS
        BOLT_MEM(trust = json_object_new_object());
        if (!ci->sent_x5c) {
            json_object_object_add(trust, "x5c", json_object_get(my_x5c));
            ci->sent_x5c = 1;
        } else {
            json_object *j_aux;
            BOLT_MEM(j_aux = json_object_new_string(my_x5t));
            json_object_object_add(trust, "x5t#S256", j_aux);
        }
        json_object_object_add(trust, "x-xl4bus", json_object_get(bus_object));

        size_t base64_len;
        BOLT_CJOSE(cjose_base64_encode(data, data_len, &base64, &base64_len, &c_err));

        json_object * j_aux;
        BOLT_MEM(j_aux = json_object_new_string_len(base64, (int)base64_len));
        json_object_object_add(trust, "data", j_aux);

        BOLT_MEM(j_aux = json_object_new_string(ct));
        json_object_object_add(trust, "content-type", j_aux);

        BOLT_MEM(*jws_data = f_strdup(json_object_get_string(trust)));
        *jws_len = strlen(*jws_data) + 1;

#else

        BOLT_CJOSE(j_hdr = cjose_header_new(&c_err));

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_ALG, "RS256", &c_err));

        ct = pack_content_type(ct);

        BOLT_CJOSE(cjose_header_set(j_hdr, CJOSE_HDR_CTY, ct, &c_err));

        if (!ci->sent_x5c) {
            BOLT_CJOSE(cjose_header_set_raw(j_hdr, "x5c", json_object_get_string(my_x5c), &c_err));
            ci->sent_x5c = 1;
        } else {
            BOLT_CJOSE(cjose_header_set(j_hdr, "x5t#S256", my_x5t, &c_err));
        }

        BOLT_CJOSE(cjose_header_set(j_hdr, "x-xl4bus", json_object_get_string(bus_object), &c_err));

        BOLT_CJOSE(jws = cjose_jws_sign(private_key, j_hdr, data, data_len, &c_err));

        const char *jws_export;

        BOLT_CJOSE(cjose_jws_export(jws, &jws_export, &c_err));

        *jws_data = f_strdup(jws_export);
        *jws_len = strlen(*jws_data) + 1;

#endif

    } while (0);

    cjose_jws_release(jws);
    cjose_header_release(j_hdr);

#if XL4_DISABLE_JWS
    json_object_put(trust);
    free(base64);
#endif

    return err;

}

int make_private_key(xl4bus_identity_t * id, mbedtls_pk_context * pk, cjose_jwk_t ** jwk) {

    int err = E_XL4BUS_OK;
    cjose_err c_err;
    char * pwd = 0;
    size_t pwd_len = 0;

    mbedtls_pk_context prk;
    mbedtls_pk_init(&prk);

    cjose_jwk_rsa_keyspec rsa_ks;
    memset(&rsa_ks, 0, sizeof(rsa_ks));

    do {

        BOLT_IF(id->type != XL4BIT_X509, E_XL4BUS_ARG, "Only x.509 is supported");
        BOLT_IF(!id->x509.private_key, E_XL4BUS_ARG, "Private key must be supplied");

        int try_pk = mbedtls_pk_parse_key(&prk, id->x509.private_key->buf.data,
                id->x509.private_key->buf.len, 0, 0);

        if (try_pk == MBEDTLS_ERR_PK_PASSWORD_REQUIRED || try_pk == MBEDTLS_ERR_PK_PASSWORD_MISMATCH) {

            if (id->x509.password) {
                pwd = id->x509.password(&id->x509);
                pwd_len = strlen(pwd);
            }

            BOLT_MTLS(mbedtls_pk_parse_key(&prk, id->x509.private_key->buf.data,
                    id->x509.private_key->buf.len, (const unsigned char*)"", 0));

        } else {
            BOLT_MTLS(try_pk);
        }

        BOLT_IF(!mbedtls_pk_can_do(&prk, MBEDTLS_PK_RSA), E_XL4BUS_ARG, "Only RSA keys are supported");

        if (pk) {
            BOLT_MTLS(mbedtls_pk_check_pair(pk, &prk));
        }

        mbedtls_rsa_context * prk_rsa = mbedtls_pk_rsa(prk);

        BOLT_SUB(mpi2jwk(&prk_rsa->E, &rsa_ks.e, &rsa_ks.elen));
        BOLT_SUB(mpi2jwk(&prk_rsa->N, &rsa_ks.n, &rsa_ks.nlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->D, &rsa_ks.d, &rsa_ks.dlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->P, &rsa_ks.p, &rsa_ks.plen));
        BOLT_SUB(mpi2jwk(&prk_rsa->Q, &rsa_ks.q, &rsa_ks.qlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->DP, &rsa_ks.dp, &rsa_ks.dplen));
        BOLT_SUB(mpi2jwk(&prk_rsa->DQ, &rsa_ks.dq, &rsa_ks.dqlen));
        BOLT_SUB(mpi2jwk(&prk_rsa->QP, &rsa_ks.qi, &rsa_ks.qilen));

        BOLT_CJOSE(*jwk = cjose_jwk_create_RSA_spec(&rsa_ks, &c_err));


    } while (0);

    if (pwd) {
        secure_bzero(pwd, pwd_len);
        free(pwd);
    }

    mbedtls_pk_free(&prk);
    clean_keyspec(&rsa_ks);

    return err;

}

int init_x509_values() {

    int err = E_XL4BUS_OK;
    json_object * json_cert = 0;
    mbedtls_x509_crt chain;

    if (!(hash_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256))) {
        FATAL("Can not find SHA-256 hash implementation");
    }

    mbedtls_x509_crl_init(&crl);
    mbedtls_x509_crt_init(&trust);
    mbedtls_x509_crt_init(&chain);

    do {

        BOLT_MEM(my_x5c = json_object_new_array());

        if (broker_identity.type == XL4BIT_X509) {

            cjose_err c_err;

            // load trust
            for (xl4bus_asn1_t ** buf = broker_identity.x509.trust; buf && *buf; buf++) {

                switch ((*buf)->enc) {
                    case XL4BUS_ASN1ENC_DER:
                    case XL4BUS_ASN1ENC_PEM:
                        BOLT_MTLS(mbedtls_x509_crt_parse(&trust, (*buf)->buf.data, (*buf)->buf.len));
                        break;
                    default:
                        BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

            }

            BOLT_NEST();

            int chain_count = 0;

            // load chain
            for (xl4bus_asn1_t ** buf = broker_identity.x509.chain; buf && *buf; buf++) {

                BOLT_SUB(asn1_to_json(*buf, &json_cert));

                switch ((*buf)->enc) {

                    case XL4BUS_ASN1ENC_DER:

                        if (buf == broker_identity.x509.chain) {
                            // first cert, need to build my x5t
                            BOLT_MEM(my_x5t = make_cert_hash((*buf)->buf.data, (*buf)->buf.len));
                        }
                        BOLT_MTLS(mbedtls_x509_crt_parse(&chain, (*buf)->buf.data, (*buf)->buf.len));

                        break;

                    case XL4BUS_ASN1ENC_PEM:
                    {

                        if (buf == broker_identity.x509.chain) {
                            // first cert, need to build my x5t

                            uint8_t * der = 0;

                            do {

                                size_t der_len;

                                const char * pem = json_object_get_string(json_cert);
                                size_t pem_len = strlen(pem);

                                BOLT_CJOSE(cjose_base64_decode(pem, pem_len, &der, &der_len, &c_err));
                                BOLT_MEM(my_x5t = make_cert_hash(der, der_len));

                            } while (0);

                            free(der);
                            BOLT_NEST();

                        }

                        BOLT_MTLS(mbedtls_x509_crt_parse(&chain, (*buf)->buf.data, (*buf)->buf.len));

                    }
                        break;
                    default:
                        BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

                BOLT_MEM(!json_object_array_add(my_x5c, json_cert));
                json_cert = 0;

                chain_count++;

            }

            BOLT_NEST();

            BOLT_IF(!chain_count, E_XL4BUS_ARG,
                    "At least one certificate must be present in the chain");

            // $TODO: do we verify that the provided cert checks out against the provided trust?
            // realistically there are no rules to say it should.

            BOLT_SUB(make_private_key(&broker_identity, &chain.pk, &private_key));

        } else {

            BOLT_SAY(E_XL4BUS_ARG, "Unsupported identity type %d", broker_identity.type);

        }

    } while(0);

    json_object_put(json_cert);
    mbedtls_x509_crt_free(&chain);

    return err;

}

int asn1_to_json(xl4bus_asn1_t *asn1, json_object **to) {

    int err = E_XL4BUS_OK;
    char * base64 = 0;
    size_t base64_len = 0;
    cjose_err c_err;

    do {

        switch (asn1->enc) {

            case XL4BUS_ASN1ENC_DER:

                BOLT_CJOSE(cjose_base64_encode(asn1->buf.data, asn1->buf.len, &base64, &base64_len, &c_err));
                break;

            case XL4BUS_ASN1ENC_PEM: {

                // encoding must be PEM, we already have the base64 data,
                // but we need to remove PEM headers and join the lines.

                base64 = f_malloc(asn1->buf.len);
                base64_len = 0;

                int skipping_comment = 1;

                const char *line_start = (const char *) asn1->buf.data;

                for (int i = 0; i < asn1->buf.len; i++) {

                    char c = asn1->buf.data[i];

                    if (c == '\n') {

                        if (!strncmp("-----BEGIN ", line_start, 11)) {

                            skipping_comment = 0;

                        } else if (!strncmp("-----END ", line_start, 9)) {

                            skipping_comment = 1;

                        } else if (!skipping_comment) {

                            for (const char *cc = line_start; (void *) cc < (void *) asn1->buf.data + i; cc++) {

                                c = *cc;

                                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                    (c == '+') || (c == '/') || (c == '=')) {

                                    base64[base64_len++] = c;

                                }

                            }

                        }

                        line_start = (const char *) (asn1->buf.data + i + 1);

                    }

                }

            }
                break;
            default:
                BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", asn1->enc);
        }

        BOLT_NEST();

        BOLT_MEM(*to = json_object_new_string_len(base64, (int) base64_len));

    } while (0);

    free(base64);

    return err;

}

int free_remote_info(remote_info_t *entry) {
    free(entry->x5t);
    cjose_jwk_release(entry->key);
    xl4bus_free_address(entry->addresses, 1);
    free(entry);
}
