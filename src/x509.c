#include <config.h>
#include "internal.h"
#include "misc.h"
#include "basics.h"
#include "lib/hash_list.h"

static int define_symmetric_key(void const * key_data, size_t key_data_len, char const * sender_x5t,
        char const * receiver_x5t, cjose_jwk_t ** jwk, char const ** kid);

static int expiration_cmp(rb_node_t * node, void * val_ptr);

#if 0

static void print_time(char *, mbedtls_x509_time *);

int x509_crt_to_write(mbedtls_x509_crt * crt, mbedtls_x509write_cert * wrt) {

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);

    int ok = 0;

#define BUF_TO_ASN(buf) \
    /* 5 bytes - maximum len, 1 byte - tag, then length of actual data */ \
    size_t asn_buf_len = 6 + (buf)->len; \
    unsigned char asn_buf[asn_buf_len]; \
    unsigned char * asn_ptr = asn_buf + asn_buf_len; \
    if (mbedtls_asn1_write_raw_buffer(&asn_ptr, asn_buf, (buf)->p, (buf)->len) < 0 || \
        mbedtls_asn1_write_len(&asn_ptr, asn_buf, (buf)->len) < 0 || \
        mbedtls_asn1_write_tag(&asn_ptr, asn_buf, (unsigned char) (buf)->tag)) { \
        break; \
    }

    do {

        // $TODO: the amount of hoops that I have to jump through here is
        // ridiculous, especially with having to convert things back to ASN.1
        // only to re-parse them later.
        // May be somebody can find easier ways of doing this.

        mbedtls_x509write_crt_init(wrt);
        mbedtls_x509write_crt_set_version(wrt, crt->version);

        {
            BUF_TO_ASN(&crt->serial);
            if (mbedtls_asn1_get_mpi(&asn_ptr, asn_buf + asn_buf_len, &serial)) { break; }
        }

        if (mbedtls_x509write_crt_set_serial(wrt, &serial)) {
            break;
        }

        // for validity times, set_validity expects 14 characters long times
        // in RFC5280 format. They say it's "UTCTime", but it's really "GeneralizedTime"
        // They also don't want the terminating Z. Go figure. The string must be 0 terminated
        // though, since strlen() is used.

        char before_time[15];
        char after_time[15];

        print_time(before_time, &crt->valid_from);
        print_time(after_time, &crt->valid_to);

        if (mbedtls_x509write_crt_set_validity(wrt, before_time, after_time)) {
            break;
        }

        {
            BUF_TO_ASN(&crt->issuer_raw);
            mbedtls_x509_string_to_names()
        }

        mbedtls_x509write_crt_set_issuer_name(wrt, )

    } while (0);

    mbedtls_mpi_free(&serial);

    if (!ok) {
        mbedtls_x509write_crt_free(wrt);
        return 1;
    }

    return 0;

}

void print_time(char * time, mbedtls_x509_time * x509_time) {

    snprintf(time, 15, "%.4d%.2d%.2d%.2d%.2d%.2d", max_int(9999, x509_time->year), max_int(99, x509_time->mon),
             max_int(99, x509_time->day), max_int(99, x509_time->hour),
             max_int(99, x509_time->min), max_int(99, x509_time->sec));

}
#endif

int accept_remote_x5c(json_object * x5c, xl4bus_connection_t * conn, remote_info_t ** rmi) {

    // $TODO: This business with ku_flags is weird, they should probably be tracked in remote_info_t,
    // rather than in connection object, it makes no sense to set them in connection here. For now they
    // are just simply ignored.
    int ku_flags;

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    return accept_x5c(conn->cache, x5c, &i_conn->trust, &i_conn->crl, &ku_flags, rmi);

}

int accept_x5c(global_cache_t * cache, json_object * x5c, mbedtls_x509_crt * trust, mbedtls_x509_crl * crl,
        int * ku_flags, remote_info_t ** rmi) {

    int err = E_XL4BUS_OK;
    remote_info_t * entry = 0;
    uint8_t * der = 0;
    cjose_jwk_rsa_keyspec rsa_ks;

    uint8_t * bin_x5t = 0;

    memset(&rsa_ks, 0, sizeof(cjose_jwk_rsa_keyspec));

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

        BOLT_MEM(entry = ref_remote_info(f_malloc(sizeof(remote_info_t))));

        mbedtls_x509_crt_init(&entry->crt);

        for (int i=0; i<l; i++) {
            const char * str;

            if (is_array) {
                str = json_object_get_string(json_object_array_get_idx(x5c, i));
            } else {
                str = json_object_get_string(x5c);
            }

            size_t chars = strlen(str);

            Z(cfg.free, der);

            size_t der_len;
            BOLT_CJOSE(cjose_base64_decode(str, chars, &der, &der_len, &c_err));

            BOLT_MTLS(mbedtls_x509_crt_parse_der(&entry->crt, der, der_len));
            if (!i) {
                BOLT_SUB(base64url_hash(der, der_len, &entry->x5t, 0));
            }

        }
        BOLT_NEST();

        uint32_t flags;
        BOLT_MTLS(mbedtls_x509_crt_verify(&entry->crt, trust, crl, 0, &flags, 0, 0));

        BOLT_IF(!mbedtls_pk_can_do(&entry->crt.pk, MBEDTLS_PK_RSA), E_XL4BUS_ARG, "Only RSA certs are supported");

        mbedtls_rsa_context * prk_rsa = mbedtls_pk_rsa(entry->crt.pk);

        // for public key, we only have N and E
        BOLT_SUB(mpi2jwk(&prk_rsa->E, &rsa_ks.e, &rsa_ks.elen));
        BOLT_SUB(mpi2jwk(&prk_rsa->N, &rsa_ks.n, &rsa_ks.nlen));
        BOLT_CJOSE(entry->remote_public_key = cjose_jwk_create_RSA_spec(&rsa_ks, &c_err));

        const char * eku_oid = "1.3.6.1.4.1.45473.3.1";
        if (!mbedtls_x509_crt_check_key_usage(&entry->crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) &&
                !mbedtls_x509_crt_check_extended_key_usage(&entry->crt, eku_oid, strlen(eku_oid))) {
            *ku_flags |= KU_FLAG_SIGN;
        }

        eku_oid = "1.3.6.1.4.1.45473.3.2";
        if (!mbedtls_x509_crt_check_key_usage(&entry->crt, MBEDTLS_X509_KU_KEY_ENCIPHERMENT) &&
                !mbedtls_x509_crt_check_extended_key_usage(&entry->crt, eku_oid, strlen(eku_oid))) {
            *ku_flags |= KU_FLAG_ENCRYPT;
        }

        BOLT_SUB(address_from_cert(&entry->crt, &entry->addresses));

        BOLT_SYS(LOCK(cache->cert_cache_lock), "");

        remote_info_t * old;
        HASH_FIND(hh, cache->x5t_cache, entry->x5t, strlen(entry->x5t), old);
        if (old) {
            HASH_DELETE(hh, cache->x5t_cache, old);
            unref_remote_info(old);
        }

        BOLT_HASH_ADD_KEYPTR(hh, cache->x5t_cache, entry->x5t, strlen(entry->x5t), entry);
        ref_remote_info(entry);

        if (rmi) {
            *rmi = ref_remote_info(entry);
        }

        UNLOCK(cache->cert_cache_lock);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    cfg.free(der);
    clean_keyspec(&rsa_ks);
    cfg.free(bin_x5t);

    unref_remote_info(entry);

    return err;

}

remote_info_t * find_by_x5t(global_cache_t * cache, const char * x5t) {

    remote_info_t * entry;

    if (!x5t) { return 0; }

    if (LOCK(cache->cert_cache_lock)) {
        return 0;
    }

    HASH_FIND(hh, cache->x5t_cache, x5t, strlen(x5t), entry);

    entry = ref_remote_info(entry);

    UNLOCK(cache->cert_cache_lock);

    return entry;

}

remote_key_t * find_by_kid(global_cache_t * cache, const char * kid) {

    remote_key_t * entry;

    if (!kid) { return 0; }

    if (LOCK(cache->cert_cache_lock)) {
        return 0;
    }

    HASH_FIND_STR(cache->kid_cache, kid, entry);
    entry = ref_remote_key(entry);

    UNLOCK(cache->cert_cache_lock);

    return entry;

}

MAKE_REF_FUNCTION(remote_info) {
    STD_REF_FUNCTION(remote_info);
}

MAKE_REF_FUNCTION(remote_key) {
    STD_REF_FUNCTION(remote_key);
}

MAKE_UNREF_FUNCTION(remote_info) {

    STD_UNREF_FUNCTION(remote_info);

    mbedtls_x509_crt_free(&obj->crt);
    cfg.free(obj->x5t);
    cjose_jwk_release(obj->remote_public_key);
    cjose_jwk_release(obj->to_key);
    cjose_jwk_release(obj->old_to_key);
    xl4bus_free_address(obj->addresses, 1);
    cfg.free(obj);

}

MAKE_UNREF_FUNCTION(remote_key) {

    STD_UNREF_FUNCTION(remote_key);

    cjose_jwk_release(obj->from_key);
    unref_remote_info(obj->remote_info);
    cfg.free(obj);

}

int process_remote_key(global_cache_t * cache, json_object * body, char const * local_x5t, remote_info_t * source, char const ** kid) {

    int err /*= E_XL4BUS_OK*/;
    cjose_err c_err;
    uint8_t * bin = 0;
    uint8_t * x5t_bin = 0;
    int locked = 0;
    cjose_jwk_t * key = 0;
    remote_key_t * entry = 0;

    do {

        char const * aux;
        BOLT_SUB(xl4json_get_pointer(body, "/body/kty", json_type_string, &aux));
        BOLT_IF(z_strcmp(aux, "oct"), E_XL4BUS_DATA, "Unknown key type %s", aux);
        BOLT_SUB(xl4json_get_pointer(body, "/body/k", json_type_string, &aux));

        size_t bin_len;

        BOLT_CJOSE(cjose_base64url_decode(aux, strlen(aux), &bin, &bin_len, &c_err));
        // check that the key size makes sense.
        BOLT_IF(bin_len != 128 / 8 && bin_len != 192 / 8 && bin_len != 256 / 8, E_XL4BUS_DATA, "Invalid key size %zu", bin_len);

        BOLT_SUB(define_symmetric_key(bin, bin_len, source->x5t, local_x5t, &key, kid));

        // $TODO: may be limit the amount of keys a remote can register, otherwise we let us being DDoSed, by
        // exhausting our memory with different keys.

        LOCK(cache->cert_cache_lock);
        locked = 1;

        HASH_FIND_STR(cache->kid_cache, *kid, entry);

        if (entry) {
            HASH_DEL(cache->kid_cache, entry);
            entry->in_kid_cache = 0;
            unref_remote_key(entry);
        }

        BOLT_MEM(entry = ref_remote_key(f_malloc(sizeof(remote_key_t))));

        entry->remote_info = ref_remote_info(source);
        BOLT_CJOSE(entry->from_key = cjose_jwk_retain(key, &c_err));
        entry->from_kid = *kid;
        entry->from_key_expiration = pf_ms_value() + XL4_HL_KEY_EXPIRATION_MS;
        BOLT_HASH_ADD_KEYPTR(hh, cache->kid_cache, *kid, strlen(*kid), entry);
        entry->in_kid_cache = 1;

        rb_tree_search_t search;
        if (rb_find(&cache->remote_key_expiration, &entry->from_key_expiration, expiration_cmp, &search)) {
            pf_abort("Found the impossible to find");
        }

        rb_insert(&entry->rb_expiration, &search, &cache->remote_key_expiration);
        ref_remote_key(entry); // added to hash
        ref_remote_key(entry); // added to RB tree

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (locked) {
        UNLOCK(cache->cert_cache_lock);
    }

    cjose_jwk_release(key);
    unref_remote_key(entry);

    cfg.free(bin);
    cfg.free(x5t_bin);

    return err;

}

int base64url_hash(void * data, size_t data_len, char ** to, xl4bus_buf_t * raw) {

    mbedtls_md_context_t mdc;
    mbedtls_md_init(&mdc);
    cjose_err c_err;

    int err = E_XL4BUS_OK;

    *to = 0;

    do {

        // the top cert is the reference point.
        size_t hash_len = mbedtls_md_get_size(hash_sha256);
        uint8_t hash_val[hash_len];
        size_t out_len;

        BOLT_MTLS(mbedtls_md_setup(&mdc, hash_sha256, 0));
        BOLT_MTLS(mbedtls_md_starts(&mdc));
        BOLT_MTLS(mbedtls_md_update(&mdc, data, data_len));
        BOLT_MTLS(mbedtls_md_finish(&mdc, hash_val));

        BOLT_CJOSE(cjose_base64url_encode(hash_val, hash_len, to, &out_len, &c_err));

        if (raw) {
            BOLT_IF(add_to_dbuf(raw, hash_val, hash_len), E_XL4BUS_MEMORY, "");
        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    mbedtls_md_free(&mdc);

    return err;

}

int update_remote_symmetric_key(char const * local_x5t, remote_info_t * remote) {

    static size_t key_size = 256/8;
    int err = E_XL4BUS_OK;
    uint8_t key[key_size];

    do {

        if (!remote->to_kid || remote->to_key_expiration < pf_ms_value()) {

            cjose_jwk_release(remote->old_to_key);
            remote->old_to_key = remote->to_key;
            remote->old_to_kid = remote->to_kid;
            remote->old_to_key_use_expiration = remote->to_key_use_expiration;
            remote->to_key = 0;
            remote->to_kid = 0;

            pf_random(key, key_size);

            BOLT_SUB(define_symmetric_key(key, key_size, local_x5t, remote->x5t, &remote->to_key, &remote->to_kid));
            uint64_t now = pf_ms_value();
            remote->to_key_expiration = now + XL4_HL_KEY_EXPIRATION_MS;
            remote->old_to_key_use_expiration = remote->to_key_expiration + XL4_HL_KEY_USE_EXPIRATION_MS;

        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    zero_s(key, key_size);

    return err;

}

int define_symmetric_key(void const * key_data, size_t key_data_len, char const * sender_x5t,
        char const * receiver_x5t, cjose_jwk_t ** jwk, char const ** kid) {

    int err = E_XL4BUS_OK;
    cjose_err c_err;
    uint8_t * x5t_bin = 0;
    char * alloc_kid = 0;

    mbedtls_md_context_t mdc;
    mbedtls_md_init(&mdc);

    do {

        BOLT_CJOSE(*jwk = cjose_jwk_create_oct_spec(key_data, key_data_len, &c_err));

        // calculate the KID
        // Let KID = Base64 ( A⌢B⌢SHA-256(A⌢B⌢K))
        // A - sender, B - receiver

        int hash_len = mbedtls_md_get_size(hash_sha256);

        uint8_t bin[max_size_t(key_data_len + hash_len * 2, hash_len * 3)];

        // let's get A⌢B⌢K first
        memcpy(bin + hash_len * 2, key_data, key_data_len);

        size_t ck_len = 0;
        cjose_base64url_decode(sender_x5t, strlen(sender_x5t), &x5t_bin, &ck_len, &c_err);
        BOLT_IF(ck_len != hash_len, E_XL4BUS_INTERNAL, "Bad hash length %zu", ck_len);
        memcpy(bin, x5t_bin, hash_len);
        Z_FREE(x5t_bin);

        cjose_base64url_decode(receiver_x5t, strlen(receiver_x5t), &x5t_bin, &ck_len, &c_err);
        BOLT_IF(ck_len != hash_len, E_XL4BUS_INTERNAL, "Bad hash length %zu", ck_len);
        memcpy(bin + hash_len, x5t_bin, hash_len);

        uint8_t hash_val[hash_len];

        BOLT_MTLS(mbedtls_md_setup(&mdc, hash_sha256, 0));
        BOLT_MTLS(mbedtls_md_starts(&mdc));
        BOLT_MTLS(mbedtls_md_update(&mdc, bin, hash_len * 3));
        BOLT_MTLS(mbedtls_md_finish(&mdc, hash_val));

        // we have hash of A⌢B⌢K, let's replace A⌢B⌢K with A⌢B⌢SHA-256(A⌢B⌢K)

        memcpy(bin + hash_len * 2, hash_val, hash_len);

        // if we base64 bin, we got our KID
        size_t alloc_kid_len;
        BOLT_CJOSE(cjose_base64url_encode(bin, hash_len * 3, &alloc_kid, &alloc_kid_len, &c_err));
        BOLT_CJOSE(cjose_jwk_set_kid(*jwk, alloc_kid, alloc_kid_len, &c_err));

        BOLT_CJOSE(*kid = cjose_jwk_get_kid(*jwk, &c_err));

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    mbedtls_md_free(&mdc);
    cfg.free(x5t_bin);
    cfg.free(alloc_kid);

    if (err != E_XL4BUS_OK) {
        Z(cjose_jwk_release, *jwk);
        *kid = 0;
    }

    return err;

}

int expiration_cmp(rb_node_t * node, void * val_ptr) {

    // we never return 0, because there is no equality.
    if (TO_RB_NODE2(remote_key_t, node, rb_expiration)->from_key_expiration < *(uint64_t*)val_ptr) {
        return -1;
    }
    return 1;

}

void release_remote_key_nl(global_cache_t * cache, remote_key_t * key) {

    if (key->in_kid_cache) {
        HASH_DEL(cache->kid_cache, key);
        unref_remote_key(key);
    }
    rb_delete(&cache->remote_key_expiration, &key->rb_expiration);
    unref_remote_key(key);

}

int address_from_cert(mbedtls_x509_crt * crt, xl4bus_address_t ** cert_addresses) {

    int err = E_XL4BUS_OK;

    do {

        mbedtls_asn1_sequence seq;
        seq.next = 0;

        unsigned char * start = crt->v3_ext.p;
        unsigned char * end = start + crt->v3_ext.len;
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

                cfg.free(x_oid);
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
                    char * group_name = 0;

                    while (start < end) {

                        if (mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_UTF8_STRING)) {
                            DBG("Group element is not utf-8 string");
                            break;
                        }

                        cfg.free(group_name);
                        BOLT_MEM(group_name = f_strndup(start, inner_len));
                        BOLT_SUB(xl4bus_chain_address(cert_addresses, XL4BAT_GROUP, group_name, 0));
                        DBG("Identity has group %s", group_name);
                        group_name = 0; // consumed.

                        start += inner_len;

                    }

                    cfg.free(group_name);
                    BOLT_NEST();

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

                        char * ua_name = 0;

                        for (mbedtls_asn1_sequence *p_addr = &addr; p_addr; p_addr = p_addr->next) {

                            // ok, address contains of an OID, followed by a parameter.

                            start = p_addr->buf.p;
                            end = start + p_addr->buf.len;

                            if (get_oid(&start, end, &oid)) {
                                DBG("Address doesn't start with an OID");
                                continue;
                            }

                            cfg.free(x_oid);
                            x_oid = make_chr_oid(&oid);
                            // DBG("extension oid %s", NULL_STR(x_oid));

                            if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.1")) {

                                BOLT_SUB(xl4bus_chain_address(cert_addresses, XL4BAT_SPECIAL, XL4BAS_BROKER));
                                DBG("Identity is BROKER");

                            } else if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.2")) {

                                BOLT_SUB(xl4bus_chain_address(cert_addresses, XL4BAT_SPECIAL, XL4BAS_DM_CLIENT));
                                DBG("Identity is DM_CLIENT");

                            } else if (!z_strcmp(x_oid, "1.3.6.1.4.1.45473.2.3")) {
                                if (!mbedtls_asn1_get_tag(&start, end, &inner_len, MBEDTLS_ASN1_UTF8_STRING)) {

                                    // $TODO: validate utf-8
                                    BOLT_MEM(ua_name = f_strndup(start, inner_len));
                                    BOLT_SUB(xl4bus_chain_address(cert_addresses, XL4BAT_UPDATE_AGENT, ua_name, 0));
                                    DBG("Identity is UA %s", ua_name);
                                    ua_name = 0; // consume

                                } else {
                                    DBG("Address value part is not utf8 string");
                                }
                            } else {
                                DBG("Unknown address OID %s", x_oid);
                            }

                        }

                        cfg.free(ua_name);

                        BOLT_NEST();

                    } else {
                        DBG("address is not a sequence of constructed sequences");
                    }

                    for (mbedtls_asn1_sequence *f_seq = addr.next; f_seq;) {
                        void *ptr = f_seq;
                        f_seq = f_seq->next;
                        cfg.free(ptr);
                    }

                    BOLT_NEST();

                }

            }

        }

        for (mbedtls_asn1_sequence * f_seq = seq.next; f_seq; ) {
            void * ptr = f_seq;
            f_seq = f_seq->next;
            cfg.free(ptr);
        }

        cfg.free(x_oid);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;

}