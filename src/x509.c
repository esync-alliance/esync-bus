#include <config.h>
#include "internal.h"
#include "misc.h"

// I thought about this for a while - whether certificate cache should be
// global or not. The key into this cache is sha-256 of the certificate.
// So, there is no real danger of collisions (the certificate still needs
// to be valid to be added to the cache, though I suppose it's possible
// to implement some padding attack and knock another certificate out of
// the cache, effectively DDoSing the caller that owns that knocked out
// cert. The fix will be to parse ASN.1 as it's being read, making sure
// that hashing stops when X.509 structure stops).
// The only way that a credential can legitimately have the same sha-256
// value, but has other differences - is when the chain is different. Meaning
// that the same certificate has been validated by different chains. However,
// the cache will only be overwritten when when the second chain is received,
// and that second chain will need to be validated first. The connection with
// the first chain identity will continue to be given a pass for the same
// sha-256 tag, but I don't see this as a security problem, as all information
// pertaining to the client still must be present in the top-level certificate,
// which is what's hashed.
// Alternative is to have cache per identity (so that identities with the same
// trust anchors can share caches), but that adds burden on the user to maintain
// those somehow, and, as stated above, doesn't provide any real additional
// security.
typedef struct x5t_cache {

    UT_hash_handle hh;
    // $TODO: we don't use crt after we processed incoming x5c, may
    // be we should dump it?
    mbedtls_x509_crt crt;
    char * x5t;
    cjose_jwk_t * key;

} x5t_cache_t;

x5t_cache_t * x5t_cache = 0;

static void free_cache_entry(x5t_cache_t *);

#if XL4_SUPPORT_THREADS
void * cert_cache_lock;
#endif

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

int accept_x5c(const char * x5c, xl4bus_connection_t * conn, char ** x5t) {

    int err = E_XL4BUS_OK;
    json_object * x5c_obj = 0;
    x5t_cache_t * entry = 0;
    uint8_t * der = 0;
    cjose_jwk_rsa_keyspec rsa_ks;

    memset(&rsa_ks, 0, sizeof(cjose_jwk_rsa_keyspec));

    *x5t = 0;

    do {

        cjose_err c_err;
        int l;

        BOLT_IF((!(x5c_obj = json_tokener_parse(x5c)) ||
                !json_object_is_type(x5c_obj, json_type_array)), E_XL4BUS_DATA, "x5c attribute is not json array");

        BOLT_IF(!(l = json_object_array_length(x5c_obj)), E_XL4BUS_DATA, "x5c array is empty");

        BOLT_MEM(entry = f_malloc(sizeof(x5t_cache_t)));

        mbedtls_x509_crt_init(&entry->crt);

        for (int i=0; i<l; i++) {
            const char * str = json_object_get_string(json_object_array_get_idx(x5c_obj, i));
            size_t chars = strlen(str);

            size_t der_len;
            BOLT_CJOSE(cjose_base64_decode(str, chars, &der, &der_len, &c_err));

            BOLT_MTLS(mbedtls_x509_crt_parse_der(&entry->crt, der, der_len));
            if (!i) {

                BOLT_MEM(entry->x5t = make_cert_hash(der, der_len));

            }
        }
        BOLT_SUB(err);

        connection_internal_t * i_conn = conn->_private;

        uint32_t flags;
        BOLT_MTLS(mbedtls_x509_crt_verify(&entry->crt, &i_conn->trust, &i_conn->crl, 0, &flags, 0, 0));

        BOLT_IF(!mbedtls_pk_can_do(&entry->crt.pk, MBEDTLS_PK_RSA), E_XL4BUS_ARG, "Only RSA certs are supported");
        mbedtls_rsa_context * prk_rsa = mbedtls_pk_rsa(entry->crt.pk);

        // for public key, we only have N and E
        BOLT_SUB(mpi2jwk(&prk_rsa->E, &rsa_ks.e, &rsa_ks.elen));
        BOLT_SUB(mpi2jwk(&prk_rsa->N, &rsa_ks.n, &rsa_ks.nlen));

        BOLT_CJOSE(entry->key = cjose_jwk_create_RSA_spec(&rsa_ks, &c_err));

        const char * eku_oid = "1.3.6.1.4.1.45473.3.1";
        if (!mbedtls_x509_crt_check_key_usage(&entry->crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) &&
                !mbedtls_x509_crt_check_extended_key_usage(&entry->crt, eku_oid, strlen(eku_oid))) {
            i_conn->ku_flags |= KU_FLAG_SIGN;
        }

        eku_oid = "1.3.6.1.4.1.45473.3.2";
        if (!mbedtls_x509_crt_check_key_usage(&entry->crt, MBEDTLS_X509_KU_KEY_ENCIPHERMENT) &&
                !mbedtls_x509_crt_check_extended_key_usage(&entry->crt, eku_oid, strlen(eku_oid))) {
            i_conn->ku_flags |= KU_FLAG_ENCRYPT;
        }

        {

            mbedtls_asn1_sequence seq;
            seq.next = 0;

            unsigned char * start = entry->crt.v3_ext.p;
            unsigned char * end = start + entry->crt.v3_ext.len;
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

                            cfg.free(bus_address);
                            BOLT_MALLOC(bus_address, sizeof(xl4bus_address_t));
                            bus_address->type = XL4BAT_GROUP;
                            BOLT_MEM(bus_address->group = f_strndup(start, inner_len));
                            bus_address->next = conn->remote_address_list;
                            conn->remote_address_list = bus_address;

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

                                cfg.free(x_oid);
                                x_oid = make_chr_oid(&oid);
                                // DBG("extension oid %s", NULL_STR(x_oid));

                                cfg.free(bus_address);
                                BOLT_MALLOC(bus_address, sizeof(xl4bus_address_t));
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
                                        BOLT_MEM(bus_address->update_agent = f_strndup(start, inner_len));
                                        bus_address_ok = 1;

                                        DBG("Identity is UA %s", bus_address->update_agent);

                                    } else {
                                        DBG("Address value part is not utf8 string");
                                    }
                                } else {
                                    DBG("Unknown address OID %s", x_oid);
                                }

                                if (bus_address_ok) {
                                    bus_address->next = conn->remote_address_list;
                                    conn->remote_address_list = bus_address;
                                    bus_address = 0;
                                }

                            }

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
            cfg.free(bus_address);

        }

        BOLT_NEST();

#if XL4_SUPPORT_THREADS
        BOLT_SYS(pf_lock(&cert_cache_lock), "");
#endif

        x5t_cache_t * old;
        HASH_FIND_STR(x5t_cache, entry->x5t, old);
        if (old) {
            HASH_DEL(x5t_cache, old);
            free_cache_entry(old);
        }
        HASH_ADD_KEYPTR(hh, x5t_cache, entry->x5t, strlen(entry->x5t), entry);
        *x5t = f_strdup(entry->x5t);

#if XL4_SUPPORT_THREADS
        BOLT_SYS(pf_unlock(&cert_cache_lock), "");
#endif

    } while (0);

    json_object_put(x5c_obj);
    cfg.free(der);
    clean_keyspec(&rsa_ks);

    if (err) {
        // we failed, so let's clean up.
        free_cache_entry(entry);
        free(*x5t);
    }

    return err;

}

cjose_jwk_t * find_key_by_x5t(const char * x5t) {

    x5t_cache_t * entry;
    cjose_jwk_t * key;

    if (!x5t) { return 0; }

#if XL4_SUPPORT_THREADS
    if (pf_lock(&cert_cache_lock)) {
        return 0;
    }
#endif

    HASH_FIND_STR(x5t_cache, x5t, entry);
    if (entry) {
        key = cjose_jwk_retain(entry->key, 0);
    } else {
        key = 0;
    }

#if XL4_SUPPORT_THREADS
    pf_unlock(&cert_cache_lock);
#endif

    return key;

}


static void free_cache_entry(x5t_cache_t * entry) {

    if (!entry) { return; }

    mbedtls_x509_crt_free(&entry->crt);
    cfg.free(entry->x5t);
    cjose_jwk_release(entry->key);
    cfg.free(entry);

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

