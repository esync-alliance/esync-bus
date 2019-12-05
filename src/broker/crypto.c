
#include <mbedtls/x509_crt.h>
#include <libxl4bus/high_level.h>
#include "lib/common.h"
#include "lib/debug.h"
#include "broker.h"

char * make_cert_hash(broker_context_t * bc, void * der, size_t der_len) {

    int err = E_XL4BUS_OK;
    mbedtls_md_context_t mdc;
    char * x5t = 0;
    cjose_err c_err;

    mbedtls_md_init(&mdc);

    do {

        // the top cert is the reference point.
        size_t hash_len = mbedtls_md_get_size(bc->hash_sha256);
        uint8_t hash_val[hash_len];
        size_t out_len;

        // calculate sha-256 of the entire DER
        BOLT_MTLS(mbedtls_md_setup(&mdc, bc->hash_sha256, 0));
        BOLT_MTLS(mbedtls_md_starts(&mdc));
        BOLT_MTLS(mbedtls_md_update(&mdc, der, der_len));
        BOLT_MTLS(mbedtls_md_finish(&mdc, hash_val));

        BOLT_CJOSE(cjose_base64url_encode(hash_val, hash_len, &x5t, &out_len, &c_err));

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

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
            DBG("MPI %p, size %lu failed to fit into %lu raw", mpi, mpi->n, *dst_len);
            *dst_len += 20;
            continue;
        }

        return 0;

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


#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (pwd) {
        secure_bzero(pwd, pwd_len);
        free(pwd);
    }

    mbedtls_pk_free(&prk);
    clean_keyspec(&rsa_ks);

    return err;

}

int init_x509_values(broker_context_t * bc) {

    int err = E_XL4BUS_OK;
    json_object * json_cert = 0;
    mbedtls_x509_crt chain;

    if (!(bc->hash_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256))) {
        FATAL("Can not find SHA-256 hash implementation");
    }

    mbedtls_x509_crl_init(&bc->crl);
    mbedtls_x509_crt_init(&bc->trust);
    mbedtls_x509_crt_init(&chain);

    do {

        BOLT_MEM(bc->my_x5c = json_object_new_array());

        if (bc->broker_identity.type == XL4BIT_X509) {

            cjose_err c_err;

            // load trust
            for (xl4bus_asn1_t ** buf = bc->broker_identity.x509.trust; buf && *buf; buf++) {

                switch ((*buf)->enc) {
                    case XL4BUS_ASN1ENC_DER:
                    case XL4BUS_ASN1ENC_PEM:
                        BOLT_MTLS(mbedtls_x509_crt_parse(&bc->trust, (*buf)->buf.data, (*buf)->buf.len));
                        break;
                    default:
                        BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

            }

            BOLT_NEST();

            int chain_count = 0;

            // load chain
            for (xl4bus_asn1_t ** buf = bc->broker_identity.x509.chain; buf && *buf; buf++) {

                BOLT_SUB(asn1_to_json(*buf, &json_cert));

                switch ((*buf)->enc) {

                    case XL4BUS_ASN1ENC_DER:

#if 0
                        if (buf == bc->broker_identity.x509.chain) {
                            // first cert, need to build my x5t
                            BOLT_MEM(bc->my_x5t = make_cert_hash(bc, (*buf)->buf.data, (*buf)->buf.len));
                        }
#endif
                        BOLT_MTLS(mbedtls_x509_crt_parse(&chain, (*buf)->buf.data, (*buf)->buf.len));

                        break;

                    case XL4BUS_ASN1ENC_PEM:
                    {

                        if (buf == bc->broker_identity.x509.chain) {
                            // first cert, need to build my x5t

                            uint8_t * der = 0;

                            do {

                                size_t der_len;

                                const char * pem = json_object_get_string(json_cert);
                                size_t pem_len = strlen(pem);

                                BOLT_CJOSE(cjose_base64_decode(pem, pem_len, &der, &der_len, &c_err));
#if 0
                                BOLT_MEM(bc->my_x5t = make_cert_hash(bc, der, der_len));
#endif

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

                BOLT_MEM(!json_object_array_add(bc->my_x5c, json_cert));
                json_cert = 0;

                chain_count++;

            }

            BOLT_NEST();

            BOLT_IF(!chain_count, E_XL4BUS_ARG,
                    "At least one certificate must be present in the chain");

            // $TODO: do we verify that the provided cert checks out against the provided trust?
            // realistically there are no rules to say it should.

            BOLT_SUB(make_private_key(&bc->broker_identity, &chain.pk, &bc->private_key));

        } else {

            BOLT_SAY(E_XL4BUS_ARG, "Unsupported identity type %d", bc->broker_identity.type);

        }

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

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

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    free(base64);

    return err;

}
