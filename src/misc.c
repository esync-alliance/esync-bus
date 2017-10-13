
#include <config.h>
#include <libxl4bus/high_level.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/oid.h>
#include <cjose/jwk.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"
#include "xl4bus_version.h"

xl4bus_ll_cfg_t cfg;

#if 0
// the table below was generated with the following code:
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t crc;

crc  crcTable[256];
#define WIDTH 32
#define POLYNOMIAL 0x04C11DB7
#define TOPBIT (1 << (WIDTH - 1))

void
crcInit(void)
{
    crc  remainder;


    /*
     * Compute the remainder of each possible dividend.
     */
    for (int dividend = 0; dividend < 256; ++dividend)
    {
        /*
         * Start with the dividend followed by zeros.
         */
        remainder = dividend << (WIDTH - 8);

        /*
         * Perform modulo-2 division, a bit at a time.
         */
        for (uint8_t bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }

        /*
         * Store the result into the table.
         */
        crcTable[dividend] = remainder;
    }

}   /* crcInit() */

int main(int argc, char ** argv) {

    crcInit();

    for (int i=0; i<32; i++) {
        for (int j=0; j<8; j++) {
            printf("0x%08x,", crcTable[i*8+j]);
        }
        printf("\n");
    }

}

#endif

const mbedtls_md_info_t * hash_sha256;

uint32_t crcTable[] = {

        0x00000000,0x04c11db7,0x09823b6e,0x0d4326d9,0x130476dc,0x17c56b6b,0x1a864db2,0x1e475005,
        0x2608edb8,0x22c9f00f,0x2f8ad6d6,0x2b4bcb61,0x350c9b64,0x31cd86d3,0x3c8ea00a,0x384fbdbd,
        0x4c11db70,0x48d0c6c7,0x4593e01e,0x4152fda9,0x5f15adac,0x5bd4b01b,0x569796c2,0x52568b75,
        0x6a1936c8,0x6ed82b7f,0x639b0da6,0x675a1011,0x791d4014,0x7ddc5da3,0x709f7b7a,0x745e66cd,
        0x9823b6e0,0x9ce2ab57,0x91a18d8e,0x95609039,0x8b27c03c,0x8fe6dd8b,0x82a5fb52,0x8664e6e5,
        0xbe2b5b58,0xbaea46ef,0xb7a96036,0xb3687d81,0xad2f2d84,0xa9ee3033,0xa4ad16ea,0xa06c0b5d,
        0xd4326d90,0xd0f37027,0xddb056fe,0xd9714b49,0xc7361b4c,0xc3f706fb,0xceb42022,0xca753d95,
        0xf23a8028,0xf6fb9d9f,0xfbb8bb46,0xff79a6f1,0xe13ef6f4,0xe5ffeb43,0xe8bccd9a,0xec7dd02d,
        0x34867077,0x30476dc0,0x3d044b19,0x39c556ae,0x278206ab,0x23431b1c,0x2e003dc5,0x2ac12072,
        0x128e9dcf,0x164f8078,0x1b0ca6a1,0x1fcdbb16,0x018aeb13,0x054bf6a4,0x0808d07d,0x0cc9cdca,
        0x7897ab07,0x7c56b6b0,0x71159069,0x75d48dde,0x6b93dddb,0x6f52c06c,0x6211e6b5,0x66d0fb02,
        0x5e9f46bf,0x5a5e5b08,0x571d7dd1,0x53dc6066,0x4d9b3063,0x495a2dd4,0x44190b0d,0x40d816ba,
        0xaca5c697,0xa864db20,0xa527fdf9,0xa1e6e04e,0xbfa1b04b,0xbb60adfc,0xb6238b25,0xb2e29692,
        0x8aad2b2f,0x8e6c3698,0x832f1041,0x87ee0df6,0x99a95df3,0x9d684044,0x902b669d,0x94ea7b2a,
        0xe0b41de7,0xe4750050,0xe9362689,0xedf73b3e,0xf3b06b3b,0xf771768c,0xfa325055,0xfef34de2,
        0xc6bcf05f,0xc27dede8,0xcf3ecb31,0xcbffd686,0xd5b88683,0xd1799b34,0xdc3abded,0xd8fba05a,
        0x690ce0ee,0x6dcdfd59,0x608edb80,0x644fc637,0x7a089632,0x7ec98b85,0x738aad5c,0x774bb0eb,
        0x4f040d56,0x4bc510e1,0x46863638,0x42472b8f,0x5c007b8a,0x58c1663d,0x558240e4,0x51435d53,
        0x251d3b9e,0x21dc2629,0x2c9f00f0,0x285e1d47,0x36194d42,0x32d850f5,0x3f9b762c,0x3b5a6b9b,
        0x0315d626,0x07d4cb91,0x0a97ed48,0x0e56f0ff,0x1011a0fa,0x14d0bd4d,0x19939b94,0x1d528623,
        0xf12f560e,0xf5ee4bb9,0xf8ad6d60,0xfc6c70d7,0xe22b20d2,0xe6ea3d65,0xeba91bbc,0xef68060b,
        0xd727bbb6,0xd3e6a601,0xdea580d8,0xda649d6f,0xc423cd6a,0xc0e2d0dd,0xcda1f604,0xc960ebb3,
        0xbd3e8d7e,0xb9ff90c9,0xb4bcb610,0xb07daba7,0xae3afba2,0xaafbe615,0xa7b8c0cc,0xa379dd7b,
        0x9b3660c6,0x9ff77d71,0x92b45ba8,0x9675461f,0x8832161a,0x8cf30bad,0x81b02d74,0x857130c3,
        0x5d8a9099,0x594b8d2e,0x5408abf7,0x50c9b640,0x4e8ee645,0x4a4ffbf2,0x470cdd2b,0x43cdc09c,
        0x7b827d21,0x7f436096,0x7200464f,0x76c15bf8,0x68860bfd,0x6c47164a,0x61043093,0x65c52d24,
        0x119b4be9,0x155a565e,0x18197087,0x1cd86d30,0x029f3d35,0x065e2082,0x0b1d065b,0x0fdc1bec,
        0x3793a651,0x3352bbe6,0x3e119d3f,0x3ad08088,0x2497d08d,0x2056cd3a,0x2d15ebe3,0x29d4f654,
        0xc5a92679,0xc1683bce,0xcc2b1d17,0xc8ea00a0,0xd6ad50a5,0xd26c4d12,0xdf2f6bcb,0xdbee767c,
        0xe3a1cbc1,0xe760d676,0xea23f0af,0xeee2ed18,0xf0a5bd1d,0xf464a0aa,0xf9278673,0xfde69bc4,
        0x89b8fd09,0x8d79e0be,0x803ac667,0x84fbdbd0,0x9abc8bd5,0x9e7d9662,0x933eb0bb,0x97ffad0c,
        0xafb010b1,0xab710d06,0xa6322bdf,0xa2f33668,0xbcb4666d,0xb8757bda,0xb5365d03,0xb1f740b4,

};


int xl4bus_init_ll(xl4bus_ll_cfg_t * in_cfg) {

    memcpy(&cfg, in_cfg, sizeof(xl4bus_ll_cfg_t));

#if XL4_HAVE_STD_MALLOC

    if (!cfg.malloc) {
        cfg.malloc = malloc;
    }
    if (!cfg.realloc) {
        cfg.realloc = realloc;
    }
    if (!cfg.free) {
        cfg.free = free;
    }

    cjose_set_alloc_funcs(cfg.malloc, cfg.realloc, cfg.free);
    ares_library_init_mem(ARES_LIB_INIT_ALL, cfg.malloc, cfg.free, cfg.realloc);
    mbedtls_platform_set_calloc_free(f_calloc, cfg.free);

#endif

    if (!(hash_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256))) {
        DBG("Can not find SHA-256 hash implementation");
        return E_XL4BUS_SYS;
    }

#if XL4_SUPPORT_THREADS
    if (pf_init_lock(&cert_cache_lock)) {
        return E_XL4BUS_SYS;
    }
#endif

    return E_XL4BUS_OK;

}

int xl4bus_init_connection(xl4bus_connection_t * conn) {

    int err = E_XL4BUS_OK;
    json_object * json_cert = 0;

    do {

        BOLT_IF(conn->_init_magic == MAGIC_INIT, E_XL4BUS_OK, "Connection already initialized");

        conn->_init_magic = MAGIC_INIT;

        connection_internal_t * i_conn;
        BOLT_MALLOC(i_conn, sizeof(connection_internal_t));

        conn->_private = i_conn;
        BOLT_SYS(pf_set_nonblocking(conn->fd), "setting non-blocking");

        /*
        if (!conn->is_client) {
            i_conn->stream_seq_out = 1;
        }
        */

        mbedtls_x509_crl_init(&i_conn->crl);
        mbedtls_x509_crt_init(&i_conn->chain);
        mbedtls_x509_crt_init(&i_conn->trust);

        BOLT_MEM(i_conn->x5c = json_object_new_array());

        if (conn->identity.type == XL4BIT_X509) {

            cjose_err c_err;

            // load trust
            for (xl4bus_asn1_t ** buf = conn->identity.x509.trust; buf && *buf; buf++) {

                switch ((*buf)->enc) {
                    case XL4BUS_ASN1ENC_DER:
                    case XL4BUS_ASN1ENC_PEM:
                        BOLT_MTLS(mbedtls_x509_crt_parse(&i_conn->trust, (*buf)->buf.data, (*buf)->buf.len));
                        break;
                    default:
                        BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

            }

            BOLT_NEST();

            int chain_count = 0;

            // load chain
            for (xl4bus_asn1_t ** buf = conn->identity.x509.chain; buf && *buf; buf++) {

                BOLT_SUB(asn1_to_json(*buf, &json_cert));

                switch ((*buf)->enc) {

                    case XL4BUS_ASN1ENC_DER:

                        if (buf == conn->identity.x509.chain) {
                            // first cert, need to build my x5t
                            BOLT_SUB(make_cert_hash((*buf)->buf.data, (*buf)->buf.len, &conn->my_x5t));
                        }
                        BOLT_MTLS(mbedtls_x509_crt_parse(&i_conn->chain, (*buf)->buf.data, (*buf)->buf.len));

                        break;

                    case XL4BUS_ASN1ENC_PEM:
                    {

                        if (buf == conn->identity.x509.chain) {
                            // first cert, need to build my x5t

                            uint8_t * der;
                            size_t der_len;

                            const char * pem = json_object_get_string(json_cert);
                            size_t pem_len = strlen(pem);

                            BOLT_CJOSE(cjose_base64_decode(pem, pem_len, &der, &der_len, &c_err));
                            BOLT_SUB(make_cert_hash(der, der_len, &conn->my_x5t));

                        }

                        BOLT_MTLS(mbedtls_x509_crt_parse(&i_conn->chain, (*buf)->buf.data, (*buf)->buf.len));

                    }
                        break;
                    default:
                    BOLT_SAY(E_XL4BUS_DATA, "Unknown encoding %d", (*buf)->enc);
                }

                BOLT_NEST();

                BOLT_MEM(!json_object_array_add(i_conn->x5c, json_cert));
                json_cert = 0;

                chain_count++;

            }

            BOLT_NEST();

            BOLT_IF(!chain_count, E_XL4BUS_ARG,
                    "At least one certificate must be present in the chain");

            // $TODO: do we verify that the provided cert checks out against the provided trust?
            // realistically there are no rules to say it should.

            BOLT_SUB(make_private_key(&conn->identity, &i_conn->chain.pk, &i_conn->private_key));

        } else {

            BOLT_SAY(E_XL4BUS_ARG, "Unsupported identity type %d", conn->identity.type);

        }

#if XL4_SUPPORT_THREADS
        if (conn->mt_support) {
            int pair[2];
            BOLT_SYS(pf_dgram_pair(pair), "creating DGRAM pair");
            BOLT_SYS(pf_set_nonblocking(i_conn->mt_read_socket = pair[0]), "setting non-blocking");
            conn->mt_write_socket = pair[1];
            BOLT_SUB(conn->set_poll(conn, i_conn->mt_read_socket, XL4BUS_POLL_READ));
        } else {
            i_conn->mt_read_socket = -1;
        }
#endif
        BOLT_SUB(check_conn_io(conn));


    } while(0);

    if (err != E_XL4BUS_OK) {
        shutdown_connection_ts(conn);
    }

    json_object_put(json_cert);

    return err;

}

int consume_dbuf(dbuf_t * into, dbuf_t * from, int do_free) {

    // quick paths
    if (do_free) {

        int do_copy = 0;

        if (!into->len) {
            free(into->data);
            do_copy = 1;
        } else if (!into->data) {
            do_copy = 1;
        }

        if (do_copy) {
            // data is not allocated, we don't have to care about anything else.
            memcpy(into, from, sizeof(dbuf_t));
            free(from->data);
            memset(from, 0, sizeof(dbuf_t));
            return 0;
        }
    }

    size_t need_len = from->len + into->len;
    ssize_t delta = need_len - into->cap;
    if (delta > 0) {
        void * x = cfg.realloc(into->data, need_len);
        if (!x) { return 1; }
        into->data = x;
        into->cap = need_len;
    }
    memcpy(into->data + into->len, from->data, from->len);
    return 0;

}

int add_to_dbuf(dbuf_t * into, void * from, size_t from_len) {

    size_t need = from_len + into->len;
    if (need > into->cap) {
        void * aux = cfg.realloc(into->data, need);
        if (!aux) { return 1; }
        into->data = aux;
        into->cap = need;
    }
    memcpy(into->data + into->len, from, from_len);
    into->len += from_len;
    return 0;

}

void free_dbuf(dbuf_t * dbuf, int and_self) {

    cfg.free(dbuf->data);
    if (and_self) {
        cfg.free(dbuf);
    } else {
        memset(dbuf, 0, sizeof(dbuf_t));
    }

}

void xl4bus_shutdown_connection(xl4bus_connection_t * conn) {

#if 0

#if XL4_SUPPORT_THREADS

    itc_shutdown_t itc;
    itc.magic = ITC_SHUTDOWN_MAGIC;

    if (pf_send(conn->mt_write_socket, &itc, sizeof(itc)) != sizeof(itc)) {
        return E_XL4BUS_SYS;
    }

#else

    shutdown_connection_ts(conn);

#endif

    return E_XL4BUS_OK;

#else

    if (conn->_init_magic != MAGIC_INIT) {
        return;
    }
    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;
    if (!i_conn->err) {
        i_conn->err = E_XL4BUS_CLIENT;
    }
    conn->set_poll(conn, XL4BUS_POLL_TIMEOUT_MS, 0);

#endif

}

void shutdown_connection_ts(xl4bus_connection_t * conn) {

    if (conn->_init_magic != MAGIC_INIT) {
        DBG("Attempting to shut down uninitialized connection %p", conn);
        return;
    }

    conn->_init_magic = 0;

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    chunk_t * c = i_conn->out_queue;
    while (c) {
        cfg.free(c->data);
        chunk_t * aux = c;
        c = c->next;
        cfg.free(aux);
    }

    free_dbuf(&i_conn->current_frame.data, 0);

    stream_t * stream;
    stream_t * aux;

    HASH_ITER(hh, i_conn->streams, stream, aux) {
        cleanup_stream(i_conn, &stream);
    }

    conn->set_poll(conn, conn->fd, XL4BUS_POLL_REMOVE);

#if XL4_SUPPORT_THREADS
    if (conn->mt_support) {
        conn->set_poll(conn, i_conn->mt_read_socket, XL4BUS_POLL_REMOVE);
        pf_close(i_conn->mt_read_socket);
        pf_close(conn->mt_write_socket);
    }
#endif

    mbedtls_x509_crl_free(&i_conn->crl);
    mbedtls_x509_crt_free(&i_conn->trust);
    mbedtls_x509_crt_free(&i_conn->chain);

    cjose_jwk_release(i_conn->private_key);
    cjose_jwk_release(i_conn->remote_key);
    cfg.free(conn->my_x5t);
    cfg.free(conn->remote_x5t);
    json_object_put(i_conn->x5c);

    cfg.free(i_conn);

    if (conn->on_shutdown) {
        conn->on_shutdown(conn);
    }

}

void cleanup_stream(connection_internal_t * i_conn, stream_t ** stream) {

    free_dbuf(&(*stream)->incoming_message_data, 0);
    HASH_DEL(i_conn->streams, *stream);
    free(*stream);
    *stream = 0;

}

int cjose_to_err(cjose_err * err) {

    switch (err->code) {

        case CJOSE_ERR_NONE:
            return E_XL4BUS_OK;
        case CJOSE_ERR_NO_MEMORY:
            return E_XL4BUS_MEMORY;
        // case CJOSE_ERR_CRYPTO:
        // case CJOSE_ERR_INVALID_ARG:
        // case CJOSE_ERR_INVALID_STATE:
        default:
            return E_XL4BUS_INTERNAL;
    }

}

char const * xl4bus_strerr(int e) {

    switch (e) {

        case E_XL4BUS_OK: return "ok";
        case E_XL4BUS_MEMORY: return "out of memory";
        case E_XL4BUS_SYS: return "system error";
        case E_XL4BUS_INTERNAL: return "internal error";
        case E_XL4BUS_EOF: return "end-of-file received";
        case E_XL4BUS_DATA: return "invalid data received";
        case E_XL4BUS_ARG: return "invalid argument";
        case E_XL4BUS_CLIENT: return "client error";
        default:
            return "unknown error";

    }

}

char * f_asprintf(char * fmt, ...) {

    char * ret;
    va_list ap;

    va_start(ap, fmt);
    int rc = vasprintf(&ret, fmt, ap);
    va_end(ap);

    if (rc < 0) {
        return 0;
    }

    return ret;

}

const char * xl4bus_version() {

    return BUILD_VERSION;

}

int mpi2jwk(mbedtls_mpi * mpi, uint8_t ** dst , size_t * dst_len) {

    *dst = 0;
    *dst_len = mpi->n * sizeof(mbedtls_mpi_uint) + 1;

    while (1) {

        void * aux = cfg.realloc(*dst, *dst_len);
        if (!aux) {
            cfg.free(*dst);
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

void clean_keyspec(cjose_jwk_rsa_keyspec * ks) {

    cfg.free(ks->e);
    cfg.free(ks->n);
    cfg.free(ks->d);
    cfg.free(ks->p);
    cfg.free(ks->q);
    cfg.free(ks->dp);
    cfg.free(ks->dq);
    cfg.free(ks->qi);

}

char * inflate_content_type(char const * ct) {

    if (!ct) { return f_strdup("application/octet-stream"); }
    if (strchr(ct, 0)) {
        return f_asprintf("application/%s", ct);
    }
    return f_strdup(ct);

}

const char * pack_content_type(const char * ct) {

    // this is for https://tools.ietf.org/html/rfc7515#section-4.1.10,
    // application/ can be omitted if there are no other slashes.

    if (!ct) {
        return "octet-stream";
    }

    if (!strncmp(ct, "application/", 12) && !strchr(ct+12, '/')) {
        ct += 12;
    }

    return ct;

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

int z_strcmp(const char * s1, const char * s2) {

    if (!s1) { return s2 ? -1 : 0; }
    if (!s2) { return 1; }
    return strcmp(s1, s2);

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
        cfg.free(chr);
        if (ret == MBEDTLS_ERR_OID_BUF_TOO_SMALL) {
            // $TODO: this can lead to DoS if there is a bug in mbedtls
            len *= 2;
        } else {
            return 0;
        }

    }

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


        if (id->x509.password) {
            pwd = id->x509.password(&id->x509);
            pwd_len = strlen(pwd);
        }

        BOLT_MTLS(mbedtls_pk_parse_key(&prk, id->x509.private_key->buf.data,
                id->x509.private_key->buf.len, (char unsigned const *)pwd, pwd_len));

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
        cfg.free(pwd);
    }

    mbedtls_pk_free(&prk);
    clean_keyspec(&rsa_ks);

    return err;

}

int asn1_to_json(xl4bus_asn1_t *asn1, json_object **to) {

    int err = E_XL4BUS_OK;
    char * base64 = 0;
    size_t base64_len;
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

    cfg.free(base64);

    return err;

}

void clean_validated_object(validated_object_t * vo) {

    cjose_jws_release(vo->exp_jws);
    json_object_put(vo->bus_object);
    json_object_put(vo->x5c);
    release_remote_info(vo->remote_info);
    cfg.free(vo->content_type);

}

int xl4bus_copy_address(xl4bus_address_t * src, int chain, xl4bus_address_t ** receiver) {

    xl4bus_address_t * new_chain = 0;
    xl4bus_address_t * last = 0;
    int err = E_XL4BUS_OK;

    while (src) {

        xl4bus_address_t * new;
        BOLT_MALLOC(new, sizeof(xl4bus_address_t));

        if (!new_chain) {
            new_chain = new;
            last = new;
        } else {
            last->next = new;
            last = new;
        }

        switch (new->type = src->type) {

            case XL4BAT_SPECIAL:
                new->special = src->special;
                break;
            case XL4BAT_UPDATE_AGENT:
                BOLT_MEM(new->update_agent = f_strdup(src->update_agent));
                break;
            case XL4BAT_GROUP:
                BOLT_MEM(new->group = f_strdup(src->group));
                break;
            default:
                BOLT_SAY(E_XL4BUS_ARG, "Unknown address type %d", src->type);
        }

        BOLT_NEST();

        if (!chain) { break; }
        src = src->next;

    }

    if (err == E_XL4BUS_OK) {
        if (last) {
            // last can be 0, if there were no addresses in src.
            last->next = *receiver;
            *receiver = new_chain;
        }
    } else {
        xl4bus_free_address(new_chain, 1);
    }

    return err;

}

