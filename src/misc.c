
#include <config.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"
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

#endif

    return 0;
}

int xl4bus_init_connection(xl4bus_connection_t * conn) {

    int err;

    do {

        connection_internal_t * i_conn;
        BOLT_MALLOC(i_conn, sizeof(connection_internal_t));

        conn->_private = i_conn;
        BOLT_SYS(pf_set_nonblocking(conn->fd), "setting non-blocking");

        /*
        if (!conn->is_client) {
            i_conn->stream_seq_out = 1;
        }
        */

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

int xl4bus_shutdown_connection(xl4bus_connection_t * conn) {

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

}

void shutdown_connection_ts(xl4bus_connection_t * conn) {

    if (conn->is_shutdown) { return; }

    conn->is_shutdown = 1;

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

xl4bus_address_t * xl4bus_make_address(xl4bus_address_t * prev, xl4bus_address_type_t type, ...) {

    va_list ap;
    va_start(ap, type);

    xl4bus_address_t * addr = f_malloc(sizeof(xl4bus_address_t));
    if (prev) {
        prev->next = addr;
    }
    addr->type = type;
    switch (type) {

        case XL4BAT_SPECIAL:
            addr->special = va_arg(ap, xl4bus_address_special_t);
            break;

        case XL4BAT_UPDATE_AGENT:
        {
            char * ua = va_arg(ap, char*);
            int copy = va_arg(ap, int);
            if (copy) {
                addr->update_agent = f_strdup(ua);
            } else {
                addr->update_agent = ua;
            }
        }
            break;
        case XL4BAT_GROUP:
        {
            char * ua = va_arg(ap, char*);
            int copy = va_arg(ap, int);
            if (copy) {
                addr->update_agent = f_strdup(ua);
            } else {
                addr->update_agent = ua;
            }
        }
            break;
    }

    return addr;

}

void xl4bus_free_address(xl4bus_address_t * addr, int chain) {

    while (addr) {

        xl4bus_address_t * next;
        if (chain) {
            next = addr->next;
        } else {
            next = 0;
        }

        switch (addr->type) {
            case XL4BAT_SPECIAL:break;
            case XL4BAT_UPDATE_AGENT:
                cfg.free(addr->update_agent);
                break;
            case XL4BAT_GROUP:
                cfg.free(addr->group);
                break;
        }

        addr = next;

    }

}

const char * xl4bus_version() {

    return BUILD_VERSION;

}

int make_json_address(xl4bus_address_t * bus_addr, json_object ** json) {

    int err = E_XL4BUS_OK;
    json_object * addr = 0;

    do {

        BOLT_IF(!(addr = json_object_new_array()), E_XL4BUS_MEMORY, "");

        for (xl4bus_address_t * ma = bus_addr; ma; ma = ma->next) {

            char * key = 0;
            char * val = 0;

            switch (ma->type) {

                case XL4BAT_SPECIAL:
                {
                    key = "special";
                    switch (ma->special) {
                        case XL4BAS_DM_CLIENT:
                            val = "dmclient";
                            break;
                        case XL4BAS_DM_BROKER:
                            val = "broker";
                            break;
                        default:
                        BOLT_SAY(E_XL4BUS_ARG, "Unknown special type %d", ma->special);
                    }
                }
                    break;
                case XL4BAT_UPDATE_AGENT:
                    key = "update-agent";
                    val = ma->update_agent;
                    break;
                case XL4BAT_GROUP:
                    key = "group";
                    val = ma->group;
                    break;
                default:
                BOLT_SAY(E_XL4BUS_ARG, "Unknown addr type %d", ma->type);

            }

            BOLT_SUB(err);

            json_object * aux;
            json_object * bux;
            BOLT_IF(!(aux = json_object_new_object()), E_XL4BUS_MEMORY, "");
            json_object_array_add(addr, aux);
            BOLT_IF(!(bux = json_object_new_string(val)), E_XL4BUS_MEMORY, "");
            json_object_object_add(aux, key, bux);

        }

    } while(0);

    if (err) {
        json_object_put(addr);
    } else {
        *json = addr;
    }

    return err;

}
