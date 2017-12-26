
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"

static int send_connectivity_test(xl4bus_connection_t* conn, int is_reply, uint8_t * value_32_bytes);
static void set_frame_size(void *, uint32_t);
static void calculate_frame_crc(void * frame_body, uint32_t size_with_crc);
static int post_frame(connection_internal_t * i_conn, void * frame_data, size_t len, int stream_id);
static int send_message_ts(xl4bus_connection_t *conn, xl4bus_ll_message_t *msg, void *arg);
static int process_normal_frame(xl4bus_connection_t * conn);
static int process_ctest_frame(xl4bus_connection_t * conn);
static int process_sabort_frame(xl4bus_connection_t * conn);

stream_t * ref_stream(stream_t * stream) {
    if (stream) {
        pf_add_and_get(&stream->ref_count, 1);
    }
    return stream;
}

void unref_stream(stream_t * stream) {
    if (stream) {
        if (pf_add_and_get(&stream->ref_count, -1)) { return; }
        clear_dbuf(&stream->incoming_message_data);
        free(stream);
    }
}

void release_stream(xl4bus_connection_t * conn, stream_t * stream) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    if (!stream) { return; }

#if XL4_SUPPORT_THREADS
    if (!pf_lock(&i_conn->hash_lock)) {
#endif
        HASH_DEL(i_conn->streams, stream);
        conn->stream_count--;
#if XL4_SUPPORT_THREADS
        pf_unlock(&i_conn->hash_lock);
    }
#endif

    // printf("UUU Stream %p-%04x released\n", i_conn, stream->stream_id);

    unref_stream(stream);

}

int check_conn_io(xl4bus_connection_t * conn) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    // we always want to read.
    int flags = XL4BUS_POLL_READ;

    if (i_conn->out_queue) {
        flags |= XL4BUS_POLL_WRITE;
    }

    return conn->set_poll(conn, conn->fd, flags);

}

int xl4bus_process_connection(xl4bus_connection_t * conn, int fd, int flags) {

    int err;

    int timeout = -1;

    int is_data_fd = fd == conn->fd;

    // do this before anything else is even attempted
    if (conn->_init_magic != MAGIC_INIT) {
        DBG("connection object not initialized : %p", conn);
        return E_XL4BUS_ARG;
    }

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

#if XL4_SUPPORT_THREADS
    void * ctl_buf = 0;
    int is_ctl_fd = conn->mt_support && i_conn->mt_read_socket == fd;
#endif

    do {

        // any error that we may have acquired earlier.
        BOLT_SUB(i_conn->err);

        if (is_data_fd && (flags & XL4BUS_POLL_ERR)) {
            pf_set_errno(pf_get_socket_error(fd));
            BOLT_SYS(1, "poll error flag set");
        }

#if XL4_SUPPORT_THREADS

        if (is_ctl_fd && (flags & XL4BUS_POLL_ERR)) {
            pf_set_errno(pf_get_socket_error(fd));
            BOLT_SYS(1, "poll error flag set");
        }

        if (is_ctl_fd && (flags & XL4BUS_POLL_READ)) {
            ssize_t buf_read = pf_recv_dgram(fd, &ctl_buf, f_malloc);
            if (buf_read <= 0) {
                BOLT_SYS(1, "recv() EOF/error");
            }

            if (buf_read == sizeof(itc_message_t) && ((itc_message_t*)ctl_buf)->magic == ITC_MESSAGE_MAGIC) {
                BOLT_SUB(send_message_ts(conn, ((itc_message_t *) ctl_buf)->msg, ((itc_message_t *) ctl_buf)->ref));
            } else if (buf_read == sizeof(itc_shutdown_t) && ((itc_shutdown_t*)ctl_buf)->magic == ITC_SHUTDOWN_MAGIC) {
                BOLT_SAY(E_XL4BUS_CLIENT, "Shutdown message received");
            } else if (conn->on_mt_message) {
                BOLT_SUB(conn->on_mt_message(conn, ctl_buf, (size_t) buf_read));
            }

        }

#endif

        if (is_data_fd && (flags & XL4BUS_POLL_WRITE)) {

            while (i_conn->out_queue) {

                chunk_t * top = i_conn->out_queue;

                ssize_t res = pf_send(fd, top->data, top->len);
                if (res < 0) {
                    int s_err = pf_get_errno();
                    if (s_err == EINTR) { continue; }
                    if (s_err == EWOULDBLOCK) {
                        break;
                    }
                    BOLT_SYS(1, "failed to send data");
                }

                if (cfg.debug_f) {
                    int count = 0;
                    chunk_t * aux;
                    DL_COUNT(top, aux, count);
                    DBG("sent %d bytes for stream %05x %d items in outgoing queue", top->len, top->stream_id, count);
                }

                if (res == top->len) {

                    DL_DELETE(i_conn->out_queue, top);

                    cfg.free(top->data);
                    cfg.free(top);

                } else {
                    // res can only be less than what we attempted to write.
                    memmove(top->data, top->data + res, top->len -= res);
                    // $TODO: should we shrink data memory block? reallocing
                    // is generally expensive, and we probably
                    // are not hoarding too much memory here, so let's not.
                }

                // ESYNC-1364, don't flush everything
                break;

            }

            BOLT_NEST();

        }

        if (is_data_fd && (flags & XL4BUS_POLL_READ)) {

#define RDP(pos, where, len, why) {\
    size_t _len = (len); \
    size_t _lim = (pos) + _len; \
    ssize_t delta = _lim - i_conn->current_frame.total_read; \
    /* printf("From %d, read %d to %d, missing %d\n", pos, len, _lim, delta); */ \
    if ((delta > 0)) {\
        int _stop = 0; \
        delta = i_conn->current_frame.total_read - (pos); \
        _len = _len - delta; \
        void * ptr = (where) + delta; \
        while (_len) { \
            ssize_t res = pf_recv(fd, ptr, _len); \
            if (res < 0) { \
                int x_err = pf_get_errno(); \
                if (x_err == EINTR) { continue; } \
                if (x_err == EWOULDBLOCK) { _stop = 1; break; } \
                BOLT_SYS(1, "Reading %s, %d more bytes (requested %d at %d)", why, _len, len, pos); \
            } \
            if (!res) { \
                /* EOF is never expected */ \
                DBG("EOF when reading %s, %d more bytes (requested %d at %d)", why, _len, len, pos); \
                err = E_XL4BUS_EOF; \
                break; \
            } \
            /* res > 0 here */ \
            i_conn->current_frame.total_read += res; \
            _len -= res; \
            ptr += res; \
        } \
        if (err != E_XL4BUS_OK) { break; } \
        if (_stop) { \
            /* DBG("Read of %s blocks, breaking until poll", why); */ \
            break; \
        } \
    } \
} \
do {} while(0)

            do {

#define frm (i_conn->current_frame)

                RDP(0, &frm.byte0, 1, "byte 0");
                RDP(1, &frm.len_bytes, 3, "length");
                if (!frm.len_converted) {
                    crcFast(&frm.byte0, 1, &frm.crc);
                    crcFast(&frm.len_bytes, 3, &frm.crc);
                    frm.len_converted = 1;
                    frm.frame_len = ((uint32_t) frm.len_bytes[0] << 16) |
                                    ((uint32_t) frm.len_bytes[1] << 8) |
                                    ((uint32_t) frm.len_bytes[2]);
                }

                if (frm.data.cap < frm.frame_len) {
                    void *t = cfg.realloc(frm.data.data, frm.frame_len);
                    BOLT_MEM(t);
                    frm.data.cap = frm.frame_len;
                    frm.data.data = t;
                }

                RDP(4, frm.data.data, frm.frame_len, "frame body");
                frm.data.len = frm.total_read - 4;

                BOLT_IF(frm.data.len < 4, E_XL4BUS_DATA, "frame smaller than CRC");

                // calculate and validate CRC
                crcFast(frm.data.data, frm.data.len -= 4, &frm.crc);
                if (frm.crc != ntohl(*(uint32_t *) (frm.data.data + frm.data.len))) {
                    // crc-32 mismatch
                    BOLT_SAY(E_XL4BUS_DATA, "CRC mismatch, recv %08x, calc %08x",
                            ntohl(*(uint32_t *) (frm.data.data + frm.data.len)), frm.crc);
                }

                switch (frm.byte0 & FRAME_TYPE_MASK) {

                    case FRAME_TYPE_NORMAL:
                        BOLT_SUB(process_normal_frame(conn));
                        break;

                    case FRAME_TYPE_CTEST:
                        BOLT_SUB(process_ctest_frame(conn));
                        break;

                    case FRAME_TYPE_SABORT:
                        BOLT_SUB(process_sabort_frame(conn));
                        break;

                    default:
                        // we shall just ignore the frames we don't understand (right?)
                        break;

                }

                BOLT_NEST();

                // we dealt with the frame
                clear_dbuf(&frm.data);
                memset(&frm, 0, sizeof(frm));

                // ESYNC-1364 don't try reading too much data at a time
            } while (0);

#undef frm

        }

        // $TODO: do all the timeouts here!!!

        BOLT_NEST();

        BOLT_SUB(check_conn_io(conn));
        BOLT_SUB(conn->set_poll(conn, XL4BUS_POLL_TIMEOUT_MS, timeout));

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    if (err != E_XL4BUS_OK) {
        shutdown_connection_ts(conn);
    }

#if XL4_SUPPORT_THREADS
    cfg.free(ctl_buf);
#endif

    return err;

}

int send_connectivity_test(xl4bus_connection_t* conn, int is_reply, uint8_t * value_32_bytes) {

    uint8_t * frame = cfg.malloc(4 + 32 + 4); // minimal header, code, crc
    if (!frame) {
        return E_XL4BUS_MEMORY;
    }
    set_frame_size(frame, 32 + 4); // without the minimal header

    uint8_t byte0 = FRAME_TYPE_CTEST | FRAME_LAST_MASK;
    if (is_reply) {
        byte0 |= FRAME_MSG_FIRST_MASK;
    }
    *frame = byte0;

    connection_internal_t * i_conn = conn->_private;

    if (!is_reply) {
        // we are requested to generate a connectivity test.
        pf_random(value_32_bytes = i_conn->connection_test_request, 32);
        i_conn->pending_connection_test = 1;
    }

    memcpy(frame + 4, value_32_bytes, 32);
    calculate_frame_crc(frame, 4 + 32 + 4); // size with crc

    int err = post_frame(i_conn, frame, 4 + 32 + 4, -1);
    if (err != E_XL4BUS_OK) {
        free(frame);
    }
    return err;

}

void set_frame_size(void * frame, uint32_t size) {

    *(((uint8_t*)frame)+1) = (uint8_t)((size >> 16)&0xff);
    *(((uint8_t*)frame)+2) = (uint8_t)((size >>  8)&0xff);
    *(((uint8_t*)frame)+3) = (uint8_t)((size      )&0xff);

}

static void calculate_frame_crc(void * frame_body, uint32_t size_with_crc) {

    uint32_t crc = 0;

    crcFast(frame_body, size_with_crc - 4, &crc);

    *(((uint32_t*)(frame_body+size_with_crc))-1) = htonl(crc);

}

static int post_frame(connection_internal_t * i_conn, void * frame_data, size_t len, int stream_id) {

    chunk_t * chunk = f_malloc(sizeof(chunk_t));
    if (!chunk) {
        return E_XL4BUS_MEMORY;
    }

    chunk->data = frame_data;
    chunk->len = len;
    chunk->stream_id = stream_id;

    DL_APPEND(i_conn->out_queue, chunk);

    return E_XL4BUS_OK;

}

int xl4bus_send_ll_message(xl4bus_connection_t *conn, xl4bus_ll_message_t *msg, void *ref
#if XL4_SUPPORT_THREADS
        , int is_mt
#endif
) {

#if XL4_SUPPORT_THREADS

    int err = E_XL4BUS_OK;

    do {

        BOLT_IF(is_mt && !conn->mt_support, E_XL4BUS_ARG, "m/t send is requested, but no m/t on conn");

        if (!is_mt) {
            err = send_message_ts(conn, msg, ref);
            break;
        }

        itc_message_t itc;
        memset(&itc, 0, sizeof(itc));
        itc.msg = msg;
        itc.ref = ref;
        itc.magic = ITC_MESSAGE_MAGIC;

        BOLT_SYS(pf_send(conn->mt_write_socket, &itc, sizeof(itc)) != sizeof(itc), "pf_send");

    } while (0);

    if (is_mt && (err != E_XL4BUS_OK)) {
        if (conn->on_sent_message) {
            conn->on_sent_message(conn, msg, ref, err);
        }
    }

    return err;

#else

    return send_message_ts(conn, msg, ref);

#endif


}

void xl4bus_abort_stream(xl4bus_connection_t *conn, uint16_t stream_id) {

    if (conn->_init_magic != MAGIC_INIT) {
        DBG("Attempting to abort stream with uninitialized connection %p", conn);
        return;
    }

    // $TODO: implement

}

static int send_message_ts(xl4bus_connection_t *conn, xl4bus_ll_message_t *msg, void *arg) {

    uint8_t * frame = 0;
    int err = E_XL4BUS_OK;
    json_object * x5c = 0;
    char * base64 = 0;
    uint8_t * signed_buf = 0;
    json_object * bus_object = 0;
    connection_internal_t * i_conn = conn->_private;
    stream_t * stream = 0;

    do {

        uint8_t ct;

        size_t ser_len = 0;

        HASH_FIND(hh, i_conn->streams, &msg->stream_id, 2, stream);
        ref_stream(stream);

        if (!msg->is_reply) {

            BOLT_IF(stream, E_XL4BUS_INTERNAL, "Stream %d already exists", msg->stream_id);
            BOLT_MALLOC(stream, sizeof(stream_t));
            ref_stream(stream);
            stream->stream_id = msg->stream_id;

#if XL4_SUPPORT_THREADS
            BOLT_SYS(pf_lock(&i_conn->hash_lock), "");
#endif
            // $TODO: HASH mem check!
            HASH_ADD(hh, i_conn->streams, stream_id, 2, stream);
            ref_stream(stream);
            conn->stream_count++;

            // printf("UUU Stream %p-%04x created\n", conn->_private, stream->stream_id);

#if XL4_SUPPORT_THREADS
            pf_unlock(&i_conn->hash_lock);
#endif

        } else {

            BOLT_IF(!stream, E_XL4BUS_INTERNAL, "Replying to stream %d that doesn't exist", msg->stream_id);

        }

#if !XL4_DISABLE_ENCRYPTION

        // encrypt if we can
        if (i_conn->remote_key) {

            BOLT_SUB(encrypt_jwe(i_conn->remote_key, conn->remote_x5t, msg->data, msg->data_len,
                    msg->content_type, 13, 9, (char**)&frame, &ser_len));
            ct = CT_JOSE_COMPACT;

            DBG("Message encrypted with remote key");

        } else {

#else

        // clear out x5c if encryption is disabled, it will never
        // otherwise be cleared, and we'll be doing expensive validation
        json_object_put(i_conn->x5c);
        i_conn->x5c = 0;

#endif /* !XL4_DISABLE_ENCRYPTION */

            DBG("Not encrypting message, remote public key not set");

            if (!z_strcmp(msg->content_type, "application/jose")) {
                ct = CT_JOSE_COMPACT;
            } else if (!z_strcmp(msg->content_type, "application/jose+json")) {
                ct = CT_JOSE_JSON;
            } else if (!z_strcmp(msg->content_type, "application/json")) {
                ct = CT_APPLICATION_JSON;
            } else if (!z_strcmp(msg->content_type, "application/vnd.xl4.busmessage-trust+json")) {
                ct = CT_TRUST_MESSAGE;
            } else {
                BOLT_SAY(E_XL4BUS_ARG, "Unsupported content type %s", msg->content_type);
            }

            BOLT_MALLOC(frame, msg->data_len + 13);
            memcpy(frame + 9, msg->data, ser_len = msg->data_len);

#if !XL4_DISABLE_ENCRYPTION
        }
#endif

        // $TODO: support large messages!
        BOLT_IF(ser_len > 65000, E_XL4BUS_ARG, "Frame size too large: %d", ser_len);

        set_frame_size(frame, (uint32_t)ser_len + 9);

        uint8_t byte0 = (uint8_t)(FRAME_TYPE_NORMAL | (msg->is_final ? FRAME_MSG_FINAL_MASK : 0) | FRAME_LAST_MASK);
        if (msg->is_reply) {
            byte0 |= FRAME_MSG_FIRST_MASK;
        }
        *frame = byte0;

        *((uint16_t*)(frame+4)) = htons(stream->stream_id);
        *((uint16_t*)(frame+6)) = htons(stream->frame_seq_out++);
        *(frame+8) = ct;

        calculate_frame_crc(frame, (uint32_t)(ser_len + 13)); // size with crc

        err = post_frame(i_conn, frame, ser_len + 13, stream->stream_id);
        if (err == E_XL4BUS_OK) {
            frame = 0; // consumed.
        }

        if (msg->is_final) {
            release_stream(conn, stream);
        }

    } while(0);

    cfg.free(frame);
    cfg.free(base64);
    json_object_put(x5c);
    cfg.free(signed_buf);
    unref_stream(stream);

    json_object_put(bus_object);

    if (conn->on_sent_message) {
        conn->on_sent_message(conn, msg, arg, err);
    }

    if (err == E_XL4BUS_OK) {
        err = check_conn_io(conn);
        if (err != E_XL4BUS_OK) {
            // shutdown_connection_ts(conn);
            i_conn->err = err;
            conn->set_poll(conn, XL4BUS_POLL_TIMEOUT_MS, 0);
        }
    }

    return err;

}

int process_normal_frame(xl4bus_connection_t * conn) {

#define frm (i_conn->current_frame)

    int err = E_XL4BUS_OK;
    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;
    stream_t *stream = 0;

    do {

        // we must have at least 4 bytes.
        size_t offset = 4;
        BOLT_IF(frm.data.len < offset, E_XL4BUS_DATA, "Not enough data for header");

        uint16_t stream_id = ntohs(*(uint16_t *) frm.data.data);
        HASH_FIND(hh, i_conn->streams, &stream_id, 2, stream);
        ref_stream(stream);

        if (cfg.debug_f) {
            DBG("received frame stream %05x opened stream=%s socket has %d bytes ready",
                    stream_id, stream?"yes":"no", pf_fionread(conn->fd));
        }

        int is_not_first;

        if (!stream) {

            // there is no stream. We can only create a stream for
            // first message, and if stream ID is not ours.

            if ((is_not_first = (frm.byte0 & FRAME_MSG_FIRST_MASK)) ||
                (stream_id & 0x1) != (conn->is_client ? 1 : 0)) {
                BOLT_SAY(E_XL4BUS_DATA,
                        "Stream ID %d has incorrect parity or not a stream starter (byte0 is %x, exp parity %d)",
                        stream_id, frm.byte0, (conn->is_client ? 1 : 0));
            }

            BOLT_MALLOC(stream, sizeof(stream_t));
            ref_stream(stream);

            stream->stream_id = stream_id;

#if XL4_SUPPORT_THREADS
            BOLT_SYS(pf_lock(&i_conn->hash_lock), "");
#endif

            // printf("UUU Stream %p-%04x created\n", conn->_private, stream->stream_id);

            // $TODO: HASH mem check!
            HASH_ADD(hh, i_conn->streams, stream_id, 2, stream);
            ref_stream(stream);
            conn->stream_count++;

#if XL4_SUPPORT_THREADS
            pf_unlock(&i_conn->hash_lock);
#endif

        } else {

            if (!(frm.byte0 & FRAME_MSG_FIRST_MASK)) {
                BOLT_SAY(E_XL4BUS_DATA, "Frame attempts to start existing stream %d", stream_id);
            }

            is_not_first = 1;

        }

        // Does this frame start a message?
        if (!stream->message_started) {

            // the message must contain CT code.
            offset++;

            BOLT_IF(frm.data.len < offset, E_XL4BUS_DATA, "Not enough bytes for message content type");

            stream->message_started = 1;
            stream->incoming_message_ct = *(frm.data.data + 4);

            stream->is_final = (frm.byte0 & FRAME_MSG_FINAL_MASK) > 0;
            stream->is_reply = is_not_first > 0;

        }

        // does frame sequence match our expectations?
        BOLT_IF(stream->frame_seq_in++ != ntohs(*(uint16_t *) (frm.data.data + 2)),
                E_XL4BUS_DATA, "Expected frame sequence %d, got %d", stream->frame_seq_in - 1,
                ntohs(*(uint16_t *) (frm.data.data + 2)));

        // OK, we are ready to consume the frame's contents.
        BOLT_IF(add_to_dbuf(&stream->incoming_message_data, frm.data.data + offset,
                frm.data.len - offset),
                E_XL4BUS_MEMORY, "Not enough memory to expand message buffer");

        // $TODO: must check if the message size is too big!!!

        // Is the message now complete?
        if (frm.byte0 & FRAME_LAST_MASK) {

            cjose_jws_t *jws = 0;

            char *decrypted_ct = 0;
            void *decrypted_data = 0;
            json_object *bus_object = 0;

            do {

                // the message is completed! Let's purge it.
                xl4bus_ll_message_t message;
                memset(&message, 0, sizeof(xl4bus_ll_message_t));

                // the message can be encrypted with our private key, or not.
                // let's try to treat it as encrypted message first.

                int decrypt_err = decrypt_jwe(stream->incoming_message_data.data,
                        stream->incoming_message_data.len, stream->incoming_message_ct,
                        conn->my_x5t, i_conn->private_key,
                        &decrypted_data, &message.data_len, &decrypted_ct);

                if (!decrypt_err) {

                    // decrypted OK

                    if (decrypted_ct) {
                        message.content_type = decrypted_ct;
                    } else {
                        message.content_type = decrypted_ct =
                                f_strdup("application/octet-stream");
                    }

                    message.data = decrypted_data;
                    message.was_encrypted = 1;

                    // we were able to decrypt our data, which means that the remote
                    // has learned our public key, so we can drop sending it in full.
                    json_object_put(i_conn->x5c);
                    i_conn->x5c = 0;

                } else {

                    message.data = stream->incoming_message_data.data;
                    message.data_len = stream->incoming_message_data.len;
                    message.was_encrypted = 0;
                    const char *ct = 0;
                    switch (stream->incoming_message_ct) {
                        case CT_JOSE_COMPACT:
                            ct = "application/jose";
                            break;
                        case CT_JOSE_JSON:
                            ct = "application/jose+json";
                            break;
                        case CT_APPLICATION_JSON:
                            ct = "application/json";
                            break;
                        case CT_TRUST_MESSAGE:
                            ct = "application/vnd.xl4.busmessage-trust+json";
                            break;
                        default:
                            ct = "application/octet-stream";
                            break;
                    }
                    message.content_type = decrypted_ct = f_strdup(ct);

                }

                message.stream_id = stream_id;
                message.is_reply = stream->is_reply;
                message.is_final = stream->is_final;

                BOLT_SUB(conn->on_message(conn, &message));

            } while (0);

            clear_dbuf(&stream->incoming_message_data);
            stream->message_started = 0;
            cjose_jws_release(jws);
            cfg.free(decrypted_data);
            cfg.free(decrypted_ct);

            json_object_put(bus_object);

            if (stream->is_final) {
                release_stream(conn, stream);
            }

        }

    } while(0);

    unref_stream(stream);

    return err;


}

int process_ctest_frame(xl4bus_connection_t * conn) {

    int err = E_XL4BUS_OK;
    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    do {

        BOLT_IF(frm.data.len != 32, E_XL4BUS_DATA, "conn test frame must be 32 bytes");

        if (frm.byte0 & FRAME_MSG_FIRST_MASK) {
            // it's a response
            if (i_conn->pending_connection_test &&
                !memcmp(frm.data.data, i_conn->connection_test_request, 32)) {
                i_conn->pending_connection_test = 0;
                i_conn->connectivity_test_ts = pf_msvalue();
            }
        } else {
            // we have been requested a connectivity test.
            i_conn->connectivity_test_ts = pf_msvalue();
            err = send_connectivity_test(conn, 1, frm.data.data);
        }

    } while(0);

    return err;
}

int process_sabort_frame(xl4bus_connection_t * conn) {

    int err = E_XL4BUS_OK;
    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    do {
        // must at least be 1 byte that indicates the content type.
        BOLT_IF(!frm.data.len, E_XL4BUS_DATA, "Abort frame must not be empty");

        uint16_t stream_id;
        json_object *bus_object = 0;
        validated_object_t vo;
        if (validate_jws(frm.data.data + 1, frm.data.len - 1, (int) frm.data.data[0],
                conn, &vo, 0) == E_XL4BUS_OK) {

            json_object *j;
            if (bus_object && json_object_object_get_ex(bus_object, "stream-id", &j) &&
                json_object_is_type(j, json_type_int)) {

                int val = json_object_get_int(j);
                if (!(val & 0xffff)) {

                    stream_id = (uint16_t) val;

                    stream_t *stream;
                    HASH_FIND(hh, i_conn->streams, &stream_id, 2, stream);
                    release_stream(conn, stream);

                    if (conn->on_stream_abort) {
                        conn->on_stream_abort(conn, stream_id);
                    }
                }
            }

            json_object_put(bus_object);

            clean_validated_object(&vo);

        }


    } while (0);

    return err;

}

#undef frm
