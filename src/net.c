
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"

static int send_connectivity_test(xl4bus_connection_t* conn, int is_reply, uint8_t * value_32_bytes);
static void set_frame_size(void *, uint32_t);
static void calculate_frame_crc(void * frame_body, uint32_t size_with_crc);
static int post_frame(connection_internal_t * i_conn, void * frame_data, size_t len);
static int send_message_ts(xl4bus_connection_t *conn, xl4bus_ll_message_t *msg, void *arg);

int check_conn_io(xl4bus_connection_t * conn) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    // we always want to read.
    int flags = XL4BUS_POLL_READ;

    if (i_conn->out_queue) {
        flags |= XL4BUS_POLL_WRITE;
    }

    return conn->set_poll(conn, conn->fd, flags);

}

int xl4bus_process_connection(xl4bus_connection_t * conn, int fd, int flags, int * timeout) {

    if (conn->is_shutdown) {
        return E_XL4BUS_CLIENT;
    }

    int err = E_XL4BUS_OK;

    *timeout = -1;

    int is_data_fd = fd == conn->fd;

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

#if XL4_SUPPORT_THREADS
    void * ctl_buf = 0;
    int is_ctl_fd = conn->mt_support && i_conn->mt_read_socket == fd;
#endif

    do {

        if (is_data_fd && (flags & XL4BUS_POLL_ERR)) {
            pf_set_errno(pf_get_socket_error(fd));
            err = E_XL4BUS_SYS;
            break;
        }

#if XL4_SUPPORT_THREADS

        if (is_ctl_fd && (flags & XL4BUS_POLL_ERR)) {
            pf_set_errno(pf_get_socket_error(fd));
            err = E_XL4BUS_SYS;
            break;
        }

        if (is_ctl_fd && (flags & XL4BUS_POLL_READ)) {
            ssize_t buf_read = pf_recv_dgram(fd, &ctl_buf, f_malloc);
            if (buf_read <= 0) {
                err = E_XL4BUS_SYS;
                break;
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
                    err = E_XL4BUS_SYS;
                    break;
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

            }

            if (err != E_XL4BUS_OK) { break; }

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

            while (1) {

#define frm (i_conn->current_frame)

                RDP(0, &frm.byte0, 1, "byte 0");
                RDP(1, &frm.len_bytes, 3, "length");
                if (!frm.len_converted) {
                    crcFast(&frm.byte0, 1, &frm.crc);
                    crcFast(&frm.len_bytes, 3, &frm.crc);
                    frm.len_converted = 1;
                    frm.frame_len = ((uint32_t)frm.len_bytes[0] << 16) |
                            ((uint32_t)frm.len_bytes[1] << 8) |
                            ((uint32_t)frm.len_bytes[2]);
                }

                if (frm.data.cap < frm.frame_len) {
                    void * t = cfg.realloc(frm.data.data, frm.frame_len);
                    if (!t) {
                        err = E_XL4BUS_MEMORY;
                        break;
                    }
                    frm.data.cap = frm.frame_len;
                    frm.data.data= t;
                }

                RDP(4, frm.data.data, frm.frame_len, "frame body");
                frm.data.len = frm.total_read - 4;

                if (frm.data.len < 4) {
                    // not even enough for CRC
                    err = E_XL4BUS_DATA;
                    break;
                }

                // calculate and validate CRC
                crcFast(frm.data.data, frm.data.len -= 4, &frm.crc);
                if (frm.crc != ntohl(*(uint32_t*)(frm.data.data + frm.data.len))) {
                    // crc-32 mismatch
                    BOLT_SAY(E_XL4BUS_DATA, "CRC mismatch, recv %08x, calc %08x",
                            ntohl(*(uint32_t*)(frm.data.data + frm.data.len)), frm.crc);
                }

                switch (frm.byte0 & FRAME_TYPE_MASK) {

                    case FRAME_TYPE_NORMAL: {

                        // we must have at least 4 bytes.
                        size_t offset = 4;
                        if (frm.data.len < offset) {
                            err = E_XL4BUS_DATA;
                            break;
                        }

                        stream_t * stream;
                        uint16_t stream_id = ntohs(*(uint16_t*)frm.data.data);
                        HASH_FIND(hh, i_conn->streams, &stream_id, 2, stream);

                        // DBG("LL: recv frame stream %d, opened stream=%s", stream_id, stream?"yes":"no");

                        int is_not_first;

                        if (!stream) {

                            // there is no stream. We can only create a stream for
                            // first message, and if stream ID is not ours.

                            if ((is_not_first = (frm.byte0 & FRAME_MSG_FIRST_MASK)) ||
                                    (stream_id&0x1) != (conn->is_client ? 1 : 0)) {
                                BOLT_SAY(E_XL4BUS_DATA, "Stream ID %d has incorrect parity or not a stream starter (byte0 is %x, exp parity %d)",
                                        stream_id, frm.byte0, (conn->is_client?1:0));
                            }

                            BOLT_MEM(stream = f_malloc(sizeof(stream_t)));

                            stream->stream_id = stream_id;
                            // $TODO: HASH mem check!
                            HASH_ADD(hh, i_conn->streams, stream_id, 2, stream);

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
                            stream->incoming_message_ct = *(frm.data.data+4);

                            stream->is_final = (frm.byte0 & FRAME_MSG_FINAL_MASK) > 0;
                            stream->is_reply = is_not_first > 0;

                        }

                        // does frame sequence match our expectations?
                        BOLT_IF(stream->frame_seq_in++ != ntohs(*(uint16_t*)(frm.data.data+2)),
                                E_XL4BUS_DATA, "Expected frame sequence %d, got %d", stream->frame_seq_in-1,
                                ntohs(*(uint16_t*)(frm.data.data+2)));

                        // OK, we are ready to consume the frame's contents.
                        BOLT_IF(add_to_dbuf(&stream->incoming_message_data, frm.data.data + offset, frm.data.len - offset),
                                E_XL4BUS_MEMORY, "Not enough memory to expand message buffer");

                        // $TODO: must check if the message size is too big!!!

                        // Is the message now complete?
                        if (frm.byte0 & FRAME_LAST_MASK) {

                            cjose_jws_t * jws = 0;

                            void * decrypted_data = 0;
                            char * decrypted_ct = 0;

                            do {

                                cjose_err c_err;

                                // the message is completed! Let's purge it.
                                xl4bus_ll_message_t message;

                                // the message can be encrypted with our private key, or not.
                                // let's try to treat it as encrypted message first.

                                size_t signed_len;
                                void * signed_data;

                                int received_ct = stream->incoming_message_ct;

                                int decrypted = decrypt_jwe(stream->incoming_message_data.data,
                                        stream->incoming_message_data.len, stream->incoming_message_ct,
                                        &decrypted_data, &signed_len, &decrypted_ct);

                                if (!decrypted) {

                                    if (decrypted_ct && !strcmp("application/jose", decrypted_ct)) {
                                        received_ct = CT_JOSE_COMPACT;
                                    } else if (decrypted_ct && !strcmp("application/jose+json", decrypted_ct)) {
                                        received_ct = CT_JOSE_JSON;
                                    } else {
                                        BOLT_SAY(E_XL4BUS_DATA, "Can't process content type %s of decrypted message",
                                                NULL_STR(decrypted_ct));
                                    }

                                    signed_data = decrypted_data;

                                } else {

                                    signed_data = stream->incoming_message_data.data;
                                    signed_len = stream->incoming_message_data.len;

                                }

                                BOLT_SUB(validate_jws(signed_data, signed_len, received_ct, 0, i_conn, &jws));

                                BOLT_CJOSE(cjose_jws_get_plaintext(jws, (uint8_t**)&message.message.data,
                                        &message.message.data_len, &c_err));

                                cjose_header_t * hdr = cjose_jws_get_protected(jws);
                                const char * aux;
                                BOLT_CJOSE(aux = cjose_header_get(hdr, CJOSE_HDR_CTY, &c_err));
                                if (aux) {
                                    BOLT_MEM(message.message.content_type = f_strdup(aux));
                                } else {
                                    message.message.content_type = 0;
                                }

                                message.stream_id = stream_id;
                                message.is_reply = stream->is_reply;
                                message.is_final = stream->is_final;

                                BOLT_SUB(conn->on_message(conn, &message));

                            } while (0);

                            free_dbuf(&stream->incoming_message_data, 0);
                            stream->message_started = 0;
                            cjose_jws_release(jws);
                            cfg.free(decrypted_data);
                            cfg.free(decrypted_ct);

                            if (stream->is_final) {
                                cleanup_stream(i_conn, &stream);
                            }

                        }

                    }
                    break;

                    case FRAME_TYPE_CTEST: {

                        if (frm.data.len != 32) {
                            err = E_XL4BUS_DATA;
                            break;
                        }

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
                    }
                    break;

                    case FRAME_TYPE_SABORT: {

                        // must at least be 1 byte that indicates the content type.
                        if (!frm.data.len) {
                            err = E_XL4BUS_DATA;
                            break;
                        }

                        uint16_t stream_id;
                        if (validate_jws(frm.data.data + 1, frm.data.len - 1,
                                (int)frm.data.data[0], &stream_id, i_conn, 0) == E_XL4BUS_OK) {
                            stream_t * stream;
                            HASH_FIND(hh, i_conn->streams, &stream_id, 2, stream);
                            if (stream) {
                                cleanup_stream(i_conn, &stream);
                            }
                            if (conn->on_stream_abort) {
                                conn->on_stream_abort(conn, stream_id);
                            }
                        }

                    }
                    break;

                    default:
                        // we shall just ignore the frames we don't understand (right?)
                        break;

                }

                if (err != E_XL4BUS_OK) { break; }

                // we dealt with the frame
                free_dbuf(&frm.data, 0);
                memset(&frm, 0, sizeof(frm));

            }

#undef frm

        }

        // $TODO: do all the timeouts here!!!

        if (err != E_XL4BUS_OK) { break; }

        BOLT_SUB(check_conn_io(conn));

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

    int err = post_frame(i_conn, frame, 4 + 32 + 4);
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

static int post_frame(connection_internal_t * i_conn, void * frame_data, size_t len) {

    chunk_t * chunk = f_malloc(sizeof(chunk_t));
    if (!chunk) {
        return E_XL4BUS_MEMORY;
    }

    chunk->data = frame_data;
    chunk->len = len;

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
        itc.msg = msg;
        itc.ref = ref;
        itc.magic = ITC_MESSAGE_MAGIC;

        BOLT_SYS(pf_send(conn->mt_write_socket, &itc, sizeof(itc)) != sizeof(itc), "pf_send");

    } while (0);

    if (err != E_XL4BUS_OK) {
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

    // $TODO: implement

}

static int send_message_ts(xl4bus_connection_t *conn, xl4bus_ll_message_t *msg, void *arg) {

    uint8_t * frame = 0;
    int err;
    json_object * x5c = 0;
    char * base64 = 0;

    do {

        size_t ser_len;

        stream_t * stream = 0;

        connection_internal_t * i_conn = conn->_private;

        HASH_FIND(hh, i_conn->streams, &msg->stream_id, 2, stream);

        if (!msg->is_reply) {

            BOLT_IF(stream, E_XL4BUS_INTERNAL, "Stream %d already exists", msg->stream_id);
            stream = f_malloc(sizeof(stream_t));
            if (!stream) { err = E_XL4BUS_MEMORY; break; }
            // stream->stream_id = msg->stream_id = i_conn->stream_seq_out;
            // i_conn->stream_seq_out += 2;
            stream->stream_id = msg->stream_id;

            // $TODO: HASH mem check!
            HASH_ADD(hh, i_conn->streams, stream_id, 2, stream);

        } else {

            BOLT_IF(!stream, E_XL4BUS_INTERNAL, "Replying to stream %d that doesn't exist", msg->stream_id);

        }

        // if we can encrypt, then : encrypt + sign
        // if we can't encrypt (no remote key), then : sign

        void const * bytes_to_sign;
        size_t bytes_to_sign_sz;
        char const * ct;

        if (i_conn->remote_key) {

            BOLT_SUB(encrypt_jwe(i_conn->remote_key, i_conn->remote_x5t, msg->message.data, msg->message.data_len,
                    msg->message.content_type, 0, 0, (char**)&bytes_to_sign, &bytes_to_sign_sz));
            ct = "application/jose";

        } else {

            bytes_to_sign = msg->message.data;
            bytes_to_sign_sz = msg->message.data_len;
            ct = msg->message.content_type;
        }

        if (!i_conn->sent_full_x5) {

            i_conn->sent_full_x5 = 1;

            x5c = json_object_new_array();

            // $TODO: it's *really* tedious to get mbedtls to convert a loaded certificate
            // into a DER buffer, see x509.c for comments.

            for (xl4bus_asn1_t ** cin = conn->identity.x509.chain; *cin; cin++) {

                size_t base64_len;

                if ((*cin)->enc == XL4BUS_ASN1ENC_DER) {

                    cjose_err c_err;
                    BOLT_CJOSE(cjose_base64_encode((*cin)->buf.data, (*cin)->buf.len, &base64, &base64_len, &c_err));

                } else {

                    // encoding must be PEM, we already have the base64 data,
                    // but we need to remove PEM headers and join the lines.

                    base64 = f_malloc((*cin)->buf.len);
                    base64_len = 0;

                    int skipping_comment = 1;

                    const char * line_start = (const char *) (*cin)->buf.data;

                    for (int i=0; i<(*cin)->buf.len; i++) {

                        char c = (*cin)->buf.data[i];

                        if (c == '\n') {

                            if (!strncmp("-----BEGIN ", line_start, 11)) {

                                skipping_comment = 0;

                            } else if (!strncmp("-----END ", line_start, 9)) {

                                skipping_comment = 1;

                            } else if (!skipping_comment) {

                                for (const char * cc = line_start; (void*)cc < (*cin)->buf.data+i; cc++) {

                                    c = *cc;

                                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                        (c == '+') || (c == '/') || (c == '=')) {

                                        base64[base64_len++] = c;

                                    }

                                }

                            }

                            line_start = (const char *) ((*cin)->buf.data + i + 1);

                        }

                    }

                }

                json_object_array_add(x5c, json_object_new_string_len(base64, (int) base64_len));
                cfg.free(base64);
                base64 = 0;

            }

            BOLT_SUB(sign_jws(i_conn->private_key, json_object_get_string(x5c), 1, bytes_to_sign, bytes_to_sign_sz, ct, 13, 9,
                    (char **) &frame, &ser_len));

        } else {

            BOLT_SUB(sign_jws(i_conn->private_key, i_conn->my_x5t, 0, bytes_to_sign, bytes_to_sign_sz, ct, 13, 9,
                    (char **) &frame, &ser_len));

        }

        // $TODO: support large messages!
        if (ser_len > 65000) { break; }

        set_frame_size(frame, (uint32_t)ser_len + 9);

        uint8_t byte0 = (uint8_t)(FRAME_TYPE_NORMAL | (msg->is_final ? FRAME_MSG_FINAL_MASK : 0) | FRAME_LAST_MASK);
        if (msg->is_reply) {
            byte0 |= FRAME_MSG_FIRST_MASK;
        }
        *frame = byte0;

        *((uint16_t*)(frame+4)) = htons(stream->stream_id);
        *((uint16_t*)(frame+6)) = htons(stream->frame_seq_out++);
        *(frame+8) = CT_JOSE_COMPACT;

        calculate_frame_crc(frame, (uint32_t)(ser_len + 13)); // size with crc

        err = post_frame(i_conn, frame, ser_len + 13);
        if (err == E_XL4BUS_OK) {
            frame = 0; // consumed.
        }

    } while(0);

    cfg.free(frame);
    cfg.free(base64);
    json_object_put(x5c);

    if (conn->on_sent_message) {
        conn->on_sent_message(conn, msg, arg, err);
    }

    if (err == E_XL4BUS_OK) {
        err = check_conn_io(conn);
        if (err != E_XL4BUS_OK) {
            shutdown_connection_ts(conn);
        }
    }

    return err;

}
