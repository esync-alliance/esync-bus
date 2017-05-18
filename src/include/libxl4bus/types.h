#ifndef _XL4BUS_TYPES_H_
#define _XL4BUS_TYPES_H_

#include "types_base.h"
#include "build_config.h"

typedef struct xl4bus_buf {
    uint8_t * data;
    size_t len;
} xl4bus_buf_t;

typedef void * (*xl4bus_malloc)(size_t);
typedef void * (*xl4bus_realloc)(void *, size_t);
typedef void (*xl4bus_free)(void*);

#if XL4_PROVIDE_DEBUG
typedef void (*xl4bus_debug)(const char *);
#endif

typedef struct xl4bus_ll_cfg {

    xl4bus_malloc malloc;
    xl4bus_realloc realloc;
    xl4bus_free free;
#if XL4_PROVIDE_DEBUG
    xl4bus_debug debug_f;
#endif

} xl4bus_ll_cfg_t;

typedef enum xl4bus_payload_form {
    XL4BPF_JSON
} xl4bus_payload_form_t;

typedef struct xl4bus_ll_message {

    xl4bus_payload_form_t form;
    union {
        char * json;
    };

    uint16_t stream_id;
    int is_final;
    int is_reply;

} xl4bus_ll_message_t;

struct xl4bus_X509v3_Identity;
struct xl4bus_connection;

#define XL4BUS_POLL_READ  (1<<1)
#define XL4BUS_POLL_WRITE (1<<2)
#define XL4BUS_POLL_ERR (1<<3)
#define XL4BUS_POLL_REMOVE (1<<4)

#define E_XL4BUS_OK         (0)
#define E_XL4BUS_MEMORY     (-1) // malloc failed
#define E_XL4BUS_SYS        (-2) // syscall failed, check errno
#define E_XL4BUS_INTERNAL   (-3) // internal error
#define E_XL4BUS_EOF        (-4) // unexpected EOF from channel
#define E_XL4BUS_DATA       (-5) // communication channel received unrecognized data.
#define E_XL4BUS_ARG        (-6) // invalid argument provided to the function

typedef void (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_ll_message_t *);
typedef void (*xl4bus_ll_send_callback) (struct xl4bus_connection*, void *);

typedef char * (*xl4bus_password_callback_t) (struct xl4bus_X509v3_Identity *);
typedef int (*xl4bus_set_ll_poll) (struct xl4bus_connection*, int);
// No need to support close - as long as valued returned from
// xl4bus_process_connection() is ERR, the caller can assume connection is
// closed.
// typedef void (*xl4bus_notify_close) (struct xl4bus_connection*);

typedef struct xl4bus_X509v3_Identity {

    xl4bus_buf_t certificate;
    xl4bus_buf_t private_key;
    xl4bus_password_callback_t password;
    xl4bus_buf_t * trust;
    size_t trust_len;

} xl4bus_X509v3_Identity_t;

typedef struct xl4bus_connection {

    int fd;
    int is_client;

    xl4bus_set_ll_poll set_poll;
    xl4bus_handle_ll_message ll_message;
    xl4bus_ll_send_callback ll_send_callback;
    // xl4bus_notify_close notify_close;

    void * custom;
    void * _private;

} xl4bus_connection_t;

typedef struct xl4bus_message {
    char * content_type;
    void * data;
    int data_len;
} xl4bus_message_t;

typedef int (*xl4bus_set_poll) (struct xl4bus_client *, int fd, int modes);
typedef void (*xl4bus_handle_message)(struct xl4bus_client *, xl4bus_message_t *);

typedef enum xl4bus_client_condition {
    RUNNING,
    RESOLUTION_FAILED,
    CONNECTION_FAILED,
    CONNECTION_BROKE,
    CLIENT_STOPPED
} xl4bus_client_condition_t;

typedef void (*xl4bus_conn_info)(struct xl4bus_client *, xl4bus_client_condition_t, int);

typedef struct xl4bus_client {

#if XL4_PROVIDE_THREADS
    int use_internal_thread;
#endif

    char * url;

    xl4bus_set_poll set_poll;
    xl4bus_conn_info conn_notify;

    void * custom;
    void * _private;

} xl4bus_client_t;

#endif
