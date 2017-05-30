#ifndef _XL4BUS_TYPES_H_
#define _XL4BUS_TYPES_H_

#include "types_base.h"
#include "build_config.h"

struct xl4bus_client;

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

typedef struct xl4bus_message {
    char * content_type;
    char * xl4bus_address;
    void const * data;
    size_t data_len;
} xl4bus_message_t;

typedef struct xl4bus_ll_message {

    xl4bus_message_t message;

    uint16_t stream_id;
    int is_final;
    int is_reply;

} xl4bus_ll_message_t;

struct xl4bus_X509v3_Identity;
struct xl4bus_connection;

#define XL4BUS_POLL_READ   (1<<0)
#define XL4BUS_POLL_WRITE  (1<<1)
#define XL4BUS_POLL_ERR    (1<<2)
#define XL4BUS_POLL_REMOVE (1<<3)

#define E_XL4BUS_OK         (0)
#define E_XL4BUS_MEMORY     (-1) // malloc failed
#define E_XL4BUS_SYS        (-2) // syscall failed, check errno
#define E_XL4BUS_INTERNAL   (-3) // internal error
#define E_XL4BUS_EOF        (-4) // unexpected EOF from channel
#define E_XL4BUS_DATA       (-5) // communication channel received unrecognized data.
#define E_XL4BUS_ARG        (-6) // invalid argument provided to the function
#define E_XL4BUS_CLIENT     (-7) // client code reported an error

typedef int (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_ll_message_t *);
typedef void (*xl4bus_ll_send_callback) (struct xl4bus_connection*, xl4bus_ll_message_t *, void *, int);

typedef char * (*xl4bus_password_callback_t) (struct xl4bus_X509v3_Identity *);
typedef int (*xl4bus_set_ll_poll) (struct xl4bus_connection*, int, int);
typedef int (*xl4bus_stream_callback) (struct xl4bus_connection *, uint16_t stream);

#if XL4_SUPPORT_THREADS
typedef int (*xl4bus_mt_message_callback) (struct xl4bus_connection *, void *, size_t);
#endif

typedef struct xl4bus_X509v3_Identity {

    xl4bus_buf_t certificate;
    xl4bus_buf_t private_key;
    xl4bus_password_callback_t password;
    size_t trust_len;
    xl4bus_buf_t * trust;

} xl4bus_X509v3_Identity_t;

typedef struct xl4bus_Trust_Identity {

    char * update_agent;
    int is_dm_client;
    int is_broker;
    int group_cnt;
    char ** groups;

} xl4bus_Trust_Identity;

typedef enum xl4bus_identity_type {
    XL4BIT_X509,
    XL4BIT_TRUST
} xl4bus_identity_type_t;

typedef struct xl4bus_identity {

    xl4bus_identity_type_t type;
    union {
        xl4bus_X509v3_Identity_t x509;
        xl4bus_Trust_Identity trust;
    };

} xl4bus_identity_t;

typedef struct xl4bus_connection {

    int fd;
    int is_client;

    xl4bus_identity_t identity;

    xl4bus_set_ll_poll set_poll;
    xl4bus_handle_ll_message on_message;
    xl4bus_ll_send_callback send_callback;
    xl4bus_stream_callback on_stream_abort;
    int is_shutdown;
#if XL4_SUPPORT_THREADS
    int mt_support;
    int mt_write_socket;
    // int mt_read_socket;
    xl4bus_mt_message_callback on_mt_message;
#endif

    void * custom;
    void * _private;

} xl4bus_connection_t;

typedef enum xl4bus_client_condition {
    XL4BCC_RUNNING,
    XL4BCC_RESOLUTION_FAILED,
    XL4BCC_CONNECTION_FAILED,
    XL4BCC_REGISTRATION_FAILED,
    XL4BCC_CONNECTION_BROKE,
    XL4BCC_CLIENT_STOPPED
} xl4bus_client_condition_t;

typedef int (*xl4bus_set_poll) (struct xl4bus_client *, int fd, int modes);
typedef void (*xl4bus_handle_message)(struct xl4bus_client *, xl4bus_message_t *);
typedef void (*xl4bus_conn_info)(struct xl4bus_client *, xl4bus_client_condition_t);
typedef void (*xl4bus_message_info)(struct xl4bus_client *, xl4bus_message_t *, void *, int);

typedef struct xl4bus_client {

#if XL4_PROVIDE_THREADS
    int use_internal_thread;
#endif

    xl4bus_set_poll set_poll;
    xl4bus_conn_info conn_notify;
    xl4bus_message_info message_notify;
    xl4bus_handle_message handle_message;
    xl4bus_identity_t identity;

#if XL4_SUPPORT_THREADS
    int mt_support;
#endif

    void * custom;
    void * _private;

} xl4bus_client_t;

#endif
