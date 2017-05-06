#ifndef _XL4BUS_TYPES_H_
#define _XL4BUS_TYPES_H_

#include <json-c/json.h>

typedef struct xl4bus_buf {
    uint8_t * data;
    size_t len;
} xl4bus_buf_t;

typedef void * (*xl4bus_malloc)(size_t);
typedef void * (*xl4bus_realloc)(void *, size_t);
typedef void (*xl4bus_free)(void*);

typedef struct xl4bus_ll_cfg {

    xl4bus_malloc malloc;
    xl4bus_realloc realloc;
    xl4bus_free free;

} xl4bus_ll_cfg_t;

typedef enum xl4bus_payload_form {
    JSON
} xl4bus_payload_form_t;

typedef struct xl4bus_message_t {

    xl4bus_payload_form_t form;
    union {
        json_object * json;
    };

} xl4bus_message_t;

struct xl4bus_X509v3_Identity;
struct xl4bus_connection;

#define XL4BUS_POLL_READ  (1<<1)
#define XL4BUS_POLL_WRITE (1<<2)
#define XL4BUS_POLL_ERR (1<<3)

#define E_XL4BUS_OK         (0)
#define E_XL4BUS_MEMORY     (-1) // malloc failed
#define E_XL4BUS_SYS        (-2) // syscall failed, check errno
#define E_XL4BUS_INTERNAL   (-3) // internal error
#define E_XL4BUS_EOF        (-4) // unexpected EOF from channel

typedef void (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_message_t *);

typedef char * (*xl4bus_password_callback_t) (struct xl4bus_X509v3_Identity *);
typedef int (*xl4bus_set_poll) (struct xl4bus_connection*, int);
typedef void (*xl4bus_notify_close) (struct xl4bus_connection*);

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

    xl4bus_set_poll set_poll;
    xl4bus_handle_ll_message ll_message;
    xl4bus_notify_close notify_close;

    void * custom;
    void * _private;

} xl4bus_connection_t;

#endif
