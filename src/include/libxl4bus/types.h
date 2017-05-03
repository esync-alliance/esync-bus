#ifndef _XL4BUS_TYPES_H_
#define _XL4BUS_TYPES_H_

typedef struct xl4bus_buf {
    uint8_t * data;
    size_t len;
} xl4bus_buf_t;

typedef enum xl4bus_payload_form {

    JSON

} xl4bus_payload_form_t;

typedef struct xl4bus_message_t {

    xl4bus_payload_form_t form;
    union {
    };

};

struct xl4bus_X509v3_Identity;
struct xl4bus_connection_t;

#define XL4BUS_POLL_READ  1
#define XL4BUS_POLL_WRITE 2

typedef void (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_message_t *);

typedef char * (*xl4bus_password_callback_t) (struct xl4bus_X509v3_Identity *);
typedef void (*xl4bus_set_poll(struct xl4bus_connection_t*, int));

typedef struct xl4bus_X509v3_Identity {

    xl4bus_buf_t certificate;
    xl4bus_buf_t private_key;
    xl4bus_password_callback_t password;
    xl4bus_buf_t * trust;
    size_t trust_len;

} xl4bus_X509v3_Identity_t;

typedef struct xl4bus_connection {

    int fd;

    xl4bus_set_poll set_poll;

    void * custom;

    void * _private;


} xl4bus_connection_t;

#endif
