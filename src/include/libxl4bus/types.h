
/**
 * @file
 */

#ifndef _XL4BUS_TYPES_H_
#define _XL4BUS_TYPES_H_

#include "types_base.h"
#include "build_config.h"

struct xl4bus_client;

/**
 * Used as a general buffer, when variably sized
 * data needs to be exchanged.
 */
typedef struct xl4bus_buf {
    uint8_t * data;
    size_t len;
} xl4bus_buf_t;

typedef enum xl4bus_asn1enc_t {

    XL4BUS_ASN1ENC_DER = 1,
    XL4BUS_ASN1ENC_PEM

} xl4bus_asn1enc_t;

/**
 * Used as a buffer for storing ASN.1 information,
 * so that the encoding method can be specified.
 * data needs to be exchanged.
 */
typedef struct xl4bus_asn1 {
    xl4bus_buf_t buf;
    xl4bus_asn1enc_t enc;
} xl4bus_asn1_t;

/**
 * Function type for allocation memory.
 */
typedef void * (*xl4bus_malloc)(size_t);

/**
 * Function type for reallocating memory
 */
typedef void * (*xl4bus_realloc)(void *, size_t);

/**
 * Function type for releasing allocated memory
 */
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

/**
 * Special addresses enumeration.
 */
typedef enum xl4bus_address_special {
    /**
     * The destination is the DM Client
     */
    XL4BAS_DM_CLIENT,
    /**
     * The destination is the XL4-Bus broker.
     * It's unusual to need to send a message to the broker.
     */
    XL4BAS_DM_BROKER,
} xl4bus_address_special_t;

typedef enum xl4bus_address_type {
    /**
     * Indicates a special bus address.
     * Use ::xl4bus_address_t.special to specify the
     * special destination.
     */
    XL4BAT_SPECIAL,

    /**
     * Indicates that the address is an update agent
     * name. Use ::xl4bus_address_t.update_agent to specify
     * the name of the corresponding update agent.
     */
    XL4BAT_UPDATE_AGENT,

    /**
     * Indicates that the address is a group.
     * Use ::xl4bus_address_t.group to specify the name of the
     * group.
     */
    XL4BAT_GROUP
} xl4bus_address_type_t;

/**
 * Represents a XL4-Bus destination address.
 */
typedef struct xl4bus_address {

    /**
     * Address type.
     */
    xl4bus_address_type_t type;
    union {
        /**
         * Used if type is ::XL4BAT_SPECIAL
         */
        xl4bus_address_special_t special;
        /**
         * Used if type is ::XL4BAT_UPDATE_AGENT
         */
        char * update_agent;
        /**
         * Used if type is ::XL4BAT_UPDATE_AGENT
         */
        char * group;
    };
    /**
     * Pointer to the next address.
     * When multiple addresses are used, they must be linked into a list.
     */
    struct xl4bus_address * next;

} xl4bus_address_t;

/**
 * Message object, wraps actual message payload
 * exchanged by the clients.
 */
typedef struct xl4bus_message {
    /**
     * Mime-type of the message, as declared by the sender.
     */
    char const * content_type;

    /**
     * List of addresses the message is to be delivered to.
     * Note that this field is not filled in for delivered messages.
     */
    xl4bus_address_t * address;

    /**
     * Payload data
     */
    void const * data;

    /**
     * Payload size. If sending ASCIIZ strings, make sure
     * to include the terminating 0 into the size (or expect it to be
     * missing on receipt).
     */
    size_t data_len;
} xl4bus_message_t;

typedef struct xl4bus_ll_message {

    xl4bus_message_t message;

    uint16_t stream_id;
    int is_final;
    int is_reply;
    int was_encrypted;

} xl4bus_ll_message_t;

struct xl4bus_X509v3_Identity;
struct xl4bus_connection;

/**
 * Requests read availability to be polled for, or indicates a read operation is available.
 */
#define XL4BUS_POLL_READ   (1<<0)

/**
 * Requests write availability to be polled for, or indicates a write operation is available.
 */
#define XL4BUS_POLL_WRITE  (1<<1)

/**
 * Indicates an error condition is present
 */
#define XL4BUS_POLL_ERR    (1<<2)

/**
 * Requests descriptor to be removed from polling all together.
 */
#define XL4BUS_POLL_REMOVE (1<<3)

/**
 * Successful operation
 */
#define E_XL4BUS_OK         ( 0)

/**
 * Memory allocation failed.
 */
#define E_XL4BUS_MEMORY     (-1)

/**
 * Underlying system call failed, the system call errno
 * was saved and should be examined.
 */
#define E_XL4BUS_SYS        (-2)

/**
 * Internal error, this typically indicates there is a bug
 * in the library.
 */
#define E_XL4BUS_INTERNAL   (-3)

/**
 * Communication stream failed with an early end-of-file.
 */
#define E_XL4BUS_EOF        (-4)

/**
 * The communication stream failed after unrecognizable data was received.
 */
#define E_XL4BUS_DATA       (-5)

/**
 * Invalid argument
 */
#define E_XL4BUS_ARG        (-6)

/**
 * The library client reported an error.
 */
#define E_XL4BUS_CLIENT     (-7)

typedef int (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_ll_message_t *);
typedef void (*xl4bus_ll_send_callback) (struct xl4bus_connection*, xl4bus_ll_message_t *, void *, int);

typedef char * (*xl4bus_password_callback_t) (struct xl4bus_X509v3_Identity *);
typedef int (*xl4bus_set_ll_poll) (struct xl4bus_connection*, int, int);
typedef int (*xl4bus_stream_callback) (struct xl4bus_connection *, uint16_t stream);

#if XL4_SUPPORT_THREADS
typedef int (*xl4bus_mt_message_callback) (struct xl4bus_connection *, void *, size_t);
#endif

typedef struct xl4bus_certificate_cache xl4bus_certificate_cache_t;

/**
 * X.509 based identity. Must contain X.509 certification and private key data.
 */
typedef struct xl4bus_X509v3_Identity {

    /**
     * Certificate chain that represents the caller. Must be terminated with NULL.
     */
    xl4bus_asn1_t ** chain;

    /**
     * Private key of the caller.
     */
    xl4bus_asn1_t * private_key;

    /**
     * If the private key is encrypted, then this call back is used to obtain the
     * password.
     */
    xl4bus_password_callback_t password;

    /**
     * List of trust anchors. Must be terminated with NULL.
     */
    xl4bus_asn1_t ** trust;

    /**
     * Custom value that is used for carrying arbitrary data for the password callback.
     */
    void * custom;

} xl4bus_X509v3_Identity_t;

/**
 * Trust-based identity. No verification of identity
 * claims are performed. Used for insecure environments only.
 * The caller can either identify as a DM Client
 * (set ::xl4bus_Trust_Identity.is_dm_client), a Broker
 * (set ::xl4bus_Trust_Identity.is_broker), or
 * an Update Agent (set ::xl4bus_Trust_Identity.update_agent).
 * Only one field must be set.
 */
typedef struct xl4bus_Trust_Identity {

    /**
     * If !0, then the caller identifies as a DM Client.
     */
    int is_dm_client;

    /**
     * If !0, then the caller identifies as a broker.
     */
    int is_broker;

    /**
     * Update agent name.
     */
    char * update_agent;

    /**
     * Number of group entries.
     */
    int group_cnt;

    /**
     * Array of pointers to group names. The length of the array is
     * ::xl4bus_Trust_Identity.group_cnt.
     */
    char ** groups;

} xl4bus_Trust_Identity;

/**
 * Identity type enumeration.
 */
typedef enum xl4bus_identity_type {
    /**
     * X.509 identity, use ::xl4bus_identity.x509 to specify
     * identity details.
     */
    XL4BIT_X509 = 1,
    /**
     * Trust identity, used for unsecure environments only.
     * Use ::xl4bus_identity.trust to specify
     * identity details.
     */
    XL4BIT_TRUST
} xl4bus_identity_type_t;

/**
 * Values of this type are used to provide identity information
 * to the library. The identity is then exposed to the broker,
 * and other clients. Any private components of the identity are
 * kept locally only.
 */
typedef struct xl4bus_identity {

    /**
     * Identity type, must be specified.
     */
    xl4bus_identity_type_t type;
    union {
        /**
         * X.509 identity details, if type is ::XL4BIT_X509.
         */
        xl4bus_X509v3_Identity_t x509;
        /**
         * Trust identity details, if type is ::XL4BIT_TRUST
         */
        xl4bus_Trust_Identity trust;
    };

} xl4bus_identity_t;

typedef struct xl4bus_connection {

    int fd;
    int is_client;

    xl4bus_identity_t identity;

    xl4bus_set_ll_poll set_poll;
    xl4bus_handle_ll_message on_message;
    xl4bus_ll_send_callback on_sent_message;
    xl4bus_stream_callback on_stream_abort;

    xl4bus_address_t * remote_address_list;

#if XL4_SUPPORT_THREADS
    int mt_support;
    int mt_write_socket;
    // int mt_read_socket;
    xl4bus_mt_message_callback on_mt_message;
#endif

    void * custom;
    void * _private;
    int _init_magic;

} xl4bus_connection_t;

/**
 * Used to indicate the state of the connection to the broker.
 */
typedef enum xl4bus_client_condition {
    /**
     * The broker connection is established and is valid.
     * This state is reported only once, unless followed
     * by some other state.
     */
    XL4BCC_RUNNING,
    /**
     * Attempts to resolve all of the provided host names
     * have failed.
     */
    XL4BCC_RESOLUTION_FAILED,

    /**
     * Attempts to connect to any of the IP addresses
     * derived from the specified host name have failed.
     */
    XL4BCC_CONNECTION_FAILED,

    /**
     * Attempt to register with the selected broker has failed.
     */
    XL4BCC_REGISTRATION_FAILED,

    /**
     * The previously established connection failed.
     */
    XL4BCC_CONNECTION_BROKE,

    /**
     * The connection was explicitly stopped. This only delivered
     * once, and no more status updates will be delivered afterwards.
     * Note that all undelivered messages will be reported to the
     * corresponding handler beforehands.
     */
    XL4BCC_CLIENT_STOPPED
} xl4bus_client_condition_t;

typedef int (*xl4bus_set_poll) (struct xl4bus_client *, int fd, int modes);

/**
 * Callback invoked for incoming messages.
 * @param clt client that received the message
 * @param msg message object
 */
typedef void (*xl4bus_handle_message)(struct xl4bus_client * clt, xl4bus_message_t * msg);

/**
 * Call back to be invoked when new connection state changes.
 * The connection is only considered "normal" when the state is
 * ::XL4BCC_RUNNING, in all other cases the method is invoked to indicate
 * that connection has failed, or attempt to connect has failed.
 *
 * Note that the connection is handled internally, and is attempted permanently
 * until ::xl4bus_stop_client is called.
 */
typedef void (*xl4bus_conn_info)(struct xl4bus_client *, xl4bus_client_condition_t);

/**
 * Call back to be invoked when a previously scheduled message has been processed.
 * The message could have been sent to the broker successfully, return due to
 * missing destinations, or returned because the client has been stopped.
 * The caller should dispose of any previously allocated structures at this point.
 * @param clt client structure through which the message was sent
 * @param msg message that has been sent
 * @param arg custom argument provided along with the message
 * @param ok !0 if the message was sent to the broker successfully, 0 otherwise.
 */
typedef void (*xl4bus_message_info)(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok);

/**
 * Call back to be invoked when new presence information is available.
 * The library guarantees that the connect and disconnect events will be
 * published for all connected clients.
 * When the connection to the broker establishes (or re-establishes), this
 * callback is invoked with the list of currently connected addresses.
 * Note that the callback is not invoked when the connection to the broker
 * is lost. Caller should use ::xl4bus_client_t.on_status to detect this
 * condition.
 *
 * @param clt client structure for which the update is published.
 * @param connected list of addresses that were announced as connected
 * @param disconnected list of addresses that were announced as disconnected
 */
typedef void (*xl4bus_presence_info)(struct xl4bus_client * clt,
        xl4bus_address_t * connected, xl4bus_address_t * disconnected);

/**
 * Represents high level client handler into the library.
 * All high level operations exchange the client object.
 */
typedef struct xl4bus_client {

#if XL4_PROVIDE_THREADS
    /**
     * If set to 1, requests that the library runs an internal
     * thread to service the client. All I/O multiplexing is
     * then handled by the client. The library will override any
     * provided polling callbacks. Neither ::xl4bus_run_client nor ::xl4bus_flag_poll
     * functions may be called for such client structure.
     *
     * This option is only available if the client is compiled with
     */
    int use_internal_thread;
#endif

    /**
     * Specifies the identity to be used for this connection.
     */
    xl4bus_identity_t identity;

    /**
     * Callback invoked when presence information is provided by the broker.
     * The callback can be set to 0 to ignore presence events. Note that the
     * presence handler will be invoke every time the client reconnects to
     * the broker.
     */
    xl4bus_presence_info on_presence;

    /**
     * Invoked when the connection status changes.
     */
    xl4bus_conn_info on_status;

    /**
     * Invoked when a previously submitted message has been delivered
     * (or when delivery has been given up upon).
     */
    xl4bus_message_info on_delivered;

    /**
     * Invoked when a message is delivered to this client.
     */
    xl4bus_handle_message on_message;

    /**
     * Invoked when the library requests for changing poll properties
     * of needed socket descriptors. This does not need to be implemented
     * if internal threads are used.
     */
    xl4bus_set_poll set_poll;

#if XL4_SUPPORT_THREADS
    /**
     * If the caller implements their own poll loop (and not use internal threads)
     */
    int mt_support;
#endif

    /**
     * The caller can use this field to reference their own data. This field is
     * never changed by the library.
     */
    void * custom;

    /**
     * This field is internally used by the library.
     */
    void * _private;

} xl4bus_client_t;

#endif
