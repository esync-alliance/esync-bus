
/**
 * @file
 */

#ifndef _XL4BUS_TYPES_H_
#define _XL4BUS_TYPES_H_

#include <libxl4bus/types_base.h>
#include <libxl4bus/build_config.h>

// forward declarations
struct xl4bus_client;
struct xl4bus_identity;
struct xl4bus_X509v3_Identity;
struct xl4bus_connection;

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
 * @param sz number of bytes to be allocated
 * @return address of the allocated memory block, or `0` if no memory can be allocated.
 */
typedef void * (*xl4bus_malloc)(size_t sz);

/**
 * Function type for reallocating memory.
 * @param ptr pointer to previously allocated memory block. Can be `0`, for a new block to be
 * of the specified size to be allocated instead.
 * @param sz number of bytes that the reallocated block should occupy, at least.
 * @return `0` if reallocation is not possible. Previous block should not be modified. Otherwise,
 * returns the address of the block that contained all the data that `ptr` was pointing to, up to new size. The
 * old memory block (unless the same block is returned) should be freed.
 */
typedef void * (*xl4bus_realloc)(void *, size_t);

/**
 * Function type for releasing allocated memory.
 * @param ptr memory block to release.
 */
typedef void (*xl4bus_free)(void* ptr);

#if XL4_PROVIDE_DEBUG
typedef void (*xl4bus_debug)(const char *);
#endif

typedef struct xl4bus_ll_cfg {

    /**
     * Function to use to allocation memory.
     */
    xl4bus_malloc malloc;
    /**
     * Function to use to change size of allocated block.
     */
    xl4bus_realloc realloc;
    /**
     * Function to free the memory.
     */
    xl4bus_free free;
#if XL4_PROVIDE_DEBUG
    /**
     * Function to be called for printing debugging output of the library
     */
    xl4bus_debug debug_f;
    /**
     * If `!0`, then debugging output will not contain a time stamp. Intended for logging systems that
     * use their own timestamp.
     */
    int debug_no_time;
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
    XL4BAT_SPECIAL = 1,

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
     */
    xl4bus_address_t * address;

    /**
     * List of addresses the message was sent from. For received messages,
     * this contains the address that the message sent from (declared, or inferred).
     * For sent messages, this can be set to declare the "sent" address. Note that
     * the sent address must be present in the identity, otherwise the message will
     * not be delivered.
     */
    xl4bus_address_t * source_address;

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

   /**
    * If !0, then the message was encrypted by the sender, and was decrypted
    * successfully before being passed down.
    */
    int was_encrypted;

    /**
     * Set by the library, when message is scheduled for delivery,
     * or when message is delivered to the user, this value is set
     * to help identify the message through its routing.
     */
    int tracking_id;

    /**
     * Set by the library, when the message is returned through
     * a call back.
     */
    int err;

} xl4bus_message_t;

typedef struct xl4bus_ll_message {

    /**
     * message data
     */
    void const * data;

    /**
     * Message data length
     */
    size_t data_len;

    /**
     * Declared content type of the message.
     */
    char const * content_type;

    /**
     * Low-level stream ID that the data came over on
     */
    uint16_t stream_id;

    /**
     * If !0, then the message is final, i.e. no more messages
     * can be exchanged on the same stream ID.
     */
    int is_final;

    /**
     * If !0, then the message is a reply, i.e. not the first message
     * in the stream.
     */
    int is_reply;

    /**
     * For received messages, `!0` indicates that the message was encrypted when received,
     * and has been decrypted since, or `0` otherwise, including cases when it could not be decrypted.
     * For sending messages, `!0` indicates that the message must be encrypted, or `0` not to encrypt it.
     */
    int uses_encryption;

    /**
     * For received messages, `!0` is set when ::uses_encryption is `!0`, and the session key was used for
     * decryption, instead of identity's key, `0` otherwise.
     * For sending messages, `!0` indicates that the message should be encrypted using session key, if such is
     * available.
     */
    int uses_session_key;

    /**
     * For received messages, `!0` indicates that the message contained signature that was validated, `0` otherwise.
     * For sending messages, `!0` indicates that the message must be signed, or `0` not to sign it.
     */
    int uses_validation;

    /**
     * If !0, then contains the timeout value, next message should
     * be sent or received for the same stream within that specified amount
     * of milliseconds. If 0, then timeout is set as defined by the
     * connection.
     */
    unsigned timeout_ms;

    /**
     * If set, then the remote has provided a full identity, as specified. Note that this is possible
     * even if the identity has previously been provided, and the newly provided identity may differ.
     */
    struct xl4bus_identity * remote_identity;

    /**
     * If set, contains additional data that is either to be sent as authenticated header data, or has been
     * received as authenticated header data; only from the signed part of the message.
     */
    char const * bus_data;

} xl4bus_ll_message_t;

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
 * Special constant value, if used for the file descriptor,
 * indicates that the flag value is instead a timeout value,
 * specified in milliseconds.
 */
#define XL4BUS_POLL_TIMEOUT_MS -1

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

/**
 * Some requested resource is fully used and can not
 * be returned.
 */
#define E_XL4BUS_FULL     (-8)

/**
 * Message can not be delivered to any destinations
 */
#define E_XL4BUS_UNDELIVERABLE     (-9)

typedef enum xl4bus_stream_close_reason {

    XL4SCR_LOCAL_CLOSED,
    XL4SCR_REMOTE_CLOSED,
    XL4SCR_CONN_SHUTDOWN,
    XL4SCR_TIMED_OUT,
    XL4SCR_REMOTE_ABORTED,

} xl4bus_stream_close_reason_t;

typedef int (*xl4bus_handle_ll_message)(struct xl4bus_connection*, xl4bus_ll_message_t *);
typedef void (*xl4bus_ll_send_callback) (struct xl4bus_connection*, xl4bus_ll_message_t *, void *, int);

typedef char *(*xl4bus_password_callback_t)(struct xl4bus_X509v3_Identity *);
typedef int (*xl4bus_set_ll_poll)(struct xl4bus_connection *, int, int);
typedef int (*xl4bus_stream_callback)(struct xl4bus_connection *, uint16_t stream, xl4bus_stream_close_reason_t);
typedef void (*xl4bus_shutdown_callback)(struct xl4bus_connection *);

#if XL4_SUPPORT_THREADS
typedef int (*xl4bus_mt_message_callback) (struct xl4bus_connection *, void *, size_t);
#endif

typedef struct xl4bus_certificate_cache xl4bus_certificate_cache_t;

/**
 * X.509 based identity. For representing own identity,
 * must contain X.509 certification and private key data.
 * For representing remote identities, only certificate chain is provided.
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
     * password. If the callback is set, a non-NULL string *must* be returned (but can be empty),
     * it will be zeroed and freed by the library once the private key was decrypted.
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
     * Reserved for invalid/uninitialized value
     */
    XL4BIT_INVALID = 0,
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

/**
 * Enumerates support key types.
 */
typedef enum xl4bus_key_type {

    /**
     * Represents invalid key type value.
     */
    XL4KT_INVALID,

    /**
     * Represents 256 bit AES key.
     */
    XL4KT_AES_256

} xl4bus_key_type_t;

typedef struct xl4bus_key {

    xl4bus_key_type_t type;
    uint64_t expires;
    union {
        uint8_t aes_256[256/8];
    };

} xl4bus_key_t;

typedef struct xl4bus_connection {

    int fd;
    int is_client;

    xl4bus_identity_t identity;

    xl4bus_set_ll_poll set_poll;
    xl4bus_handle_ll_message on_message;
    xl4bus_ll_send_callback on_sent_message;
    xl4bus_stream_callback on_stream_closure;
    xl4bus_shutdown_callback on_shutdown;

    xl4bus_address_t * remote_address_list;

    union {
        // X.509 support
        struct {
            char * remote_x5t;
            char * remote_x5c;
            char * my_x5t;
        };
    };

#if XL4_SUPPORT_THREADS
    int mt_support;
    int mt_write_socket;
    // int mt_read_socket;
    xl4bus_mt_message_callback on_mt_message;
#endif

    int stream_count;

    /**
     * Indicates the amount of time that a stream will be kept open
     * while there is no data sent through it. 0 disables timeout.
     */
    unsigned stream_timeout_ms;
    /**
     * Contains keep-alive configuration.
     */
    struct {

        /**
         * Amount of milliseconds to wait since last data or keep-alive
         * before starting to send keep-alive packets. 0 indicates that
         * keep-alive is disabled.
         */
        unsigned wait_until_ms;

        /**
         * Amount of keep-alive probes to send. At least that many probes
         * will be waited without response before the stream is terminated.
         */
        unsigned probe_count;

        /**
         * Amount of time to wait before configuring the probe lost and
         * either terminating the connection, or issuing the next probe.
         */
        unsigned wait_for_response_ms;

    } keep_alive;

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
     * Note that this condition will be used if the client is managed
     * by an internal library thread, and the thread ran into I/O issue.
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

typedef void (*xl4bus_release_client)(struct xl4bus_client *);

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
     * then handled by the library. The library will override any
     * provided polling callbacks. Neither ::xl4bus_run_client nor ::xl4bus_flag_poll
     * functions are allowed be called for such configuration.
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
     * Used as a callback for cleaning up any allocated client structures. The caller
     * must only clean up any memory used for creating the client object after this
     * callback is invoked, if the client initialization succeeded. The caller can either
     * clean up the structure, or re-initialize it. The client object will remain
     * unusable if it is not re-initialized.
     *
     * Not setting this handler will result into memory leaks.
     */
    xl4bus_release_client on_release;

    /**
     * Callback invoked when presence information is provided by the broker.
     * The callback can be set to 0 to ignore presence events. Note that the
     * presence handler will be invoked every time the client reconnects to
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
     * This field is internally used by the library, and must not be modified by
     * the caller.
     */
    void * _private;

} xl4bus_client_t;

#endif
