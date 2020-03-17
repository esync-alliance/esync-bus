#ifndef _XL4BUS_ITC_H_
#define _XL4BUS_ITC_H_

#include <libxl4bus/low_level.h>

#define ITC_MESSAGE_MAGIC      0xda8de347
#define ITC_SHUTDOWN_MAGIC     0x947b67d3
#define ITC_STOP_CLIENT_MAGIC  0x829fde1e

#if WITH_UNIT_TEST
#define ITC_PAUSE_RCV_MAGIC    0xf99291db
#endif

#pragma pack(push,1)
// if we don't pack that structure, the padding bytes
// are not initialized if we use a structure initializer,
// which raises valgrind warnings. Even though warnings
// are benign (i.e. we are not actually using any of the
// uninitialized memory), it's just easier to pack it.
typedef struct itc_message {
    uint32_t magic;

    union {

        struct {
            xl4bus_ll_message_t * msg;
            void * ref;
        } msg; // ITC_MESSAGE_MAGIC

        xl4bus_client_t * client; // ITC_STOP_CLIENT_MAGIC

#if WITH_UNIT_TEST
        struct {
            int pause;
            xl4bus_client_t * client;
        } pause; // ITC_PAUSE_RCV_MAGIC
#endif

};

} itc_message_t;
#pragma pack(pop)

#endif
