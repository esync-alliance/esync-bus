#ifndef _XL4BUS_ITC_H_
#define _XL4BUS_ITC_H_

#include <libxl4bus/low_level.h>

#define ITC_MESSAGE_MAGIC      0xda8de347
#define ITC_SHUTDOWN_MAGIC     0x947b67d3
#define ITC_STOP_CLIENT_MAGIC  0x829fde1e

#if WITH_UNIT_TEST
#define ITC_PAUSE_RCV_MAGIC    0xf99291db
#endif

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

#endif
