#ifndef _XL4BUS_ITC_H_
#define _XL4BUS_ITC_H_

#include <libxl4bus/low_level.h>

#define ITC_MESSAGE_MAGIC   0xda8de347
#define ITC_SHUTDOWN_MAGIC  0x947b67d3

typedef struct itc_message {
    uint32_t magic;
    xl4bus_ll_message_t * msg;
    void * ref;
} itc_message_t;

typedef struct itc_shutdown {
    uint32_t magic;
} itc_shutdown_t;

#endif