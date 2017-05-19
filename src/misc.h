#ifndef _XL4BUS_MISC_H_
#define _XL4BUS_MISC_H_

#include "internal.h"
#include "debug.h"

extern uint32_t crcTable[];

// Credit : https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
static inline void crcFast(void * data, size_t len, uint32_t * crc) {

    uint8_t one_byte;
    uint32_t remainder = *crc;

    /*
     * Divide the message by the polynomial, a byte at a time.
     */
    for (int i = 0; i < len; i++) {
#if DEBUG_CRC
#if XL4BUS_PROVIDE_DEBUG
        uint32_t old_crc = remainder;
#endif
#endif
        one_byte = ((uint8_t*)data)[i] ^ (uint8_t)(remainder >> 24);
        remainder = crcTable[one_byte] ^ (remainder << 8);

#if DEBUG_CRC
        DBG("CRC32 %08x %02x -> %08x", old_crc, ((uint8_t*)data)[i], remainder);
#endif
    }

    /*
     * The final remainder is the CRC.
     */
    *crc = remainder;

}

static inline void * f_malloc(size_t size) {

    if (!size) { return 0; }
    void * r = cfg.malloc(size);
    if (r) {
        memset(r, 0, size);
    }
    return r;

}

static inline int timeval_to_millis(struct timeval * tv) {
    // $TODO check for overflows.
    return  (int) (tv->tv_sec * 1000 + tv->tv_usec / 1000);
}

#endif
