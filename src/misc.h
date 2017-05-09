#ifndef _XL4BUS_MISC_H_
#define _XL4BUS_MISC_H_

#include "internal.h"

extern uint8_t crcTable[];

// Credit : https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
inline void crcFast(void * data, size_t len, uint32_t * crc) {

    uint8_t one_byte;
    uint32_t remainder = *crc;

    /*
     * Divide the message by the polynomial, a byte at a time.
     */
    for (int i = 0; i < len; i++) {
        one_byte = ((uint8_t*)data)[i] ^ (uint8_t)(remainder >> 24);
        remainder = crcTable[one_byte] ^ (remainder << 8);
    }

    /*
     * The final remainder is the CRC.
     */
    *crc = remainder;

}

inline void * f_malloc(size_t size) {

    if (!size) { return 0; }
    void * r = cfg.malloc(size);
    if (r) {
        memset(r, 0, size);
    }
    return r;

}

#endif
