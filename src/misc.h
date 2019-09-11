#ifndef _XL4BUS_MISC_H_
#define _XL4BUS_MISC_H_

#include "internal.h"
#include "debug.h"

#define crcTable XI(crcTable)
extern uint32_t crcTable[];

#define NULL_STR(a) ((a)?(a):"(null)")

#define Z_FREE(a) do { cfg.free(a); a = 0; } while (0)
#define Z(op, p) do { op(p); p = 0; } while (0)

static inline int always_ok(void) { return E_XL4BUS_OK; }

#if XL4_SUPPORT_THREADS
#define LOCK(a) pf_lock(&a)
#define UNLOCK(a) pf_unlock(&a)
#else
#define LOCK(a) always_ok()
#define UNLOCK(a) do{}while(0)
#endif

// Credit : https://barrgroup.com/Embedded-Systems/How-To/CRC-Calculation-C-Code
static inline void crcFast(void * data, size_t len, uint32_t * crc) {

    uint8_t one_byte;
    uint32_t remainder = *crc;

    /*
     * Divide the message by the polynomial, a byte at a time.
     */
    for (int i = 0; i < len; i++) {
#if DEBUG_CRC
#if XL4_PROVIDE_DEBUG
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

static inline void * f_calloc(size_t n_mem_b, size_t size) {

    return f_malloc(n_mem_b * size);

}

static inline char * f_strdup(const char *s) {

    if (!s) { return 0; }
    size_t l = strlen(s) + 1;
    char * s2 = cfg.malloc(l);
    if (!s2) { return 0; }
    memcpy(s2, s, l);
    return s2;
}

static inline char * f_strndup(const void *s, size_t len) {

    if (!s) { return 0; }
    char * s2 = cfg.malloc(len+1);
    if (!s2) { return 0; }
    memcpy(s2, s, len);
    s2[len] = 0;
    return s2;
}

static inline int timeval_to_millis(struct timeval * tv) {
    // $TODO check for overflows.
    return  (int) (tv->tv_sec * 1000 + tv->tv_usec / 1000);
}

static inline int max_int(int a1, int a2) {
    return a1 > a2 ? a1 : a2;
}

static inline void secure_bzero(void * addr, size_t len) {
    for (size_t i = 0; i<len; i++) {
        ((char*)addr)[i] = 0;
    }
}

#endif
