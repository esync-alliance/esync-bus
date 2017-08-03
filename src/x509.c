#include <config.h>
#include "internal.h"
#include "porting.h"
#include "misc.h"
#include "debug.h"

#if 0

static void print_time(char *, mbedtls_x509_time *);

int x509_crt_to_write(mbedtls_x509_crt * crt, mbedtls_x509write_cert * wrt) {

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);

    int ok = 0;

#define BUF_TO_ASN(buf) \
    /* 5 bytes - maximum len, 1 byte - tag, then length of actual data */ \
    size_t asn_buf_len = 6 + (buf)->len; \
    unsigned char asn_buf[asn_buf_len]; \
    unsigned char * asn_ptr = asn_buf + asn_buf_len; \
    if (mbedtls_asn1_write_raw_buffer(&asn_ptr, asn_buf, (buf)->p, (buf)->len) < 0 || \
        mbedtls_asn1_write_len(&asn_ptr, asn_buf, (buf)->len) < 0 || \
        mbedtls_asn1_write_tag(&asn_ptr, asn_buf, (unsigned char) (buf)->tag)) { \
        break; \
    }

    do {

        // $TODO: the amount of hoops that I have to jump through here is
        // ridiculous, especially with having to convert things back to ASN.1
        // only to re-parse them later.
        // May be somebody can find easier ways of doing this.

        mbedtls_x509write_crt_init(wrt);
        mbedtls_x509write_crt_set_version(wrt, crt->version);

        {
            BUF_TO_ASN(&crt->serial);
            if (mbedtls_asn1_get_mpi(&asn_ptr, asn_buf + asn_buf_len, &serial)) { break; }
        }

        if (mbedtls_x509write_crt_set_serial(wrt, &serial)) {
            break;
        }

        // for validity times, set_validity expects 14 characters long times
        // in RFC5280 format. They say it's "UTCTime", but it's really "GeneralizedTime"
        // They also don't want the terminating Z. Go figure. The string must be 0 terminated
        // though, since strlen() is used.

        char before_time[15];
        char after_time[15];

        print_time(before_time, &crt->valid_from);
        print_time(after_time, &crt->valid_to);

        if (mbedtls_x509write_crt_set_validity(wrt, before_time, after_time)) {
            break;
        }

        {
            BUF_TO_ASN(&crt->issuer_raw);
            mbedtls_x509_string_to_names()
        }

        mbedtls_x509write_crt_set_issuer_name(wrt, )

    } while (0);

    mbedtls_mpi_free(&serial);

    if (!ok) {
        mbedtls_x509write_crt_free(wrt);
        return 1;
    }

    return 0;

}

void print_time(char * time, mbedtls_x509_time * x509_time) {

    snprintf(time, 15, "%.4d%.2d%.2d%.2d%.2d%.2d", max_int(9999, x509_time->year), max_int(99, x509_time->mon),
             max_int(99, x509_time->day), max_int(99, x509_time->hour),
             max_int(99, x509_time->min), max_int(99, x509_time->sec));

}
#endif
