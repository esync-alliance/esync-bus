
#include "url_decode.h"

static int decode_hex(unsigned char lit, int shift, unsigned char * out);
static void dump_incomplete(char * data, int * write_ptr, int state, unsigned char a1, unsigned char a2);

void decode_url(char * data) {

    if (!data) { return; }

    int state = 0;
    unsigned char acc;

    int read = 0;
    int write = 0;

    while (1) {

        unsigned char c = data[read++];
        if (!c) { break; }

        if (state == 0) {
            if (c == '+') { c = ' '; }
            if (c == '%') {
                state = 1;
                continue;
            }
            data[write++] = c;
            continue;
        }

        if (state == 1) {
            acc = c;
            state = 2;
            continue;
        }

        unsigned char dec_val = 0;
        if (decode_hex(acc, 4, &dec_val) || decode_hex(c, 0, &dec_val)) {
            dump_incomplete(data, &write, 3, acc, c);
        } else {
            data[write++] = dec_val;
        }
        state = 0;

    }

    dump_incomplete(data, &write, state, acc, 0);
    data[write] = 0;

}

void dump_incomplete(char * data, int * write_ptr, int state, unsigned char a1, unsigned char a2) {

    if (state) {
        data[(*write_ptr)++] = '%';
        if (state > 1) {
            data[(*write_ptr)++] = a1 == '+' ? ' ' : a1;
        }
        if (state > 2) {
            data[(*write_ptr)++] = a2 == '+' ? ' ' : a2;
        }
    }

}

int decode_hex(unsigned char lit, int shift, unsigned char * out) {

    unsigned char dec;

    if (lit >= '0' && lit <= '9') {
        dec = lit - '0';
    } else if (lit >= 'a' && lit <= 'f') {
        dec = lit - 'a' + 10;
    } else if (lit >= 'A' && lit <= 'F') {
        dec = lit - 'A' + 10;
    } else {
        return 1;
    }

    *out |= dec << shift;
    return 0;

}
