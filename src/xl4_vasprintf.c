
#include "internal.h"

#if XL4_PROVIDE_VASPRINTF

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include "xl4_vasprintf.h"

int xl4_vasprintf(char **buf, const char *fmt, va_list ap) {

    int chars;
    char *b;

    if (!buf) {
        return -1;
    }

#ifdef WIN32
    chars = _vscprintf(fmt, ap)+1;
#else // !defined(WIN32)
    va_list args;
    va_copy (args, ap);
    chars = vsnprintf (NULL, 0, fmt, args);
    va_end (args);

    if (chars < 0) {
        return -1;
    }
#endif // defined(WIN32)

    b = (char*)malloc(chars + 1);
    if (!b) {
        return -1;
    }

    va_copy (args, ap);
    int len;
    if((len = vsprintf(b, fmt, args)) < 0) {
        free(b);
    } else {
        *buf = b;
        assert(len == chars);
    }
    va_end (args);

    return chars;
}

#endif

