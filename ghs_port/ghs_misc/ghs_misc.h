#ifndef __GHS_MISC__
#define __GHS_MISC__
#include <stdarg.h>
#include <stdint.h> /*Need by uthash.h*/

int vasprintf(char **result, const char *format, va_list args);
char *strcasestr(const char *s, const char *find);
int asprintf(char **str, const char *fmt, ...);

#endif /* __GHS_MISC__*/
