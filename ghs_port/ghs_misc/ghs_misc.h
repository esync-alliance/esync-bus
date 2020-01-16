#ifndef __GHS_MISC__
#define __GHS_MISC__
#include <stdarg.h>
#include <stdint.h> /*Need by uthash.h*/

int vasprintf(char **result, const char *format,
#if defined (_BSD_VA_LIST_) && defined (__FreeBSD__)
              _BSD_VA_LIST_ args);
#else
			  va_list args);
#endif

char *strcasestr(const char *s, const char *find);
int asprintf(char **str, const char *fmt, ...);

#endif /* __GHS_MISC__*/
