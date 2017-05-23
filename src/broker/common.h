
#ifndef _XL4BROKER_COMMON_H_
#define _XL4BROKER_COMMON_H_

#include <sys/types.h>

void print_out(const char *);
char * f_asprintf(char * fmt, ...);
char * f_strdup(const char *);
void * f_malloc(size_t);
void * f_realloc(void *, size_t);

#endif
