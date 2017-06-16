
#ifndef _XL4BROKER_COMMON_H_
#define _XL4BROKER_COMMON_H_

#include <stdint.h>
#include <sys/types.h>
#include <include/libxl4bus/types.h>

void print_out(const char *);
char * f_asprintf(char * fmt, ...);
char * f_strdup(const char *);
void * f_malloc(size_t);
void * f_realloc(void *, size_t);
int set_nonblocking(int fd);
uint64_t msvalue();
int get_socket_error(int fd);

void load_simple_x509_creds(xl4bus_identity_t * identity, char * p_key_path, char * cert_path, char * ca_path, char * password);

#endif
