#ifndef __XL4_TABLEFD__
#define __XL4_TABLEFD__
#include <stdbool.h>

#define FD_MIN_VALUE    32768
#define FD_MAX_COUNT    1024 

#define FD_TYPE_ATFUNC  0x01
#define FD_TYPE_EPOLL   0x02

int xl4_tablefd_open(int type, void* data);
int xl4_tablefd_dup(int fd);
void* xl4_tablefd_get_data(int fd, int type);
int xl4_tablefd_unref_data(int fd);
int fd_entry_rename_path(char *old_path, char *new_path);
bool xl4_tablefd_is_last_link(char *path);

#endif // __XL4_TABLEFD__
