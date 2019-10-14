#ifndef _QTABLEFD_H_
#define _QTABLEFD_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>

#define FD_MIN_VALUE    32768
#define FD_MAX_COUNT    1024 

#define FD_TYPE_ATFUNC  0x01
#define FD_TYPE_EPOLL   0x02

int qtablefd_open(int type, void* data);
int qtablefd_dup(int fd);
void* qtablefd_get_data(int fd, int type);
int qtablefd_unref_data(int fd);

#endif // _QTABLEFD_H_
