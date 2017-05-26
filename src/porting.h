#ifndef _XL4BUS_PORTING_H_
#define _XL4BUS_PORTING_H_

#include "build_config.h"
#include "config.h"

#if XL4_PROVIDE_THREADS && !XL4_SUPPORT_THREADS
#error You are requesting threading support (XL4_PROVIDE_THREADS=>1), but disabling use of threads (XL4_SUPPORT_THREADS=>0).
#endif

#if XL4_SUPPORT_THREADS
#if !XL4_SUPPORT_UNIX_DGRAM_PAIR
#error You are requesting threading support, but no ITC mechanisms are enabled (XL4_SUPPORT_UNIX_DGRAM_PAIR).
#endif
#endif

#if XL4_SUPPORT_UNIX_DGRAM_PAIR && !XL4_NEED_DGRAM
#define XL4_NEED_DGRAM 1
#endif

/*
 * This file contains headers for
 * porting functions - such functions must be
 * implemented in the corresponding porting layer.
 */

typedef void * (*pf_malloc_fun)(size_t);

// SEND(2), but flags are always 0
ssize_t pf_send(int sockfd, const void *buf, size_t len);
// RECV(2), but flags are always 0
ssize_t pf_recv(int sockfd, void *buf, size_t len);

#if XL4_NEED_DGRAM
// this must receive a whole datagram from the specified
// (datagram) socket. The size of the read datagram should
// be returned. 0 for EOF, or <0 for error should be returned.
// the buffer is to be allocated with the specified allocation function.
// the allocation function may return 0 to indicate out of memory.
// however, if the allocation succeeded, and later attempt to receive
// data failed, the buffer shall remain allocated, and the caller
// must free it.
ssize_t pf_recv_dgram(int sockfd, void ** addr, pf_malloc_fun);
#endif

// sets descriptor to non-blocking mode, return 0 if OK,
// !0 if not OK (errno must be set)
int pf_set_nonblocking(int);

// set errno. The errno must be thread safe
// (unless a single thread environment is guaranteed).
void pf_set_errno(int);

// get errno.
int pf_get_errno(void);

// millisecond timer. Get the number of
// milliseconds that passed since beginning of some local timer.
// The value doesn't need to represent any actual time, just
// consistently grow at an approximately millisecond rate.
uint64_t pf_msvalue();

// generate specified number of random bytes into
// the specified address.
void pf_random(void *, size_t);

#if XL4_PROVIDE_THREADS
typedef void (*pf_runnable_t)(void *);
// start new thread. The thread is to end when
// pf_runnable_t exits. The argument included
// in this function must be provided to the runnable.
// return 0 if thread started successfully, or return 1
// and set errno.
int pf_start_thread(pf_runnable_t, void *);

// connect to a TCP destination.
// the operation must be asynchronous if possible.
// The *async should be set to 1, if the operation
// must finish the connection later. Polling for
// writeability will be requested, and when indicated,
// the connection will be considered connected or
// failed, if pf_get_socket_error() returns !0.
// ip will always be an IP address (never host name),
// and may be IPV6. Return -1 and set errno, if unable
// to connect. The IP address is raw, encoded in host order,
// as if in hostent structure, the ip_len contains its
// length.
int pf_connect_tcp(void * ip, size_t ip_len, uint16_t port, int * async);

// return 0 if the socket is OK, otherwise return !0
// and set errno.
int pf_get_socket_error(int);

// this is copied from poll(2)
typedef struct pf_poll {
    int fd;
    // events/revents are:
    // XL4BUS_POLL_READ  (1<<1)
    // XL4BUS_POLL_WRITE (1<<2)
    // XL4BUS_POLL_ERR   (1<<3)
    short events;
    short revents;
} pf_poll_t;

// this is analogous to poll(2)
int pf_poll(pf_poll_t *, int, int);

// like shutdown(2), but always with RDWR flag.
void pf_shutdown_rdwr(int);

// like close(2), but library doesn't care if close() failed
void pf_close(int);

#endif

#if XL4_SUPPORT_UNIX_DGRAM_PAIR
int pf_dgram_pair(int sv[2]);
#endif

#endif
