#ifndef _XL4BUS_PORTING_H_
#define _XL4BUS_PORTING_H_

/*
 * This file contains headers for
 * porting functions - such functions must be
 * implemented in the corresponding porting layer.
 */

// SEND(2), but flags are always 0
ssize_t pf_send(int sockfd, const void *buf, size_t len);
// RECV(2), but flags are always 0
ssize_t pf_recv(int sockfd, void *buf, size_t len);

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

#ifndef HAVE_STD_MALLOC
#define HAVE_STD_MALLOC 0
#endif

#ifndef HAVE_GETTIMEOFDAY
#define HAVE_GETTIMEOFDAY 0
#endif

#ifndef XL4BUS_PROVIDE_DEBUG
#define XL4BUS_PROVIDE_DEBUG 0
#endif

#ifndef NEED_PRINTF
// if NEED_PRINTF is 0, then please add
// a header definition of vasprintf
#define NEED_PRINTF 0
#endif

#endif
