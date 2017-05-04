#ifndef _XL4BUS_PORTING_H_
#define _XL4BUS_PORTING_H_

/*
 * This file contains headers for
 * porting functions - such functions must be
 * implemented in the corresponding porting layer.
 */

// SEND(2)
ssize_t pf_send(int sockfd, const void *buf, size_t len, int flags);
// RECV(2)
ssize_t pf_recv(int sockfd, void *buf, size_t len, int flags);



#endif