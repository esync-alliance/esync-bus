#ifndef _FRAGMENT_LINUX_IF_BIND_H_
#define _FRAGMENT_LINUX_IF_BIND_H_

#include <ifaddrs.h>
#include <netinet/in.h>

// RANT: struct sockaddr can't contain sockaddr_in6, which is, IMHO, beyond stupid, as there is
// no value in sockaddr, or at least none in sockaddr.data. But, anyway, struct sockaddr can't be used
// as a type holder for either sockaddr4 or sockaddr6

// port must be in network order!
static int if_bind(int fd, char const * net_if, int family, in_port_t port) {

    if (!net_if && !port) { return 0; }

    union {
        struct sockaddr s;
#if XL4_SUPPORT_IPV4
        struct sockaddr_in s4;
#endif
#if XL4_SUPPORT_IPV6
        struct sockaddr_in6 s6;
#endif
    } selected = {
            .s = { .sa_family = AF_UNSPEC}
    };

    struct ifaddrs *if_addr = 0;

    if (net_if) {
        if (getifaddrs(&if_addr)) {
            return -1;
        }

        for (struct ifaddrs *addr = if_addr; addr; addr = addr->ifa_next) {

            if (z_strcmp(addr->ifa_name, net_if)) { continue; }

            if (!addr->ifa_addr || addr->ifa_addr->sa_family != family) { continue; }

#if XL4_SUPPORT_IPV4
            if (family == AF_INET) {
                selected.s4 = *(struct sockaddr_in*)addr->ifa_addr;
                break;
            }
#endif

#if XL4_SUPPORT_IPV4 || XL4_SUPPORT_IPV6
            if (family == AF_INET6) {
                selected.s6 = *(struct sockaddr_in6*)addr->ifa_addr;
                break;
            }
#endif

        }
    } else {

#if XL4_SUPPORT_IPV4
        selected.s.sa_family = family;
        if (family == AF_INET) {
            selected.s4.sin_addr.s_addr = INADDR_ANY;
        }
#endif
#if XL4_SUPPORT_IPV6
        selected.s.sa_family = family;
        if (family == AF_INET6) {
            struct in6_addr x = IN6ADDR_ANY_INIT;
            selected.s6.sin6_addr = x;
        }
#endif

    }

    int rc;

    if (selected.s.sa_family != family) {

        errno = ENOENT;
        rc = -1;

    } else {

        socklen_t len;

#if XL4_SUPPORT_IPV4
        if (family == AF_INET) {
            selected.s4.sin_port = port;
            len = sizeof(selected.s4);
        }
#endif
#if XL4_SUPPORT_IPV6
        if (family == AF_INET6) {
            selected.s6.sin6_port = port;
            len = sizeof(selected.s6);
        }
#endif

        rc = bind(fd, &selected.s, len);

    }

    freeifaddrs(if_addr);

    return rc;


}


#endif // _STATIC_IF_BIND_C_