
#if !XL4_HAVE_EPOLL
#if !defined(__GHS__)
#include <sys/resource.h>
#endif
#else
#include "config.h"
#endif
#include <poll.h>

#if XL4_HAVE_EPOLL
#if XL4_PROVIDE_EPOLL_CREATE1

static inline int epoll_create1(int flags) {
    if (flags) {
        // we currently never use non-zero flag
        // values, and if we did, they are not
        // implemented through here.
        errno = EINVAL;
        return -1;
    }
    return epoll_create(1);
}
#endif /* XL4_HAVE_EPOLL */
#endif /* XL4_PROVIDE_EPOLL_CREATE1 */
