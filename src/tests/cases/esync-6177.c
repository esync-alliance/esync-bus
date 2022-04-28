#include "tests/tests.h"
#include "tests/full-test.h"
#include "tests/cases.h"
#include "bus-test-support.h"
#include "lib/debug.h"
#include "lib/url_decode.h"
#include <libxl4bus/low_level.h>
#include "uthash.h"

#if __linux__

#include "fragments/linux_if_bind.h"

union addr {
    struct sockaddr s;
#if XL4_SUPPORT_IPV4
    struct sockaddr_in s4;
#endif
#if XL4_SUPPORT_IPV6
    struct sockaddr_in6 s6;
#endif
};

struct if_and_addr {
    char * net_if;
    union addr addr;
};

static connect_test;
static char const * expected_net_if;

static void intercept_connect(struct xl4bus_client * clt, void * ip, size_t ip_len, in_port_t port, char const * net_if) {

    if (!z_strcmp(net_if, expected_net_if)) { connect_test = E_XL4BUS_OK; }

}

static void free_if_and_addr(struct if_and_addr * s) {
    if (s) {
        free(s->net_if);
    }
    free(s);
}

static struct if_and_addr * get_if_and_addr(int family) {

    struct ifaddrs *if_addr = 0;
    if (getifaddrs(&if_addr)) {
        return 0;
    }
    struct if_and_addr * ret = 0;
    for (struct ifaddrs *addr = if_addr; addr; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == family) {
            ret = f_malloc(sizeof(struct if_and_addr));
            ret->net_if = f_strdup(addr->ifa_name);
#if XL4_SUPPORT_IPV4
            if (family == AF_INET) {
                ret->addr.s4 = *(struct sockaddr_in*)addr->ifa_addr;
            }
#endif

#if XL4_SUPPORT_IPV4 || XL4_SUPPORT_IPV6
            if (family == AF_INET6) {
                ret->addr.s6 = *(struct sockaddr_in6*)addr->ifa_addr;
            }
#endif
            break;
        }
    }

    freeifaddrs(if_addr);

    if (!ret) { errno = ENOENT; }

    return ret;

}

static int verify_address(int fd, int family, struct if_and_addr * spec, in_port_t port) {

    int err = E_XL4BUS_OK;

    do {

        union addr test_addr;
        socklen_t test_addr_len = sizeof(test_addr);

        BOLT_SYS(getsockname(fd, &test_addr.s, &test_addr_len), "getsockname()");

#if XL4_SUPPORT_IPV4
        if (family == AF_INET) {
            BOLT_IF(test_addr.s.sa_family != family, E_XL4BUS_INTERNAL, "family");
            struct sockaddr_in * in4 = (struct sockaddr_in*)&test_addr;
            if (port) {
                BOLT_IF(ntohs(in4->sin_port) != port, E_XL4BUS_INTERNAL, "port");
            }
            if (spec) {
                BOLT_IF(in4->sin_addr.s_addr != spec->addr.s4.sin_addr.s_addr, E_XL4BUS_INTERNAL, "addr");
            } else {
                BOLT_IF(in4->sin_addr.s_addr != INADDR_ANY, E_XL4BUS_INTERNAL, "addr");
            }
        }
#endif
#if XL4_SUPPORT_IPV6
        if (family == AF_INET6) {
            BOLT_IF(test_addr.s.sa_family != family, E_XL4BUS_INTERNAL, "family");
            struct sockaddr_in6 * in6 = (struct sockaddr_in6*)&test_addr;
            if (port) {
                BOLT_IF(ntohs(in6->sin6_port) != port, E_XL4BUS_INTERNAL, "port");
            }
            if (spec) {
                BOLT_IF(memcmp(&in6->sin6_addr, &spec->addr.s6.sin6_addr, sizeof(struct in6_addr)), E_XL4BUS_INTERNAL, "addr");
            } else {
                struct in6_addr any = IN6ADDR_ANY_INIT;
                BOLT_IF(memcmp(&in6->sin6_addr, &any, sizeof(struct in6_addr)), E_XL4BUS_INTERNAL, "addr");
            }
        }
#endif


    } while (0);

    return err;

}

static int bind_to_if() {

    int err = E_XL4BUS_OK;

    do {

        for (int i=0; i<4; i++) {

            iDBG("i=%d", i);

            int family;

            if (i%2) {
#if XL4_SUPPORT_IPV6
                family = AF_INET6;
#else
                continue;
#endif
            } else {
#if XL4_SUPPORT_IPV4
                family = AF_INET;
#else
                continue;
#endif
            }

            struct if_and_addr * spec = 0;

            if (i>=2) {
                spec = get_if_and_addr(family);
                BOLT_NULL(spec, "if/addr");
            }

            int fd = socket(family, SOCK_STREAM, 0);
            BOLT_M1(fd, "socket");

            in_port_t port = htons(0x55aa);

            BOLT_SYS(if_bind(fd, spec?spec->net_if:0, family, port), "if_bind");

            BOLT_SUB(verify_address(fd, family, spec, 0x55aa));

            close(fd);
            free_if_and_addr(spec);

        }

    } while(0);

    return err;

}

static int connect_from_if() {

    int err /*= E_XL4BUS_OK */;

    do {

        struct if_and_addr * spec = get_if_and_addr(AF_INET);
        BOLT_NULL(spec, "get_if_and_addr");

        iDBG("Selected if %s", spec->net_if);

        for (int i=0; i<5; i++) {

            iDBG("i=%d", i);

            char * query;
            expected_net_if = spec->net_if;

            if (i == 0) {
                query = f_asprintf("?%%69%%66=%s&boo=foo", spec->net_if);
            } else if (i == 1) {
                query = f_asprintf("?if=%s", spec->net_if);
            } else if (i == 2) {
                query = f_asprintf("?boo=%%A0&a0=z");
                expected_net_if = 0;
            } else if (i == 3) {
                query = f_asprintf("?c=0&b&d");
                expected_net_if = 0;
            } else if (i == 4) {
                query = f_asprintf("?");
                expected_net_if = 0;
            }

            test_client_t client1 = {
                    .label = f_strdup("client-grp1"),
                    .query = query
            };
            test_broker_t broker = { .net_if = f_strdup(spec->net_if) };
            // test_broker_t broker = { 0 };

            connect_test = E_XL4BUS_INTERNAL;
            test_connect_interceptor = intercept_connect;

            BOLT_SUB(full_test_broker_start(&broker));
            BOLT_SUB(full_test_client_start(&client1, &broker, 1));

            test_connect_interceptor = 0;

            BOLT_SUB(verify_address(broker.context.fd, AF_INET, spec, broker.context.port));

            full_test_client_stop(&client1, 1);
            full_test_broker_stop(&broker, 1);

            BOLT_SUB(connect_test);

        }

        free_if_and_addr(spec);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCSimplifyInspection"
    } while (0);
#pragma clang diagnostic pop

    return err;


}

static int test_decode_url_one(char const * in, char const * out) {

    char * in2 = f_strdup(in);
    decode_url(in2);
    int r = z_strcmp(in2, out);
    free(in2);
    if (!r) {
        return E_XL4BUS_OK;
    }
    return E_XL4BUS_DATA;

}

static int test_decode_url() {

    int err = E_XL4BUS_OK;

    do {

        BOLT_SUB(test_decode_url_one("%", "%"));
        BOLT_SUB(test_decode_url_one("c%", "c%"));
        BOLT_SUB(test_decode_url_one("b%a", "b%a"));
        BOLT_SUB(test_decode_url_one("d%x0a", "d%x0a"));
        BOLT_SUB(test_decode_url_one("%F0%c9", "\xf0\xc9"));
        BOLT_SUB(test_decode_url_one("a+b", "a b"));
        BOLT_SUB(test_decode_url_one("a%+", "a% "));
        decode_url(0); // this should just not crash.

    } while (0);

    return err;

}

int esync_6177() {

    int err = E_XL4BUS_OK;

    do {
        BOLT_SUB(bind_to_if());
        BOLT_SUB(connect_from_if());
        BOLT_SUB(test_decode_url());
    } while (0);

    return err;

}

#else

int esync_6177() {
    return E_XL4BUS_OK;
}

#endif