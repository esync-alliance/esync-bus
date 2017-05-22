
#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>

static void conn_info(struct xl4bus_client *, xl4bus_client_condition_t);

static void print_out(const char *);

int main(int argc, char ** argv) {

    xl4bus_ll_cfg_t ll_cfg;
    xl4bus_client_t clt;

    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    ll_cfg.debug_f = print_out;

    memset(&clt, 0, sizeof(xl4bus_client_t));

    xl4bus_init_ll(&ll_cfg);

    clt.use_internal_thread = 1;
    clt.conn_notify = conn_info;

    xl4bus_init_client(&clt, "tcp://localhost:9133");

    while (1) {
        sleep(60);
    }

}

void print_out(const char * msg) {

    printf("%s\n", msg);

}

void conn_info(struct xl4bus_client * clt, xl4bus_client_condition_t cond) {

    printf("Client %p changed to %d\n", clt, cond);

}
