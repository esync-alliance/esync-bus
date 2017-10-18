

#include "lib/common.h"

#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int debug = 1;

static void conn_info(struct xl4bus_client *, xl4bus_client_condition_t);
static void msg_info(struct xl4bus_client *, xl4bus_message_t *, void *, int);
static void handle_message(struct xl4bus_client *, xl4bus_message_t *);
static void handle_presence(struct xl4bus_client *, xl4bus_address_t * connected, xl4bus_address_t * disconnected);
static void handle_delivered(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok);

static void reconnect(xl4bus_client_t * clt) {
    xl4bus_init_client(clt, "tcp://localhost:9133");
}

static void help(void);

int main(int argc, char ** argv) {

    int c;
    char * cert_dir = 0;
    int debug = 0;
    int flood = 0;

    while ((c = getopt(argc, argv, "c:df")) != -1) {

        switch (c) {

            case 'c':
                free(cert_dir);
                cert_dir = f_strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'f':
                flood = 1;
                break;

            default: help(); break;

        }

    }

    if (!cert_dir) {
        cert_dir = f_strdup("hl-client");
    }

    xl4bus_ll_cfg_t ll_cfg;
    xl4bus_client_t clt;

    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    if (debug) {
        ll_cfg.debug_f = print_out;
    }

    memset(&clt, 0, sizeof(xl4bus_client_t));

    if (xl4bus_init_ll(&ll_cfg)) {
        printf("failed to initialize xl4bus\n");
        return 1;
    }

    clt.use_internal_thread = 1;
    clt.on_status = conn_info;
    clt.on_delivered = msg_info;
    clt.on_message = handle_message;
    clt.on_presence = handle_presence;
    clt.on_delivered = handle_delivered;

    load_test_x509_creds(&clt.identity, cert_dir, argv[0]);

    free(cert_dir);

    clt.on_release = reconnect;
    reconnect(&clt);

    do {

        xl4bus_message_t * msg = f_malloc(sizeof(xl4bus_message_t));

        xl4bus_address_t addr = {
                .type = XL4BAT_UPDATE_AGENT,
                .update_agent = "test1",
                .next = 0
        };

        xl4bus_copy_address(&addr, 1, &msg->address);
        msg->content_type = "application/json";
        msg->data = "{\"say\":\"hello\"}";
        msg->data_len = strlen(msg->data) + 1;

        xl4bus_send_message(&clt, msg, 0);

    } while (flood);

    while (1) {
        sleep(60);
    }

}

void conn_info(struct xl4bus_client * clt, xl4bus_client_condition_t cond) {
    printf("Client %p changed to %d\n", clt, cond);
}

void help() {

    printf("%s",
#if 0
            "-u <name> : authenticate as an update agent with the specified name\n"
            "-g <group> : report as a member of a group, can be specified multiple times\n"
            "-d : report as a DM Client (not an update agent)\n"
#endif
            "-c <cert> : certificate directory to use for authentication\n"
            "-d        : turn on debug output\n"
            "-f        : flood\n"
    );
    _exit(1);

}

static void msg_info(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok) {

    // we don't have to do any clean up.
    printf("Message %p delivered %s\n", msg, ok?"OK":"NOT OK");

}

void handle_message(struct xl4bus_client * clt, xl4bus_message_t * msg) {

    char * src = addr_to_str(msg->address);

    if (!src) {
        src = f_strdup("no source!");
    }

    char * fmt = f_asprintf("From %s came message of %s : %%%ds\n", src, msg->content_type, msg->data_len);
    printf(fmt, msg->data);
    free(fmt);
    free(src);

    xl4bus_message_t * r_msg = f_malloc(sizeof(xl4bus_message_t));
    xl4bus_copy_address(msg->source_address, 1, &r_msg->address);
    r_msg->content_type = "application/json";
    r_msg->data = "{\"say\":\"hello-back\"}";
    r_msg->data_len = strlen(r_msg->data) + 1;

    if (xl4bus_send_message(clt, r_msg, 0)) {
        handle_delivered(clt, r_msg, 0, 0);
    }

}

void handle_presence(struct xl4bus_client * clt, xl4bus_address_t * connected, xl4bus_address_t * disconnected) {

    char * as = addr_to_str(connected);
    printf("CONNECTED: %s\n", as);
    free(as);

    as = addr_to_str(disconnected);
    printf("DISCONNECTED: %s\n", as);
    free(as);

}

void handle_delivered(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok) {

    xl4bus_free_address(msg->address, 1);
    free(msg);

}
