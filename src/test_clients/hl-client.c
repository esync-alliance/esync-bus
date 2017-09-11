
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

#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>
#include <lib/common.h>

int debug = 1;

static char *addr_to_string(xl4bus_address_t *);

static void conn_info(struct xl4bus_client *, xl4bus_client_condition_t);
static void msg_info(struct xl4bus_client *, xl4bus_message_t *, void *, int);
static void handle_message(struct xl4bus_client *, xl4bus_message_t *);
static void handle_presence(struct xl4bus_client *, xl4bus_address_t * connected, xl4bus_address_t * disconnected);

static void help(void);

int main(int argc, char ** argv) {

    int c;
    char * cert_dir = 0;

    while ((c = getopt(argc, argv, "c:")) != -1) {

        switch (c) {

            case 'c':
                free(cert_dir);
                cert_dir = f_strdup(optarg);
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
    ll_cfg.debug_f = print_out;

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

    load_test_x509_creds(&clt.identity, cert_dir, argv[0]);

    free(cert_dir);

    xl4bus_init_client(&clt, "tcp://localhost:9133");

    xl4bus_message_t msg;
    memset(&msg, 0, sizeof(msg));

    xl4bus_address_t addr = {
            .type = XL4BAT_UPDATE_AGENT,
            .update_agent = "test1",
            .next = 0
    };

    msg.address = &addr;
    // msg.xl4bus_address = "[{\"update-agent\":\"test1\"}]";
    msg.content_type = "application/json";
    msg.data = "{\"say\":\"hello\"}";
    msg.data_len = strlen(msg.data) + 1;

    xl4bus_send_message(&clt, &msg, 0);

    while (1) {
        sleep(60);
    }

}

void conn_info(struct xl4bus_client * clt, xl4bus_client_condition_t cond) {
    printf("Client %p changed to %d\n", clt, cond);
}

void help() {

    printf("%s",
            "-u <name> : authenticate as an update agent with the specified name\n"
            "-g <group> : report as a member of a group, can be specified multiple times\n"
            "-d : report as a DM Client (not an update agent)\n"
    );
    _exit(1);

}

static void msg_info(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok) {

    // we don't have to do any clean up.
    printf("Message %p delivered %s\n", msg, ok?"OK":"NOT OK");

}

void handle_message(struct xl4bus_client * clt, xl4bus_message_t * msg) {

    char * fmt = f_asprintf("And the message %s has come : %%%ds\n", msg->content_type, msg->data_len);
    printf(fmt, msg->data);
    free(fmt);

}

void handle_presence(struct xl4bus_client * clt, xl4bus_address_t * connected, xl4bus_address_t * disconnected) {

    for (xl4bus_address_t * a = connected; a; a=a->next) {
        char * as = addr_to_string(a);
        printf("CONNECTED: %s\n", as);
        free(as);
    }
    for (xl4bus_address_t * a = disconnected; a; a=a->next) {
        char * as = addr_to_string(a);
        printf("DISCONNECTED: %s\n", as);
        free(as);
    }

}

char *addr_to_string(xl4bus_address_t * addr) {

    switch (addr->type) {

        case XL4BAT_SPECIAL:

            switch (addr->special) {

                case XL4BAS_DM_CLIENT:
                    return f_strdup("<DM-CLIENT>");
                case XL4BAS_DM_BROKER:
                    return f_strdup("<BROKER>");
                default:
                    return f_asprintf("<UNKNOWN SPECIAL %d>", addr->special);
            }

            break;
        case XL4BAT_UPDATE_AGENT:
            return f_asprintf("<UA: %s>", addr->update_agent);
        case XL4BAT_GROUP:
            return f_asprintf("<GRP: %s>", addr->group);
        default:
            return f_asprintf("<UNKNOWN TYPE %d>", addr->type);
    }

}
