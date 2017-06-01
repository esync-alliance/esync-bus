
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
#include <broker/common.h>

int debug = 1;

static void conn_info(struct xl4bus_client *, xl4bus_client_condition_t);
static void msg_info(struct xl4bus_client *, xl4bus_message_t *, void *, int);
static void handle_message(struct xl4bus_client *, xl4bus_message_t *);

static void help(void);

int main(int argc, char ** argv) {

    int c;

    char * update_agent = 0;
    int dm_client = 0;
    char ** groups = 0;
    size_t group_cnt = 0;

    while ((c = getopt(argc, argv, "u:dg:")) != -1) {

        switch (c) {

            case 'u':
                update_agent = f_strdup(optarg);
                break;

            case 'd':
                dm_client = 1;
                break;

            case 'g':
                groups = f_realloc(groups, group_cnt + 1);
                groups[group_cnt++] = f_strdup(optarg);
                break;

            default: help(); break;

        }

    }

    if (update_agent && dm_client) {
        printf("Can not ID as both an update agent and DMClient\n");
        help();
    }

    if (!update_agent && !dm_client) {
        printf("Must either be an update agent, or a DM Client\n");
        help();
    }

    xl4bus_ll_cfg_t ll_cfg;
    xl4bus_client_t clt;

    memset(&ll_cfg, 0, sizeof(xl4bus_ll_cfg_t));
    ll_cfg.debug_f = print_out;

    memset(&clt, 0, sizeof(xl4bus_client_t));

    xl4bus_init_ll(&ll_cfg);

    clt.use_internal_thread = 1;
    clt.on_connection = conn_info;
    clt.on_delivered = msg_info;
    clt.on_message = handle_message;

    clt.identity.type = XL4BIT_TRUST;
    clt.identity.trust.groups = groups;
    clt.identity.trust.group_cnt = (int) group_cnt;
    clt.identity.trust.is_broker = 0;
    clt.identity.trust.is_dm_client = dm_client;
    clt.identity.trust.update_agent = update_agent;

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
