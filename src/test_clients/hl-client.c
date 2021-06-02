
#include "lib/common.h"

#include <libxl4bus/low_level.h>
#include <libxl4bus/high_level.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

int debug = 0;
int g_respond = 1;
int g_msg_size = 0;

static void conn_info(struct xl4bus_client *, xl4bus_client_condition_t);
static void msg_info(struct xl4bus_client *, xl4bus_message_t *, void *, int);
static void handle_message(struct xl4bus_client *, xl4bus_message_t *);
static void handle_presence(struct xl4bus_client *, xl4bus_address_t * connected, xl4bus_address_t * disconnected);
static void handle_delivered(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok);
static void signal_f(int);

static void reconnect(xl4bus_client_t * clt) {
    xl4bus_init_client(clt, "tcp://localhost:9133");
}

static void help(void);

void *make_j_msg(const char *say, size_t size) {
    const char *fmt = "{\"say\":\"%s\",\"pad\":\".\"}";
    size_t min_len = strlen(say) + strlen(fmt) - 2 + 1;
    if (size < min_len) {
        size = min_len;
    }
    char *msg = malloc(size);
    int n = snprintf(msg, size, fmt, say) + 1;
    if (size > n) {
        memset(msg + (n - 4), 'x', size - (n - 4) - 1);   // 4 chars are  .\"}\0
        memcpy(msg + size - 3, "\"}", 3);           // 3 chars are \"}\0
    }
    return msg;
}

int main(int argc, char ** argv) {

    int c;
    char * end = 0;
    char * cert_dir = 0;
    int flood = 0;
    int msg_count = 1;
    char * cl_type = 0;

    signal(SIGINT, signal_f);

    while ((c = getopt(argc, argv, "Cc:dfm:s:t:xh")) != -1) {

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
            case 'm':
                msg_count = strtol(optarg, &end, BASE_TEN_CONVERSION);
                break;
            case 's':
                g_msg_size = strtol(optarg, &end, BASE_TEN_CONVERSION);
                break;
            case 't':
                if(cl_type)
                    free(cl_type);
                cl_type = f_strdup(optarg);
                break;
            case 'x':
                g_respond = 0;
                break;
            default: help(); break;

        }

    }

    if (!cert_dir) {
        cert_dir = f_strdup("hl-client");
    }

    if (!cl_type) {
        cl_type = f_strdup("hl-client");
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

    clt.on_release = reconnect;
    reconnect(&clt);

    while (flood || msg_count--) {

        xl4bus_message_t * msg = f_malloc(sizeof(xl4bus_message_t));

        xl4bus_address_t addr = {
                .type = XL4BAT_UPDATE_AGENT,
                .update_agent = cl_type,
                .next = 0
        };

        xl4bus_copy_address(&addr, 1, &msg->address);
        msg->content_type = "application/json";

        void *msg_data = NULL;
        if (g_msg_size) {
            msg_data = make_j_msg("hello", (size_t) g_msg_size);
            msg->data = msg_data;
        } else {
            msg->data = "{\"say\":\"hello\"}";
        }

        msg->data_len = strlen(msg->data) + 1;

        if (xl4bus_send_message(&clt, msg, msg_data)) {
            printf("xl4bus_send_message failed!\n");
            handle_delivered(&clt, msg, msg_data, 0);     // if send message failed cleanup here
        }
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while (1) {
        sleep(60);
    }
#pragma clang diagnostic pop
    // free(cert_dir);
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
            "-m <cnt>  : send that many messages to start with, 1 by default\n"
            "-x        : don't reflect incoming messages\n"
            "-f        : flood\n"
            "-t <addr> : send messages to addr\n"
    );
    _exit(1);

}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
static void msg_info(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok) {
#pragma clang diagnostic pop

    // we don't have to do any clean up.
    printf("Message %p delivered %s\n", msg, ok?"OK":"NOT OK");

}

struct timespec ts_diff(struct timespec end, struct timespec start) {
    struct timespec d;
    if (end.tv_nsec < start.tv_nsec) {
        d.tv_sec = end.tv_sec - start.tv_sec - 1;
        d.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    } else {
        d.tv_sec = end.tv_sec - start.tv_sec;
        d.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return d;
}

void handle_message(struct xl4bus_client * clt, xl4bus_message_t * msg) {

    printf("!!!!!!!!!!!  handle_message  !!!!!!!!!!!\n");

    char * src = addr_to_str(msg->address);

    if (!src) {
        src = f_strdup("no source!");
    }

    static struct timespec last_time;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct timespec diff = ts_diff(now,last_time);
    double ms=(diff.tv_sec*1e6+diff.tv_nsec/1000)/1000;
    last_time=now;

    char raw_msg_data[40];
    size_t len = msg->data_len;
    if (len > sizeof(raw_msg_data) - 5) {
        len = sizeof(raw_msg_data) - 5;
        memcpy(raw_msg_data, msg->data, len);
        strcpy(raw_msg_data + len, "...\n");
    } else {
        snprintf(raw_msg_data, sizeof(raw_msg_data), "%s\n", (const char *) msg->data);
    }
    printf("%.03fmS:  From %s %s(%zd) %s", ms, src, msg->content_type, msg->data_len, raw_msg_data);

    free(src);

    if (g_respond == 0) {
        return;
    }

    xl4bus_message_t *r_msg = f_malloc(sizeof(xl4bus_message_t));
    xl4bus_copy_address(msg->source_address, 1, &r_msg->address);
    r_msg->content_type = "application/json";
    void *msg_data = NULL;
    if (g_msg_size) {
        msg_data = make_j_msg("hello-back", (size_t) g_msg_size);
        r_msg->data = msg_data;
    } else {
        r_msg->data = "{\"say\":\"hello-back\"}";
    }

    r_msg->data_len = strlen(r_msg->data) + 1;

    if (xl4bus_send_message2(clt, r_msg, msg_data, 0)) {
        handle_delivered(clt, r_msg, msg_data, 0);     // if send message failed cleanup here
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
void handle_presence(struct xl4bus_client * clt, xl4bus_address_t * connected, xl4bus_address_t * disconnected) {
#pragma clang diagnostic pop

    char * as = addr_to_str(connected);
    printf("CONNECTED: %s\n", as);
    free(as);

    as = addr_to_str(disconnected);
    printf("DISCONNECTED: %s\n", as);
    free(as);

}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
void handle_delivered(struct xl4bus_client * clt, xl4bus_message_t * msg, void * arg, int ok) {
#pragma clang diagnostic pop
    msg_info(clt, msg, arg, ok);
    xl4bus_free_address(msg->address, 1);
    if (arg == msg->data)
      free(arg);
    free(msg);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
void signal_f(int s) {
#pragma clang diagnostic pop
    exit(3);
}
