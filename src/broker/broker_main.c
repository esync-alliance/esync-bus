
#include "lib/debug.h"
#include "lib/common.h"
#include "broker.h"
#include <libxl4bus/low_level.h>

#define DEFAULT_PORT 9133
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static void help(void);

#ifndef LIBRARY_STARTUP_GHS_INTEGRITY
static int broker_main(int argc, char ** argv);
int main(int argc, char **argv)
{
    return broker_main(argc, argv);
}
#endif

int broker_main(int argc, char ** argv) {

    int c;
    char *end = 0;

    MSG("xl4-broker %s", xl4bus_version());
    MSG("Use -h to see help options");

    broker_context_t broker_context;
    init_broker_context(&broker_context);

    broker_context.argv0 = argv[0];

    broker_context.port = DEFAULT_PORT;

    while ((c = getopt(argc, argv, "hk:K:c:t:D:T:qdpiI:P:N:")) != -1) {

        switch (c) {

            case 'h':
                help();
                break;
            case 'k':
                if (broker_context.key_path) {
                    FATAL("Key can only be specified once");
                }
                broker_context.key_path = f_strdup(optarg);
                break;
            case 'K':
                broker_context.key_password = f_strdup(optarg);
                secure_bzero(optarg, strlen(optarg));
                *optarg = '*';
                break;
            case 'c':
                add_to_str_array(&broker_context.cert_path, optarg);
                break;
            case 't':
                add_to_str_array(&broker_context.ca_list, optarg);
                break;
            case 'D':
                if (broker_context.demo_pki) {
                    FATAL("demo PKI label dir can only be specified once");
                }
                broker_context.demo_pki = f_strdup(optarg);
                break;
            case 'd':
                debug = 1;
                break;
            case 'p':
                broker_context.perf_enabled = 1;
                break;
            case 'q':
                broker_context.be_quiet = 1;
                break;
            case 'T':
            {
                int val = strtol(optarg, &end, BASE_TEN_CONVERSION);
                if (val < 0) {
                    FATAL("timeout can not be negative");
                }
                broker_context.stream_timeout_ms = (unsigned)val;
            }
            break;

            case 'i':
                broker_context.use_bcc = 1;
                break;

            case 'P':
                broker_context.port = strtol(optarg, &end, BASE_TEN_CONVERSION);
                break;

            case 'I':
                if (broker_context.bcc_path) {
                    FATAL("multiple BCC paths are not supported");
                }
                broker_context.bcc_path = f_strdup(optarg);
                break;

            case 'N':
                if (broker_context.net_if) {
                    FATAL("multiple network interfaces are not supported");
                }
                broker_context.net_if = f_strdup(optarg);
                break;

            default:
                help();
                break;

        }

    }

    int res = start_broker(&broker_context);
    if (res) { return res; }
    while (1) {
        res = cycle_broker(&broker_context, -1);
        if (res) { return res; }
        if (broker_context.quit) {
            return 0;
        }
    }
    return 0;
}

void help() {

    printf("%s",
            "-h\n"
            "   print this text (no other options can be used with -h)\n"
            "-k <path>\n"
            "   specify private key file (PEM format) to use\n"
            "-K <text>\n"
            "   specify private key file password, if needed\n"
            "-c <path>\n"
            "   certificate to use (PEM format), specify multiple times for a chain\n"
            "-t <path>\n"
            "   trust anchor to use (PEM format), \n"
            "   specify multiple times for multiple anchors\n"
            "-D <dir>\n"
            "   use demo PKI directory layout, \n"
            "   reading credentials from specified directory in ../pki\n"
            "   The current directory id determined by the location of this binary\n"
            "-T <num>\n"
            "   Milliseconds for stream timeout, 0 to disable timeout. Default is 10000\n"
            "-q\n"
            "   Be quiet, don't produce any output that is not explicitly requested\n"
            "-d\n"
            "   turn on debugging output\n"
            "-p\n"
            "   turn on performance output\n"
            "-i\n"
            "   turn on broker control channel (AF_UNIX socket)\n"
            "-I <path>\n"
            "   broker control channel path name\n"
            "-P <port>\n"
            "   TCP port to listen on. Otherwise, default " STR(DEFAULT_PORT) " is used \n"
            "-N <interface>\n"
            "   Bind to a specified network interface. Otherwise, interface is not\n"
            "   explicitly specified\n"
    );
    _exit(1);

}
