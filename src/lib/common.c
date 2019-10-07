
#include "lib/common.h"
#include "lib/debug.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <mbedtls/x509_crt.h>

#include "libxl4bus/types.h"
#include <termios.h>

#ifdef __QNX__
static int vasprintf(char **buf, const char *fmt, va_list ap)
{
    static char _T_emptybuffer = '\0';
    int chars;
    char *b;

    if(!buf) { return -1; }

#ifdef WIN32
    chars = _vscprintf(fmt, ap)+1;
#else /* !defined(WIN32) */
    /* CAW: RAWR! We have to hope to god here that vsnprintf doesn't overwrite
       our buffer like on some 64bit sun systems.... but hey, its time to move on */
    chars = vsnprintf(&_T_emptybuffer, 0, fmt, ap)+1;
    if(chars < 0) { chars *= -1; } /* CAW: old glibc versions have this problem */
#endif /* defined(WIN32) */

    b = (char*)malloc(sizeof(char)*chars);
    if(!b) { return -1; }

    if((chars = vsprintf(b, fmt, ap)) < 0)
    {
        free(b);
    } else {
        *buf = b;
    }

    return chars;
}
#endif

void print_out(const char * msg) {

#if XL4BUS_ANDROID
    __android_log_write(ANDROID_LOG_DEBUG, XL4BUS_ANDROID_TAG, msg);
#else
    fprintf(stderr, "%s\n", msg);
#endif

}

char * f_asprintf(char * fmt, ...) {

    char * ret;
    va_list ap;

    va_start(ap, fmt);
    int rc = vasprintf(&ret, fmt, ap);
    va_end(ap);

    if (rc < 0) {
        return 0;
    }

    return ret;

}

char * f_strdup(const char * s) {
    if (!s) { return 0; }
    size_t l = strlen(s) + 1;
    char * r = f_malloc(l);
    return memcpy(r, s, l);
}

char * f_strndup(const char * s, size_t n) {

    if (!s) { return 0; }
    for (size_t i = 0; i<n; i++) {
        if (!s[i]) {
            n = i;
            break;
        }
    }
    char * r = f_malloc(n+1);
    return memcpy(r, s, n);
}

void * f_malloc(size_t t) {

    void * r = malloc(t);
    if (!r) {
        FATAL("Failed to malloc %ld bytes", t);
    }

    memset(r, 0, t);

    return r;

}

void * f_realloc(void * m, size_t t) {

    void * r = realloc(m, t);
    if (!r) {
        FATAL("Failed to realloc %p to %ld bytes", m, t);
        abort();
    }

    return r;

}

int set_nonblocking(int fd) {

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;

}

uint64_t msvalue() {
    struct timespec tp;
#ifdef __QNX__
    clock_gettime(CLOCK_MONOTONIC, &tp);
#else
    clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
#endif
    return ((unsigned long long) tp.tv_sec) * 1000L +
            tp.tv_nsec / 1000000L;
}

int get_socket_error(int fd) {

    int error;
    socklen_t err_len = sizeof(int);
    int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &err_len);
    if (rc) { return 1; }
    if (error) {
        errno = error;
        return 1;
    }

    return 0;

}

int load_test_x509_creds(xl4bus_identity_t * identity, char * key, const char * argv0) {

    char * dir = strrchr(argv0, '/');
    if (!dir) {
        dir = f_strdup("./../pki/certs");
    } else {
        char * aux = dir;
        *aux = 0;
        dir = f_asprintf("%s/../pki/certs", argv0);
        *aux = '/';
    }

    char * p_key = f_asprintf("%s/%s/private.pem", dir, key);
    char * cert = f_asprintf("%s/%s/cert.pem", dir, key);
    char * ca = f_asprintf("%s/ca/ca.pem", dir);

    free(dir);

    int ret = load_simple_x509_creds(identity, p_key, cert, ca, 0);

    free(p_key);
    free(cert);
    free(ca);

    return ret;

}

int load_test_data_x509_creds(xl4bus_identity_t * identity, char * key) {

    char * dir = f_strdup("./../test_data/");

    char * p_key = f_asprintf("%s/%s/private.pem", dir, key);
    char * cert = f_asprintf("%s/%s/cert.pem", dir, key);
    char * ca = f_asprintf("%s/ca.pem", dir);

    free(dir);

    int ret = load_simple_x509_creds(identity, p_key, cert, ca, 0);

    free(p_key);
    free(cert);
    free(ca);

    return ret;

}

void release_identity(xl4bus_identity_t * identity) {

    if (identity->type == XL4BIT_X509) {

        if (identity->x509.trust) {
            for (xl4bus_asn1_t ** buf = identity->x509.trust; *buf; buf++) {
                free((*buf)->buf.data);
            }
            free(identity->x509.trust);
        }

        if (identity->x509.chain) {
            for (xl4bus_asn1_t ** buf = identity->x509.chain; *buf; buf++) {
                free((*buf)->buf.data);
            }
            free(identity->x509.chain);
        }

        free(identity->x509.custom);

        identity->type = XL4BIT_INVALID;

    }

}

int load_simple_x509_creds(xl4bus_identity_t * identity, char * p_key_path,
        char * cert_path, char * ca_path, char * password) {

    // xl4bus_identity_t * identity = f_malloc(sizeof(xl4bus_identity_t));

    memset(identity, 0, sizeof(xl4bus_identity_t));
    identity->type = XL4BIT_X509;
    int ok = 0;

    do {

        identity->x509.private_key = load_pem(p_key_path);
        if (!(identity->x509.trust = f_malloc(2 * sizeof(void*)))) {
            break;
        }
        if (!(identity->x509.chain = f_malloc(2 * sizeof(void*)))) {
            break;
        }
        if (!(identity->x509.trust[0] = load_pem(ca_path))) {
            break;
        }
        if (!(identity->x509.chain[0] = load_pem(cert_path))) {
            break;
        }
        if (password) {
            identity->x509.custom = f_strdup(password);
            identity->x509.password = simple_password_input;
        }

        ok = 1;

    } while(0);

    if (!ok) {
        release_identity(identity);
    }

    return !ok;

}

// note that we return buffer with PEM, and a terminating
// 0, and length includes the terminating 0. This is what
// mbedtls requires.
xl4bus_asn1_t * load_pem(char *path) {

    int fd = open(path, O_RDONLY);
    int ok = 0;
    if (fd < 0) {
        ERR_SYS("Failed to open %s", path);
        return 0;
    }

    xl4bus_asn1_t * buf = f_malloc(sizeof(xl4bus_asn1_t));
    buf->enc = XL4BUS_ASN1ENC_PEM;

    do {

        off_t size = lseek(fd, 0, SEEK_END);
        if (size == (off_t)-1) {
            ERR_SYS("Failed to seek %s", path);
            break;
        }
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            ERR_SYS("Failed to rewind %s", path);
            break;
        }

        buf->buf.len = (size_t) (size + 1);
        void * ptr = buf->buf.data = f_malloc(buf->buf.len);
        while (size) {
            ssize_t rd = read(fd, ptr, (size_t) size);
            if (rd < 0) {
                ERR_SYS("Failed to read from %s", path);
                break;
            }
            if (!rd) {
                DBG("Premature EOF reading %s, file declared %ld bytes, read %ld bytes, remaining %ld bytes",
                        path, buf->buf.len-1, ptr-(void*)buf->buf.data, size);
                break;
            }
            size -= rd;
            ptr += rd;
        }

        if (!size) { ok = 1; }

    } while(0);

    close(fd);

    if (!ok) {
        free(buf->buf.data);
        free(buf);
        return 0;
    }

    return buf;


}

char * console_password_input(struct xl4bus_X509v3_Identity * id) {

    // code from https://stackoverflow.com/a/39792014/622266

    static struct termios old_terminal;
    static struct termios new_terminal;

    //get settings of the actual terminal
    if (tcgetattr(STDIN_FILENO, &old_terminal)) {
        FATAL_SYS("Not running at terminal?");
    }

    // do not echo the characters
    new_terminal = old_terminal;
    new_terminal.c_lflag &= ~(ECHO);

    // set this as the new terminal options
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal)) {
        FATAL_SYS("Failed to change terminal settings");
    }

    fprintf(stdout, "Enter password for %s: ", (char*)id->custom);
    fflush(stdout);

    // $TODO: what is the max?
    char password[128];
    memset(password, 0, 128);

    // get the password
    // the user can add chars and delete if he puts it wrong
    // the input process is done when he hits the enter
    // the \n is stored, we replace it with \0
    if (fgets(password, 127, stdin) == NULL) {
        password[0] = '\0';
    } else {
        password[strlen(password) - 1] = '\0';
    }

    // go back to the old settings
    if (tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal)) {
        ERR_SYS("Failed to restore terminal");
    }

    fprintf(stdout, "\n");

    char * ret = f_strdup(password);
    secure_bzero(password, 128);
    return ret;

}

char * simple_password_input(struct xl4bus_X509v3_Identity *id) {

    return id->custom;

}

int pick_timeout(int t1, int t2) {
    if (t1 < 0) { return t2; }
    if (t2 < 0) { return t1; }
    if (t1 < t2) { return t1; }
    return t2;
}

char * addr_to_str(xl4bus_address_t * addr) {

    if (!addr) {
        // special case handling of 0
        return f_strdup("(NULL)");
    }

    char * so_far = 0;

    while (addr) {

        char * new = 0;

        switch (addr->type) {

            case XL4BAT_SPECIAL:

                switch (addr->special) {

                    case XL4BAS_DM_CLIENT:
                        new = f_strdup("<DM-CLIENT>");
                        break;
                    case XL4BAS_DM_BROKER:
                        new = f_strdup("<BROKER>");
                        break;
                    default:
                        new = f_asprintf("<UNKNOWN SPECIAL %d>", addr->special);
                }

                break;
            case XL4BAT_UPDATE_AGENT:
                new = f_asprintf("<UA: %s>", addr->update_agent);
                break;
            case XL4BAT_GROUP:
                new = f_asprintf("<GRP: %s>", addr->group);
                break;
            case XL4BAT_X5T_S256:
                new = f_asprintf("<X5T#S256: %s>", addr->x5ts256);
                break;
            default:
                new = f_asprintf("<UNKNOWN TYPE %d>", addr->type);
        }

        addr = addr->next;

        if (!new) {
            // something didn't go right...
            free(so_far);
            return 0;
        }

        if (!so_far) {
            so_far = new;
        } else {
            // concatenate!
            char * aux = f_asprintf("%s,%s", so_far, new);
            free(so_far);
            free(new);
            if (!aux) { return 0; }
            so_far = aux;
        }

    }

    return so_far;

}
