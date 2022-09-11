
#include "common.h"
#include "debug.h"

#if XL4BUS_ANDROID
#include <android/log.h>
#endif

#if WITH_UNIT_TEST
#include "tests/full-test.h"
#endif

static void v_debug_out(char const * func, char const * file, int line, int how, char const * str, va_list va);

void debug_out(char const * func, char const * file, int line, int how, char const * str, ...) {

    va_list ap;
    va_start(ap, str);
    v_debug_out(func, file, line, how, str, ap);
    va_end(ap);

}

void str_output_time(char * now) {

    struct tm __tmnow;
    struct timeval __tv;
    memset(now, 0, 24);
    gettimeofday(&__tv, 0);
    localtime_r(&__tv.tv_sec, &__tmnow);
    strftime(now, 20, "%m-%d_%H:%M:%S.", &__tmnow);
    sprintf(now+15, "%03d ", (int)(__tv.tv_usec/1000));

}

#ifndef LOG_PREFIX
#define LOG_PREFIX ""
#endif//LOG_PREFIX

static void v_debug_out(char const * func, char const * file, int line, int how, char const * str, va_list va) {

    char now[25];

#if XL4BUS_ANDROID
    now[0] = 0;
#else
    str_output_time(now);
#endif

    char const * eol;

#if XL4BUS_ANDROID || WITH_UNIT_TEST
    eol = "";
#else
    eol = "\n";
#endif

    char const * how_str = "";
#if !XL4BUS_ANDROID
    if (how == HOW_ERR) {
        how_str = "ERR ";
    }
#endif

    // time func:file:line how <orig>
    char * final_fmt = f_asprintf(LOG_PREFIX"%s%s:%s:%d %s%s%s", now, func, file, line, how_str, str, eol);

#if WITH_UNIT_TEST

    va_list va2;
    va_copy(va2, va);

    char * msg;
    int rc = vasprintf(&msg, final_fmt, va2);
    if (rc < 0) {
        abort();
    }

    full_test_print_out(msg);

    free(msg);

#else

#if XL4BUS_ANDROID
    int prio;
    if (how == HOW_ERR) {
        prio = ANDROID_LOG_ERROR;
    } else if (how == HOW_FATAL) {
        prio = ANDROID_LOG_FATAL;
    } else {
        prio = ANDROID_LOG_INFO;
    }
    __android_log_vprint(prio, XL4BUS_ANDROID_TAG, final_fmt, va);
    if (prio == ANDROID_LOG_FATAL) {
        kill(getpid(), SIGTRAP);
        _exit(1);
    }
#else
    vfprintf(stderr, final_fmt, va);
    if (how == HOW_FATAL) {
        abort();
    }
#endif

#endif

    free(final_fmt);

}
