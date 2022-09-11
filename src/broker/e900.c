

#include <libxl4bus/types.h>
#include <lib/common.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef LOG_PREFIX
#define LOG_PREFIX ""
#endif//LOG_PREFIX

void e900(char * alloc_msg, xl4bus_address_t * from, xl4bus_address_t * to) {

    char my_time[20];

    my_str_time(my_time);

    char const * msg = alloc_msg;

    char * alloc_from_str = addr_to_str(from);
    char const * from_str = alloc_from_str;
    if (!from_str) {
        from_str = "(FAIL)";
    }

    // no (to) address from certain output, used for connection labelling

    char * alloc_to_str = 0;
    char const * to_str;
    if (!to) {
        to_str = "";
    } else {
        to_str = alloc_to_str = addr_to_str(to);
        if (!to_str) {
            to_str = "(FAIL)";
        }
    }

    if (!msg) {
        msg = "(NULL MSG!)";
    }

    MSG_OUT(LOG_PREFIX"E900 %s (%s)->(%s) : %s\n", my_time, from_str, to_str, msg);
    fflush(stdout);

    free(alloc_msg);
    free(alloc_from_str);
    free(alloc_to_str);

}
