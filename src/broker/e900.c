

#include <libxl4bus/types.h>
#include <lib/common.h>
#include <stdio.h>
#include <stdlib.h>

void e900(char * msg, xl4bus_address_t * from, xl4bus_address_t * to) {

    char my_time[20];

    my_str_time(my_time);

    int alloc_src = 1;
    int alloc_dst = 1;
    int alloc_msg = 1;

    char * from_str = addr_to_str(from);
    if (!from_str) {
        from_str = "(FAIL)";
        alloc_src = 0;
    }
    char * to_str = addr_to_str(to);
    if (!from_str) {
        to_str = "(FAIL)";
        alloc_dst = 0;
    }

    if (!msg) {
        alloc_msg = 0;
        msg = "(NULL MSG!)";
    }

    printf("E900 %s (%s)->(%s) : %s\n", my_time, from_str, to_str, msg);
    fflush(stdout);

    if (alloc_msg) {
        free(msg);
    }
    if (alloc_src) {
        free(from_str);
    }
    if (alloc_dst) {
        free(to_str);
    }

}