
#include "broker.h"
#include "lib/debug.h"
#include "lib/common.h"
#include "lib/hash_list.h"

void gather_destinations(json_object * array, json_object ** x5t, UT_array * conns) {

    int l;
    if (!array || !json_object_is_type(array, json_type_array) || (l = json_object_array_length(array)) <= 0) {
        return;
    }

    str_t * set = 0;

    for (int i=0; i<l; i++) {

        json_object * el = json_object_array_get_idx(array, i);
        if (!json_object_is_type(el, json_type_object)) {
            DBG("BRK : skipping destination - not an object");
            continue;
        }

        json_object * cux;

        xl4bus_address_t addr;
        memset(&addr, 0, sizeof(xl4bus_address_t));
        int ok = 0;

        if (json_object_object_get_ex(el, "update-agent", &cux) &&
            json_object_is_type(cux, json_type_string)) {
            addr.type = XL4BAT_UPDATE_AGENT;
            addr.update_agent = (char *) json_object_get_string(cux);
            ok = 1;
        } else if (json_object_object_get_ex(el, "group", &cux) &&
                   json_object_is_type(cux, json_type_string)) {
            addr.type = XL4BAT_GROUP;
            addr.group = (char *) json_object_get_string(cux);
            ok = 1;
        } else if (json_object_object_get_ex(el, "special", &cux) &&
                   json_object_is_type(cux, json_type_string) &&
                   !strcmp("dmclient",json_object_get_string(cux))) {
            addr.type = XL4BAT_SPECIAL;
            addr.special = XL4BAS_DM_CLIENT;
            ok = 1;
        }

        if (ok) {
            gather_destination(&addr, x5t ? &set : 0, conns);
        }


    }

    if (set) {
        finish_x5t_destinations(x5t, set);
    }

}

void gather_destination(xl4bus_address_t * addr, str_t ** x5t, UT_array * conns) {

    UT_array * send_list = 0;
    int clear_send_list = 0;

    if (addr->type == XL4BAT_UPDATE_AGENT) {
        utarray_new(send_list, &ut_ptr_icd);
        hash_tree_do_rec(ci_ua_tree, 0, 0, addr->update_agent, XL4_MAX_UA_PATHS, 0, send_list);
        clear_send_list = 1;
    } else if (addr->type == XL4BAT_GROUP) {
        hash_list_t * val;
        HASH_FIND(hh, ci_by_group, addr->group, strlen(addr->group)+1, val);
        if (val) {
            send_list = &val->items;
        }
    } else if (addr->type == XL4BAT_X5T_S256) {
        hash_list_t * val;
        HASH_FIND(hh, ci_by_x5t, addr->x5ts256, strlen(addr->x5ts256)+1, val);
        if (val) {
            send_list = &val->items;
        }
    } else if (addr->type == XL4BAT_SPECIAL && addr->special == XL4BAS_DM_CLIENT) {
        send_list = &dm_clients;
    }

    if (!send_list) {
        return;
    }

    int l = utarray_len(send_list);

    // DBG("BRK: Found %d conns", l);

    for (int j=0; j<l; j++) {
        conn_info_t * ci2 = *(conn_info_t **) utarray_eltptr(send_list, j);
        if (x5t) {
            str_t * str_el;
            HASH_FIND_STR(*x5t, ci2->conn->remote_x5t, str_el);
            if (!str_el) {
                str_el = f_malloc(sizeof(str_t));
                str_el->str = ci2->conn->remote_x5t;
                HASH_ADD_STR(*x5t, str, str_el);
            }
        }

        if (conns) {
            // conns array must only contain unique elements.
            ADD_TO_ARRAY_ONCE(conns, ci2);
        }

    }

    if (clear_send_list) {
        utarray_free(send_list);
    }


}


void finish_x5t_destinations(json_object ** x5t, str_t * strings) {

    *x5t = json_object_new_array();

    // 'set' now contains all X5T values that we need to return back
    str_t * str_el;
    str_t * dux;

    HASH_ITER(hh, strings, str_el, dux) {
        HASH_DEL(strings, str_el);
        json_object_array_add(*x5t, json_object_new_string(str_el->str));
        free(str_el);
    }

}

void gather_all_destinations(xl4bus_address_t * first, UT_array * conns) {
    for (xl4bus_address_t * addr = first; addr; addr = addr->next) {
        gather_destination(addr, 0, conns);
    }
}
