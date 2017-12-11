
#include "config.h"
#include <libxl4bus/high_level.h>
#include "internal.h"
#include "debug.h"
#include "misc.h"

int xl4bus_chain_address(xl4bus_address_t ** rec, xl4bus_address_type_t type, ...) {

    int err = E_XL4BUS_OK;
    xl4bus_address_t * addr = 0;

    va_list ap;
    va_start(ap, type);

    do {

        BOLT_MALLOC(addr, sizeof(xl4bus_address_t));
        addr->type = type;
        switch (type) {

            case XL4BAT_SPECIAL:
                addr->special = va_arg(ap, xl4bus_address_special_t);
                break;

            case XL4BAT_UPDATE_AGENT:
            {
                char * ua = va_arg(ap, char*);
                int copy = va_arg(ap, int);
                if (copy) {
                    BOLT_MEM(addr->update_agent = f_strdup(ua));
                } else {
                    addr->update_agent = ua;
                }
            }
                break;
            case XL4BAT_GROUP:
            {
                char * grp = va_arg(ap, char*);
                int copy = va_arg(ap, int);
                if (copy) {
                    BOLT_MEM(addr->group = f_strdup(grp));
                } else {
                    addr->group = grp;
                }
            }
                break;
            default:
                BOLT_SAY(E_XL4BUS_ARG, "Unknown address type %d", type);
        }

    } while(0);

    if (!err) {
        addr->next = *rec;
        *rec = addr;
    } else {
        // no need to clean up addr->update_agent or addr->group
        cfg.free(addr);
    }

    return err;

}


void xl4bus_free_address(xl4bus_address_t * addr, int chain) {

    while (addr) {

        xl4bus_address_t * next;
        if (chain) {
            next = addr->next;
        } else {
            next = 0;
        }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wswitch"

        switch (addr->type) {
            // case XL4BAT_SPECIAL:break;
            case XL4BAT_UPDATE_AGENT:
                cfg.free(addr->update_agent);
                break;
            case XL4BAT_GROUP:
                cfg.free(addr->group);
                break;
        }

#pragma clang diagnostic pop

        cfg.free(addr);

        addr = next;

    }

}

int make_json_address(xl4bus_address_t * bus_addr, json_object ** json) {

    int err = E_XL4BUS_OK;
    json_object * addr = 0;

    do {

        BOLT_MEM(addr = json_object_new_array());

        for (xl4bus_address_t * ma = bus_addr; ma; ma = ma->next) {

            char * key = 0;
            char * val = 0;

            switch (ma->type) {

                case XL4BAT_SPECIAL:
                {
                    key = "special";
                    switch (ma->special) {
                        case XL4BAS_DM_CLIENT:
                            val = "dmclient";
                            break;
                        case XL4BAS_DM_BROKER:
                            val = "broker";
                            break;
                        default:
                        BOLT_SAY(E_XL4BUS_ARG, "Unknown special type %d", ma->special);
                    }
                }
                    break;
                case XL4BAT_UPDATE_AGENT:
                    key = "update-agent";
                    val = ma->update_agent;
                    break;
                case XL4BAT_GROUP:
                    key = "group";
                    val = ma->group;
                    break;
                default:
                BOLT_SAY(E_XL4BUS_ARG, "Unknown addr type %d", ma->type);

            }

            BOLT_SUB(err);

            json_object * aux;
            json_object * bux;
            BOLT_IF(!(aux = json_object_new_object()), E_XL4BUS_MEMORY, "");
            json_object_array_add(addr, aux);
            BOLT_IF(!(bux = json_object_new_string(val)), E_XL4BUS_MEMORY, "");
            json_object_object_add(aux, key, bux);

        }

    } while(0);

    if (err) {
        json_object_put(addr);
    } else {
        *json = addr;
    }

    return err;

}

int xl4bus_json_to_address(char const *json, xl4bus_address_t **addr) {

    int err/* = E_XL4BUS_OK*/;
    xl4bus_address_t * new_addr = 0;
    json_object * json_obj = 0;

    do {

        BOLT_IF(!(json_obj = json_tokener_parse(json)), E_XL4BUS_ARG, "Can't parse address json %s", json);
        if (!json_object_is_type(json_obj, json_type_array)) {
            json_object * top;
            BOLT_MEM(top = json_object_new_array());
            BOLT_MEM(!json_object_array_add(top, json_obj));
            json_obj = top;
        }

        BOLT_SUB(build_address_list(json_obj, &new_addr));

        if (*addr) {
            xl4bus_address_t * aux = *addr;
            *addr = new_addr;
            while (new_addr->next) {
                new_addr = new_addr->next;
            }
            new_addr->next = aux;
        } else {
            *addr = new_addr;
        }

    } while (0);

    if (err != E_XL4BUS_OK) {
        xl4bus_free_address(new_addr, 1);
    }

    json_object_put(json_obj);

    return err;


}

int build_address_list(json_object * j_list, xl4bus_address_t ** new_list) {

    int l = json_object_array_length(j_list);
    xl4bus_address_t * last = 0;
    xl4bus_address_t * next = 0;
    int err = E_XL4BUS_OK;

    for (int i=0; i<l; i++) {

        if (!next) {
            BOLT_MALLOC(next, sizeof(xl4bus_address_t));
        }

        json_object * el = json_object_array_get_idx(j_list, i);

        DBG("BAL: Processing el %s", json_object_get_string(el));
        json_object * aux;
        if (json_object_object_get_ex(el, "update-agent", &aux) && json_object_is_type(aux, json_type_string)) {
            next->type = XL4BAT_UPDATE_AGENT;
            BOLT_MEM(next->update_agent = f_strdup(json_object_get_string(aux)));
        } else if (json_object_object_get_ex(el, "group", &aux) && json_object_is_type(aux, json_type_string)) {
            next->type = XL4BAT_GROUP;
            BOLT_MEM(next->group = f_strdup(json_object_get_string(aux)));
        } else if (json_object_object_get_ex(el, "special", &aux) && json_object_is_type(aux, json_type_string)) {

            char const * bux = json_object_get_string(aux);
            next->type = XL4BAT_SPECIAL;

            if (!strcmp("dmclient", bux)) {
                next->special = XL4BAS_DM_CLIENT;
            } else if (!strcmp("broker", bux)) {
                next->special = XL4BAS_DM_BROKER;
            } else {
                continue;
            }

        } else {
            continue;
        }

        if (!last) {
            *new_list = next;
        } else {
            last->next = next;
        }
        last = next;
        next = 0;

    }

    cfg.free(next);

    if (err) {
        xl4bus_free_address(*new_list, 1);
    }

    return err;

}

int xl4bus_require_address(xl4bus_address_t * needle, xl4bus_address_t * haystack, xl4bus_address_t ** failed) {

    // we assume that haystack has more items than needle, in general,
    // so we should iterate over haystack. However, this makes it more complicated
    // to reject faster, and also white out the needle addresses that did match.
    // So, we gonna have a simple implementation for now.
    // this is no matter what is O(NM) so far, but more complex implementation will
    // be a little faster in majority of the cases.

    if (!needle) {
        // it's questionable what we should return in this case
        if (haystack) { *failed = 0; }
        return E_XL4BUS_ARG;
    }

    for (; needle; needle = needle->next) {

        int found = 0;

        for (xl4bus_address_t * ck = haystack; ck; ck = ck->next) {

            if (needle->type != ck->type) { continue; }

            switch (ck->type) {
                case XL4BAT_SPECIAL:
                    found = needle->special == ck->special;
                    break;
                case XL4BAT_UPDATE_AGENT:
                    // update-agent in haystack must fully fit into the value in the needle
                {
                    size_t l_haystack = strlen(ck->update_agent);
                    size_t l_needle = strlen(needle->update_agent);
                    if (l_haystack > l_needle) {
                        // it won't fit.
                        break;
                    }
                    // there is enough characters that fit, let's compare just them.
                    if (strncmp(ck->update_agent, needle->update_agent, l_haystack)) {
                        // characters are different, fail comparison
                        break;
                    }
                    // whatever is left in needle, must either be 0 (end) or '/' (separator)
                    char c = needle->update_agent[l_haystack];
                    found = c == '/' || c == 0;
                }
                    break;
                case XL4BAT_GROUP:
                    found = !z_strcmp(needle->group, ck->group);
                    break;
            }

            if (found) { break; }

        }

        if (!found) {
            if (failed) {
                *failed = needle;
            }
            return E_XL4BUS_ARG;
        }

        return E_XL4BUS_OK;

    }

}

int xl4bus_require_special(xl4bus_address_special_t special, xl4bus_address_t * haystack) {

    xl4bus_address_t addr = {
            .type = XL4BAT_SPECIAL,
            .special = special
    };

    return xl4bus_require_address(&addr, haystack, 0);

}
int xl4bus_require_group(const char * name, xl4bus_address_t * haystack) {

    xl4bus_address_t addr = {
            .type = XL4BAT_GROUP,
            .group = (char*)name
    };

    return xl4bus_require_address(&addr, haystack, 0);

}

int xl4bus_require_update_agent(const char * name, xl4bus_address_t * haystack) {

    xl4bus_address_t addr = {
            .type = XL4BAT_UPDATE_AGENT,
            .update_agent = (char*)name
    };

    return xl4bus_require_address(&addr, haystack, 0);

}

