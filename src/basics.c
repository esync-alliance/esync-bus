
#include "basics.h"
#include <libxl4bus/types.h>

int xl4json_get_pointer(json_object * obj, char const * path, json_type type, void * target) {

    json_object * leaf;
    if (json_pointer_get(obj, path, &leaf)) {
        return E_XL4BUS_ARG;
    }
    if (!json_object_is_type(leaf, type)) {
        return E_XL4BUS_ARG;
    }

    if (target) {

        switch (type) {

            case json_type_null:
                *(void**)target = 0;
                break;
            case json_type_boolean:
                *(int*)target = json_object_get_boolean(leaf);
                break;
            case json_type_double:
                *(double*)target = json_object_get_double(leaf);
                break;
            case json_type_int:
                *(int64_t*)target = json_object_get_int64(leaf);
                break;
            case json_type_object:
            case json_type_array:
                *(json_object**)target = leaf;
                break;
            case json_type_string:
                *(char const **)target = json_object_get_string(leaf);
                break;
            default:
                return E_XL4BUS_ARG;
        }

    }

    return E_XL4BUS_OK;

}
