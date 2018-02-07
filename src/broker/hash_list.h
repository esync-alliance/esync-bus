#ifndef _XL4BUS_BROKER_HASH_LIST_H_
#define _XL4BUS_BROKER_HASH_LIST_H_

#include "uthash.h"
#include "utarray.h"

#define REMOVE_FROM_ARRAY(array, item, msg, x...) do { \
    void * __addr = utarray_find(array, &item, void_cmp_fun); \
    if (__addr) { \
        long idx = (long)utarray_eltidx(array, __addr); \
        if (idx >= 0) { \
            utarray_erase(array, idx, 1); \
        } else {\
            DBG(msg " : index not found for array %p elt %p, addr %p", ##x, array, item, __addr); \
        } \
    } else { \
        DBG(msg " : address not found for array %p elt %p", ##x, array, item); \
    }\
} while(0)

#define UTCOUNT_WITHOUT(array, item, to) do { \
    unsigned long __a = utarray_len(array); \
    if (__a && (item)) { \
        if (utarray_find(array, &(item), void_cmp_fun)) { \
            __a--; \
        } \
    } \
    (to) = __a; \
} while(0)

#define ADD_TO_ARRAY_ONCE(array, item) do {\
    if (!utarray_find(array, &(item), void_cmp_fun)) { \
        utarray_push_back(array, &(item)); \
        utarray_sort(array, void_cmp_fun); \
    } \
} while(0)

#define REMOVE_FROM_HASH(root, obj, key_fld, n_len, msg, x...) do { \
    conn_info_hash_list_t * __list; \
    const char * __keyval = (obj)->key_fld; \
    size_t __keylen = strlen(__keyval) + 1; \
    HASH_FIND(hh, root, __keyval, __keylen, __list); \
    if (__list) { \
        REMOVE_FROM_ARRAY(&__list->items, obj, msg " - key %s", ##x, __keyval); \
        if (!(n_len = utarray_len(&__list->items))) { \
            utarray_done(&__list->items); \
            HASH_DEL(root, __list); \
            free(__list->key); \
            free(__list); \
        } \
    } else { \
        DBG(msg " : no entry for %s", ##x, __keyval); \
        n_len = 0; \
    } \
} while(0)

#define HASH_LIST_ADD(root, obj, key_fld) do { \
    conn_info_hash_list_t * __list; \
    const char * __keyval = (obj)->key_fld; \
    size_t __keylen = strlen(__keyval) + 1; \
    HASH_FIND(hh, root, __keyval, __keylen, __list); \
    if (!__list) { \
        __list = f_malloc(sizeof(conn_info_hash_list_t)); \
        __list->key = f_strdup(__keyval); \
        HASH_ADD_KEYPTR(hh, root, __list->key, __keylen, __list); \
        /* utarray_new(__list->items, &ut_ptr_icd); */ \
        utarray_init(&__list->items, &ut_ptr_icd); \
    } \
    ADD_TO_ARRAY_ONCE(&__list->items, obj); \
} while(0)


#endif