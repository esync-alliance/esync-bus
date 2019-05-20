
#include <unistd.h>

#include "broker.h"
#include "lib/common.h"
#include "hash_list.h"
#include "lib/debug.h"

conn_info_hash_tree_t * ci_ua_tree = 0;

void hash_tree_add(conn_info_t * ci, const char * ua_name) {

    ci->ua_names = f_realloc(ci->ua_names, sizeof(char *) * (ci->ua_count + 1));
    ci->ua_names[ci->ua_count] = f_strdup(ua_name);
    // HASH_LIST_ADD(ci_by_name, ci, ua_names[ci->ua_count]);

    // we have to deal with root, before calling in recursive tree storage.
    if (!ci_ua_tree) {
        ci_ua_tree = f_malloc(sizeof(conn_info_hash_tree_t));
        utarray_init(&ci_ua_tree->items, &ut_ptr_icd);
    }

    hash_tree_do_rec(ci_ua_tree, ci, ua_name, ua_name, XL4_MAX_UA_PATHS, 0, 0);

#if 0
    // honestly, there is no point to deleting the root.
    if (hash_tree_maybe_delete(ci_ua_tree)) {
        // root died.
        ci_ua_tree = 0;
    }
#endif

}

void hash_tree_do_rec(conn_info_hash_tree_t * current, conn_info_t * ci, const char * full_name,
        const char * ua_name, int ok_more, int is_delete, UT_array * gather) {

    // ESYNC-1155
    // If there is no current (can be called in from main code, before any UA connected)
    // then there is nothing we can do, no matter what the requested operation is.
    if (!current) { return; }

    // NOTE! Gathering - we need to add all conn_info_t objects at each level we encounter.
    if (gather && utarray_len(&current->items)) {
        utarray_concat(gather, &current->items);
    }

    while (*ua_name && (*ua_name == '/')) { ua_name++; }

    if (!*ua_name) {
        // we ran out of name, so this is the place where we need to drop this conn_info.
        if (is_delete) {
            REMOVE_FROM_ARRAY(&current->items, ci, "Removing %s from terminal array", full_name);
        } else if (!gather) {
            ADD_TO_ARRAY_ONCE(&current->items, ci);
        }
        return;
    }

    if (!ok_more) { return; }

    size_t key_len;

    char * ua_name_sep = strchr(ua_name, '/');
    if (ua_name_sep) {
        // there is a separator
        key_len = (size_t)(ua_name_sep - ua_name);
    } else {
        key_len = strlen(ua_name);
    }

    conn_info_hash_tree_t * child;
    HASH_FIND(hh, current->nodes, ua_name, key_len, child);
    if (!child) {
        if (is_delete) {
            MSG_OUT("While looking for sub-tree %s, for UA %s, next sub-node could not be found", ua_name, full_name);
        } else {
            child = f_malloc(sizeof(conn_info_hash_tree_t));
            child->key = f_strndup(ua_name, key_len);
            child->parent = current;
            HASH_ADD_KEYPTR(hh, current->nodes, child->key, key_len, child);
            utarray_init(&child->items, &ut_ptr_icd);
        }
    }

    ua_name += key_len;

    if (child) {
        hash_tree_do_rec(child, ci, full_name, ua_name, ok_more - 1, is_delete, gather);
    }

    // NOTE! We only check if we can delete the child container, but not current.
    // This is because current can be root, and deleting root without resetting it's
    // address is fatal. So we never delete root (if we did, this would be in hash_tree_add/hash_tree_remove
    // functions.
    if (!gather) {
        // only if !gather, for !!gather, we are not making any changes, only looking
        hash_tree_maybe_delete(child);
    }

}

int hash_tree_maybe_delete(conn_info_hash_tree_t * current) {

    // do I have property at this level?
    if (utarray_len(&current->items)) {
        return 0;
    }

    // no property at this level, but do I have kids?
    if (HASH_COUNT(current->nodes)) {
        // yeah, pesky kids, have to stay on
        return 0;
    }

    // no property, no kids, no reason to live.

    if (current->parent) {
        // if I have a parent, check out from it.
        HASH_DEL(current->parent->nodes, current);
        free(current->key);
    }

    utarray_done(&current->items);

    free(current);
    return 1;

}

void hash_tree_remove(conn_info_t * ci) {

    for (int i = 0; i<ci->ua_count; i++) {

        const char * ua_name = ci->ua_names[i];

        if (!ci_ua_tree) {
            ERR("Cleaning UA %s - no root UA has tree root!", ua_name);
            continue;
        }

        hash_tree_do_rec(ci_ua_tree, ci, ua_name, ua_name, XL4_MAX_UA_PATHS, 1, 0);

    }

}
