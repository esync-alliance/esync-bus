
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdbool.h>
#include "uthash.h"
#include "utlist.h"
#include "xl4_tablefd.h"
#include "porting.h"
#include "lib/debug.h"

typedef struct refcnt {
    void *data;
    int count;
} refcnt_t;

typedef struct fd_entry {
    //! dir, file path or epollsocket handle
    int type;
    //! hash key.
    int value;
    //! the fd of a descriptor that this node is duplicated.
    int dupfd;
    //! hold the path of dir, file of handle of epoll and reference counter
    refcnt_t *ref;
    //! Make a structure hashable
    UT_hash_handle hh;
    //! Make a structure listable
    struct fd_entry *next, *prev;
} fd_entry_t;

static void *g_table_lock;
struct files_resource_ctx {
    //! Containing all possible file descriptor entries
    fd_entry_t tablefd[FD_MAX_COUNT];
    //! List of unused file descriptor entry
    fd_entry_t *fd_pool_list;
    //! Hash table for accessing file descriptor entry with id
    fd_entry_t *fd_by_id;
};

static struct files_resource_ctx g_fs_ctx = {0};

#if !defined(ATTRIBUTE_CONSTRUCTOR)
#define ATTRIBUTE_CONSTRUCTOR __attribute__((constructor))
#endif

#if !defined(ATTRIBUTE_DESTRUCTOR)
#define ATTRIBUTE_DESTRUCTOR __attribute__((destructor))
#endif

ATTRIBUTE_CONSTRUCTOR void xl4_tablefd_preinit() {

    memset(&g_fs_ctx, 0, sizeof(g_fs_ctx));
    for (int i = 0; i < FD_MAX_COUNT; i++) {
        g_fs_ctx.tablefd[i].value = i+FD_MIN_VALUE;
        DL_APPEND(g_fs_ctx.fd_pool_list, &g_fs_ctx.tablefd[i]);
    }
    pf_init_lock(&g_table_lock);
}

ATTRIBUTE_DESTRUCTOR void xl4_tablefd_deinit() {
    pf_release_lock(g_table_lock);
}

extern int fd_entry_rename_path(char *old_path, char *new_path) {
    int res = -1;
    fd_entry_t *entry, *tmp;

    assert(pf_lock(&g_table_lock) == 0);
    HASH_ITER(hh, g_fs_ctx.fd_by_id, entry, tmp) {
        if (entry->ref && entry->type == FD_TYPE_ATFUNC) {
            if (strcmp((char *)entry->ref->data, old_path) == 0) {
                free(entry->ref->data);
                entry->ref->data = new_path;
                res = 0;
                break;
            }
        }
    }
    assert(pf_unlock(&g_table_lock) == 0);
    return res;
}

extern int xl4_tablefd_open(int type, void* data) {
    int res;
    fd_entry_t *entry = NULL, *tmp;

    assert(type == FD_TYPE_ATFUNC || type == FD_TYPE_EPOLL);
    assert(pf_lock(&g_table_lock) == 0);
    HASH_ITER(hh, g_fs_ctx.fd_by_id, entry, tmp) {
        if (type == FD_TYPE_EPOLL) {
            if (entry->ref && entry->ref->data == data) {
                break;
            }
        } else {
            if (entry->ref &&
                strcmp((char *)entry->ref->data, (char *)data) == 0) {
                break;
            }
        }
    }
    if (entry) {
        // Same directory is openned by multiple threads?
        // Found the same entry in the existing hash table.
        // Simply return the fd of the existing entry and
        // do not add to avoid redundancy.
        entry->ref->count++;
        res = entry->value;
        // Free the input argument since we don't put it to the hash.
        free(data);
    } else {
        // Not found, add a new entry. Get an empty entry from the pool
        // and put to the hash table.
        entry = g_fs_ctx.fd_pool_list;
        if (entry) {
            entry->type = type;
            entry->dupfd = 0;
            if (!(entry->ref = malloc(sizeof(refcnt_t)))) {
                free(data);
                assert(pf_unlock(&g_table_lock) == 0);
                return -1;
            }
            DL_DELETE(g_fs_ctx.fd_pool_list, entry);
            entry->ref->count = 1;
            entry->ref->data = data;
            res = entry->value;
            HASH_ADD_INT(g_fs_ctx.fd_by_id, value, entry);
        } else {
            free(data);
            assert(0);
        }
    }
    if (res == -1) {
        errno = ENOMEM;
        assert(0);
    }
    assert(pf_unlock(&g_table_lock) == 0);

    return res;
}

extern int xl4_tablefd_dup(int fd) {
    int err = EBADF;
    int res = -1;

    assert(pf_lock(&g_table_lock) == 0);
    fd_entry_t *entry = NULL;
    HASH_FIND_INT(g_fs_ctx.fd_by_id, &fd, entry);
    assert(entry);
    if (entry) {
        fd_entry_t *clone_entry = g_fs_ctx.fd_pool_list;
        if (clone_entry) {
            DL_DELETE(g_fs_ctx.fd_pool_list, clone_entry);
            clone_entry->type = entry->type;
            if (entry->dupfd) {
                clone_entry->dupfd = entry->dupfd;
            } else {
                clone_entry->dupfd = entry->value;
            }
            clone_entry->ref = entry->ref;
            clone_entry->ref->count++;
            res = clone_entry->value;
            HASH_ADD_INT(g_fs_ctx.fd_by_id, value, clone_entry);
        }
    }
    assert(pf_unlock(&g_table_lock) == 0);
    if (res == -1) {
        errno = err;
    }
    return res;
}

extern void* xl4_tablefd_get_data(int fd, int type) {
    void *res = NULL;

    assert(pf_lock(&g_table_lock) == 0);
    fd_entry_t *entry;
    HASH_FIND_INT(g_fs_ctx.fd_by_id, &fd, entry);
    FATAL_UNLESS(entry, "Failed to find entry with fd: %d", fd);
    if (entry) {
        res = entry->ref->data;
        entry->ref->count++;
        assert(entry->type == type);
    }
    assert(pf_unlock(&g_table_lock) == 0);
    return res;
}

static inline  void reset_hash_node(fd_entry_t *fe) {
    // Do not reset the value of the entry.
    // We must keep the value for a key of hash table
    // and that value is also a descriptor id of each entry.
    fe->type = 0;
    fe->dupfd = 0;
    fe->ref = NULL;
}

extern bool xl4_tablefd_is_last_link(char *path) {
    fd_entry_t *cur, *tmp;
    bool last_link = true;
    assert(pf_lock(&g_table_lock) == 0);
    HASH_ITER(hh, g_fs_ctx.fd_by_id, cur, tmp) {
        if (cur->type == FD_TYPE_ATFUNC &&
            strcmp(path, (char *)cur->ref->data) == 0) {
            if (cur->ref->count > 0) {
                last_link = false;
            }
            break;
        }
    }
    assert(pf_unlock(&g_table_lock) == 0);
    return last_link;
}

int get_hash_table_fd_count(void) {
    return HASH_COUNT(g_fs_ctx.fd_by_id);
}

int get_list_of_tablefd_pool(void) {
    int count;
    fd_entry_t *elt;
    LL_COUNT(g_fs_ctx.fd_pool_list, elt, count);
    return count;
}

extern int xl4_tablefd_unref_data(int fd) {
    int err = EBADF;
    int res = 0;
    assert(pf_lock(&g_table_lock) == 0);
    fd_entry_t *entry;
    HASH_FIND_INT(g_fs_ctx.fd_by_id, &fd, entry);
    FATAL_UNLESS(entry, "Failed to find entry from hash table, key: %d", fd);
    if (entry) {
        entry->ref->count--;
        if (entry->ref->count == 0) {
            HASH_DEL(g_fs_ctx.fd_by_id, entry);
            if (entry->ref->data) {
                free(entry->ref->data);
                entry->ref->data = NULL;
            }
            fd_entry_t *cur, *tmp;
            // Find and remove duplicated entry from the hash table.
            HASH_ITER(hh, g_fs_ctx.fd_by_id, cur, tmp) {
                int remove_dup_entry = 0;
                if (cur->dupfd) {
                    // Current entry is a duplicated
                    // entry of the one to be removed.
                    if (cur->dupfd == entry->dupfd ||
                        cur->dupfd == entry->value) {
                        remove_dup_entry = 1;
                    }
                } else {
                    // Current entry is duplicated by the one to be removed.
                    if (entry->dupfd && cur->value == entry->dupfd) {
                        remove_dup_entry = 1;
                    }
                }
                if (remove_dup_entry) {
                    // Remove the entry from the hash
                    // and return to empty pool.
                    HASH_DEL(g_fs_ctx.fd_by_id, cur);
                    reset_hash_node(cur);
                    DL_APPEND(g_fs_ctx.fd_pool_list, cur);
                }
            }

            free(entry->ref);
            reset_hash_node(entry);
            DL_APPEND(g_fs_ctx.fd_pool_list, entry);
        }
    } else {
        res = -1;
        errno = err;
        FATAL("No more free fd in the pool");
    }
    assert(pf_unlock(&g_table_lock) == 0);
    return res;
}
