#include "qtablefd.h"
    
typedef struct refcnt {
    void *data;
    int count;
} refcnt_t;

typedef struct fd_entry {
    int used;
    int type;
    int value;
    int dupfd;
    refcnt_t *ref;
} fd_entry_t;

static fd_entry_t tablefd[FD_MAX_COUNT];
static pthread_mutex_t datalock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t tablelock = PTHREAD_MUTEX_INITIALIZER;

extern void epoll_close(void* ptr);

extern int qtablefd_open(int type, void* data)
{
    int i;
    
    pthread_mutex_lock(&tablelock);
    
    for(i = 0; i < FD_MAX_COUNT; i++) {
        if(!tablefd[i].used) {
            fd_entry_t* entry = &tablefd[i];
            entry->type = type;
            entry->dupfd = 0;
            entry->value = i + FD_MIN_VALUE;
            if(!(entry->ref = malloc(sizeof(refcnt_t)))) {
                pthread_mutex_unlock(&tablelock);
                return -1;
            }        
            entry->ref->count = 1;
            entry->ref->data = data;            
            entry->used = 1;        
            pthread_mutex_unlock(&tablelock);     
            return entry->value;
        }
    }
    
    pthread_mutex_unlock(&tablelock);
    
    errno = ENOMEM;
    return -1;
}

extern int qtablefd_dup(int fd)
{
    int i, j, err = EBADF;
    
    pthread_mutex_lock(&tablelock);
    
    for(i = 0; i < FD_MAX_COUNT; i++) {
        if(tablefd[i].used && (tablefd[i].value == fd)) {
            err = ENOMEM;
            fd_entry_t* real = &tablefd[i];            
            for(j = 0; j < FD_MAX_COUNT; j++) {
                if(!tablefd[j].used) {    
                    fd_entry_t* clone = &tablefd[j];                            
                    clone->type = real->type;
                    if(real->dupfd) {
                        clone->dupfd = real->dupfd;
                    } else {
                        clone->dupfd = real->value;
                    } 
                    clone->value = j + FD_MIN_VALUE;
                    clone->ref = real->ref;                    
                    clone->ref->count++;
                    clone->used = 1;                
                    pthread_mutex_unlock(&tablelock);                    
                    return clone->value;
                }
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&tablelock);
    
    errno = err;
    return -1;
}

extern void* qtablefd_get_data(int fd, int type)
{
    int i, err = EBADF;
    
    pthread_mutex_lock(&datalock);
    
    for(i = 0; i < FD_MAX_COUNT; i++) {
        if(tablefd[i].used && (tablefd[i].value == fd)) {
            err = EINVAL;
            if(tablefd[i].type == type) {
                tablefd[i].ref->count++;
                pthread_mutex_unlock(&datalock);
                return tablefd[i].ref->data;
            }
        }
    }
    
    pthread_mutex_unlock(&datalock);
    
    errno = err;
    return NULL;
}

extern int qtablefd_unref_data(int fd)
{
    int i, j, err = EBADF;
    
    pthread_mutex_lock(&datalock);
    
    for(i = 0; i < FD_MAX_COUNT; i++) {
        if(tablefd[i].used && (tablefd[i].value == fd)) {
            fd_entry_t* entry = &tablefd[i];
            entry->ref->count--;
            if(entry->ref->count == 0) {
                if(entry->ref->data) {
                    if(entry->type == FD_TYPE_EPOLL) {
                        epoll_close(entry->ref->data);
                    }
                    free(entry->ref->data);
                }
                pthread_mutex_lock(&tablelock);
                for(j = 0; j < FD_MAX_COUNT; j++) {
                    if(entry->dupfd) {
                        if((tablefd[j].value == entry->dupfd) || (tablefd[j].dupfd == entry->dupfd)) {
                            tablefd[j].used = 0;
                        }
                    }
                    else {
                        if(tablefd[j].dupfd == entry->value) {
                            tablefd[j].used = 0;
                        }
                    }
                }
                free(entry->ref);
                entry->used = 0;
                pthread_mutex_unlock(&tablelock);
            }
            pthread_mutex_unlock(&datalock);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&datalock);
    
    errno = err;
    return -1;
}
