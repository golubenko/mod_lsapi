/*
 * Copyright 2014-2015 Cloud Linux Zug GmbH
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * The part the support library for lsapi & proxy_lsapi Apache modules
 * author Alexander Demeshko <ademeshko@cloudlinux.com>
 *
 */

#include <lscapi_util.h>

#include <apr_thread_rwlock.h>


typedef struct lsapi_connentry_t {
    apr_thread_mutex_t *conn_mutex;
    int sock_num;
    lsapi_connslot_t *conn_slots;
} lsapi_connentry_t;


typedef struct lsapi_conntable_t {
    apr_table_t *conn_table;
    apr_thread_rwlock_t *conn_lock;
    apr_pool_t *p;
} lsapi_conntable_t;


static apr_status_t lscapi_cleanup_connections(void *data) {
    //TODO: close all connections to lsphp
    return APR_SUCCESS;
}

static const char CONNECTION_KEY[] = "LSAPI_CONNECTIONS_KEY";

static lsapi_conntable_t* lscapi_get_connection_table(server_rec *s) {
    apr_pool_t *p = s->process->pool;
    lsapi_conntable_t *conntable = NULL;
    apr_status_t rc = apr_pool_userdata_get((void**)(&conntable), CONNECTION_KEY, p);

    if(rc != APR_SUCCESS || conntable == NULL) {
        conntable = apr_palloc(p, sizeof(lsapi_conntable_t));
        conntable->p = p;
        conntable->conn_table = apr_table_make(p, 100);
        apr_thread_rwlock_create(&(conntable->conn_lock), p);
        apr_pool_userdata_setn(conntable, CONNECTION_KEY, lscapi_cleanup_connections, p);
    }

    rc = apr_pool_userdata_get((void**)(&conntable), CONNECTION_KEY, p);

    return conntable;
}


apr_status_t
lscapi_connpool_child_init(const char *prefix, server_rec *main_server, apr_pool_t *config_pool, lsapi_svr_conf_t *cfg)
{
    lsapi_conntable_t *connections = lscapi_get_connection_table(main_server);
    if(connections == NULL) {
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

#define DEFAULT_MAX_POOL_SIZE 50

int
lscapi_grab_sock_slot(server_rec *s, lsapi_svr_conf_t *cfg, const char *sock_name, lsapi_connslot_info_t *slot_info) {
    apr_status_t rc;
    lsapi_connentry_t *entry;

    lsapi_conntable_t *connections = lscapi_get_connection_table(s);
    if(connections == NULL) {
        lscapi_log(APLOG_WARNING, 0, s, "lscapi_grab_sock_slot: Could not get connection pool for sock(%s)", sock_name);
        return -1;
    }

    /*
        Provide the entry for sock_name in connections.
    */

    // Grab the lock in shared mode
    rc = apr_thread_rwlock_rdlock(connections->conn_lock);
    if(rc != APR_SUCCESS) {
        lscapi_log(APLOG_WARNING, errno, s, "lscapi_grab_sock_slot: apr_thread_rwlock_rdlock failed: %d", rc);
        return -1;
    }

    // Try to find an entry for sock_name
    entry = (lsapi_connentry_t*)apr_table_get(connections->conn_table, sock_name);

    // So we need to add an entry for sock_name into connections
    if(entry == NULL) {
        // Regrab the lock in exclusive mode
        apr_thread_rwlock_unlock(connections->conn_lock);
        rc = apr_thread_rwlock_wrlock(connections->conn_lock);
        if(rc != APR_SUCCESS) {
            lscapi_log(APLOG_WARNING, errno, s, "lscapi_grab_sock_slot: apr_thread_rwlock_wrlock failed: %d", rc);
            return -1;
        }

        // Maybe some another thread has already created our entry
        entry = (lsapi_connentry_t*)apr_table_get(connections->conn_table, sock_name);
    }

    if(entry == NULL) {
        // Now we have an exclusive lock, so lets create new entry and install it into connections
        char *sock_name_copy;

        entry = apr_palloc(connections->p, sizeof *entry);
        if(!entry) {
            lscapi_log(APLOG_WARNING, errno, s,
                       "lscapi_grab_sock_slot: alloc(%" APR_SIZE_T_FMT ") failed", sizeof *entry);
        }

        if(entry) {
            sock_name_copy = apr_pstrdup(connections->p, sock_name);
            if(!sock_name_copy) {
                lscapi_log(APLOG_WARNING, errno, s, "lscapi_grab_sock_slot: ptrdup(%s) failed", sock_name);
                entry = NULL; // as error indicator
            }
        }

        if(entry) {
            entry->sock_num = cfg->max_pool_size > 0 ? cfg->max_pool_size : DEFAULT_MAX_POOL_SIZE;
            entry->conn_slots = apr_pcalloc(connections->p, sizeof(lsapi_connslot_t) * entry->sock_num);
            if(!entry->conn_slots) {
                lscapi_log(APLOG_WARNING, errno, s,
                           "lscapi_grab_sock_slot: alloc(%" APR_SIZE_T_FMT ") failed",
                            sizeof(lsapi_connslot_t) * entry->sock_num);
                entry = NULL; // as error indicator
            }
        }

        if(entry) {
            rc = apr_thread_mutex_create(&(entry->conn_mutex), APR_THREAD_MUTEX_DEFAULT, connections->p);
            if(rc != APR_SUCCESS) {
                lscapi_log(APLOG_WARNING, errno, s, "lscapi_grab_sock_slot: apr_thread_mutex_create failed(%d)",
                            APR_THREAD_MUTEX_DEFAULT);
                entry = NULL; // as error indicator
            }
        }

        if(entry) {
            apr_table_addn(connections->conn_table, sock_name_copy, (char*)entry);
        }

    } // if(entry == NULL)

    apr_thread_rwlock_unlock(connections->conn_lock);
    // error indicator - something bad happened above
    if(entry == NULL) {
        return -1;
    }

    /*
        An entry for sock_name in connections is provided.
        Lets find a usable slot in it.
    */

    // Grab the mutex
    rc = apr_thread_mutex_lock(entry->conn_mutex);
    if(rc != APR_SUCCESS) {
        lscapi_log(APLOG_WARNING, errno, s, "lscapi_grab_sock_slot: apr_thread_mutex_lock failed: %d", rc);
        return -1;
    }

    int someClosedFreeSlot = -1, firstOpenFreeSlot = -1, foundSlot;
    int i = 0;
    for(i = 0; i < entry->sock_num; i++) {
        if(entry->conn_slots[i].is_used == 0) {
            if(entry->conn_slots[i].is_open != 0) {
                // we've found free and open slot - stop searching
                firstOpenFreeSlot = i;
                break;
            } else {
                // we've found free but closed slot - lets remember it
                someClosedFreeSlot = i;
            }
        }
    }

    if(firstOpenFreeSlot >= 0) {
        // reserve it for us
        foundSlot = firstOpenFreeSlot;
        entry->conn_slots[foundSlot].is_used = 1;
    } else if(someClosedFreeSlot >= 0) {
        // reserve it for us
        foundSlot = someClosedFreeSlot;
        entry->conn_slots[foundSlot].is_used = 1;
    } else {
        foundSlot = -1;
    }

    apr_thread_mutex_unlock(entry->conn_mutex);

    if(foundSlot >= 0) {
        slot_info->slot = entry->conn_slots + foundSlot;
        slot_info->conn_mutex = entry->conn_mutex;
        return 0;
    } else {
        return -1;
    }
}

int
lscapi_ungrab_sock_slot(server_rec *s, lsapi_connslot_info_t *slot_info) {
    // Grab the mutex
    apr_status_t rc = apr_thread_mutex_lock(slot_info->conn_mutex);
    if(rc != APR_SUCCESS) {
        lscapi_log(APLOG_WARNING, errno, s, "lscapi_ungrab_sock_slot: apr_thread_mutex_lock failed: %d", rc);
        return -1;
    }

    slot_info->slot->is_used = 0;

    apr_thread_mutex_unlock(slot_info->conn_mutex);
    return 0;
}
