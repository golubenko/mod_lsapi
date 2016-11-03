/*
 * Copyright 2014-2015 Cloud Linux Zug GmbH
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * The part the support library for lsapi & proxy_lsapi Apache modules
 * author Alexander Demeshko <ademeshko@cloudlinux.com>
 *
 * Here you define functions are to be used (means directly called) from
 * mod_lsapi (mod_lsapi/mod_lsapi.c + liblscapi-util/ *.c)
 */

#ifndef _LSCAPI_UTIL_H_
#define _LSCAPI_UTIL_H_

#include <lscapi.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <unixd.h>
#include <apr_strings.h>

#ifdef LSCAPI_WITH_DUMP_HEADER
#undef LSCAPI_WITH_DUMP_HEADER
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20100504,0)

#define LSCAPI_WITH_MUTEX_API 1

#else

#define LSCAPI_WITH_MUTEX_API 0

#endif

#ifdef APACHE2_2

#define APLOGNO(n)              "AH" #n ": "

#define APLOG_USE_MODULE(foo) \
    extern module AP_MODULE_DECLARE_DATA foo##_module

#else

extern const int *lsapilog_module_index;

#ifdef APLOG_MODULE_INDEX
#undef APLOG_MODULE_INDEX
#endif

#define APLOG_MODULE_INDEX  \
    (aplog_module_index ? *aplog_module_index : (lsapilog_module_index ? *lsapilog_module_index : APLOG_NO_MODULE) )
#endif

#ifdef WITH_LIBPERFLOG
extern int lsapi_use_perflog;
#endif // WITH_LIBPERFLOG

struct lsapi_svr_conf_t {
    char *socket_path;
    char *phprc;
    char *selfstarter_socket_path;
    char *hostname_on_debug;
    const char *backend_env_path;
    const char *tmpdir;
    uint32_t default_uid;
    uint32_t default_gid;
    uint32_t max_pool_size;
#if !LSCAPI_WITH_MUTEX_API
    apr_lockmech_e mutex_mech;
#endif

    lscapi_backend_info_t backend_info;
    apr_table_t *envTable;

    /*
        Define these fields unconditionally though they will be used in fact 
        only when compiled with -DWITH_CRIU flag
    */
    char *criu_socket_path;
    char *criu_imgs_dir_path;

    unsigned lve_enabled:1;
    unsigned debug_enabled:1;
    unsigned terminate_backends_on_exit: 1;
    unsigned check_target_perm: 1;
    unsigned paranoid: 1;
    unsigned use_default_uid:1;
    unsigned skip_check_document_root:1;
    unsigned phprc_auto:1;

    unsigned debug_enabled_was_set:1;
    unsigned terminate_backends_was_set: 1;
    unsigned check_target_perm_was_set: 1;
    unsigned paranoid_was_set: 1;
    unsigned use_default_uid_was_set:1;
    unsigned skip_check_document_root_was_set:1;
    unsigned phprc_auto_was_set:1;
};
typedef struct lsapi_svr_conf_t lsapi_svr_conf_t;

struct php_param_t {
    char *value;
    size_t valueLen;
    int isAdmin;
    int htaccess;
};
typedef struct php_param_t php_param_t;

struct lsapi_dir_conf_t {
    apr_hash_t *phpParams;
    uint32_t lsapi_uid;
    uint32_t lsapi_gid;
    uint32_t suphp_uid;
    uint32_t suphp_gid;
    uint32_t ruid;
    uint32_t rgid;
    uint32_t itk_uid;
    uint32_t itk_gid;
    
    int err_server_docroot;       // default HTTP_INTERNAL_SERVER_ERROR
    int err_server_uid;           // default HTTP_INTERNAL_SERVER_ERROR
    int err_script_perms;         // default HTTP_INTERNAL_SERVER_ERROR

    int err_lsapi_create;         // default HTTP_SERVICE_UNAVAILABLE
    int err_lsapi_internal;       // default HTTP_SERVICE_UNAVAILABLE
    int err_lsapi_conn_acquire;   // default HTTP_SERVICE_UNAVAILABLE
    int err_lsapi_conn_determine; // default HTTP_SERVICE_UNAVAILABLE
    
    int err_backend_nohdrs;       // default HTTP_SERVICE_UNAVAILABLE
    int err_backend_endhdrs;      // default HTTP_SERVICE_UNAVAILABLE (Premature end of headers)
    int err_backend_sendreq;      // default HTTP_SERVICE_UNAVAILABLE
    int err_backend_recvhdr;      // default HTTP_SERVICE_UNAVAILABLE
    int err_backend_recvrsp;      // default HTTP_SERVICE_UNAVAILABLE
    int err_backend_connect;      // default HTTP_SERVICE_UNAVAILABLE
    
    int err_client_setup;         // default HTTP_BAD_REQUEST

    const char *path_regex;

    apr_hash_t *resend_if_method;

    unsigned mod_php_behaviour_off: 1;
    unsigned dir_accept_notify: 1;
    unsigned resend_if_crashed: 3; // up to 7 times (as 2³-1)

    unsigned mod_php_behaviour_off_was_set: 1;
    unsigned dir_accept_notify_was_set: 1;
    unsigned resend_if_crashed_was_set: 1;
    unsigned resend_if_method_was_set: 1;

    unsigned err_server_docroot_was_set: 1;
    unsigned err_server_uid_was_set: 1;
    unsigned err_script_perms_was_set: 1;

    unsigned err_lsapi_create_was_set: 1;
    unsigned err_lsapi_internal_was_set: 1;
    unsigned err_lsapi_init_was_set: 1;
    unsigned err_lsapi_init_util_was_set: 1;
    unsigned err_lsapi_conn_acquire_was_set: 1;
    unsigned err_lsapi_conn_determine_was_set: 1;
    
    unsigned err_backend_nohdrs_was_set: 1;
    unsigned err_backend_endhdrs_was_set: 1;
    unsigned err_backend_sendreq_was_set: 1;
    unsigned err_backend_recvhdr_was_set: 1;
    unsigned err_backend_recvrsp_was_set: 1;
    unsigned err_backend_connect_was_set: 1;
    
    unsigned err_client_setup_was_set: 1;

};
typedef struct lsapi_dir_conf_t lsapi_dir_conf_t;

lsapi_svr_conf_t *lsapi_get_svr_config(server_rec *s);

int lscapi_util_init(char *errbuf, size_t errlen);
//apr_status_t lscapi_util_child_init(apr_pool_t *configpool, server_rec *s);

lscapi_rec *lscapi_create_connection(request_rec *r, const char *backend_path,
                                       unsigned *flagsPtr, apr_status_t *statusPtr,
                                       char *errbuf, size_t errlen,
                                       const module *m);

int lscapi_parse_server_vars(request_rec *r, lscapi_var_t **varsPtr);
int lscapi_parse_special_vars(request_rec *r, apr_hash_t *cfgH, lscapi_var_t **varsPtr);

apr_hash_t *lscapi_parse_cfg_resend_if_method(const char *value, apr_pool_t *pool);

void lscapi_recreate_http_header(request_rec *r,
                                lsapi_http_header_index_t **hdrIndexPtr,
                                lsapi_header_offset_t **hdrOffsetsPtr,
                                size_t *hdrOffsetsNumPtr,
                                size_t *contentLengthPtr,
                                char **bufPtr, size_t *bufLenPtr);

#ifdef lscapi_rlog
#undef lscapi_rlog
#endif

#define lscapi_rlog(level, status, r, fmt, ...)           \
    lscapi_log_rerror(__FILE__, __LINE__, level, status, r, fmt, __VA_ARGS__)


void lscapi_log_rerror(const char *file, int line, int level,
                       apr_status_t status,
                        const request_rec *r, const char *fmt, ...)
                        __attribute__((format(printf,6,7)));

#ifdef lscapi_log
#undef lscapi_log
#endif

#define lscapi_log(level, status, s, fmt, ...)           \
    lscapi_log_error(__FILE__, __LINE__, level, status, s, fmt, __VA_ARGS__)


void lscapi_log_error(const char *file, int line, int level,
                       apr_status_t status,
                        const server_rec *s, const char *fmt, ...)
                        __attribute__((format(printf,6,7)));

apr_status_t lscapi_do_request(lscapi_rec *lscapi, lsphp_conn_t *backend, request_rec *r, 
                               lsapi_svr_conf_t *svrcfg, lsapi_dir_conf_t *dircfg);

const char* lscapi_php_value_handler(cmd_parms* cmd, void *cfg,
                                    const char *name, const char *value,
                                    int isAdmin);
const char *lscapi_php_flag_handler(cmd_parms *cmd, void *cfg,
                                    const char *name, const char *value, int isAdmin);
void *lscapi_create_dir_config(apr_pool_t *pool, char *x);
void *lscapi_merge_dir_config(apr_pool_t *pool, void *base, void *cur);
void *lscapi_create_svr_config(apr_pool_t *pool, server_rec *s);
void *lscapi_merge_svr_config(apr_pool_t *pool, void *base, void *cur);


//int process_lve_error (request_rec * r, lsapi_dir_conf_t * cfg);

apr_status_t lscapi_mutex_register(const char *mutex_type,
                                  apr_pool_t *pconf);

apr_status_t lscapi_mutex_create(apr_global_mutex_t **mutex,
                                const char **lockfile,
                                const char *mutex_type,
                                apr_pool_t *pconf,
                                server_rec *s,
                                lsapi_svr_conf_t *cfg);

#if 0
void lscapi_cleanup_mutex(const char *apache_user);
#endif


pid_t lscapi_starter_send_spawn_cmd(const spawn_info_t *spawn_info, request_rec *r, int force_start);


apr_status_t lscapi_starter_child_init(server_rec* main_server, apr_pool_t* config_pool, const char *prefix);
apr_status_t lscapi_starter_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp);
apr_status_t lscapi_starter_init(const char *prefix, server_rec *main_server, apr_pool_t *config_pool, lsapi_svr_conf_t *cfg);


typedef struct lsapi_connslot_t {
    int sock;
    int is_open;
    int is_used;
} lsapi_connslot_t;

typedef struct lsapi_connslot_info_t {
    apr_thread_mutex_t *conn_mutex;
    lsapi_connslot_t *slot;
} lsapi_connslot_info_t;

apr_status_t lscapi_connpool_child_init(const char *prefix, server_rec *main_server, apr_pool_t *config_pool, lsapi_svr_conf_t *cfg);
int lscapi_grab_sock_slot(server_rec *s, lsapi_svr_conf_t *cfg, const char *sock_name, lsapi_connslot_info_t *slot_info);
int lscapi_ungrab_sock_slot(server_rec *s, lsapi_connslot_info_t *slot_info);

char* lscapi_make_fname_in_logdir(server_rec *s, apr_pool_t *pool, const char *fname);

void lscapi_reset_http_error_state(request_rec *r);

#endif //_LSCAPI_UTIL_H_

