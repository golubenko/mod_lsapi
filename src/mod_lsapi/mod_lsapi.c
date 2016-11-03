/*
 * Copyright 2014-2015 Cloud Linux Zug GmbH
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * author Alexander Demeshko <ademeshko@cloudlinux.com>
 *
 */

#include <lscapi_util.h>
#include <string.h>
#include <unixd.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_signal.h>
#include <mpm_common.h>
#include <ap_mpm.h>

#define PREFIX "mod_lsapi: "
#define MOD_LSAPI_VERSION MOD_LSAPI_VERSION_MAJOR "." MOD_LSAPI_VERSION_MINOR "-" MOD_LSAPI_VERSION_RELEASE

static int with_connection_pool = 1;

module AP_MODULE_DECLARE_DATA lsapi_module;

APLOG_USE_MODULE(lsapi);

lsapi_svr_conf_t *lsapi_get_svr_config(server_rec *s)
{
    return ap_get_module_config(s->module_config, &lsapi_module);
}


static void* alloc_by_pool(size_t sz, void *user_data)
{
    return apr_palloc((apr_pool_t*)user_data, sz);
}

/*
 * Connect to backend occur in scope of this function and it's callees
 *
 * Return codes:
 *   -1: error occured
 *    1: connection established in connection pool mode
 *    0: connection estableshed in pool-less mode
 */
static apr_status_t connect_to_backend_impl(lsphp_conn_t *backend, request_rec *r, 
                                    lscapi_rec *lscapi, lsapi_connslot_info_t* slotInfoPtr,
                                    char *errbuf, size_t errlen)
{
    apr_status_t status;
    lsapi_svr_conf_t *svrcfg = ap_get_module_config(r->server->module_config, &lsapi_module);

    int with_connpool = with_connection_pool;
    if(with_connpool != 0) {
        const char *sock_name = lscapi_conn_get_socket_name(backend);
        int rc = lscapi_grab_sock_slot(r->server, svrcfg, sock_name, slotInfoPtr);
        if(rc != 0) {
            // something wrong with connection pool, so will use conventional mode
            with_connpool = 0;
        }
    }

    if(with_connpool != 0) {

        if(slotInfoPtr->slot->is_open) {
            if(lscapi_is_socket_closed(slotInfoPtr->slot->sock)) {
                slotInfoPtr->slot->sock = 0;
                slotInfoPtr->slot->is_open = 0;
            }
        }

        if(slotInfoPtr->slot->is_open) {
            lscapi_lsphp_use_sock(backend, slotInfoPtr->slot->sock, errbuf, sizeof errbuf);

        } else {

            status = lscapi_connect_lsphp(backend, errbuf, errlen);
            if(status != 0) {
                lscapi_ungrab_sock_slot(r->server, slotInfoPtr);
                return -1;
            }
            slotInfoPtr->slot->sock = lscapi_lsphp_conn_get_socket(backend);
            slotInfoPtr->slot->is_open = 1;

        }

    } else { // if(with_conpool != 0)

        status = lscapi_connect_lsphp(backend, errbuf, errlen);
        //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
        //                PREFIX "lscapi_connect_lsphp() return %d", status);

        if(status != 0) {
            return -1;
        }

    } // else of if(with_conpool != 0)
    
    return (with_connpool != 0);
}

/*
 * Backend communications occur in scope of this function and it's callees
 */
static apr_status_t talk_to_backend_impl(lsphp_conn_t *backend, request_rec *r, 
                                         lsapi_connslot_info_t* slotInfoPtr, lscapi_rec *lscapi)
{
    apr_status_t status;
    int with_connpool = (slotInfoPtr != NULL);
    lsapi_svr_conf_t *svrcfg = ap_get_module_config(r->server->module_config, &lsapi_module);
    lsapi_dir_conf_t *dircfg = (lsapi_dir_conf_t*) ap_get_module_config(r->per_dir_config, &lsapi_module);

    status = lscapi_do_request(lscapi, backend, r, svrcfg, dircfg);
    //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
    //              PREFIX "lscapi_do_request() status = %d", status);

    if(with_connpool) {
        lscapi_ungrab_sock_slot(r->server, slotInfoPtr);
    } else {
        lscapi_release_lsphp_conn(backend);
        //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
        //              PREFIX "lscapi_release_lsphp_conn() finished");
    }

    return status;
}

static void reset_error_state(request_rec *r, lscapi_rec *lscapi)
{
    lscapi_reset_http_error_state(r);
    lscapi_reset_internal_error_state(lscapi);
}

static bool is_resend_ok_with_body_len(lscapi_rec *lscapi, lsapi_svr_conf_t *svrcfg)
{
    return (lscapi_get_body_len(lscapi) <= svrcfg->backend_info.max_resend_buffer_kb * 1024L);
}

static bool is_resend_ok_with_http_method(request_rec *r,
                                          lsapi_dir_conf_t *dircfg,
                                          const char **outRequestMethod)
{
    *outRequestMethod = apr_table_get(r->subprocess_env, "REQUEST_METHOD");

    // not using APR_HASH_KEY_STRING here as far counting in null terminator for hash key
    // appears to be implementation specific
    size_t len = strlen(*outRequestMethod);

    return (apr_hash_get(dircfg->resend_if_method, *outRequestMethod, len) != NULL);
}

static bool is_resend_condition_met(request_rec *r,
                                    lscapi_rec *lscapi,
                                    lsapi_svr_conf_t *svrcfg,
                                    lsapi_dir_conf_t *dircfg)
{
    if (!is_resend_ok_with_body_len(lscapi, svrcfg))
    {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      PREFIX "will not re-send previously crashed request because "
                             "request body length is > lsapi_max_resend_buffer");
        return false;
    }

    const char *requestMethod;
    if (!is_resend_ok_with_http_method(r, dircfg, &requestMethod))
    {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      PREFIX "will not re-send previously crashed request because "
                             "request method %s is not in lsapi_resend_if_method list", requestMethod);
        return false;
    }

    return true;
}

/*
 * Talk to backend, re-send request to backend again when backend has crashed
 */
static apr_status_t talk_to_backend(lsphp_conn_t *backend, request_rec *r, 
                                    lscapi_rec *lscapi,
                                    lsapi_svr_conf_t *svrcfg,
                                    lsapi_dir_conf_t *dircfg)
{
    apr_status_t status;
    lsapi_connslot_info_t slotInfo;
    char errbuf[256];

    // lets connect backend
    int num_to_retry = dircfg->resend_if_crashed;
    do
    {
        bool prev_req_fail = (num_to_retry < dircfg->resend_if_crashed);
        if (prev_req_fail)
        {
            // always consider connection error as recoverable one
            reset_error_state(r, lscapi);
        }

        status = connect_to_backend_impl(backend, r, lscapi, &slotInfo, errbuf, sizeof errbuf);

    } while (status < 0 && num_to_retry-- > 0);

    if(status < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      PREFIX "[host %s] [req %s] Could not connect to lsphp backend: %s", 
                       r->hostname, r->the_request, errbuf );
        return dircfg->err_backend_connect; //HTTP_SERVICE_UNAVAILABLE
    }
    
    int with_connpool = (status > 0);

    // lets do the request
    num_to_retry = dircfg->resend_if_crashed;
    do
    {
        bool prev_req_fail = (num_to_retry < dircfg->resend_if_crashed);
        if (prev_req_fail)
        {
            bool isRecoverableErr;
            lscapi_get_error(lscapi, &isRecoverableErr);
            if (isRecoverableErr && is_resend_condition_met(r, lscapi, svrcfg, dircfg))
            {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              PREFIX "re-sending previously crashed request again (%d)",
                              (dircfg->resend_if_crashed - num_to_retry));
                lsapi_perf_inc(PFL_RESEND_IF_CRASHED);
                reset_error_state(r, lscapi);
            }
            else
            {
                break;
            }
        }

        status = talk_to_backend_impl(backend, r, with_connpool ? &slotInfo : NULL, lscapi);

    } while (status == 500 && num_to_retry-- > 0);
    
    return status;
}

static apr_status_t lsapi_handler(request_rec * r)
{
    apr_status_t status;
    lscapi_rec *lscapi;
    lsphp_conn_t *backend;
    lsapi_svr_conf_t *svrcfg = ap_get_module_config(r->server->module_config, &lsapi_module);
    lsapi_dir_conf_t *dircfg = (lsapi_dir_conf_t*) ap_get_module_config(r->per_dir_config, &lsapi_module);

    const char *backend_path = lscapi_get_backend(r->handler);
    if(!backend_path)
    {
        return DECLINED;
    }

    unsigned flags = 0;
    char errbuf[256];
    lscapi = lscapi_create_connection(r, backend_path, &flags, &status,
                                      errbuf, sizeof errbuf, &lsapi_module);
    if(!lscapi) {
        if(status != HTTP_NOT_FOUND) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            PREFIX "[host %s] [req %s]: %s", 
                            r->hostname, r->the_request, errbuf);
        }
        return status;
    }

    backend = lscapi_acquire_lsphp_conn(lscapi, errbuf, sizeof errbuf );
    if(!backend) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      PREFIX "[host %s] [req %s] Could not acquire lsphp connection: %s", 
                      r->hostname, r->the_request, errbuf);
        lscapi_destroy(lscapi);
        return dircfg->err_lsapi_conn_acquire; //HTTP_SERVICE_UNAVAILABLE
    }

    // will be ready to get deal with request body
    status = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);
    if(status != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                      PREFIX "[host %s] [req %s] ap_client_block failed: %d", 
                      r->hostname, r->the_request, status);
        lscapi_destroy(lscapi);
        return dircfg->err_client_setup; //HTTP_BAD_REQUEST
    }

/*
#ifdef LSCAPI_WITH_RANDOM_SOCKET_NAMES
    char suffix[128];
    status = lscapi_get_socket_suffix(lscapi, lveuid, lvegid, r, svrcfg, suffix, sizeof suffix );
    if(status != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      PREFIX "[host %s] Could not get socket suffix", r->hostname);
        lscapi_destroy(lscapi);
        return HTTP_INTERNAL_SERVER_ERROR; //error from lscapi_get_socket_suffix is (almost) impossible
    }

    status = lscapi_determine_conn_lsphp_ex(backend, &(svrcfg->backend_info), suffix, errbuf, sizeof errbuf);
    if(status != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      PREFIX "[host %s] Could not determine lsphp connection: %s", r->hostname, errbuf );
        lscapi_destroy(lscapi);
        return HTTP_SERVICE_UNAVAILABLE;
     }
#else
*/
     status = lscapi_determine_conn_lsphp(backend, &(svrcfg->backend_info), errbuf, sizeof errbuf);
     if(status != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      PREFIX "[host %s] [req %s] Could not determine lsphp connection: %s", 
                      r->hostname, r->the_request, errbuf );
        lscapi_destroy(lscapi);
        return dircfg->err_lsapi_conn_determine; //HTTP_SERVICE_UNAVAILABLE
     }
/*
#endif
*/
    status = talk_to_backend(backend, r, lscapi, svrcfg, dircfg);

    lscapi_destroy(lscapi);

    return status;
}


static void lsapi_child_init(apr_pool_t *configpool, server_rec *s) {
    apr_status_t rc;

    lsapi_svr_conf_t *cfg = ap_get_module_config(s->module_config, &lsapi_module);

    apr_signal_unblock(SIGCHLD);
    apr_signal(SIGCHLD, SIG_IGN);
    lscapi_child_init(alloc_by_pool, s->process->pool);

/*
    rc = lscapi_util_child_init(configpool, s);
    if(rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rc, s,
                    PREFIX " Can't initialize self");
        return;
    }
*/

    if(!lscapi_is_lve_loaded())
        cfg->lve_enabled = 0;

    if ((rc = lscapi_starter_child_init(s, configpool, PREFIX)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rc, s,
                    PREFIX " Can't initialize selfstarter");
        return;
    }
    //ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
    //                  "in lsapi_child_init: lveEnabled:%d",
    //                  cfg->lveEnabled );


    rc = lscapi_connpool_child_init(PREFIX, s, configpool, cfg);
    if(rc != APR_SUCCESS) {

        ap_log_error(APLOG_MARK, APLOG_EMERG, rc, s,
                        PREFIX "Can't initialize connection pool");
        return;
    }

    return;
}

static int is_server_restart(void) {
    int rc, mpm_state;

    rc = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state);

    /*
        We expect that on restart (both immediate and graceful) mpm_query hook is not registered
        and ap_mpm_query will return APR_EGENERAL.
    */
    if (rc == APR_EGENERAL) {
        return 1;
    }

    return 0;
}

static apr_status_t lsapi_cleanup(void *data)
{
    lsapi_svr_conf_t *cfg = ap_get_module_config(((server_rec*)data)->module_config,
                                                    &lsapi_module);
    if(cfg->debug_enabled) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, (server_rec*)data, PREFIX "Cleanup");
    }

    if(cfg->terminate_backends_on_exit) {

        if(is_server_restart()) {

            if(cfg->debug_enabled) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, (server_rec*)data, PREFIX "Backend termination cancelled due to server restart");
            }

        } else {
#ifdef WITH_CRIU
            lscapi_terminate_backends_criu(cfg->socket_path, cfg->criu_imgs_dir_path);
#else
            lscapi_terminate_backends_ex(cfg->socket_path);
#endif // USE_CRIU
        }
    }

#if 0
    lscapi_cleanup_mutex(SULSPHP_HTTPD_USER);
#endif

    return APR_SUCCESS;
}

static int lsapi_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    apr_status_t rc;

    rc = lscapi_starter_pre_config(pconf, plog, ptemp);
    if (rc != APR_SUCCESS) {
        return rc;
    }

    return OK;
}

static int lsapi_init(apr_pool_t * config_pool, apr_pool_t * plog, apr_pool_t * ptemp,
                      server_rec * main_server)
{
    const char *userdata_key = "lsapi_init";
    void *dummy = NULL;
    char errbuf[256];

    /* Initialize selfstarter only once */
    apr_pool_userdata_get(&dummy, userdata_key,
                          main_server->process->pool);
    if (!dummy) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null,
                              main_server->process->pool);
        return APR_SUCCESS;
    }

    lsapi_svr_conf_t *cfg = ap_get_module_config(main_server->module_config,
                                                    &lsapi_module);
    if(with_connection_pool != 0)
    {
        int max_daemons_limit;
        ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_daemons_limit);

        // Temporary hack in 1.0 branch, in order to do not add new exported 
        // function into the library.
        // lscapi_get_backend_children is used in the 1.1 branch
        int backend_children = (cfg->backend_info.backend_children == (uint32_t)-1) ? 120 : cfg->backend_info.backend_children;
 
        int children_for_daemon = backend_children / max_daemons_limit;
        
        if(children_for_daemon <= 3) {
            ap_log_error (APLOG_MARK, APLOG_WARNING, 0, main_server,
                        PREFIX "Connection Pool Mode is forcibly turned off - too few backend children for %d MaxDaemons",
                        max_daemons_limit);
            ap_log_error (APLOG_MARK, APLOG_WARNING, 0, main_server,
                        PREFIX "please increase lsapi_backend_children to %d at least",
                        max_daemons_limit * 4);
            with_connection_pool = 0;
        } else {
            if(cfg->max_pool_size <= 0)
            {
                // no explicit value in config - set it here
                cfg->max_pool_size = children_for_daemon - 1;
            } else if(cfg->max_pool_size > children_for_daemon - 1) {
                ap_log_error (APLOG_MARK, APLOG_WARNING, 0, main_server,
                                PREFIX "lsapi_max_connection(%d) is too high for lsapi_backend_children(%d) and %d MaxDaemons Limit", 
                                cfg->max_pool_size, backend_children, max_daemons_limit);
                cfg->max_pool_size = children_for_daemon - 1;
                ap_log_error (APLOG_MARK, APLOG_WARNING, 0, main_server,
                                PREFIX "lsapi_max_connection is decreased to %d", 
                                cfg->max_pool_size);
            }
        }
    }

    apr_status_t rc = lscapi_init(errbuf, sizeof errbuf);
    if(rc) {
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, main_server,
		    PREFIX " version " MOD_LSAPI_VERSION ": initialization error: %s", errbuf );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = lscapi_util_init(errbuf, sizeof errbuf);
    if(rc) {
        ap_log_error (APLOG_MARK, APLOG_ERR, 0, main_server,
		    PREFIX " version " MOD_LSAPI_VERSION ": initialization error: %s", errbuf );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#ifdef WITH_CRIU
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, main_server,
                PREFIX " version " MOD_LSAPI_VERSION " with CRIU support. Connection pool mode is switched %s",
                with_connection_pool ? "on" : "off" );
#else
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, main_server,
                PREFIX " version " MOD_LSAPI_VERSION " Connection pool mode is switched %s",
                with_connection_pool ? "on" : "off" );
#endif

    rc = lscapi_starter_init(PREFIX, main_server, config_pool, cfg);
    if(rc != APR_SUCCESS) {

        ap_log_error(APLOG_MARK, APLOG_EMERG, rc, main_server,
                        PREFIX "Can't initialize selfstarter");
        return rc;
    }

    apr_pool_cleanup_register(config_pool, main_server,
                                lsapi_cleanup, apr_pool_cleanup_null);

    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t * p)
{
    ap_hook_pre_config(lsapi_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(lsapi_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(lsapi_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(lsapi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
static const char *lsapi_secret_file_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    return lscapi_secret_file_handler(cmd, cfg, value);
}
*/

static const char *lsapi_debug_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->debug_enabled = ( strcasecmp(value, "on") == 0 );
    cfg->debug_enabled_was_set = 1;
    return NULL;
}

static const char *lsapi_terminate_backends_on_exit_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);

    cfg->terminate_backends_on_exit = ( strcasecmp(value, "off") != 0 );
    cfg->terminate_backends_was_set = 1;

    return NULL;
}

static const char *lsapi_socket_path_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->socket_path = apr_pstrdup(cmd->pool, value);
    return NULL;
}

static const char *lsapi_phprc_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    if(strcasecmp(value, "no") == 0) {
        cfg->phprc = NULL;
        cfg->phprc_auto = 0;
    } else if(strcasecmp(value, "auto") == 0) {
        cfg->phprc = NULL;
        cfg->phprc_auto = 1;
    } else {
        cfg->phprc = apr_pstrdup(cmd->pool, value);
        cfg->phprc_auto = 0;
    }
    cfg->phprc_auto_was_set = 1;
    return NULL;
}

static const char *lsapi_target_perm_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->check_target_perm = ( strcasecmp(value, "on") == 0);
    cfg->check_target_perm_was_set = 1;
    return NULL;
}

static const char *lsapi_paranoid_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->paranoid = ( strcasecmp(value, "on") == 0);
    cfg->paranoid_was_set = 1;
    return NULL;
}

static const char *lsapi_check_document_root_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->skip_check_document_root = ( strcasecmp(value, "off") == 0);
    cfg->skip_check_document_root_was_set = 1;
    return NULL;
}

static const char *lsapi_use_default_uid_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->use_default_uid = ( strcasecmp(value, "off") != 0 );
    cfg->use_default_uid_was_set = 1;
    return NULL;
}

static const char *lsapi_backend_connect_timeout_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 0) {
        cfg->backend_info.connect_timeout = ival;
    }
    return NULL;
}

static const char *lsapi_backend_pgrp_max_idle_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    cfg->backend_info.backend_pgrp_max_idle = ival;
    return NULL;
}

static const char *lsapi_backend_max_idle_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    cfg->backend_info.backend_max_idle = ival;
    return NULL;
}

static const char *lsapi_backend_max_process_time_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 0) {
        cfg->backend_info.backend_max_process_time = ival;
    }
    return NULL;
}

static const char *lsapi_backend_max_reqs_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 0) {
        cfg->backend_info.backend_max_reqs = ival;
    }
    return NULL;
}


static const char *lsapi_backend_connect_tries_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 0) {
        cfg->backend_info.connect_tries = ival;
    }
    return NULL;
}


static const char *lsapi_backend_children_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 1) {
        cfg->backend_info.backend_children = ival;
    }
    return NULL;
}


static const char *lsapi_uid_gid_handler(cmd_parms *cmd, void* CFG,
                                           const char *arg1, const char *arg2)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    uint32_t uid = (uint32_t) apr_atoi64 (arg1);
    uint32_t gid = (uint32_t) apr_atoi64 (arg2);
    if(uid > 0 && gid > 0) {
        cfg->lsapi_uid = uid;
        cfg->lsapi_gid = gid;
    }

    return NULL;
}

static const char *lsapi_user_group_handler(cmd_parms *cmd, void* CFG,
                                           const char *arg1, const char *arg2)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    uint32_t uid = ap_uname2id(arg1);
    uint32_t gid = ap_gname2id(arg2);
    if(uid > 0 && gid > 0) {
        cfg->lsapi_uid = uid;
        cfg->lsapi_gid = gid;
    }

    return NULL;
}

static const char *lsapi_with_connection_pool_handler(cmd_parms *cmd, void *dummy, const char *value) {
    const char *err = ap_check_cmd_context (cmd, GLOBAL_ONLY);
    if (err != NULL)
    {
      return err;
    }

    with_connection_pool = ( strcasecmp(value, "off") != 0 );
    return NULL;
}

static const char *lsapi_selfstarter_handler(cmd_parms *cmd, void *dummy, const char *value) {
    return NULL;
}

static const char *lsapi_max_connection_handler(cmd_parms *cmd, void *dummy, const char *value) {
    const char *err = ap_check_cmd_context (cmd, GLOBAL_ONLY);
    if (err != NULL)
    {
      return err;
    }
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 0) {
        cfg->max_pool_size = ival;
    }
    return NULL;
}



#ifdef LSCAPI_WITH_DUMP_HEADER
static const char *lsapi_hostname_on_debug_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->hostname_on_debug = apr_pstrdup(cmd->pool, value);
    return NULL;
}
#endif

static const char *lsapi_set_env_handler(cmd_parms *cmd, void *dummy,
                                    const char *name, const char *value) {
    const char *err = ap_check_cmd_context (cmd, (NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE));
    if (err != NULL)
    {
      return err;
    }

    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    apr_table_set(cfg->envTable, name, value); // is using of name&value safe? apr_table_setn maybe?
    return NULL;
}

static const char *lsapi_set_env_path_handler(cmd_parms *cmd, void *dummy,
                                                const char *value) {
    const char *err = ap_check_cmd_context (cmd, (NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE));
    if (err != NULL)
    {
      return err;
    }

    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->backend_env_path = value;
    return NULL;
}


static const char *lsapi_backend_accept_notify_handler(cmd_parms *cmd, void *CFG, const char *value) {
    const char *err = ap_check_cmd_context (cmd, (NOT_IN_LIMIT|NOT_IN_DIR_LOC_FILE));
    if (err != NULL)
    {
      return err;
    }

    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    cfg->dir_accept_notify = ( strcasecmp(value, "off") != 0 );
    cfg->dir_accept_notify_was_set = 1;

    return NULL;
}

static const char *lsapi_backend_use_own_log_handler(cmd_parms *cmd, void *CFG, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->backend_info.use_own_log = ( strcasecmp(value, "on") == 0 );
    cfg->backend_info.use_own_log_was_set = 1;
    return NULL;
}

static const char *lsapi_resend_if_crashed_handler(cmd_parms *cmd, void* CFG, const char *arg1)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;

    // TODO: check range is in ["off", 0..7]
    uint32_t ival = (uint32_t) apr_atoi64 (arg1);
    if(ival > 0) {
        cfg->resend_if_crashed = ival;
        cfg->resend_if_crashed_was_set = 1;
    }

    return NULL;
}

static const char *lsapi_max_resend_buffer_handler(cmd_parms *cmd, void* CFG, const char *arg1)
{
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);

    uint32_t ival = (uint32_t) apr_atoi64 (arg1);
    if(ival > 0) {
        cfg->backend_info.max_resend_buffer_kb = ival;
        cfg->backend_info.max_resend_buffer_was_set = 1;
    }

    return NULL;
}

static const char *lsapi_resend_if_method_handler(cmd_parms *cmd, void* CFG, const char *arg1)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    apr_hash_t *parsed = lscapi_parse_cfg_resend_if_method(arg1, cmd->pool);
    if (parsed)
    {
        cfg->resend_if_method = parsed;
        cfg->resend_if_method_was_set = 1;
    }

    return NULL;
}

static const char *lsapi_error_code_handler(cmd_parms *cmd, void* CFG, const char *arg1, const char *arg2)
{
    uint32_t ival;
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;

    if(strcmp(arg1, "SERVER_DOCROOT") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_server_docroot = ival;
            cfg->err_server_docroot_was_set = 1;
        }
    } else if(strcmp(arg1, "SERVER_UID") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_server_uid = ival;
            cfg->err_server_uid_was_set = 1;
        }
    } else if(strcmp(arg1, "SCRIPT_PERMS") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_script_perms = ival;
            cfg->err_script_perms_was_set = 1;
        }
    } else if(strcmp(arg1, "LSAPI_CREATE") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_lsapi_create = ival;
            cfg->err_lsapi_create_was_set = 1;
        }
    } else if(strcmp(arg1, "LSAPI_INTERNAL") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_lsapi_internal = ival;
            cfg->err_lsapi_internal_was_set = 1;
        }
    } else if(strcmp(arg1, "LSAPI_CONN_ACQUIRE") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_lsapi_conn_acquire = ival;
            cfg->err_lsapi_conn_acquire_was_set = 1;
        }
    } else if(strcmp(arg1, "LSAPI_CONN_DETERMINE") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_lsapi_conn_determine = ival;
            cfg->err_lsapi_conn_determine_was_set = 1;
        }
    } else if(strcmp(arg1, "BACKEND_NOHDRS") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_backend_nohdrs = ival;
            cfg->err_backend_nohdrs_was_set = 1;
        }
    } else if(strcmp(arg1, "BACKEND_ENDHDRS") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_backend_endhdrs = ival;
            cfg->err_backend_endhdrs_was_set = 1;
        }
    } else if(strcmp(arg1, "BACKEND_SENDREQ") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_backend_sendreq = ival;
            cfg->err_backend_sendreq_was_set = 1;
        }
    } else if(strcmp(arg1, "BACKEND_RECVHDR") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_backend_recvhdr = ival;
            cfg->err_backend_recvhdr_was_set = 1;
        }
    } else if(strcmp(arg1, "BACKEND_RECVRSP") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_backend_recvrsp = ival;
            cfg->err_backend_recvrsp_was_set = 1;
        }
    } else if(strcmp(arg1, "BACKEND_CONNECT") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_backend_connect = ival;
            cfg->err_backend_connect_was_set = 1;
        }
    } else if(strcmp(arg1, "CLIENT_SETUP") == 0) {
        ival = (uint32_t) apr_atoi64 (arg2);
        if(ival >= 400 && ival < 600) {
            cfg->err_client_setup = ival;
            cfg->err_client_setup_was_set = 1;
        }
    }
    return NULL;
}


static const char *lsapi_backend_coredump_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->backend_info.backend_coredump = ( strcasecmp(value, "on") == 0 );
    cfg->backend_info.backend_coredump_was_set = 1;
    return NULL;
}

static const char *lsapi_dump_debug_info_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->backend_info.dump_backend_debug_info = ( strcasecmp(value, "on") == 0 );
    cfg->backend_info.dump_backend_debug_info_was_set = 1;
    return NULL;
}

static const char *lsapi_use_suexec_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->backend_info.use_suexec = !( strcasecmp(value, "off") == 0 );
    cfg->backend_info.use_suexec_was_set = 1;
    return NULL;
}

static const char *lsapi_poll_timeout_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    uint32_t ival = (uint32_t) apr_atoi64 (value);
    if(ival > 0) {
        cfg->backend_info.poll_timeout = ival;
    }
    return NULL;
}

static const char *lsapi_mutex_mech_handler(cmd_parms *cmd, void *dummy, const char *value) {
#if !LSCAPI_WITH_MUTEX_API
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);

    if(!strcmp(value, "default")) {
        cfg->mutex_mech = APR_LOCK_DEFAULT;

    } else if(!strcmp(value, "fcntl")) {
#if APR_HAS_FCNTL_SERIALIZE
        cfg->mutex_mech = APR_LOCK_FCNTL;
#endif // APR_HAS_FCNTL_SERIALIZE

    } else if(!strcmp(value, "flock")) {
#if APR_HAS_FLOCK_SERIALIZE
        cfg->mutex_mech = APR_LOCK_FLOCK;
#endif // APR_HAS_FLOCK_SERIALIZE

    } else if(!strcmp(value, "posixsem")) {
#if APR_HAS_POSIXSEM_SERIALIZE
        cfg->mutex_mech = APR_LOCK_POSIXSEM;
#endif // APR_HAS_POSIXSEM_SERIALIZE

    } else if(!strcmp(value, "pthread")) {
#if APR_HAS_PROC_PTHREAD_SERIALIZE
        cfg->mutex_mech = APR_LOCK_PROC_PTHREAD;
#endif // APR_HAS_PROC_PTHREAD_SERIALIZE

    } else if(!strcmp(value, "sysvsem")) {
#if APR_HAS_SYSVSEM_SERIALIZE
        cfg->mutex_mech = APR_LOCK_SYSVSEM;
#endif // APR_HAS_SYSVSEM_SERIALIZE
    }

#endif //!LSCAPI_WITH_MUTEX_API
    return NULL;
}

static const char *lsapi_mod_php_behaviour_handler(cmd_parms *cmd, void* CFG, const char *arg1)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    cfg->mod_php_behaviour_off = ( strcasecmp(arg1, "off") == 0 );
    cfg->mod_php_behaviour_off_was_set = 1;

    return NULL;
}

static const char *lsapi_suphp_usergroup_handler(cmd_parms *cmd, void* CFG,
                                           const char *arg1, const char *arg2)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    uint32_t uid = ap_uname2id(arg1);
    uint32_t gid = ap_gname2id(arg2);

    if(uid > 0 && gid > 0) {
        cfg->suphp_uid = uid;
        cfg->suphp_gid = gid;
    }

    return NULL;
}


static const char *lsapi_ruidgid_handler(cmd_parms *cmd, void* CFG,
                                           const char *arg1, const char *arg2)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    uint32_t uid = ap_uname2id(arg1);
    uint32_t gid = ap_gname2id(arg2);

    if(uid > 0 && gid > 0) {
        cfg->ruid = uid;
        cfg->rgid = gid;
    }

    return NULL;
}

static const char *lsapi_assign_user_id(cmd_parms *cmd, void* CFG,
                                           const char *arg1, const char *arg2)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    uint32_t uid = ap_uname2id(arg1);
    uint32_t gid = ap_gname2id(arg2);

    if(uid > 0 && gid > 0) {
        cfg->itk_uid = uid;
        cfg->itk_gid = gid;
    }

    return NULL;
}


static const char *php_value_handler(cmd_parms *cmd, void *cfg,
                                    const char *name, const char *value) {
    return lscapi_php_value_handler(cmd, cfg, name, value, 0);
}

static const char *php_admin_value_handler(cmd_parms *cmd, void *cfg,
                                    const char *name, const char *value) {
    return lscapi_php_value_handler(cmd, cfg, name, value, 1);
}

static const char *php_flag_handler(cmd_parms *cmd, void *cfg,
                                    const char *name, const char *value) {
    return lscapi_php_flag_handler(cmd, cfg, name, value, 0);
}

static const char *php_admin_flag_handler(cmd_parms *cmd, void *cfg,
                                    const char *name, const char *value) {
    return lscapi_php_flag_handler(cmd, cfg, name, value, 1);
}

static const char *lsapi_use_perfcounters_handler(cmd_parms *cmd, void *dummy, const char *value) {
#ifdef WITH_LIBPERFLOG
    lsapi_use_perflog = ( strcasecmp(value, "on") == 0 );
    if(lsapi_use_perflog) lsapi_init_libperflog();
#endif
    return NULL;
}

static const char *lsapi_lsapipath (cmd_parms * cmd, void *CFG, const char *regexp_data)
{
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*)CFG;
    if (regexp_data)
    {
        int right_param = 1;
        ap_regex_t rx;

        // Compile regex. Error ?
        if (ap_regcomp (&rx, regexp_data, AP_REG_EXTENDED))
        {
            right_param = 0;
        } else {
            cfg->path_regex = regexp_data;
            ap_regfree (&rx);
        }

        if (!right_param)
        {
            return apr_psprintf (cmd->pool,
                                "Wrong regexp expression %s in parameter LSAPIPath",
                                regexp_data);
        }
    }
    return NULL;
}

static const char *lsapi_tmpdir_handler(cmd_parms *cmd, void *dummy, const char *value) {
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);

    cfg->tmpdir = apr_pstrdup(cmd->pool, value);
    return NULL;
}

static const char *lsapi_criu_handler(cmd_parms *cmd, void *dummy, const char *value) {
#ifdef WITH_CRIU
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->backend_info.use_criu = ( strcasecmp(value, "on") == 0 );
    cfg->backend_info.use_criu_was_set = 1;
#endif
    return NULL;
}

static const char *lsapi_criu_socket_path_handler(cmd_parms *cmd, void *dummy, const char *value) {
#ifdef WITH_CRIU
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->criu_socket_path = apr_pstrdup(cmd->pool, value);
#endif
    return NULL;
}

static const char *lsapi_criu_imgs_dir_path_handler(cmd_parms *cmd, void *dummy, const char *value) {
#ifdef WITH_CRIU
    lsapi_svr_conf_t *cfg = ap_get_module_config(cmd->server->module_config, &lsapi_module);
    cfg->criu_imgs_dir_path = apr_pstrdup(cmd->pool, value);
#endif
    return NULL;
}

static const char *fake_TAKE1_handler(cmd_parms *cmd, void *dummy, const char *args) {
    return NULL;
}

static const char *fake_FLAG_handler(cmd_parms *cmd, void *dummy, int arg) {
    return NULL;
}

static const char *fake_TAKE2_handler(cmd_parms * cmd, void *dummy,
                                       const char *arg1, const char *arg2)
{
    return NULL;
}

static const char *fake_TAKE3_handler(cmd_parms * cmd, void *dummy,
                                       const char *arg1, const char *arg2, const char *arg3)
{
    return NULL;
}

static const command_rec config_directives[] = {
    AP_INIT_TAKE2("php_value", php_value_handler, NULL, OR_OPTIONS, "PHP Value"),
    AP_INIT_TAKE2("php_admin_value", php_admin_value_handler, NULL, ACCESS_CONF|RSRC_CONF, "PHP Admin Value"),
    AP_INIT_TAKE2("php_flag", php_flag_handler, NULL, OR_OPTIONS, "PHP Flag"),
    AP_INIT_TAKE2("php_admin_flag", php_admin_flag_handler, NULL, ACCESS_CONF|RSRC_CONF, "PHP Admin Flag"),
    //AP_INIT_TAKE1("PHPINIDir", LSCAPI_PhpIniDirSetHandler, NULL, RSRC_CONF, "Directory with php.ini"),

    AP_INIT_TAKE1("lsapi_backend_connect_timeout", lsapi_backend_connect_timeout_handler, NULL, RSRC_CONF, "Backend connect timeout"),
    AP_INIT_TAKE1("lsapi_backend_connect_tries", lsapi_backend_connect_tries_handler, NULL, RSRC_CONF, "Backend connect try number"),
    AP_INIT_TAKE1("lsapi_backend_children", lsapi_backend_children_handler, NULL, RSRC_CONF, "LSAPI_CHILDREN"),
    AP_INIT_TAKE1("lsapi_backend_pgrp_max_idle", lsapi_backend_pgrp_max_idle_handler, NULL, RSRC_CONF, "LSAPI_PGRP_MAX_IDLE"),
    AP_INIT_TAKE1("lsapi_backend_max_idle", lsapi_backend_max_idle_handler, NULL, RSRC_CONF, "LSAPI_MAX_IDLE"),
    AP_INIT_TAKE1("lsapi_backend_max_process_time", lsapi_backend_max_process_time_handler, NULL, RSRC_CONF, "LSAPI_MAX_PROCESS_TIME"),
    AP_INIT_TAKE1("lsapi_backend_max_reqs", lsapi_backend_max_reqs_handler, NULL, RSRC_CONF, "LSAPI_MAX_REQS"),
    AP_INIT_TAKE1("lsapi_debug", lsapi_debug_handler, NULL, RSRC_CONF, "Extended Debug"),
    AP_INIT_TAKE1("lsapi_terminate_backends_on_exit", lsapi_terminate_backends_on_exit_handler, NULL, RSRC_CONF, "Terminate backends processes on server stop/restart"),
    AP_INIT_TAKE1("lsapi_socket_path", lsapi_socket_path_handler, NULL, RSRC_CONF, "Path for backend sockets"),

    AP_INIT_TAKE1("lsapi_phprc", lsapi_phprc_handler, NULL, RSRC_CONF, "PHPRC value"),
    AP_INIT_TAKE1("lsapi_target_perm", lsapi_target_perm_handler, NULL, RSRC_CONF, "Check or not owning of target script"),
    AP_INIT_TAKE1("lsapi_paranoid", lsapi_paranoid_handler, NULL, RSRC_CONF, "Check or not permissions of target script"),
    AP_INIT_TAKE1("lsapi_check_document_root", lsapi_check_document_root_handler, NULL, RSRC_CONF, "Check or not owner of DOCUMENT_ROOT"),
    AP_INIT_TAKE1("lsapi_use_default_uid", lsapi_use_default_uid_handler, NULL, RSRC_CONF, "Use or not apache uid/gid for request as fallback"),
    AP_INIT_TAKE2("lsapi_uid_gid", lsapi_uid_gid_handler, NULL, RSRC_CONF | ACCESS_CONF, "uid/gid for requests"),
    AP_INIT_TAKE2("lsapi_user_group", lsapi_user_group_handler, NULL, RSRC_CONF | ACCESS_CONF, "user/group for requests"),

    AP_INIT_TAKE1("lsapi_selfstarter", lsapi_selfstarter_handler, NULL, RSRC_CONF, "Backward compatibilty option. Ignored."),
    AP_INIT_TAKE1("lsapi_backend_coredump", lsapi_backend_coredump_handler, NULL, RSRC_CONF, "Backend core dump enabled or not"),
    AP_INIT_TAKE1("lsapi_dump_debug_info", lsapi_dump_debug_info_handler, NULL, RSRC_CONF, "Dump stacktrace and lsof before killing runaway backend"),
    AP_INIT_TAKE1("lsapi_use_suexec", lsapi_use_suexec_handler, NULL, RSRC_CONF, "Use or not suexec to target user"),
    AP_INIT_TAKE1("lsapi_poll_timeout", lsapi_poll_timeout_handler, NULL, RSRC_CONF, "Timeout to poll backend"),
    AP_INIT_TAKE1("lsapi_mutex_mech", lsapi_mutex_mech_handler, NULL, RSRC_CONF, "Mutex mechanism to use"),
    AP_INIT_TAKE1("lsapi_mod_php_behaviour", lsapi_mod_php_behaviour_handler, NULL, RSRC_CONF | ACCESS_CONF,
                  "Enable or disable php_* directive processing"),
    AP_INIT_TAKE1("lsapi_with_connection_pool", lsapi_with_connection_pool_handler, NULL, RSRC_CONF, "Use or not connection pool mode."),
    AP_INIT_TAKE1("lsapi_backend_accept_notify", lsapi_backend_accept_notify_handler, NULL, RSRC_CONF, "LSAPI_ACCEPT_NOTIFY mode for lsphp enabled or not"),
    AP_INIT_TAKE1("lsapi_resend_if_crashed", lsapi_resend_if_crashed_handler, NULL, RSRC_CONF | ACCESS_CONF,
                  "Whether to resend request when lsapi backend worker has occasionally crashed"),
    AP_INIT_TAKE1("lsapi_max_resend_buffer", lsapi_max_resend_buffer_handler, NULL, RSRC_CONF,
                  "Maximum buffer in KiB to resend for request that has a body (like POST request body)"),
    AP_INIT_TAKE1("lsapi_resend_if_method", lsapi_resend_if_method_handler, NULL, RSRC_CONF | ACCESS_CONF,
                  "Resend request works only for http methods in comma separated list"),
    AP_INIT_TAKE2("lsapi_set_env", lsapi_set_env_handler, NULL, RSRC_CONF, "To set variable in backend environment"),
    AP_INIT_TAKE1("lsapi_set_env_path", lsapi_set_env_path_handler, NULL, RSRC_CONF, "To set PATH in backend environment"),
    AP_INIT_TAKE1("lsapi_max_connection", lsapi_max_connection_handler, NULL, RSRC_CONF, "Max simultaneous connections to lsphp in pool"),
    AP_INIT_TAKE1("lsapi_backend_use_own_log", lsapi_backend_use_own_log_handler, NULL, RSRC_CONF, "Use own file or Apache error log file for backend output"),
#ifdef LSCAPI_WITH_DUMP_HEADER
    // Not documented
    AP_INIT_TAKE1("lsapi_hostname_on_debug", lsapi_hostname_on_debug_handler, NULL, RSRC_CONF, "Dump or not failed response header"),
#endif
#ifdef WITH_CRIU
    AP_INIT_TAKE1("lsapi_criu", lsapi_criu_handler, NULL, RSRC_CONF, "Use or not criu"),
    AP_INIT_TAKE1("lsapi_criu_socket_path", lsapi_criu_socket_path_handler, NULL, RSRC_CONF, "Path to criu service socket"),
    AP_INIT_TAKE1("lsapi_criu_imgs_dir_path", lsapi_criu_imgs_dir_path_handler, NULL, RSRC_CONF, "Path to directory for criu images"),
#else
    AP_INIT_TAKE1("lsapi_criu", lsapi_criu_handler, NULL, RSRC_CONF, "Ignored as module compiled without CRIU support"),
    AP_INIT_TAKE1("lsapi_criu_socket_path", lsapi_criu_socket_path_handler, NULL, RSRC_CONF, "Ignored as module compiled wthout CRIU support"),
    AP_INIT_TAKE1("lsapi_criu_imgs_dir_path", lsapi_criu_imgs_dir_path_handler, NULL, RSRC_CONF, "Ignored as module compiled wthout CRIU support"),
#endif
#ifdef WITH_LIBPERFLOG
    AP_INIT_TAKE1("lsapi_use_perfcounters", lsapi_use_perfcounters_handler, NULL, RSRC_CONF, "Use or not performance counters"),
#else //WITH_LIBPERFLOG
    AP_INIT_TAKE1("lsapi_use_perfcounters", lsapi_use_perfcounters_handler, NULL, RSRC_CONF, "Ignored as module compiled without LIBPERFLOG support"),
#endif //WITH_LIBPERFLOG
    AP_INIT_TAKE1("LSAPIPath", lsapi_lsapipath, NULL, RSRC_CONF, "Set template of path"),
    AP_INIT_TAKE1("lsapi_tmpdir", lsapi_tmpdir_handler, NULL, RSRC_CONF, "Set tmpdir to create temporary files per request body in"),
    AP_INIT_TAKE2("lsapi_error_code", lsapi_error_code_handler, NULL, RSRC_CONF | ACCESS_CONF,
                  "Error codes used in response to client"),

    /*
     * SU PHP param will be used too as fallback
     */
    AP_INIT_TAKE2("suPHP_UserGroup", lsapi_suphp_usergroup_handler, NULL, RSRC_CONF | ACCESS_CONF,
                  "User and group scripts shall be run as"),

    /*
     * RUidGid param will be used too as fallback
     */
	AP_INIT_TAKE2 ("RUidGid", lsapi_ruidgid_handler, NULL, RSRC_CONF | ACCESS_CONF,
                "ruid2: Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"),

    /*
     * AssignUserID param of itk module will be used too as fallback
     */
    AP_INIT_TAKE2("AssignUserID", lsapi_assign_user_id, NULL, RSRC_CONF|ACCESS_CONF,
                    "Tie a virtual host to a specific child process."),


    /*
     * Fake config directives to make fcgid-related configs compatible with mod_lsapi
     */
    AP_INIT_TAKE1("FcgidAccessChecker", fake_TAKE1_handler, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "fcgid fake: a absolute access checker file path"),
    AP_INIT_FLAG("FcgidAccessCheckerAuthoritative",
                 fake_FLAG_handler, NULL, ACCESS_CONF | OR_FILEINFO,
                 "fcgid fake: Set to 'off' to allow access control to be passed along to lower modules upon failure"),
    AP_INIT_TAKE1("FcgidAuthenticator", fake_TAKE1_handler, NULL,
                  ACCESS_CONF | OR_FILEINFO, "fcgid fake: a absolute authenticator file path"),
    AP_INIT_FLAG("FcgidAuthenticatorAuthoritative",
                 fake_FLAG_handler, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "fcgid fake: Set to 'off' to allow authentication to be passed along to lower modules upon failure"),
    AP_INIT_TAKE1("FcgidAuthorizer", fake_TAKE1_handler, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "fcgid fake: a absolute authorizer file path"),
    AP_INIT_FLAG("FcgidAuthorizerAuthoritative",
                 fake_FLAG_handler, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "fcgid fake: Set to 'off' to allow authorization to be passed along to lower modules upon failure"),
    AP_INIT_TAKE1("FcgidBusyScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: scan interval for busy timeout process"),
    AP_INIT_TAKE1("FcgidBusyTimeout", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: a fastcgi application will be killed after handling a request for BusyTimeout"),
    AP_INIT_RAW_ARGS("FcgidCmdOptions", fake_TAKE1_handler, NULL, RSRC_CONF,
                     "set processing options for a FastCGI command"),
    AP_INIT_TAKE12("FcgidInitialEnv", fake_TAKE2_handler, NULL, RSRC_CONF,
                   "fcgid fake: an environment variable name and optional value to pass to FastCGI."),
    AP_INIT_TAKE1("FcgidMaxProcessesPerClass",
                  fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Max process count of one class of fastcgi application"),
    AP_INIT_TAKE1("FcgidMinProcessesPerClass",
                  fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Min process count of one class of fastcgi application"),
    AP_INIT_TAKE1("FcgidErrorScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: scan interval for exited process"),
    AP_INIT_TAKE1("FcgidIdleScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: scan interval for idle timeout process"),
    AP_INIT_TAKE1("FcgidIdleTimeout", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: an idle fastcgi application will be killed after IdleTimeout"),
    AP_INIT_TAKE1("FcgidIOTimeout", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Communication timeout to fastcgi server"),
    AP_INIT_TAKE1("FcgidConnectTimeout", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Connect timeout to fastcgi server"),
    AP_INIT_TAKE1("FcgidMaxProcesses", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Max total process count"),
    AP_INIT_TAKE1("FcgidMaxRequestInMem", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: The part of HTTP request which greater than this limit will swap to disk"),
    AP_INIT_TAKE1("FcgidMaxRequestLen", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Max HTTP request length in byte"),
    AP_INIT_TAKE1("FcgidMaxRequestsPerProcess", fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Max requests handled by each fastcgi application"),
    AP_INIT_TAKE1("FcgidOutputBufferSize", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: CGI output buffer size"),
    AP_INIT_TAKE1("FcgidPassHeader", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Header name which will be passed to FastCGI as environment variable."),
    AP_INIT_TAKE1("FcgidFixPathinfo",
                  fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Set 1, if cgi.fix_pathinfo=1 in php.ini"),
    AP_INIT_TAKE1("FcgidProcessLifeTime", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: fastcgi application lifetime"),
    AP_INIT_TAKE1("FcgidProcessTableFile", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: fastcgi shared memory file path"),
    AP_INIT_TAKE1("FcgidIPCDir", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: fastcgi socket file path"),
    AP_INIT_TAKE1("FcgidSpawnScore", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Score of spawn"),
    AP_INIT_TAKE1("FcgidSpawnScoreUpLimit", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Spawn score up limit"),
    AP_INIT_TAKE1("FcgidTerminationScore", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Score of termination"),
    AP_INIT_TAKE1("FcgidTimeScore", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Score of passage of time (in seconds)"),
    AP_INIT_TAKE123("FcgidWrapper", fake_TAKE3_handler, NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "fcgid fake: The CGI wrapper file an optional URL suffix and an optional flag"),
    AP_INIT_TAKE1("FcgidZombieScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: scan interval for zombie process"),
    /*
     * Fake of deprecated fcgid config directives.
     */
    AP_INIT_TAKE1("BusyScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidBusyScanInterval' instead"),
    AP_INIT_TAKE1("BusyTimeout", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidBusyTimeout' instead"),
    AP_INIT_TAKE12("DefaultInitEnv", fake_TAKE2_handler, NULL, RSRC_CONF,
                   "fcgid fake: Deprecated - Use 'FcgidInitialEnv' instead"),
    AP_INIT_TAKE1("DefaultMaxClassProcessCount",
                  fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidMaxProcessesPerClass' instead"),
    AP_INIT_TAKE1("DefaultMinClassProcessCount",
                  fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidMinProcessesPerClass' instead"),
    AP_INIT_TAKE1("ErrorScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidErrorScanInterval' instead"),
    AP_INIT_TAKE1("FastCgiAccessChecker", fake_TAKE1_handler, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "fcgid fake: Deprecated - Use 'FcgidAccessChecker' instead"),
    AP_INIT_FLAG("FastCgiAccessCheckerAuthoritative",
                 fake_FLAG_handler, NULL, ACCESS_CONF | OR_FILEINFO,
                 "fcgid fake: Deprecated - Use 'FcgidAccessCheckerAuthoritative' instead"),
    AP_INIT_TAKE1("FastCgiAuthenticator", fake_TAKE1_handler, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "fcgid fake: Deprecated - Use 'FcgidAuthenticator' instead"),
    AP_INIT_FLAG("FastCgiAuthenticatorAuthoritative",
                 fake_FLAG_handler, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "fcgid fake: Deprecated - Use 'FcgidAuthenticatorAuthoritative' instead"),
    AP_INIT_TAKE1("FastCgiAuthorizer", fake_TAKE1_handler, NULL,
                  ACCESS_CONF | OR_FILEINFO,
                  "fcgid fake: Deprecated - Use 'FcgidAuthorizer' instead"),
    AP_INIT_FLAG("FastCgiAuthorizerAuthoritative",
                 fake_FLAG_handler, NULL,
                 ACCESS_CONF | OR_FILEINFO,
                 "fcgid fake: Deprecated - Use 'FcgidAuthorizerAuthoritative' instead"),
    AP_INIT_TAKE123("FCGIWrapper", fake_TAKE3_handler, NULL,
                    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
                    "fcgid fake: Deprecated - Use 'FcgidWrapper' instead"),
    AP_INIT_TAKE1("IdleScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidIdleScanInterval' instead"),
    AP_INIT_TAKE1("IdleTimeout", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidIdleTimeout' instead"),
    AP_INIT_TAKE1("IPCCommTimeout", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidIOTimeout' instead"),
    AP_INIT_TAKE1("IPCConnectTimeout", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidConnectTimeout' instead"),
    AP_INIT_TAKE1("MaxProcessCount", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidMaxProcesses' instead"),
    AP_INIT_TAKE1("MaxRequestInMem", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidMaxRequestInMem' instead"),
    AP_INIT_TAKE1("MaxRequestLen", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidMaxRequestLen' instead"),
    AP_INIT_TAKE1("MaxRequestsPerProcess", fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidMaxRequestsPerProcess' instead"),
    AP_INIT_TAKE1("OutputBufferSize", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidOutputBufferSize' instead"),
    AP_INIT_TAKE1("PassHeader", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidPassHeader' instead"),
    AP_INIT_TAKE1("PHP_Fix_Pathinfo_Enable",
                  fake_TAKE1_handler,
                  NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidFixPathinfo' instead"),
    AP_INIT_TAKE1("ProcessLifeTime", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidProcessLifeTime' instead"),
    AP_INIT_TAKE1("SharememPath", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidProcessTableFile' instead"),
    AP_INIT_TAKE1("SocketPath", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidIPCDir' instead"),
    AP_INIT_TAKE1("SpawnScore", fake_TAKE1_handler, NULL, RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidSpawnScore' instead"),
    AP_INIT_TAKE1("SpawnScoreUpLimit", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidSpawnScoreUpLimit' instead"),
    AP_INIT_TAKE1("TerminationScore", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidTerminationScore' instead"),
    AP_INIT_TAKE1("TimeScore", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidTimeScore' instead"),
    AP_INIT_TAKE1("ZombieScanInterval", fake_TAKE1_handler, NULL,
                  RSRC_CONF,
                  "fcgid fake: Deprecated - Use 'FcgidZombieScanInterval' instead"),

    /*
     * Fake config directives to make suphp configs compatible with mod_lsapi
     */
    AP_INIT_FLAG("suPHP_Engine", fake_FLAG_handler, NULL, RSRC_CONF | ACCESS_CONF,
                 "suPHP fake: Whether suPHP is on or off, default is off"),
    AP_INIT_TAKE1("suPHP_ConfigPath", fake_TAKE1_handler, NULL, OR_OPTIONS,
                  "suPHP fake: Wheres the php.ini resides, default is the PHP default"),
    AP_INIT_ITERATE("suPHP_AddHandler", fake_TAKE1_handler, NULL, RSRC_CONF | ACCESS_CONF, "suPHP fake: Tells mod_suphp to handle these MIME-types"),
    AP_INIT_ITERATE("suPHP_RemoveHandler", fake_TAKE1_handler, NULL, RSRC_CONF | ACCESS_CONF, "suPHP fake: Tells mod_suphp not to handle these MIME-types"),
    AP_INIT_TAKE1("suPHP_PHPPath", fake_TAKE1_handler, NULL, RSRC_CONF, "suPHP fake: Path to the PHP binary used to render source view"),

    /*
     * Fake config directives to make ruid2 configs compatible with mod_lsapi
     */
	AP_INIT_TAKE1 ("RMode", fake_TAKE1_handler, NULL, RSRC_CONF | ACCESS_CONF, "ruid2 fake: Set mode to config or stat (default: config)"),
	AP_INIT_ITERATE ("RGroups", fake_TAKE1_handler, NULL, RSRC_CONF | ACCESS_CONF, "ruid2 fake: Set additional groups"),
	AP_INIT_TAKE2 ("RDefaultUidGid", fake_TAKE2_handler, NULL, RSRC_CONF, "ruid2 fake: If uid or gid is < than RMinUidGid set[ug]id to this uid gid"),
	AP_INIT_TAKE2 ("RMinUidGid", fake_TAKE2_handler, NULL, RSRC_CONF, "ruid2 fake: Minimal uid or gid file/dir, else set[ug]id to default (RDefaultUidGid)"),
	AP_INIT_TAKE2 ("RDocumentChRoot", fake_TAKE2_handler, NULL, RSRC_CONF, "ruid2 fake: Set chroot directory and the document root inside"),

    {NULL}
};

module AP_MODULE_DECLARE_DATA lsapi_module = {
    STANDARD20_MODULE_STUFF,
    lscapi_create_dir_config,     /* create per-directory config structure */
    lscapi_merge_dir_config,      /* merge per-directory config structures */
    lscapi_create_svr_config,     /* create per-server config structure */
    lscapi_merge_svr_config,      /* merge per-server config structures */
    config_directives,            /* command apr_table_t */
    register_hooks                /* register hooks */
};
