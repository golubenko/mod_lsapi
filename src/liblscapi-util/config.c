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

#include <unistd.h>

#include <mod_core.h>

#include <apr_strings.h>

#ifdef WITH_LIBPERFLOG
int lsapi_use_perflog;
#endif


#define MOD_LSAPI_RESEND_IF_METHOD_DEFAULT "GET,OPTIONS,HEAD,CONNECT,PROPFIND"

const char* lscapi_php_value_handler(cmd_parms* cmd, void *cfg,
                                    const char *name, const char *value,
                                    int isAdmin) {
    php_param_t *eptr = apr_palloc(cmd->pool, sizeof(php_param_t));

    if(!strncasecmp(value, "none", 4)) {
        value = "";
    }

    eptr->valueLen = strlen(value);
    eptr->value = apr_pmemdup(cmd->pool, value, eptr->valueLen+1);
    eptr->isAdmin = isAdmin;
	eptr->htaccess = ((cmd->override & (RSRC_CONF|ACCESS_CONF)) == 0);

	//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, LSCAPI_APLOGNO
    //             "LSCAPI_PhpValueHandler: (%s)->(%s) isAdmin:%d", name, eptr->value, eptr->isAdmin);
    apr_hash_t* phpParams = ((lsapi_dir_conf_t*)cfg)->phpParams;

    apr_hash_set(phpParams, name, APR_HASH_KEY_STRING, eptr);

    return NULL;
}

const char *lscapi_php_flag_handler(cmd_parms *cmd, void *cfg,
                                    const char *name, const char *value, int isAdmin) {
    char boolVal[2];

    boolVal[0] = ( (strcasecmp(value, "On") == 0) || (value[0] == '1' && value[1] == '\0')) ? '1' : '0';
	boolVal[1] = '\0';
    return lscapi_php_value_handler(cmd, cfg, name, boolVal, isAdmin);
}

static void init_err_config(lsapi_dir_conf_t *cfg)
{
    cfg->err_server_docroot = HTTP_INTERNAL_SERVER_ERROR;
    cfg->err_server_uid = HTTP_INTERNAL_SERVER_ERROR;
    cfg->err_script_perms = HTTP_INTERNAL_SERVER_ERROR;

    cfg->err_lsapi_create = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_lsapi_internal = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_lsapi_conn_acquire = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_lsapi_conn_determine = HTTP_SERVICE_UNAVAILABLE;
    
    cfg->err_backend_nohdrs = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_backend_endhdrs = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_backend_sendreq = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_backend_recvhdr = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_backend_recvrsp = HTTP_SERVICE_UNAVAILABLE;
    cfg->err_backend_connect = HTTP_SERVICE_UNAVAILABLE;
    
    cfg->err_client_setup = HTTP_BAD_REQUEST;

}

void *lscapi_create_dir_config(apr_pool_t *pool, char *x) {
    lsapi_dir_conf_t *cfg = apr_pcalloc(pool, sizeof(lsapi_dir_conf_t));
    cfg->phpParams = apr_hash_make(pool);
    cfg->resend_if_method = lscapi_parse_cfg_resend_if_method(MOD_LSAPI_RESEND_IF_METHOD_DEFAULT,
                                                              pool);
    cfg->dir_accept_notify = 1;
    cfg->resend_if_crashed = 2;
    init_err_config(cfg);
    return cfg;
}

static apr_hash_t* merge_php_params(apr_pool_t *pool, apr_hash_t *baseH, apr_hash_t *curH)
{
    // initially lets create new config as a copy of the base one
    apr_hash_t *newH = apr_hash_copy(pool, baseH);

    // iterate over current config to check its values against values of the base config
    apr_hash_index_t *hi = NULL;
    for(hi = apr_hash_first(pool, curH); hi; hi = apr_hash_next(hi)) {
        const char *key;
        apr_ssize_t keyLen;
        php_param_t *curVal;
        apr_hash_this(hi, (const void**)(&key), &keyLen, (void**)(&curVal));

        if(curVal->isAdmin) { // new admin value will beat even old admin one
            apr_hash_set(newH, key, keyLen, curVal);
            continue;
        }

        php_param_t *baseVal = apr_hash_get(baseH, key, keyLen);
        if(!baseVal                  // there is no such key in the base config
           || !baseVal->isAdmin)  {  // old value is not admin so new one will beat it

            apr_hash_set(newH, key, keyLen, curVal);
        }

    } // for
    
    return newH;
}

#define __LSAPI_MERGE_ERR_CONFIG(nm) do { \
    if(cur->nm##_was_set) { \
        cfg->nm = cur->nm; \
        cfg->nm##_was_set = 1; \
    } else { \
        cfg->nm = base->nm; \
    } \
} while(0)

static void merge_err_config(lsapi_dir_conf_t *cfg, lsapi_dir_conf_t *cur, lsapi_dir_conf_t *base)
{
    __LSAPI_MERGE_ERR_CONFIG(err_server_docroot);
    __LSAPI_MERGE_ERR_CONFIG(err_server_uid);
    __LSAPI_MERGE_ERR_CONFIG(err_script_perms);

    __LSAPI_MERGE_ERR_CONFIG(err_lsapi_create);
    __LSAPI_MERGE_ERR_CONFIG(err_lsapi_internal);
    __LSAPI_MERGE_ERR_CONFIG(err_lsapi_conn_acquire);
    __LSAPI_MERGE_ERR_CONFIG(err_lsapi_conn_determine);
    
    __LSAPI_MERGE_ERR_CONFIG(err_backend_nohdrs);
    __LSAPI_MERGE_ERR_CONFIG(err_backend_endhdrs);
    __LSAPI_MERGE_ERR_CONFIG(err_backend_sendreq);
    __LSAPI_MERGE_ERR_CONFIG(err_backend_recvhdr);
    __LSAPI_MERGE_ERR_CONFIG(err_backend_recvrsp);
    __LSAPI_MERGE_ERR_CONFIG(err_backend_connect);
    
    __LSAPI_MERGE_ERR_CONFIG(err_client_setup);
}

#undef __LSAPI_MERGE_ERR_CONFIG

#define __LSAPI_MERGE_DIR_CONFIG(nm) do { \
    if(cur->nm##_was_set) { \
        cfg->nm = cur->nm; \
        cfg->nm##_was_set = 1; \
    } else { \
        cfg->nm = base->nm; \
    } \
} while(0)

void *lscapi_merge_dir_config(apr_pool_t *pool, void *BASE, void *CUR) {
    lsapi_dir_conf_t *base = BASE;
    lsapi_dir_conf_t *cur = CUR;

    lsapi_dir_conf_t *cfg = apr_pcalloc(pool, sizeof(lsapi_dir_conf_t));

    cfg->phpParams = merge_php_params(pool, base->phpParams, cur->phpParams);

    if(cur->lsapi_uid > 0) {
        cfg->lsapi_uid = cur->lsapi_uid;
        cfg->lsapi_gid = cur->lsapi_gid;
    } else if(base->lsapi_uid > 0) {
        cfg->lsapi_uid = base->lsapi_uid;
        cfg->lsapi_gid = base->lsapi_gid;
    }

    if(cur->suphp_uid > 0) {
        cfg->suphp_uid = cur->suphp_uid;
        cfg->suphp_gid = cur->suphp_gid;
    } else if(base->suphp_uid > 0) {
        cfg->suphp_uid = base->suphp_uid;
        cfg->suphp_gid = base->suphp_gid;
    }

    if(cur->ruid > 0) {
        cfg->ruid = cur->ruid;
        cfg->rgid = cur->rgid;
    } else if(base->ruid > 0) {
        cfg->ruid = base->ruid;
        cfg->rgid = base->rgid;
    }

    if(cur->itk_uid > 0) {
        cfg->itk_uid = cur->itk_uid;
        cfg->itk_gid = cur->itk_gid;
    } else  if(base->itk_uid > 0) {
        cfg->itk_uid = base->itk_uid;
        cfg->itk_gid = base->itk_gid;
    }

    __LSAPI_MERGE_DIR_CONFIG(resend_if_crashed);
    __LSAPI_MERGE_DIR_CONFIG(dir_accept_notify);
    __LSAPI_MERGE_DIR_CONFIG(engine_off);
    __LSAPI_MERGE_DIR_CONFIG(measure_time);
    __LSAPI_MERGE_DIR_CONFIG(mod_php_behaviour_off);
    __LSAPI_MERGE_DIR_CONFIG(resend_if_method);

    cfg->path_regex = cur->path_regex ? cur->path_regex : base->path_regex;

    merge_err_config(cfg, cur, base);

    return cfg;
}

#undef __LSAPI_MERGE_DIR_CONFIG

char* lscapi_make_fname_in_logdir(server_rec *s, apr_pool_t *pool, const char *fname) {
    if(!s->error_fname || s->error_fname[0] == '|' || !strcmp(s->error_fname, "syslog") ) {
        return ap_server_root_relative(pool, fname);
    } else {
        char *relname = apr_pstrcat(pool, ap_make_dirstr_parent(pool, s->error_fname),
                                    fname, NULL);
        return ap_server_root_relative(pool, relname);
    }
}

void *lscapi_create_svr_config(apr_pool_t *pool, server_rec *s) {
    //ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
    //             "entering lsapi_create_svr_config: is_virtual: %s; defn_name:(%s)", 
    //             s->is_virtual?"YES":"NO", s->defn_name);

    lsapi_svr_conf_t *cfg = apr_pcalloc(pool, sizeof(lsapi_svr_conf_t));
#if MODULE_MAGIC_NUMBER_MAJOR > 20081212
    cfg->default_uid = ap_unixd_config.user_id;
    cfg->default_gid = ap_unixd_config.group_id;
#else
    cfg->default_uid = unixd_config.user_id;
    cfg->default_gid = unixd_config.group_id;
#endif
    cfg->terminate_backends_on_exit = 1;
    cfg->use_default_uid = 1;
    cfg->skip_check_document_root = 1;

    lscapi_init_backend_info(&cfg->backend_info);
    cfg->envTable = apr_table_make(pool, 5);

    if (!s->is_virtual) {
        cfg->selfstarter_socket_path = lscapi_make_fname_in_logdir(s, pool, "lsapisock");
    }

#if !LSCAPI_WITH_MUTEX_API
#if APR_HAS_POSIXSEM_SERIALIZE
    cfg->mutex_mech = APR_LOCK_POSIXSEM;
#else
    cfg->mutex_mech = APR_LOCK_DEFAULT;
#endif // APR_HAS_POSIXSEM_SERIALIZE
#endif // !LSCAPI_WITH_MUTEX_API

    return cfg;
}


/*
static void dump_table(const char *prefix, apr_table_t *tbl)
{
    const apr_array_header_t *arr = apr_table_elts(tbl);
    const apr_table_entry_t *elt = (apr_table_entry_t *)arr->elts;
    fprintf(stderr, "%s: table %p has %d values\n", prefix, tbl, arr->nelts);

    int i;
    for (i = 0; i < arr->nelts; ++i) {
        fprintf(stderr,
                "%s %d/%d: (%s)->(%s)\n", prefix, i, arr->nelts, elt[i].key, elt[i].val);
    }

}
*/

static apr_table_t* merge_env_tables(apr_pool_t *pool, apr_table_t *baseT, apr_table_t *curT)
{
    // initially lets create new config as a copy of the base one
    apr_table_t *newT = apr_table_copy(pool, baseT);
    apr_table_overlap(newT, curT, APR_OVERLAP_TABLES_SET);
    return newT;
}

#define __LSAPI_MERGE_SVR_CONFIG(nm) do { \
    if(cur->nm##_was_set) { \
        cfg->nm = cur->nm; \
        cfg->nm##_was_set = 1; \
    } else { \
        cfg->nm = base->nm; \
    } \
} while(0)


void *lscapi_merge_svr_config(apr_pool_t *pool, void *BASE, void *CUR) {
    lsapi_svr_conf_t *base = BASE;
    lsapi_svr_conf_t *cur = CUR;

    lsapi_svr_conf_t *cfg = apr_pcalloc(pool, sizeof(lsapi_svr_conf_t));
    cfg->default_uid = cur->default_uid;
    cfg->default_gid = cur->default_gid;

    cfg->socket_path = cur->socket_path ?
                            cur->socket_path : base->socket_path;

    __LSAPI_MERGE_SVR_CONFIG(terminate_backends_on_exit);
    __LSAPI_MERGE_SVR_CONFIG(debug_enabled);
    __LSAPI_MERGE_SVR_CONFIG(check_target_perm);
    __LSAPI_MERGE_SVR_CONFIG(paranoid);
    __LSAPI_MERGE_SVR_CONFIG(use_default_uid);
    __LSAPI_MERGE_SVR_CONFIG(skip_check_document_root);
    cfg->hostname_on_debug = cur->hostname_on_debug ?
                                cur->hostname_on_debug : base->hostname_on_debug;

    cfg->tmpdir = cur->tmpdir ?
                  cur->tmpdir : base->tmpdir;

    if(cur->phprc_source_was_set) {
        cfg->phprc = cur->phprc;
        cfg->phprc_source = cur->phprc_source;
        cfg->phprc_source_was_set = 1;
    } else {
        cfg->phprc = base->phprc;
        cfg->phprc_source = base->phprc_source;
    }

    cfg->selfstarter_socket_path = cur->selfstarter_socket_path ?
                        cur->selfstarter_socket_path : base->selfstarter_socket_path;

    lscapi_merge_backend_info(&base->backend_info, &cur->backend_info, &cfg->backend_info);
    cfg->envTable = merge_env_tables(pool, base->envTable, cur->envTable);

    return cfg;
}

#undef __LSAPI_MERGE_SVR_CONFIG


apr_hash_t *lscapi_parse_cfg_resend_if_method(const char *value, apr_pool_t *pool)
{
    // "is present" flag, to differentiate from NULL
    // NULL will be returned by apr_hash_get() for non-existing key
    void *const is_present_flag = (void*)(-1);

    apr_hash_t *ht = apr_hash_make(pool);
    if (ht != NULL)
    {
        const char *this = value, *next = strchr(value, ',');
        while(1)
        {
            size_t len = next? (next - this) : strlen(this);
            apr_hash_set(ht, this, len, is_present_flag);

            if (!next)
                break;
            this = next + 1;
            next = strchr(this, ',');
        }
    }

    return ht;
}
