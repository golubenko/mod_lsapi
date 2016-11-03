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

struct lscapi_server_vars_t {
    request_rec *r;
    int varNum;
    int maxVarNum;
    lscapi_var_t *vars;
};

#define LSCAPI_INC_SERVER_VAR_NUM 500


static int processServerVar(struct lscapi_server_vars_t *vars, const char *key, const char *value) {
    //assert(vars->varNum <= vars->maxVarNum);
    if(vars->varNum == vars->maxVarNum) {
        size_t new_size = vars->maxVarNum + LSCAPI_INC_SERVER_VAR_NUM;
        lscapi_var_t *new_vars = apr_palloc(vars->r->pool, sizeof(lscapi_var_t) * new_size);
        memcpy(new_vars, vars->vars, sizeof(lscapi_var_t) * vars->maxVarNum );
        vars->maxVarNum = new_size;
        vars->vars = new_vars;
    }
    
    if(!key) {
        return 1;
    }

    if(strncmp(key, "LD_", 3) == 0) {
        return 1;
    }


    /*
     MODLS-231
     https://httpoxy.org 
     https://www.apache.org/security/asf-httpoxy-response.txt
    */
    if(strcmp(key, "HTTP_PROXY") == 0) {
        return 1;
    }
    if(strcmp(key, "HTTP_PROXY_AUTHORIZATION") == 0) {
        return 1;
    }
    if(strcmp(key, "HTTP_AUTHORIZATION") == 0) {
        return 1;
    }

    const char *v;
    if(strcmp(key, "PATH") == 0) {
        lsapi_svr_conf_t *cfg = lsapi_get_svr_config(vars->r->server);
        v = cfg->backend_env_path ? cfg->backend_env_path : SULSPHP_SAFE_PATH;
    } else {
        v = value;
    }

    lscapi_var_t *curVar = vars->vars + vars->varNum++;
    curVar->key = key;
    curVar->keyLen = strlen(key);
    curVar->val = v ? v : "";
    curVar->valLen = v ? strlen(v) : 0;

    return 1;
}

int lscapi_parse_server_vars(request_rec *r, lscapi_var_t **varsPtr) 
{
    lscapi_var_t *vars = apr_palloc(r->pool, sizeof(lscapi_var_t) * LSCAPI_INC_SERVER_VAR_NUM);
    struct lscapi_server_vars_t serverVars;
    serverVars.r = r;
    serverVars.maxVarNum = LSCAPI_INC_SERVER_VAR_NUM;
    serverVars.varNum = 0;
    serverVars.vars = vars;

    apr_table_do((apr_table_do_callback_fn_t*)processServerVar, &serverVars, r->subprocess_env, NULL);

    *varsPtr = vars;
    return serverVars.varNum;

}

int lscapi_parse_special_vars(request_rec *r, apr_hash_t *cfgH, lscapi_var_t **varsPtr) 
{
    int envNum = apr_hash_count(cfgH);
    lscapi_var_t *envs = apr_palloc(r->pool, sizeof(lscapi_var_t) * (envNum ? envNum : 1) );
    
    int i = 0;
    apr_hash_index_t *hi = NULL;
    for(hi = apr_hash_first(r->pool, cfgH);
        hi && i < envNum;
        hi = apr_hash_next(hi)) {

        const char *key;
        apr_ssize_t keyLen;
        php_param_t *val;
        apr_hash_this(hi, (const void**)(&key), &keyLen, (void**)(&val));

        if(!keyLen && !val->valueLen)
            continue;

        envs[i].key = key;
        envs[i].keyLen = keyLen;
        envs[i].val = val->value;
        envs[i].valLen = val->valueLen;
        envs[i].perdir = val->htaccess;

        i++;
    } // for
    *varsPtr = envs;
    return i;
}
