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

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdarg.h>
#include <unistd.h>

#include <http_request.h>
#include <util_script.h>
#include <mpm_common.h>

#ifdef APACHE2_2
#define ap_log_rerror_ ap_log_rerror
#endif

// For getpwuid_r used few times here
#define PWBUF_SIZE 2048

const int *lsapilog_module_index;

static void* alloc_by_request(size_t sz, void *user_data)
{
    return apr_palloc(((request_rec*)user_data)->pool, sz);
}

static const char get_request_body_key[] = "mod_lsapi-get_client_block-status";

static long get_request_body(char *buf, size_t bufLen, void *user_data )
{
    request_rec *r = (request_rec*)user_data;

    if(apr_table_get(r->notes, get_request_body_key)) {
        return 0;
    }

    //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "get_request_body(%lu) is called", *bufLenPtr);
    long readlen = ap_get_client_block(r, buf, bufLen);
    if(readlen < 0) {
        lscapi_rlog(LOG_ERR, 0, r, "get_client_block(%" APR_SIZE_T_FMT ") failed", bufLen);
        apr_table_set(r->notes, get_request_body_key, "failed");
    }
    //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "get_request_body(%lu): get_client_block read %lu", *bufLenPtr, readlen);
    else if(readlen == 0) {
        apr_table_set(r->notes, get_request_body_key, "eof");
    }
    return readlen;
}


void lscapi_log_error(const char *file, int line, int level, apr_status_t status,
                        const server_rec *s, const char *fmt, ...)
{
    char buf[8192];
    va_list args;

#ifndef APACHE2_2
    if (!APLOG_MODULE_IS_LEVEL(s,
                                 (lsapilog_module_index ? *lsapilog_module_index : APLOG_NO_MODULE),
                                 level))
    {
        return;
    }
#endif
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);

#ifdef APACHE2_2
    ap_log_error(file, line,
                    level, status, s, "[host %s] %s", s->server_hostname, buf);
#else
    ap_log_error_(file, line, (lsapilog_module_index ? *lsapilog_module_index : APLOG_NO_MODULE),
                    level, status, s, "[host %s] %s", s->server_hostname, buf);
#endif // APACHE2_2
    va_end(args);
}

void lscapi_log_rerror(const char *file, int line, int level,
                       apr_status_t status,
                        const request_rec *r, const char *fmt, ...)

{
    char buf[8192];
    va_list args;

#ifndef APACHE2_2
    if (!APLOG_R_MODULE_IS_LEVEL(r,
                                 (lsapilog_module_index ? *lsapilog_module_index : APLOG_NO_MODULE),
                                 level))
    {
        return;
    }
#endif
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);

#ifdef APACHE2_2
    ap_log_rerror(file, line,
                    level, status, r, "[host %s] %s", r->hostname, buf);
#else
    ap_log_rerror_(file, line, (lsapilog_module_index ? *lsapilog_module_index : APLOG_NO_MODULE),
                    level, status, r, "[host %s] %s", r->hostname, buf);
#endif // APACHE2_2
    va_end(args);
}

static void try_create_default_socket_dir(void) {
    struct stat dir_info;

    if(stat(LSCAPI_DEFAULT_SOCKET_PATH, &dir_info) != 0) {
            
        if(errno == ENOENT) {
            if(mkdir(LSCAPI_DEFAULT_SOCKET_PATH, 0755) != 0)
                return;
        } else {
            return;
        }
    
    } else { // if(stat(LSCAPI_DEFAULT_SOCKET_PATH, &dir_info) != 0)
    
        if(!S_ISDIR(dir_info.st_mode)) {
            return;
        }
    
    } // else of if(stat(LSCAPI_DEFAULT_SOCKET_PATH, &dir_info) != 0)

    uid_t uid;
    gid_t gid;

#if MODULE_MAGIC_NUMBER_MAJOR > 20081212
    uid = ap_unixd_config.user_id;
    gid = ap_unixd_config.group_id;
#else
    uid = unixd_config.user_id;
    gid = unixd_config.group_id;
#endif

   if(uid <= 0) { // use default user if unixd info is unreliable
      struct passwd *pw = getpwnam(SULSPHP_HTTPD_USER);
      if(pw) {
          uid = pw->pw_uid;
          gid = pw->pw_gid;
      }
   }
   chown(LSCAPI_DEFAULT_SOCKET_PATH, uid, gid);
}

static uint8_t global_salt[LSCAPI_SALT_SIZE];

int lscapi_util_init(char *errbuf, size_t errlen)
{
#ifdef APACHE2_2
    apr_generate_random_bytes(global_salt, sizeof global_salt);
#else
    ap_random_insecure_bytes(global_salt, sizeof global_salt);
#endif

    try_create_default_socket_dir();
    
    return 0;
}


/*
apr_status_t lscapi_util_child_init(apr_pool_t *configpool, server_rec *s)
{
    //allocate hash uid/gid to socket name
    // register cleaner

    return APR_SUCCESS;
}
*/

/* in order to have random socket names */
#ifndef LSCAPI_WITH_RANDOM_SOCKET_NAMES
#define LSCAPI_WITH_RANDOM_SOCKET_NAMES
#endif


/*
#ifdef LSCAPI_WITH_RANDOM_SOCKET_NAMES
static int lscapi_get_socket_suffix(lscapi_rec *lscapi, uint32_t uid, uint32_t gid,
                                        request_rec *r, lsapi_svr_conf_t *svrcfg,
                                        char *_buf, size_t bufLen) {

    if(svrcfg->terminate_backends_on_exit) {

        if(bufLen < LSCAPI_ENCODED_SHA1_SIGN_WITHOUT_SALT_SIZE) {
            return -1;
        }

        uint32_t uidgid[2];
        uidgid[0] = uid;
        uidgid[1] = gid;
        uint8_t sign[LSCAPI_SHA1_SIGN_SIZE];

        lscapi_sign_uidgid_sha1(lscapi, uidgid, global_salt, sign);
        lscapi_encode_sha1_sign_without_salt(sign, _buf);

    } else { // if(svrcfg->terminate_backends_on_exit)

        char uidbuf[64];
        snprintf(uidbuf, sizeof uidbuf, "%u", uid);
        size_t uidLen = strlen(uidbuf);

        size_t len = strlen(r->handler);

        if(len + uidLen + 2 > bufLen) {
            return -1;
        }

        memcpy(_buf, r->handler, len);
        for(int i = 0; i < len; i++) {
            if(_buf[i] == '/') _buf[i] = '-';
        }
        _buf[len++] = '_';
        memcpy(_buf+len, uidbuf, uidLen+1);

    } // else of if(svrcfg->terminate_backends_on_exit)

    return 0;
}
#endif
*/

static apr_status_t check_script_file(request_rec *r, uint32_t uid, uint32_t gid,
                                      lsapi_dir_conf_t* cfg,
                                      int check_document_root, int check_owner, int paranoid, 
                                      char *errbuf, size_t errlen)
{
    const char *script_filename = apr_table_get(r->subprocess_env, "SCRIPT_FILENAME");
    struct stat st_info;

    if(!script_filename) {
        snprintf(errbuf, errlen, "Could not determine script filename for request");
        // impossible case as SCRIPT_FILENAME was set in ap_add_common_vars - internal error
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if(check_document_root)
    {
        const char *document_root;
#ifdef APACHE2_2
        document_root = ap_document_root(r);
#else
        document_root = ap_context_document_root(r);
#endif
        if (stat(document_root, &st_info) != 0) {
            snprintf(errbuf, errlen, "Could not stat document root (%s): errno %d", document_root, errno);
            return cfg->err_server_docroot;  // HTTP_INTERNAL_SERVER_ERROR
        }

        if(!(S_ISDIR(st_info.st_mode))) {
            snprintf(errbuf, errlen, "Document root (%s) is not directory", document_root);
            return cfg->err_server_docroot;  // HTTP_INTERNAL_SERVER_ERROR
        }

        if(st_info.st_uid != uid) {
            snprintf(errbuf, errlen, "document root (%s) is not owned by uid %u",
                    document_root, uid);
            return cfg->err_server_docroot;  // HTTP_INTERNAL_SERVER_ERROR
        }


    } //if(check_document_root)

    if (stat(script_filename, &st_info) != 0) {
    	snprintf(errbuf, errlen, "Could not stat script filename (%s): errno %d", script_filename, errno);
    	return HTTP_NOT_FOUND;
    }

    if(!(S_ISREG(st_info.st_mode))) {
    	snprintf(errbuf, errlen, "Script file (%s) is not regular", script_filename);
    	return HTTP_NOT_FOUND;
    }

    
    if(check_owner) 
    {

        if(st_info.st_uid != uid) {
            snprintf(errbuf, errlen, "script file (%s) is not owned by uid %u",
                    script_filename, uid);
            return cfg->err_script_perms;  // HTTP_INTERNAL_SERVER_ERROR
        }

        if(paranoid) {
            if( (st_info.st_mode & S_IWOTH) ) {
                snprintf(errbuf, errlen, "Script file (%s) is writable by others", script_filename);
                return cfg->err_script_perms;  // HTTP_INTERNAL_SERVER_ERROR
            }
        }
    } //if(check_owner)

    return OK;
}

static void set_auth(request_rec *r) {
    apr_table_unset(r->subprocess_env, "PHP_AUTH_USER");
    apr_table_unset(r->subprocess_env, "PHP_AUTH_PW");
    if(r->headers_in) {
        const char *auth = NULL;
        auth = apr_table_get(r->headers_in, "Authorization");
        if(auth && auth[0] != 0 && strncmp(auth, "Basic ", 6) == 0) {
            char *user;
            char *pass;
            user = ap_pbase64decode(r->pool, auth + 6);
            if(user) {
                pass = strchr(user, ':');
                if(pass) {
                    *pass++ = '\0';
                    char* auth_user = apr_pstrdup(r->pool, user);
                    char* auth_pass = apr_pstrdup(r->pool, pass);

                    apr_table_setn(r->subprocess_env, "PHP_AUTH_USER", auth_user);
                    apr_table_setn(r->subprocess_env, "PHP_AUTH_PW", auth_pass);
                }
            }
        }
    }
}

static char *get_regexp_match (apr_pool_t *pool, ap_regex_t *rx,
                                char *buf, int match)
{
    int result;
    ap_regmatch_t *matches;
    char *bbuf;
    if (rx->re_nsub < match)
    {
        return NULL;
    }
    
    matches = (ap_regmatch_t *) apr_palloc (pool, (rx->re_nsub + 1) * sizeof (ap_regmatch_t));
    if (!matches)
    {
        return NULL;
    }
    if (!buf || !buf[0])
        return NULL;
    result = ap_regexec (rx, buf, rx->re_nsub + 1, matches, 0);
    if (!result)
    {
        int i;
        for (i = 0; i <= rx->re_nsub; i++)
        {
            if ((matches[i].rm_so != -1) && (i == match))
            {
                bbuf = apr_psprintf (pool, "%.*s", matches[i].rm_eo - matches[i].rm_so,
                                        buf + matches[i].rm_so);
                return bbuf;
            }
        }
    }
  return NULL;
}

static apr_status_t get_uid_gid(request_rec *r, lsapi_svr_conf_t *svrcfg, lsapi_dir_conf_t* cfg, uint32_t *uidptr, uint32_t *gidptr)
{
    // The most priority way to set uid/git is via LSAPIPath option
    if(cfg->path_regex) {
        char *user_name = NULL;
        //Parse path
        apr_finfo_t st;
        //Check if file exists
        if(apr_stat(&st, r->filename, APR_FINFO_NORM, r->pool)==APR_SUCCESS)
        {
            int need_prcd = 1;
            ap_regex_t rx;
            if (ap_regcomp (&rx, cfg->path_regex, AP_REG_EXTENDED))
            {
                need_prcd=0;
            }

            //Get user name from path
            if (need_prcd) 
            {
                user_name = get_regexp_match(r->pool, &rx, r->filename, 1);
                ap_regfree (&rx);
            }
            int find_uid = 0;
            if(user_name){
                //Find user id
                find_uid = (int) ap_uname2id(user_name);
                if (find_uid > 0)
                {
                    struct passwd *pw;
                    struct passwd pwd;
                    char pwbuf[PWBUF_SIZE];
    
                    getpwuid_r(find_uid, &pwd, pwbuf, sizeof pwbuf, &pw);

                    if(pw)
                    {
                        *uidptr = pw->pw_uid;
                        *gidptr = pw->pw_gid;
                        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from path_regex", *uidptr, *gidptr);
                        return APR_SUCCESS;
                    }
                }
            }
        }
    } // if(cfg->path_regex)
    
    ap_unix_identity_t *ugid = ap_run_get_suexec_identity(r);
    // path_regex is not set or some error, to be continued
    if(cfg->lsapi_uid > 0) {
        *uidptr = cfg->lsapi_uid;
        *gidptr = cfg->lsapi_gid;
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from lsapi", *uidptr, *gidptr);
    } else if(ugid) {
        *uidptr = ugid->uid;
        *gidptr = ugid->gid;
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from suexec", *uidptr, *gidptr);
    } else if(cfg->suphp_uid > 0) {
        *uidptr = cfg->suphp_uid;
        *gidptr = cfg->suphp_gid;
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from suphp", *uidptr, *gidptr);
    } else if(cfg->ruid > 0) {
        *uidptr = cfg->ruid;
        *gidptr = cfg->rgid;
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from ruid", *uidptr, *gidptr);
    } else if(cfg->itk_uid > 0) {
        *uidptr = cfg->itk_uid;
        *gidptr = cfg->itk_gid;
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from itk", *uidptr, *gidptr);
    } else if(svrcfg->use_default_uid) {
        *uidptr = svrcfg->default_uid;
        *gidptr = svrcfg->default_gid;
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid %d/%d from default", *uidptr, *gidptr);
    } else {
        //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "ugid is absent");
        return APR_EGENERAL;
    }
    
    return APR_SUCCESS;
}


static const char* get_phprc(request_rec *r, lsapi_svr_conf_t *svrcfg, uint32_t lveuid)
{
    if(!svrcfg->phprc_auto)
    {
        return svrcfg->phprc;
    }

    const char *docroot;
    size_t docroot_len;
    struct stat phpini_stat;
    static const char phpini_name[] = "/php.ini";

    // Try to use document root
#ifdef APACHE2_2
    docroot = ap_document_root(r);
#else
    docroot = ap_context_document_root(r);
#endif
    docroot_len = strlen(docroot);

    {
        char phpini_in_docroot[docroot_len + sizeof(phpini_name)];
        memcpy(phpini_in_docroot, docroot, docroot_len);
        memcpy(phpini_in_docroot+docroot_len, phpini_name, sizeof(phpini_name));
        if(stat(phpini_in_docroot, &phpini_stat) < 0)
        {
            // in case of ENOENT php.ini just does not exist in document root, it is ok 
            if(errno != ENOENT)
            {
                lscapi_rlog(LOG_WARNING, errno, r, 
                        "Failed to stat php.ini in document root(%s) - proceed to searching php.ini in home dir", phpini_in_docroot);
            }
        } else if(!S_ISREG(phpini_stat.st_mode))
        {
            lscapi_rlog(LOG_WARNING, errno, r, 
                        "php.ini in document root(%s) is not regular file - proceed to searching php.ini in home dir", phpini_in_docroot);
        }
        else
        {
            return docroot;
        }
    }

    // php.ini is not found in document root, so try to use homedir
    struct passwd *pw;
    struct passwd pwd;
    char pwbuf[PWBUF_SIZE];
    int rc;
    
    rc = getpwuid_r(lveuid, &pwd, pwbuf, sizeof pwbuf, &pw);

    if(!pw)
    {
        lscapi_rlog(LOG_WARNING, rc, r, 
                    "gepwuid(%d) failed - cannot find php.ini in home dir", lveuid);
        return NULL;
    }
        
    // we will use php.ini from home dir only if doc root is inside of home dir
    // pw->pw_dir against docroot
    size_t pwdir_len = strlen(pw->pw_dir);

    // no, it is not inside
    if(docroot_len < pwdir_len)
        return NULL;
        
    // prefix of docroot is not equal to home dir
    if(memcmp(docroot, pw->pw_dir, pwdir_len) != 0)
        return NULL;

    char phpini_in_homedir[pwdir_len + sizeof(phpini_name)];
    memcpy(phpini_in_homedir, pw->pw_dir, pwdir_len);
    memcpy(phpini_in_homedir+pwdir_len, phpini_name, sizeof(phpini_name));
    if(stat(phpini_in_homedir, &phpini_stat) < 0)
    {
        // in case of ENOENT php.ini just does not exist in home dir, it is ok 
        if(errno != ENOENT)
        {
            lscapi_rlog(LOG_WARNING, errno, r, 
                    "Failed to stat php.ini in home dir(%s) - will not use phprc", phpini_in_homedir);
        }
        return NULL;
    } else if(!S_ISREG(phpini_stat.st_mode))
    {
        lscapi_rlog(LOG_WARNING, errno, r, 
                    "php.ini in document root(%s) is not regular file - will not use phprc", phpini_in_homedir);
        return NULL;
    }
    
    return apr_pstrdup(r->pool, pw->pw_dir); 
}

lscapi_rec *lscapi_create_connection(request_rec *r, const char *backend_path,
                                       unsigned *flagsPtr, apr_status_t *statusPtr,
                                       char *errbuf, size_t errlen,
                                       const module *m)
{
    lsapilog_module_index = &(m->module_index);

    apr_status_t status;
    char my_errbuf[128];
    lsapi_dir_conf_t* cfg = (lsapi_dir_conf_t*) ap_get_module_config(r->per_dir_config, m);
    lsapi_svr_conf_t *svrcfg = ap_get_module_config(r->server->module_config, m);
    uint32_t lveuid = 0;
    uint32_t lvegid = 0;

    if(get_uid_gid(r, svrcfg, cfg, &lveuid, &lvegid) != APR_SUCCESS)
    {
        snprintf(errbuf, errlen, "Could not determine uid/gid for request");
        *statusPtr = cfg->err_server_uid; //HTTP_INTERNAL_SERVER_ERROR
        return NULL;
    }

    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    apr_table_unset(r->subprocess_env, "GATEWAY_INTERFACE");

    /*
      MODLS-231
      https://httpoxy.org 
      https://www.apache.org/security/asf-httpoxy-response.txt
    */
    apr_table_unset(r->subprocess_env, "HTTP_PROXY");
    apr_table_unset(r->subprocess_env, "HTTP_PROXY_AUTHORIZATION");
    apr_table_unset(r->subprocess_env, "HTTP_AUTHORIZATION");

    set_auth(r);

    status = check_script_file(r, lveuid, lvegid, cfg, !svrcfg->skip_check_document_root, 
                               svrcfg->check_target_perm, svrcfg->paranoid, errbuf, errlen);
    if(status != OK) {
        *statusPtr = status;
        return NULL;
    }

    lscapi_rec *lscapi = lscapi_create(alloc_by_request,
                                       (lscapi_log_fn)lscapi_log_rerror, r,
                                       lveuid, lvegid,
                                       flagsPtr,
                                       my_errbuf, sizeof my_errbuf);
    if(!lscapi) {
        snprintf(errbuf, errlen, "Could not create lsapi connection: %s", my_errbuf);
        *statusPtr = cfg->err_lsapi_create; // HTTP_SERVICE_UNAVAILABLE
        return NULL;
    }

    lscapi_set_socket_path(lscapi, svrcfg->socket_path);

    lscapi_set_phprc(lscapi, get_phprc(r, svrcfg, lveuid) );

    lscapi_set_debug_enabled(lscapi, svrcfg->debug_enabled);

    lscapi_set_backend_path(lscapi, r->handler, backend_path);

    lscapi_set_user_spawn_backend(lscapi, (lscapi_spawn_backend_fn)lscapi_starter_send_spawn_cmd);

    lscapi_set_accept_notify(lscapi, cfg->dir_accept_notify);

    lscapi_set_use_request_scope_buffer(lscapi, cfg->resend_if_crashed != 0);
    
    lscapi_set_domain(lscapi, r->server->server_hostname);
    
#ifdef APACHE2_2
    lscapi_set_random(lscapi, (lscapi_random_fn)apr_generate_random_bytes);
#else
    lscapi_set_random(lscapi, ap_random_insecure_bytes);
#endif

    lscapi_set_tmpdir(lscapi, svrcfg->tmpdir);

    lsapi_http_header_index_t *hdrIndexPtr;
    lsapi_header_offset_t *hdrOffsets;
    size_t hdrOffsetsNum;
    char *httpHeader;
    size_t httpHeaderLen;
    size_t contentLength;

    // Ignore Content-Length in the case of GET method
    // For example in the case of redirecting POST request with ErrorDocument
    if(r->method_number == M_GET) {
        apr_table_setn(r->headers_in, "Content-Length", "0");
    }

    lscapi_recreate_http_header(r, &hdrIndexPtr, &hdrOffsets,
                                &hdrOffsetsNum, &contentLength,
                                &httpHeader, &httpHeaderLen);

    // Ignore Content-Length in the case of Expect: 100-continue ?
/*
    if(contentLength) {
        const char *expect = apr_table_get(r->headers_in, "Expect");
        if(expect && !strcmp(expect, "100-continue")) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Content-Length(%lu) is unreliable due to Expect:100-continue header", contentLength);
            contentLength = 0;
        }
    }
*/

    // set length of remaining request body and callback to read it
    lscapi_set_user_body_info(lscapi, contentLength, get_request_body,
                              (lscapi_should_get_block_fn)ap_should_client_block);

    lscapi_set_header_info(lscapi, hdrIndexPtr, hdrOffsets, hdrOffsetsNum,
                            httpHeader, httpHeaderLen);
    lscapi_var_t *envs;
    int envNum = lscapi_parse_server_vars(r, &envs);
    lscapi_set_envs(lscapi, envs, envNum);

    if(!cfg->mod_php_behaviour_off) {
        lscapi_var_t *specialEnvs;
        int specialEnvNum = lscapi_parse_special_vars(r, cfg->phpParams, &specialEnvs);
        lscapi_set_special_envs(lscapi, specialEnvs, specialEnvNum);
    }

    return lscapi;
}
