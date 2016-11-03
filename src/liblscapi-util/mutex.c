/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <lscapi_util.h>

#include <stdio.h>

#include <apr_global_mutex.h>
#include <httpd.h>
#include <ap_mmn.h>
#include <http_log.h>

#ifndef LSCAPI_PROC_CREATE_EXPORTED
#include <unistd.h>
#endif

#if LSCAPI_WITH_MUTEX_API

#include <util_mutex.h>

apr_status_t lscapi_mutex_register(const char *mutex_type,
                                  apr_pool_t *pconf)
{
    return ap_mutex_register(pconf, mutex_type, NULL, APR_LOCK_POSIXSEM, 0);
}

apr_status_t lscapi_mutex_create(apr_global_mutex_t **mutex,
                                const char **lockfile,
                                const char *mutex_type,
                                apr_pool_t *pconf,
                                server_rec *main_server,
                                lsapi_svr_conf_t *cfg)
{
    apr_status_t rv;

    rv = ap_global_mutex_create(mutex, lockfile, mutex_type, NULL, main_server,
                                pconf, 0);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return APR_SUCCESS;
}

#else

/* no support for Mutex directive and related APIs */

#include <ap_mpm.h>

#if MODULE_MAGIC_NUMBER_MAJOR < 20051115
#ifndef AP_NEED_SET_MUTEX_PERMS
#define AP_NEED_SET_MUTEX_PERMS 1
#endif
#endif

#if AP_NEED_SET_MUTEX_PERMS
#include <unixd.h>
#endif

#if MODULE_MAGIC_NUMBER_MAJOR < 20081201
#define ap_unixd_set_global_mutex_perms unixd_set_global_mutex_perms
#endif

apr_status_t lscapi_mutex_register(const char *mutex_type,
                                  apr_pool_t *pconf)
{
    return APR_SUCCESS;
}

apr_status_t lscapi_mutex_create(apr_global_mutex_t **mutex,
                                const char **lockfilep,
                                const char *mutex_type,
                                apr_pool_t *pconf,
                                server_rec *s,
                                lsapi_svr_conf_t *cfg)
{
    apr_status_t rv;
    char *lockfile;
    unsigned char random[8];

#define LOCKFILE_LEN 64

    lockfile = apr_palloc(pconf, LOCKFILE_LEN);
    rv = apr_generate_random_bytes(random, 8);
    if(rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "apr_generate_random_bytes failed");
        return rv;
    }
    snprintf(lockfile, LOCKFILE_LEN, "%s/lsapi-mutex-%02x%02x%02x%02x%02x%02x%02x%02x", P_tmpdir,
             random[0], random[1], random[2], random[3], random[4], random[5], random[6], random[7] );
    rv = apr_global_mutex_create(mutex, lockfile, cfg->mutex_mech, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Can't create global %s mutex", mutex_type);
        return rv;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(*mutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Can't set global %s mutex perms", mutex_type);
        return rv;
    }
#endif

    *lockfilep = lockfile;
    

    return APR_SUCCESS;
}

#endif

#if 0

static const char terminate_script[] =
"/bin/sleep 2; for id in `/usr/bin/ipcs -s|grep $LSAPI_APACHE_USER|/bin/cut -d ' ' -f 2`; do /usr/bin/ipcrm -s $id; done";

static const char* args[] =
{
    "/bin/sh",
    "-c",
    terminate_script,
    NULL
};

static const char* envs[] =
{
    "PATH=/bin:/usr/bin:/usr/local/bin",
    NULL,
    NULL
};

#ifndef LSCAPI_PROC_CREATE_EXPORTED
static pid_t proc_create(const char * const *args,
                         const char * const *env )
{
    const char * const empty_envp[] = {NULL};

    if (!env) {
        env = empty_envp;
    }

    pid_t pid;

    if ((pid = fork()) < 0) {
        return -1;
    }
    else if (pid == 0) {
        /* child process */

        /* daemonize new process */
        setsid();
        setpgid(0, 0);

        execve(args[0], (char * const *)args, (char * const *)env);
        _exit(-1);
    }

    return pid;
}

#endif

void lscapi_cleanup_mutex(const char *apache_user)
{
    char env1[64];

    snprintf(env1, sizeof env1, "LSAPI_APACHE_USER=%s", apache_user ? apache_user : SULSPHP_HTTPD_USER);
    envs[1] = env1;
#ifdef LSCAPI_PROC_CREATE_EXPORTED
    lscapi_proc_create(args, envs);
#else
    proc_create(args, envs);
#endif
    envs[1] = NULL;
}

#endif //0
