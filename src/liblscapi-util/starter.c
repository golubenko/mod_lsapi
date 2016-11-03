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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <unixd.h>
#include <ap_mpm.h>
#include <apr_thread_proc.h>
#include <apr_strings.h>
#include <apr_queue.h>
#include <apr_global_mutex.h>
#include <apr_version.h>
#if APR_MAJOR_VERSION < 2
#include <apr_support.h>
#endif
#include <http_config.h>
#include <util_time.h>

#if MODULE_MAGIC_NUMBER_MAJOR >= 20090209
#include "mod_unixd.h"
#endif

#if MODULE_MAGIC_NUMBER_MAJOR < 20081201
#define ap_unixd_config unixd_config
#define ap_unixd_setup_child unixd_setup_child
#endif

struct lsapi_starter_command {
    spawn_info_t spawn_info;
    int force_start;
};
typedef struct lsapi_starter_command lsapi_starter_command;

struct lsapi_starter_notify {
    pid_t pid;
    int err;
};
typedef struct lsapi_starter_notify lsapi_starter_notify;

void lscapi_spawn_lsphp(server_rec *s, spawn_info_t *spawn_info, int log_sock);

/* The APR other-child API doesn't tell us how the daemon exited
 * (SIGSEGV vs. exit(1)).  The other-child maintenance function
 * needs to decide whether to restart the daemon after a failure
 * based on whether or not it exited due to a fatal startup error
 * or something that happened at steady-state.  This exit status
 * is unlikely to collide with exit signals.
 */
#define DAEMON_STARTUP_ERROR 254


static int g_wakeup_timeout = 0;
static apr_proc_t *g_starter_proc = NULL;
static apr_file_t *g_st_read_pipe = NULL;
static apr_file_t *g_st_write_pipe = NULL;
static apr_file_t *g_ap_write_pipe = NULL;
static apr_file_t *g_ap_read_pipe = NULL;
static apr_global_mutex_t *g_pipelock = NULL;
static const char *g_pipelock_name;
static const char *g_pipelock_mutex_type = "lsapi-pipe";
static const char *g_prefix = "lsapi-util";

static int volatile g_caughtSigTerm = 0;
static pid_t g_starter_pid = 0;


static apr_status_t global_cleanup(void *dummy)
{
    if(g_pipelock != NULL)
    {
        apr_global_mutex_destroy(g_pipelock);
        g_pipelock = NULL;
    }
    
    return APR_SUCCESS;
}

static void signal_handler(int signo)
{
    /* Sanity check, Make sure I am not the subprocess. A subprocess may
       get signal after fork() and before execve() */
    if (getpid() != g_starter_pid) {
        exit(0);
        return;
    }

    if ((signo == SIGTERM) || (signo == SIGUSR1) || (signo == SIGHUP)) {
        g_caughtSigTerm = 1;
    }
}

static int starter_should_exit(void)
{
    return g_caughtSigTerm;
}

static apr_status_t init_signal(const char *prefix, server_rec * main_server)
{
    struct sigaction sa;

    /* Setup handlers */
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        lscapi_log(APLOG_ERR, errno, main_server,
                     "%s Can't install SIGTERM handler", prefix);
        return APR_EGENERAL;
    }

    /* Httpd restart */
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        lscapi_log(APLOG_ERR, errno, main_server,
                     "%s Can't install SIGHUP handler", prefix);
        return APR_EGENERAL;
    }

    /* Httpd graceful restart */
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        lscapi_log(APLOG_ERR, errno, main_server,
                     "%s Can't install SIGUSR1 handler", prefix);
        return APR_EGENERAL;
    }

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        lscapi_log(APLOG_ERR, errno, main_server,
                     "%s Can't install SIGPIPE handler", prefix);
        return APR_EGENERAL;
    }

    /* Ignore SIGCHLD */
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        lscapi_log(APLOG_ERR, errno, main_server,
                     "%s Can't install SIGCHLD handler", prefix);
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static int set_group_privs(void)
{
    if (!geteuid()) {
        const char *name;

        /* Get username if passed as a uid */
        if (ap_unixd_config.user_name[0] == '#') {
            struct passwd *ent;

            uid_t uid = atoi(&ap_unixd_config.user_name[1]);

            if ((ent = getpwuid(uid)) == NULL) {
                lscapi_log(APLOG_ALERT, errno, NULL,
                             "getpwuid: couldn't determine user name from uid %"APR_PID_T_FMT", "
                             "you probably need to modify the User directive",
                             uid);
                return -1;
            }
            name = ent->pw_name;
        }

        else
            name = ap_unixd_config.user_name;

#if !defined(OS2) && !defined(TPF)
        /* OS/2 and TPF don't support groups. */

        /*
         * Set the GID before initgroups(), since on some platforms
         * setgid() is known to zap the group list.
         */
        if (setgid(ap_unixd_config.group_id) == -1) {
            lscapi_log(APLOG_ALERT, errno, NULL,
                         "setgid: unable to set group id to Group %"APR_PID_T_FMT,
                         ap_unixd_config.group_id);
            return -1;
        }

        /* Reset `groups' attributes. */
        if (initgroups(name, ap_unixd_config.group_id) == -1) {
            lscapi_log(APLOG_ALERT, errno, NULL,
                         "initgroups: unable to set groups for User %s "
                         "and Group %"APR_PID_T_FMT, name,
                         ap_unixd_config.group_id);
            return -1;
        }
#endif                          /* !defined(OS2) && !defined(TPF) */
    }
    return 0;
}

static void starter_maint(int reason, void *data, apr_wait_t status)
{
    apr_proc_t *proc = data;
    int mpm_state;

    switch (reason) {
    case APR_OC_REASON_DEATH:
        apr_proc_other_child_unregister(data);
        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
            && mpm_state != AP_MPMQ_STOPPING) {
            if (status == DAEMON_STARTUP_ERROR) {
                lscapi_log(APLOG_CRIT, 0, NULL,
                             "%s: lsapi starter failed to initialize; stopping httpd", g_prefix);
                /*
                 * try to terminate httpd
                 */
                kill(getpid(), SIGTERM);

            }
            else {
                lscapi_log(APLOG_ERR, 0, NULL,
                             "%s: lsapi starter died, restarting the server", g_prefix);

                /* HACK: I can't just call create_process_manager() to
                   restart a process manager, because it will use the dirty
                   share memory, I have to kill myself a SIGHUP, to make
                   a clean restart */
                /* FIXME: This is the httpd parent; it is doing a hard
                 * restart of the server!
                 */
                if (kill(getpid(), SIGHUP) < 0) {
                    lscapi_log(APLOG_EMERG,
                                 apr_get_os_error(), NULL,
                                 "%s: can't send SIGHUP to self", g_prefix);
                    exit(0);
                }
            }
        }
        break;
    case APR_OC_REASON_RESTART:
        apr_proc_other_child_unregister(data);
        break;
    case APR_OC_REASON_LOST:
        apr_proc_other_child_unregister(data);
        /* It hack here too, a note above */
        /* FIXME: This is the httpd parent; mod_lsapi is doing a hard
         * restart of the server!
         */
        if (kill(getpid(), SIGHUP) < 0) {
            lscapi_log(APLOG_EMERG,
                         apr_get_os_error(), NULL,
                         "%s: can't send SIGHUP to self", g_prefix);
            exit(0);
        }
        break;
    case APR_OC_REASON_UNREGISTER:
        /* I don't think it's going to happen */
        kill(proc->pid, SIGHUP);
        break;
    }
}

static apr_status_t starter_main(const char *prefix, server_rec * main_server, apr_pool_t * config_pool);

apr_status_t lscapi_starter_child_init(server_rec* main_server, apr_pool_t* config_pool, const char *prefix)
{
    apr_status_t rc;

    if ((rc = apr_global_mutex_child_init(&g_pipelock,
                                          g_pipelock_name,
                                          main_server->process->pconf)) != APR_SUCCESS) {
        lscapi_log(APLOG_EMERG, rc, main_server,
                     "%s apr_global_mutex_child_init error for pipe mutex", prefix);
        exit(1);
    }

    return APR_SUCCESS;
}

apr_status_t lscapi_starter_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    return lscapi_mutex_register(g_pipelock_mutex_type, p);
}

static const char *g_logfile_name;
static int g_logfile = -1;

int starter_log_error(server_rec *s, int errnum, const char *fmt, ...) {
    if(g_logfile < 0) return -1;

    char errbuf[MAX_STRING_LEN];
    va_list args;
    int errlen;
    int len = 0;
    
    errbuf[len++] = '[';
#ifdef APACHE2_4
    errlen = sizeof errbuf - len;
    ap_recent_ctime_ex(errbuf + len, apr_time_now(), AP_CTIME_OPTION_NONE, &errlen);
    len += errlen-1;
#else
    ap_recent_ctime(errbuf + len, apr_time_now());
    errlen = strlen(errbuf + len);
    len += errlen;
#endif
    errbuf[len++] = ']';
    errbuf[len++] = ' ';

    if(errnum != 0) {
        errlen = sizeof errbuf - len;
        if(errnum > 0) {
            errlen = snprintf(errbuf+len, errlen, "[ERROR %s:%d] ", strerror(errnum), errnum);
        } else {
            errlen = snprintf(errbuf+len, errlen, "[ERROR] ");
        }
        len += errlen;
    }
    
    va_start(args, fmt);
    errlen = sizeof errbuf - len - 1; // one less for trailing \n
    errlen = apr_vsnprintf(errbuf+len, errlen, fmt, args);
    len += errlen;
    va_end(args);

    errbuf[len++] = '\n';

    return write(g_logfile, errbuf, len);
}

/*
static void close_sockets(server_rec *s)
{
    static const char fd_dir_nm[] = "/proc/self/fd";
    int stdin_sock;
    int stdout_sock;
    int stderr_sock;
    int fd_sock;

    DIR *fd_dir = opendir(fd_dir_nm);
    if(!fd_dir) {
        return;
    }

    stdin_sock = stdin ? fileno(stdin) : -1;
    stdout_sock = stdout ? fileno(stdout) : -1;
    stderr_sock = stderr ? fileno(stderr) : -1;
    fd_sock = dirfd(fd_dir);

    while(1) {
        struct dirent *dentry = readdir(fd_dir);
        if(!dentry) {
            break;
        }

        int cur_sock = 0;
        for(char *nm_ptr = dentry->d_name; *nm_ptr; nm_ptr++) {
            if(!isdigit(*nm_ptr)) {
                cur_sock = -1;
                break;
            }
            cur_sock = cur_sock * 10 + ( (*nm_ptr) - '0' );
        }

        // non-digits in file name
        if(cur_sock < 0) {
            continue;
        }

        if(cur_sock == stdin_sock
           || cur_sock == stdout_sock
           || cur_sock == stderr_sock
           || cur_sock == fd_sock)     continue;

        struct stat st;
        if(fstat(cur_sock, &st) != 0) continue;

        if(S_ISREG(st.st_mode))
        {
            close(cur_sock);
        }

    }

    closedir(fd_dir);
}
*/

apr_status_t lscapi_starter_init(const char *prefix, server_rec *main_server, apr_pool_t *config_pool, lsapi_svr_conf_t *cfg)
{
    apr_status_t rc;
    apr_finfo_t finfo;

    g_wakeup_timeout = 1; // TODO: some config?
    g_prefix = prefix;

    rc = apr_stat(&finfo, cfg->selfstarter_socket_path, APR_FINFO_USER, config_pool);
    if (rc != APR_SUCCESS) {

        /* Make dir for unix domain socket */
        if ((rc = apr_dir_make_recursive(cfg->selfstarter_socket_path,
                                         APR_UREAD | APR_UWRITE | APR_UEXECUTE,
                                         config_pool)) != APR_SUCCESS) {
            lscapi_log(APLOG_ERR, rc, main_server,
                         "%s Can't create unix socket dir %s",
                         prefix, cfg->selfstarter_socket_path);
            exit(1);
        }

        if (!geteuid()) {
            if (chown(cfg->selfstarter_socket_path,
                      ap_unixd_config.user_id, -1) < 0) {
                lscapi_log(APLOG_ERR, errno, main_server,
                             "%s Can't set ownership of unix socket dir %s",
                             prefix, cfg->selfstarter_socket_path);
                exit(1);
            }
        } //if (!geteuid())

    } //if (rc != APR_SUCCESS)

    apr_pool_cleanup_register(config_pool, NULL, global_cleanup, apr_pool_cleanup_null);

    //close_sockets(main_server);

    /* Create mutex for pipe reading and writing */
    rc = lscapi_mutex_create(&g_pipelock, &g_pipelock_name,
                            g_pipelock_mutex_type,
                            main_server->process->pconf, main_server, cfg);
    if (rc != APR_SUCCESS) {
        exit(1);
    }

    /* Create pipes to communicate between starter and apache */
    if ((rc = apr_file_pipe_create_ex(&g_st_read_pipe, &g_ap_write_pipe,
                                      APR_FULL_BLOCK,  config_pool)) != APR_SUCCESS
        || (rc = apr_file_pipe_create_ex(&g_ap_read_pipe, &g_st_write_pipe,
                                      APR_FULL_BLOCK, config_pool))) {
        lscapi_log(APLOG_ERR, rc, main_server,
                     "%s Can't create pipe between starter and module", prefix);
        return rc;
    }

    apr_interval_time_t interval = 10000000; // ten seconds
    apr_file_pipe_timeout_set(g_ap_write_pipe, interval);
    apr_file_pipe_timeout_set(g_st_write_pipe, interval);
    apr_file_pipe_timeout_set(g_ap_read_pipe, interval);
    apr_file_pipe_timeout_set(g_st_read_pipe, interval);

    /* Spawn the starter */
    g_starter_proc =
        (apr_proc_t *) apr_pcalloc(config_pool, sizeof(*g_starter_proc));
    rc = apr_proc_fork(g_starter_proc, config_pool);
    if (rc == APR_INCHILD) {
        /* I am the child */
        g_starter_pid = getpid();
        lscapi_log(APLOG_NOTICE, 0, main_server,
                     "%s Selfstarter %" APR_PID_T_FMT  " started", prefix, getpid());

        if ((rc = init_signal(prefix, main_server)) != APR_SUCCESS) {
            lscapi_log(APLOG_EMERG, rc, main_server,
                         "%s can't install signal handler, exiting now", prefix);
            exit(DAEMON_STARTUP_ERROR);
        }

        if (getuid() != 0) {
            lscapi_log(APLOG_EMERG, 0, main_server,
                            "%s current user is not root, exiting now", prefix);
            exit(DAEMON_STARTUP_ERROR);
        }

        g_logfile_name = lscapi_make_fname_in_logdir(main_server, config_pool, "sulsphp_log");
        g_logfile = open(g_logfile_name, O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0640);

        if (set_group_privs()) {
            lscapi_log(APLOG_EMERG, errno, main_server,
                            "%s Can't set group privs, exiting now", prefix);
            exit(DAEMON_STARTUP_ERROR);
        }


        if (NULL != ap_unixd_config.chroot_dir) {
            if (chdir(ap_unixd_config.chroot_dir) != 0) {
                lscapi_log(APLOG_EMERG, errno, main_server,
                            "%s Can't chdir to %s, exiting now", prefix, ap_unixd_config.chroot_dir);
                exit(DAEMON_STARTUP_ERROR);
            }
            if (chroot(ap_unixd_config.chroot_dir) != 0) {
                lscapi_log(APLOG_EMERG, errno, main_server,
                            "%s Can't chroot to %s, exiting now", prefix, ap_unixd_config.chroot_dir);
                exit(DAEMON_STARTUP_ERROR);
            }
            if (chdir("/") != 0) {
                lscapi_log(APLOG_EMERG, errno, main_server,
                            "%s Can't chdir to new root, exiting now", prefix);
                exit(DAEMON_STARTUP_ERROR);
            }
        }

        // Starter will (in lscapi_spawn_lsphp) change its privs several times up and down.
        // So it should have superuser privs in its saved set-user-ID
        // ruid will be nobody 
        if (setresuid(ap_unixd_config.user_id, ap_unixd_config.user_id, 0) == -1) {
            lscapi_log(APLOG_EMERG, errno, main_server,
                        "%s unable to change uid to %ld, exiting now", prefix, (long) ap_unixd_config.user_id);
            exit(DAEMON_STARTUP_ERROR);
        }

#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
        /* this applies to Linux 2.4+ */
        if (ap_coredumpdir_configured) {
            if (prctl(PR_SET_DUMPABLE, 1)) {
                lscapi_log(APLOG_EMERG, errno, main_server,
                            "%s Set dumpable failed - this child will not coredump"
                            " after software errors", prefix );
            }
        }
#endif

        apr_file_pipe_timeout_set(g_st_read_pipe, apr_time_from_sec(g_wakeup_timeout));
        apr_file_close(g_ap_write_pipe);
        apr_file_close(g_ap_read_pipe);

        starter_main(prefix, main_server, config_pool);

        lscapi_log(APLOG_NOTICE, 0, main_server,
                    "%s Selfstarter %" APR_PID_T_FMT " stopped", prefix, getpid());
        exit(0);

    } else if (rc != APR_INPARENT) {
        lscapi_log(APLOG_EMERG, rc, main_server,
                    "%s Create selfstarter error", prefix );
        exit(1);
    }

    /* I am the parent
        I will send the stop signal in procmgr_stop_procmgr() */
    apr_pool_note_subprocess(config_pool, g_starter_proc,
                                APR_KILL_ONLY_ONCE);
    apr_proc_other_child_register(g_starter_proc, starter_maint,
                                  g_starter_proc, NULL, config_pool);

    return APR_SUCCESS;
}


static apr_status_t starter_fetch_cmd(const char* prefix,
                                      lsapi_starter_command* command,
                                      server_rec* main_server)
{
    apr_status_t rc;

    /* Sanity check */
    if (!g_st_read_pipe)
        return APR_EPIPE;

    /* Wait for next command */
#if APR_MAJOR_VERSION < 2
    rc = apr_wait_for_io_or_timeout(g_st_read_pipe, NULL, 1);
#else
    rc = apr_file_pipe_wait(g_pm_read_pipe, APR_WAIT_READ);
#endif

    /* Log any unexpect result */
    if (rc != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(rc)) {
        lscapi_log(APLOG_WARNING, rc, main_server,
                     "%s: error while waiting for message from pipe", prefix);
        return rc;
    }

    /* Timeout */
    if (rc != APR_SUCCESS)
        return rc;

    return apr_file_read_full(g_st_read_pipe, command, sizeof(*command), NULL);
}

/*
static int starter_is_spawn_allowed(server_rec * main_server, fcgid_command * command)
{
    return 1;
}
*/

static void starter_spawn(const char *prefix,
                          lsapi_starter_command *command,
                          lsapi_starter_notify *notify,
                          server_rec *main_server,
                          apr_pool_t *config_pool) {

    pid_t pid;
    
#ifdef WITH_CRIU
   /*
     * Try restore from images first. It uses criu_restore() inside,
     * which does just what we want -- it daemonizes a process.
     */
    if(command->spawn_info.use_criu) {

        char errbuf[256];
        if ((pid = lscapi_restore(&(command->spawn_info), errbuf, sizeof errbuf)) > 0)
        {
            goto exit;
        } else {
            lscapi_log(APLOG_WARNING, 0, main_server, "%s: CRIU restoring image error: %s - ignore", prefix, errbuf);
        }

    }
#endif

    if ((pid = fork()) < 0) {
        notify->pid = -1;
        notify->err = errno;
        return;
    }
    else if (pid == 0) {
        /* child process */

        /* daemonize new process */
        setsid();
        setpgid(0, 0);

        lscapi_spawn_lsphp(main_server, &(command->spawn_info), g_logfile );
        lscapi_log(APLOG_ERR, errno, main_server, "%s: spawn_lsphp", prefix);
        _exit(-1);
    }

#ifdef WITH_CRIU
exit:
#endif
    notify->pid = pid;
    notify->err = 0;
}

static apr_status_t starter_main(const char *prefix,
                                 server_rec * main_server,
                                 apr_pool_t * config_pool)
{
    lsapi_starter_command command;
    lsapi_starter_notify notify;
    apr_size_t notify_size;
    apr_status_t rc;

    apr_hash_t *starttime_by_socket = apr_hash_make(config_pool);

    while(1) {
        if(starter_should_exit())
            break;

        /* Wait for command */
        if(starter_fetch_cmd(prefix, &command, main_server) == APR_SUCCESS) {
/*
            if(!starter_is_spawn_allowed(main_server, &command)) continue;
*/
            // HACK. Starter knows that socket name is in argv[4]
            const char *key = command.spawn_info.socket_name;

            apr_time_t *startTimePtr = apr_hash_get(starttime_by_socket, key, APR_HASH_KEY_STRING);

            if(!startTimePtr) {
                //lscapi_log(APLOG_DEBUG, 0, main_server, "Could not find starting time for (%s) - try to invoke", key);

                // the first invoking with this socket path
                //lscapi_log(APLOG_DEBUG, 0, main_server, "Try to invoke sulsphp %d", 1);
                starter_spawn(prefix, &command, &notify, main_server, config_pool);
                //lscapi_log(APLOG_DEBUG, 0, main_server, "After invoking sulsphp %d", 1);

                if(notify.pid > 0) {
                    startTimePtr = apr_palloc(config_pool, sizeof(apr_time_t) );

                    // store invoking time associating with socket path
                    *startTimePtr = apr_time_now();
                    //lscapi_log(APLOG_DEBUG, 0, main_server, "Setting starting time for (%s) to %ld", key, *startTimePtr);
                    apr_hash_set(starttime_by_socket, key, APR_HASH_KEY_STRING, startTimePtr);
                //} else {
                //        lscapi_log(APLOG_DEBUG, 0, main_server, "Invoke (%s) successful so setting start time to %ld and storing it", key, *startTimePtr);
                }


            } else {

                //lscapi_log(APLOG_DEBUG, 0, main_server, "Starting time for (%s) is %ld", key, *startTimePtr);

#define STARTER_TIMEOUT  (2 * (APR_USEC_PER_SEC))

                if(command.force_start || apr_time_now() - *startTimePtr > STARTER_TIMEOUT) {

                    //lscapi_log(APLOG_DEBUG, 0, main_server, "Try to invoke for(%s) due to force_start(%d) or to timediff(%ld) more than timeout(%ld)",
                    //            key, command.force_start, apr_time_now() - *startTimePtr, STARTER_TIMEOUT);
                    starter_spawn(prefix, &command, &notify, main_server, config_pool);
                    //lscapi_log(APLOG_DEBUG, 0, main_server, "After invoking sulsphp %d", 2);

                    if(notify.pid > 0) {
                        // store invoking time associating with socket path
                        *startTimePtr = apr_time_now();
                        //lscapi_log(APLOG_DEBUG, 0, main_server, "Invoke (%s) successful so setting start time to %ld",
                        //        key, *startTimePtr);
                    //} else {
                        //lscapi_log(APLOG_DEBUG, 0, main_server, "Invoke (%s) failed so leaving start time prev %ld",
                        //        key, *startTimePtr);
                    }

                } else {
                    notify.pid = 0;  // special case of delayed invoke
                    notify.err = 0;
                }

            }

#if APR_MAJOR_VERSION < 2
            rc = apr_wait_for_io_or_timeout(g_st_write_pipe, NULL, 0);
#else
            rc = apr_file_pipe_wait(g_st_write_pipe, APR_WAIT_WRITE);
#endif
            if(rc != APR_SUCCESS) {
                
                lscapi_log(APLOG_WARNING, rc, main_server,
                            "%s: can't send notify from selfstarter: pipe is full", prefix);
                
            } else {
                
                notify_size = sizeof notify;
                //lscapi_log(APLOG_NOTICE, 0, main_server,
                //                "%s: selfstarter just before write; pid:%d; err:%d", prefix, notify.pid, notify.err);
                if ((rc = apr_file_write(g_st_write_pipe, &notify, &notify_size)) != APR_SUCCESS) {
                        lscapi_log(APLOG_WARNING, rc, main_server,
                                    "%s: can't send notify from selfstarter", prefix);
                }
            }

        } //if(starter_fetch_cmd(prefix, &command, main_server) == APR_SUCCESS)

    } //while (1)

    return APR_SUCCESS;
}

pid_t lscapi_starter_send_spawn_cmd(const spawn_info_t *spawn_info, request_rec *r, int force_start) {
    apr_status_t rc;
    lsapi_starter_command command;
    lsapi_starter_notify notify;
    apr_size_t msgsize;
    const char *errptr = "";

    command.spawn_info = *spawn_info;
    command.force_start = force_start;

    /* Get the global mutex before posting the request */
    if ((rc = apr_global_mutex_lock(g_pipelock)) != APR_SUCCESS) {
        lscapi_rlog(APLOG_ERR, rc, r,
                      "%s: can't get pipe mutex", g_prefix);
        return -1;
    }

#if APR_MAJOR_VERSION < 2
    rc = apr_wait_for_io_or_timeout(g_ap_write_pipe, NULL, 0);
#else
    rc = apr_file_pipe_wait(g_ap_write_pipe, APR_WAIT_WRITE);
#endif
    if(rc == APR_SUCCESS) {

        //lscapi_rlog(APLOG_NOTICE, rc, r,
        //              "%s: in lscapi_starter_send_spawn_cmd wait_io_for_write ret success", g_prefix);
        rc = apr_file_write_full(g_ap_write_pipe, &command, sizeof command, NULL);

        if(rc == APR_SUCCESS) {

            //lscapi_rlog(APLOG_NOTICE, rc, r,
            //            "%s: apr_file_write_full ret success", g_prefix);
#if APR_MAJOR_VERSION < 2
            rc = apr_wait_for_io_or_timeout(g_ap_read_pipe, NULL, 1);
#else
            rc = apr_file_pipe_wait(g_ap_read_pipe, APR_WAIT_READ);
#endif

            if(rc == APR_SUCCESS) {

                //lscapi_rlog(APLOG_NOTICE, rc, r,
                //            "%s: wait_io_for_read ret success", g_prefix);
                msgsize = sizeof notify;
                rc = apr_file_read(g_ap_read_pipe, &notify, &msgsize);

                if(rc != APR_SUCCESS) {

                    //lscapi_rlog(APLOG_NOTICE, rc, r,
                    //            "%s: apr_file_read ret error %d", g_prefix, rc);
                    errptr = ": apr_file_read on read_pipe failed";
                    notify.pid = -1;
                    notify.err = rc;
/*
                } else { // apr_file_read(g_ap_read_pipe, ...) ret not success
                    lscapi_rlog(APLOG_NOTICE, rc, r,
                                "%s: apr_file_read success; pid:%d; err:%d", g_prefix, notify.pid, notify.err);
*/
                }

            } else { // apr_wait_for_io_or_timeout(g_ap_read_pipe, NULL, 1) ret success

                //lscapi_rlog(APLOG_NOTICE, rc, r,
                //            "%s: wait_io_for_read ret error code %d", g_prefix, rc);
                errptr = ": apr_wait_for_io_or_timeout on read_pipe failed";
                notify.pid = -1;
                notify.err = rc;

            } // else of apr_wait_for_io_or_timeout(g_ap_read_pipe, NULL, 1) ret success

        } else { // apr_file_write_full(g_ap_write_pipe, ...) ret success

            //lscapi_rlog(APLOG_NOTICE, rc, r,
            //            "%s: apr_file_write_full ret error %d", g_prefix, rc);
            errptr = ": apr_file_write_full on write_pipe failed";
            notify.pid = -1;
            notify.err = rc;

        } // else of apr_file_write_full(g_ap_write_pipe, ...) ret success

    } else { // apr_wait_for_io_or_timeout(g_ap_write_pipe, NULL, 0) ret success

        //lscapi_rlog(APLOG_NOTICE, rc, r,
        //              "%s: wait_io_for_write ret error code %d", g_prefix, rc);
        errptr = ": apr_wait_for_io_or_timeout on write_pipe failed";
        notify.pid = -1;
        notify.err = rc;

    } // else of apr_wait_for_io_or_timeout(g_ap_write_pipe, NULL, 0) ret success

    /* Release the lock */
    if ((rc = apr_global_mutex_unlock(g_pipelock)) != APR_SUCCESS) {
        lscapi_rlog(APLOG_ERR, rc, r,
                      "%s: can't release pipe mutex", g_prefix);
        return -1;
    }

    if(notify.pid < 0) {
        lscapi_rlog(APLOG_ERR, notify.err, r,
                      "%s: Backend spawn failed%s", g_prefix, errptr);
        return -1;
    }

    /*
    if(notify.pid == 0) {
        lscapi_rlog(APLOG_DEBUG, 0, r, "%s: Spawn delayed", g_prefix);
    }
    */

    return notify.pid;
}
