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

#include <apr.h>
#include <ap_config.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <libgen.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#if APR_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <pwd.h>
#include <grp.h>

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>

#ifdef SULSPHP_MAXPATH
#undef SULSPHP_MAXPATH
#endif // SULSPHP_MAXPATH

#if defined(PATH_MAX)
#define SULSPHP_MAXPATH PATH_MAX
#elif defined(MAXPATHLEN)
#define SULSPHP_MAXPATH MAXPATHLEN
#else
#define SULSPHP_MAXPATH 8192
#endif

#ifdef SULSPHP_ENVBUF
#undef SULSPHP_ENVBUF
#endif // SULSPHP_ENVBUF
#define SULSPHP_ENVBUF 256

#ifdef SULSPHP_UMASK
#undef SULSPHP_UMASK
#endif // SULSPHP_UMASK
#define SULSPHP_UMASK 022

/*
 * HTTPD_USER -- Define as the username under which Apache normally
 *               runs.  This is the only user allowed to execute
 *               this program.
 */
#ifndef SULSPHP_HTTPD_USER

#ifdef AP_HTTPD_USER
#define SULSPHP_HTTPD_USER AP_HTTPD_USER
#else
#define SULSPHP_HTTPD_USER "nobody"
#endif //AP_HTTPD_USER

#endif //SULSPHP_HTTPD_USER

/*
 * UID_MIN -- Define this as the lowest UID allowed to be a target user
 *            for sulsphp.  For most systems, 500 or 100 is common.
 */
#ifndef SULSPHP_UID_MIN

#ifdef AP_UID_MIN
#define SULSPHP_UID_MIN AP_UID_MIN
#else
#define SULSPHP_UID_MIN 100
#endif //AP_UID_MIN

#endif //SULSPHP_UID_MIN

/*
 * GID_MIN -- Define this as the lowest GID allowed to be a target group
 *            for sulsphp.  For most systems, 100 is common.
 */
#ifndef SULSPHP_GID_MIN

#ifdef AP_GID_MIN
#define SULSPHP_GID_MIN AP_GID_MIN
#else
#define SULSPHP_GID_MIN 100
#endif //AP_GID_MIN

#endif //SULSPHP_GID_MIN

/*
 * DOC_ROOT -- Define as the DocumentRoot set for Apache.  This
 *             will be the only hierarchy (aside from UserDirs)
 *             that can be used for su behavior.
 */
#ifndef SULSPHP_DOC_ROOT

#ifdef AP_DOC_ROOT
#define SULSPHP_DOC_ROOT AP_DOC_ROOT
#else
#define SULSPHP_DOC_ROOT "/"
#endif //AP_DOC_ROOT

#endif //SULSPHP_DOC_ROOT

/*
 * SAFE_PATH -- Define a safe PATH environment to pass to executable.
 *
 */
#ifndef SULSPHP_SAFE_PATH

#ifdef AP_SAFE_PATH
#define SULSPHP_SAFE_PATH AP_SAFE_PATH
#else
#define SULSPHP_SAFE_PATH "/usr/local/bin:/usr/bin:/bin"
#endif //AP_SAFE_PATH

#endif //SULSPHP_SAFE_PATH

/*
 * ALLOWED_CMD -- Define the only allowed executable.
 *
 */
#ifndef SULSPHP_ALLOWED_CMD
#define SULSPHP_ALLOWED_CMD "lsphp"
#endif // SULSPHP_ALLOWED_CMD

/*
 * ALLOWED_DIR -- Define a allowable directory.
 *
 */
#ifndef SULSPHP_ALLOWED_DIR
#define SULSPHP_ALLOWED_DIR "/usr/local/bin"
#endif // SULSPHP_ALLOWED_DIR

/*
 * SAFE_DIR -- Define a safe directory.
 *
 */
#ifndef SULSPHP_SAFE_DIR
#define SULSPHP_SAFE_DIR "/opt/alt"
#endif // SULSPHP_SAFE_DIR

/*
 * CPANELSAFE_DIR -- Define a safe directory for cPanel.
 *
 */
#ifndef SULSPHP_CPANELSAFE_DIR
#define SULSPHP_CPANELSAFE_DIR "/opt/cpanel"
#endif // SULSPHP_SAFE_DIR


#define APACHE_DEFAULT_UID 48
#define NOBODY_DEFAULT_UID 99

#define APACHE_DEFAULT_GID 48
#define NOBODY_DEFAULT_GID 99

static const unsigned int BUFSIZE = 8192;

static const char prefix[] = "sulsphp:";

void starter_log_error(server_rec *s, int errnum, const char *fmt, ...)
                        __attribute__((format(printf,3,4)));


static void create_socket_base_hierarchy(server_rec *s, char *sock_name) {
    struct stat dir_info;
    int rc;
    
    if(*sock_name != '/') {
        return;
    }
    for(char *ptr = sock_name+1; *ptr; ptr++) {
        if(*ptr == '/') {
            *ptr = '\0';
            rc = stat(sock_name, &dir_info);
            if(rc != 0 && errno == ENOENT) {
                if(mkdir(sock_name, 0755) != 0) {
                    starter_log_error(s, errno, "%s mkdir(%s) failed", prefix, sock_name);
                    *ptr = '/';
                    return;
                }
            }
            *ptr = '/';
        }
    }
}

static int create_listen_socket(server_rec *s, const char *sock_name, int backlog,
                                int target_uid, int target_gid)
{
    struct sockaddr_un sock_addr;
    int sock, saved_errno, flag;

    sock_addr.sun_family = AF_UNIX;
    strncpy(sock_addr.sun_path, sock_name, sizeof sock_addr.sun_path );
    sock_addr.sun_path[sizeof(sock_addr.sun_path)-1] = '\0';
    unlink(sock_addr.sun_path);

    sock = socket( AF_UNIX, SOCK_STREAM, 0 );
    if ( sock == -1 ) {
        starter_log_error(s, errno, "%s uid:%u; gid:%u; socket failed", prefix,
                          target_uid, target_gid );
        return -1;
    }

    flag = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag ) )
    {
        saved_errno = errno;
        close(sock);
        errno = saved_errno;
        starter_log_error(s, errno, "%s uid:%u; gid:%u; setsockopt failed", prefix,
                          target_uid, target_gid);
        return -1;
    }

    flag = bind(sock, (struct sockaddr*)(&sock_addr), sizeof sock_addr);
    if(flag && errno == ENOENT)
    {
        // It seems that the base catalog for socket absent. Lets try to create it
        create_socket_base_hierarchy(s, sock_addr.sun_path);
        flag = bind(sock, (struct sockaddr*)(&sock_addr), sizeof sock_addr);
    }
    
    if(flag) {
        saved_errno = errno;
        close(sock);
        errno = saved_errno;
        starter_log_error(s, errno, "%s uid:%u; gid:%u; socket bind failed", prefix,
                          target_uid, target_gid);
        return -1;
    }

    if(listen(sock, backlog) )
    {
        saved_errno = errno;
        close(sock);
        errno = saved_errno;
        starter_log_error(s, errno, "%s uid:%u; gid:%u; setsockopt failed", prefix, 
                          target_uid, target_gid);
        return -1;
    }

    return sock;
}

static void *lib_handle;

static int (*lve_enter_flags_sym)();
static int (*lve_jail_sym)();
static int (*lve_exit_sym)();
static int (*destroy_lve_sym)();

static void *struct_liblve;
static uint32_t cookie;

static int lve_entered = 0;
static const char liblve_str[] = "liblve.so.0";

static void* find_sym(const char *sym_str, char *errbuf, int errlen)
{
    void *sym = dlsym(lib_handle, sym_str);
    if(sym == NULL)
    {
        snprintf(errbuf, errlen, "cannot find %s symbol in lve library %s", sym_str, liblve_str);
    }
    return sym;
}

/*
    On success: return 1
    On fail: return -1, write description into errbuf
    When LVE is not available: return 0, write description into errbuf
*/
static int dl_init_lve(char *errbuf, int errlen) 
{
    static const char init_lve_str[] = "init_lve";
    static const char lve_enter_flags_str[] = "lve_enter_flags";
    static const char lve_jail_str[] = "lve_jail";
    static const char lve_exit_str[] = "lve_exit";
    static const char destroy_lve_str[] = "lve_exit";

    lib_handle = dlopen(liblve_str, RTLD_LAZY);
    if(!lib_handle) {
        snprintf(errbuf, errlen, "cannot open lve library %s", liblve_str);
        // it is ok though
        return 0;
    }

    void* (*init_lve_sym)() = find_sym(init_lve_str, errbuf, errlen);
    if(!init_lve_sym) {
        return -1;
    }

    lve_enter_flags_sym = find_sym(lve_enter_flags_str, errbuf, errlen);
    if(!lve_enter_flags_sym) {
        return -1;
    }

    lve_jail_sym = find_sym(lve_jail_str, errbuf, errlen);
    if(!lve_jail_sym) {
        return -1;
    }

    lve_exit_sym = find_sym(lve_exit_str, errbuf, errlen);
    if(!lve_exit_sym) {
        return -1;
    }

    destroy_lve_sym = find_sym(destroy_lve_str, errbuf, errlen);
    if(!destroy_lve_sym) {
        return -1;
    }

/*
struct liblve *init_lve(liblve_alloc alloc, liblve_free free);
*/
    struct_liblve = init_lve_sym(malloc, free);
    if(!struct_liblve) {
        snprintf(errbuf, errlen, "init_lve failed: %d", errno);
        return -1;
    }

    return 1;
}

/*
    On success: return 1
    On fail: return -1, write description into errbuf
    When LVE is not available: return 0, write description into errbuf
*/
static int dl_enter_lve(pid_t uid, char *errbuf, int errlen) {
    // LVE-less configuration, it's ok
    if(!lib_handle)
    {
        snprintf(errbuf, errlen, "LVE-less mode");
        return 0;
    }

    if(!struct_liblve || !lve_enter_flags_sym)
    {
        snprintf(errbuf, errlen, "lve library is not proper initialized");
        return -1;
    }

/*
int lve_enter_flags(struct liblve *lve,
		    uint32_t lve_id, uint32_t *cookie, enum liblve_enter_flags flags);
*/

// LVE_NO_MAXENTER flag is defined in lve-type.h
#define LVE_NO_MAXENTER (1 << 2)
    int rc = lve_enter_flags_sym(struct_liblve, uid, &cookie, LVE_NO_MAXENTER);
    if(rc == 0)
    {
        lve_entered = 1;
        return 1;
    }

    snprintf(errbuf, errlen, "lve_enter failed: %d", -rc);
    return -1;
}


/*
    On success: return 1
    On fail: return -1, write description into errbuf
    When LVE is not available or jail is disabled: return 0, write description into errbuf
*/
static int dl_jail_lve(struct passwd *pw, char *errbuf, int errlen) {
    // LVE-less configuration, it's ok
    if(!lib_handle)
    {
        snprintf(errbuf, errlen, "LVE-less mode");
        return 0;
    }

    if(!struct_liblve || !lve_jail_sym) {
        snprintf(errbuf, errlen, "lve library is not proper initialized");
        return -1;
    }

    if(lve_entered == 0) {
        snprintf(errbuf, errlen, "not in LVE");
        return 0;
    }

    char sym = errbuf[0];
    errbuf[0] = '\0';
    
/*
int lve_jail(struct passwd *pw, char * error_str);
*/
    // lve_jail signature does not contain errlen. in hope, that errlen is quite big
    int rc = lve_jail_sym(pw, errbuf);
    if(rc == 1) {
        errbuf[0] = sym;
        return 1;
    }

    if(errbuf[0] == '\0') {
        if(rc == 0) {
            snprintf(errbuf, errlen, "CageFS is disabled");
        } else {
            snprintf(errbuf, errlen, "lve_jail failed");
        }
    }
    return rc;
}


static int dl_exit_lve(void) {
    // LVE-less configuration, it's ok
    if(!lib_handle)
        return 0;

    if(!struct_liblve || !lve_exit_sym)
        return -1;
    
    if(lve_entered == 0)
        return -1;

/*
int lve_exit(struct liblve *lve, uint32_t *cookie);
*/
    int rc = lve_exit_sym(struct_liblve, &cookie);
    if(rc < 0) {
        return -1;
    }

    lve_entered = 0;

    return 0;
}


static int dl_destroy_lve(void) {
    // LVE-less configuration, it's ok
    if(!lib_handle)
        return 0;

    if(!struct_liblve || !destroy_lve_sym)
        return -1;

/*
int destroy_lve(struct liblve *lve);
*/
    int rc = destroy_lve_sym(struct_liblve);
    struct_liblve = NULL;
    lve_entered = 0;

    if(rc < 0)
        return -1;

    return 0;
}


static void dl_clean_all_lve(void) {
    dl_exit_lve();
    dl_destroy_lve();
}

static void set_signals(void)
{
    sigset_t sig_set;
    struct sigaction act = { { 0 } };

    sigemptyset(&sig_set);
    sigprocmask(SIG_SETMASK, &sig_set, NULL);

    act.sa_flags = 0;
    act.sa_handler = SIG_DFL;
    sigemptyset(&(act.sa_mask));
    sigaction(SIGCHLD, &act, NULL);
}

static int close_sockets(server_rec *s, int log_sock)
{
    static const char fd_dir_nm[] = "/proc/self/fd";
    int stdin_sock;
    int stdout_sock;
    int stderr_sock;
    int fd_sock;

    DIR *fd_dir = opendir(fd_dir_nm);
    if(!fd_dir) {
        starter_log_error(s, errno, "%s opendir(%s) failed", prefix, fd_dir_nm);
        return -1;
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

        /* non-digits in file name */
        if(cur_sock < 0) {
            continue;
        }

        if(cur_sock == stdin_sock
           || cur_sock == stdout_sock
           || cur_sock == stderr_sock
           || cur_sock == log_sock
           || cur_sock == fd_sock)     continue;

        close(cur_sock);
    }

    closedir(fd_dir);
    return 0;
}

static void make_custom_env(server_rec *s, apr_table_t *envTable, char *buf, size_t bufLen, int *envLenPtr, int *envNumPtr)
{
    const apr_array_header_t *arr = apr_table_elts(envTable);
    const apr_table_entry_t *elt = (apr_table_entry_t *)arr->elts;
    int i;
    size_t usedLen = 0;
 
    for (i = 0; i < arr->nelts; ++i) {
        size_t keyLen = strlen(elt[i].key);
        size_t valLen = strlen(elt[i].val);
        
        // no space even for current env in format KEY=VAL<NUL> - ignore all
        if(bufLen - usedLen < keyLen + valLen + 2)
            return;
        //lscapi_log(APLOG_NOTICE, 0, s, "make_custom_env: %d: key(%s); val(%s); len %lu/%lu", 
        //           i, elt[i].key, elt[i].val, usedLen, bufLen);
        memcpy(buf+usedLen, elt[i].key, keyLen); usedLen += keyLen;
        buf[usedLen++] = '=';
        memcpy(buf+usedLen, elt[i].val, valLen+1); usedLen += valLen+1;
    }
    *envLenPtr = usedLen;
    *envNumPtr = arr->nelts;
}

void lscapi_spawn_lsphp(server_rec *s, spawn_info_t *spawn_info, int log_sock)
{
    uid_t real_uid;         /* real user information     */
    uid_t target_uid;       /* target user information   */
    gid_t target_gid;       /* target group placeholder  */
    char *target_homedir;   /* target home directory     */
    char *actual_uname;     /* actual user name          */
    char *actual_gname;     /* actual group name         */
    char cwd[SULSPHP_MAXPATH];   /* current working directory */
    char dwd[SULSPHP_MAXPATH];   /* docroot working directory */
    struct stat dir_info;   /* directory info holder     */
    struct stat prg_info;   /* program info holder       */
    char errbuf[BUFSIZE];
    char custom_env[2048];
    int envLen = 0, envNum = 0;
    int rc;

    char real_pw_storage[16384];
    char target_pw_storage[16384];
    char target_gr_storage[16384];
    struct passwd real_pw;
    struct passwd target_pw;
    struct group target_gr;
    struct passwd *indicator_pw;
    struct group *indicator_gr; 

    /* inherited sigmask can be very confused */
    set_signals();

    lsapi_svr_conf_t *cfg = lsapi_get_svr_config(s);

    make_custom_env(s, cfg->envTable, custom_env, sizeof custom_env, &envLen, &envNum);
    
    const char *path = cfg->backend_env_path ? cfg->backend_env_path : SULSPHP_SAFE_PATH;

    char **lsphpEnv = lscapi_prepare_env(spawn_info, custom_env, envLen, envNum, path, errbuf, sizeof errbuf);
    if(lsphpEnv == NULL) {
        starter_log_error(s, errno, "%s prepare_env failed: %s", prefix, errbuf);
        dl_clean_all_lve();
        exit(101);
    }
    char **oldEnv = environ;
    environ = lsphpEnv;

#ifdef SULSPHP_UMASK
    /*
     * umask() uses inverse logic; bits are CLEAR for allowed access.
     */
    umask(SULSPHP_UMASK);
#endif /* SULSPHP_UMASK */

    real_uid = getuid();

    /*
       Switch euid to super-user due to saved-user-id
    */
    if (setresuid(-1, 0, -1) != 0) {
        starter_log_error(s, errno, "%s setreuid(-1, 0, -1) failed", prefix);
        dl_clean_all_lve();
        exit(102);
    }

    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     */
    rc = getpwuid_r(real_uid, &real_pw, real_pw_storage, sizeof real_pw_storage, &indicator_pw);
    if(rc != 0)
    {
        starter_log_error(s, rc, "%s could not get user info uid:(%"APR_PID_T_FMT")", prefix, real_uid);
        dl_clean_all_lve();
        exit(103);
    }

    if(indicator_pw == NULL)
    {
        starter_log_error(s, -1, "%s invalid uid:(%"APR_PID_T_FMT")", prefix, real_uid);
        dl_clean_all_lve();
        exit(103);
    }

    rc = dl_init_lve(errbuf, sizeof errbuf);
    if(rc < 0) {
        starter_log_error(s, -1, "%s LVE initialization error: %s", prefix, errbuf);
        dl_clean_all_lve();
        exit(104);
    }
    if(rc == 0) {
        starter_log_error(s, 0, "%s LVE initialization warning: %s", prefix, errbuf);
    }

    target_uid = spawn_info->uid;
    target_gid = spawn_info->gid;

    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * sulsphp.h.  If not the allowed user, error out.
     */
    if (strcmp(SULSPHP_HTTPD_USER, real_pw.pw_name)) {
        starter_log_error(s, -1, "%s user mismatch (%s instead of %s)", prefix, real_pw.pw_name, SULSPHP_HTTPD_USER);
        dl_clean_all_lve();
        exit(106);
    }

    /*
     * Check for an allowable command.
     */
    size_t allowed_cmd_len = strlen(SULSPHP_ALLOWED_CMD);
    size_t cmd_len = strlen(spawn_info->cmd);
    if( (cmd_len < (allowed_cmd_len+1))
       || (spawn_info->cmd[cmd_len - allowed_cmd_len - 1] != '/')
       ||  strncmp(spawn_info->cmd + cmd_len - allowed_cmd_len, SULSPHP_ALLOWED_CMD, allowed_cmd_len) )
    {
        starter_log_error(s, -1, "%s uid:%u; gid:%u; invalid command (%s)", prefix, 
                          target_uid, target_gid, 
                          spawn_info->cmd );
        dl_clean_all_lve();
        exit(107);
    }

    /*
     * Check for an allowable (or safe) directory.
     */
    size_t safe_dir_len = strlen(SULSPHP_SAFE_DIR);
    size_t cpanelsafe_dir_len = strlen(SULSPHP_CPANELSAFE_DIR);
    size_t allowed_dir_len = strlen(SULSPHP_ALLOWED_DIR);
    if( ( (cmd_len != allowed_dir_len + allowed_cmd_len + 1)
            || strncmp(spawn_info->cmd, SULSPHP_ALLOWED_DIR, allowed_dir_len)
            || (spawn_info->cmd[allowed_dir_len] != '/') )
     && ( (cmd_len < safe_dir_len + allowed_cmd_len + 1)
            || strncmp(spawn_info->cmd, SULSPHP_SAFE_DIR, safe_dir_len)
            || (spawn_info->cmd[safe_dir_len] != '/') )
    && ( (cmd_len < cpanelsafe_dir_len + allowed_cmd_len + 1)
            || strncmp(spawn_info->cmd, SULSPHP_CPANELSAFE_DIR, cpanelsafe_dir_len)
            || (spawn_info->cmd[cpanelsafe_dir_len] != '/') ) )
    {
        starter_log_error(s, -1, "%s uid:%u; gid:%u; invalid command (%s)", prefix, 
                          target_uid, target_gid, 
                          spawn_info->cmd );
        dl_clean_all_lve();
        exit(108);
    }

    /*
     * Check for attempts to back up in directory tree,
     */
    if (strstr(spawn_info->cmd, "/../"))
    {
        starter_log_error(s, -1, "%s invalid command (%s)", prefix, spawn_info->cmd );
        dl_clean_all_lve();
        exit(109);
    }

    rc = getpwuid_r(target_uid, &target_pw, target_pw_storage, sizeof target_pw_storage, &indicator_pw);
    if(rc != 0)
    {
        starter_log_error(s, rc, "%s could not get target user info:%d", prefix, target_uid);
        dl_clean_all_lve();
        exit(111);
    }

    if(indicator_pw == NULL)
    {
        starter_log_error(s, -1, "%s invalid target user id:%d", prefix, target_uid);
        dl_clean_all_lve();
        exit(111);
    }

    
    if(dl_enter_lve(target_pw.pw_uid, errbuf, sizeof errbuf) < 0) {
        starter_log_error(s, -1, "%s uid:%u; gid:%u; entering lve error: %s", prefix,
                          target_uid, target_gid, errbuf);
        dl_clean_all_lve();
        exit(112);
    }

    rc = getgrgid_r(target_gid, &target_gr, target_gr_storage, sizeof target_gr_storage, &indicator_gr);
    if(rc != 0)
    {
        starter_log_error(s, rc, "%s could not get target group info:%d", prefix, target_gid);
        dl_clean_all_lve();
        exit(114);
    }

    if(indicator_gr == NULL)
    {
        starter_log_error(s, -1, "%s invalid target group id:%d", prefix, target_gid);
        dl_clean_all_lve();
        exit(114);
    }


    if ((actual_gname = strdup(target_gr.gr_name)) == NULL) {
        starter_log_error(s, -1, "%s uid:%u; gid:%u; failed to alloc memory", prefix,
                          target_uid, target_gid);
        dl_clean_all_lve();
        exit(115);
    }

    /*
     * Save these for later since initgroups will hose the struct
     */
    actual_uname = strdup(target_pw.pw_name);
    target_homedir = strdup(target_pw.pw_dir);
    if (actual_uname == NULL || target_homedir == NULL) {
        starter_log_error(s, -1, "%s uid:(%u/%s); gid:(%u/%s); failed to alloc memory", prefix,
                          target_uid, actual_uname, target_gid, actual_gname);
        dl_clean_all_lve();
        exit(116);
    }

    /*
     * Error out if attempt is made to execute as root or as
     * a UID less than SULSPHP_UID_MIN.
     * Though default good known apache and nobody uids are allowed.
     */
    if ( (target_uid == 0) ||
         ( (target_uid != APACHE_DEFAULT_UID) &&
           (target_uid != NOBODY_DEFAULT_UID) &&
           (target_uid < SULSPHP_UID_MIN) )
    ) {
        starter_log_error(s, -1, "%s cannot run as forbidden uid (%"APR_PID_T_FMT"/%s)", prefix, target_uid, spawn_info->cmd);
        dl_clean_all_lve();
        exit(117);
    }

    /*
     * Error out if attempt is made to execute as root group
     * or as a GID less than SULSPHP_GID_MIN.
     * Though default good known apache and nobody gids are allowed.
     */
    if ( (target_gid == 0) ||
         ( (target_gid != APACHE_DEFAULT_GID) &&
           (target_gid != NOBODY_DEFAULT_GID) &&
           (target_gid < SULSPHP_GID_MIN) )
    ) {
        starter_log_error(s, -1, "%s cannot run as forbidden gid (%"APR_PID_T_FMT"/%s)", prefix, target_gid, spawn_info->cmd);
        dl_clean_all_lve();
        exit(118);
    }

    /*
     *  Switch to real user (nobody) to open socket.
     */
     if (setresuid(-1, real_uid, -1) != 0) {
        starter_log_error(s, errno, "%s setreuid(-1, %"APR_PID_T_FMT", -1) failed", prefix, real_uid);
        dl_clean_all_lve();
        exit(119);
     }

     /*
      * Close all sockets except stdin, stdout, stderr
     */
     if(close_sockets(s, log_sock) != 0) {
        dl_clean_all_lve();
        exit(120);
     }

     /*
      *  Create a listen socket.
      */
     int sock = create_listen_socket(s, spawn_info->socket_name, 10, target_uid, target_gid);
     if(sock < 0) {
        dl_clean_all_lve();
        exit(121);
     }
     dup2(sock, 0);
     close(sock);
     
#ifdef WITH_CRIU
    /*
     * Prepare criu-related stuff
     */
    if(spawn_info->use_criu) {
        if (lscapi_prepare_dump(spawn_info, errbuf, sizeof errbuf) != 0) {
            lscapi_log(APLOG_WARNING, errno, s,
                    "%s uid:(%u/%s); gid:(%u/%s); prepare dump for CRIU: %s - ignore", prefix, 
                    target_uid, actual_uname, target_gid, actual_gname, 
                    errbuf);
        }
    }
#endif //WITH_CRIU


    /*
     *  Switch back to superuser.
     */
     if (setresuid(-1, 0, -1) != 0) {
        starter_log_error(s, errno, "%s uid:(%u/%s); gid:(%u/%s); setreuid(-1, 0, -1) failed", prefix,
                          target_uid, actual_uname, target_gid, actual_gname );
        dl_clean_all_lve();
        exit(122);
     }

     /*
      *  Reopen stderr if needed
      */
     if(spawn_info->use_own_log) {
        char stderr_fname[128];
        ssize_t len = readlink("/proc/self/fd/2", stderr_fname, sizeof stderr_fname - 1);
        stderr_fname[len] = '\0';  // readlink do not write it

        char *stderr_dirname = dirname(stderr_fname);
        char fname[256];
        snprintf(fname, sizeof fname, "%s/lsphp-%d-stderr.log", stderr_dirname, target_uid);
        int outsock = open(fname, O_WRONLY | O_APPEND | O_CREAT, 
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(outsock < 0) {
            starter_log_error(s, errno, "%s uid:(%u/%s); gid:(%u/%s); open(%s) failed", prefix, 
                              target_uid, actual_uname, target_gid, actual_gname, 
                              fname);
            dl_clean_all_lve();
            exit(139);
        }
        dup2(outsock, 2);
        close(outsock);
     }

    /* Entering into jail */
    rc = dl_jail_lve(&target_pw, errbuf, sizeof errbuf); 
    if(rc < 0)
    {
        starter_log_error(s, errno, "%s uid:(%u/%s); gid:(%u/%s); entering jail error: %s", prefix,
                          target_uid, actual_uname, target_gid, actual_gname, errbuf);
        dl_clean_all_lve();
        exit(123);
    }
    
    if(rc == 0)
    {
       starter_log_error(s, -1, "%s uid:(%u/%s); gid:(%u/%s); entering jail warning: %s", prefix,
                          target_uid, actual_uname, target_gid, actual_gname, errbuf);
    }

    if(spawn_info->use_suexec)
    {

        /*
         * Change UID/GID here so that the following tests work over NFS.
         *
         * Initialize the group access list for the target user,
         * and setgid() to the target group. If unsuccessful, error out.
         */
        if (((setgid(target_gid)) != 0) || (initgroups(actual_uname, target_gid) != 0)) {
            starter_log_error(s, errno, "%s setgid(%"APR_PID_T_FMT") failed", prefix, target_gid);
            dl_clean_all_lve();
            exit(124);
        }

        /*
         * setuid() to the target user.  Error out on fail.
         */
        // Do not forget to remove supeuser privs in saved set-user-ID
        if ((setresuid(target_uid, target_uid, target_uid)) != 0) {
            starter_log_error(s, errno, "%s setreuid(%"APR_PID_T_FMT", %"APR_PID_T_FMT", %"APR_PID_T_FMT") failed", 
                    prefix, target_uid, target_uid, target_uid);
            dl_clean_all_lve();
            exit(125);
        }

    } else //if(spawn_info->use_suexec)
    {

        /*
         * setuid() to the real user.  Error out on fail.
         */
        // Do not forget to remove supeuser privs in saved set-user-ID
        if ((setresuid(real_uid, real_uid, real_uid)) != 0) {
            starter_log_error(s, errno, "%s setreuid(%"APR_PID_T_FMT", %"APR_PID_T_FMT", %"APR_PID_T_FMT") failed", 
                    prefix, real_uid, real_uid, real_uid);
            dl_clean_all_lve();
            exit(138);
        }

    } //else of if(spawn_info->use_suexec)

    /*
     * Get the current working directory, as well as the proper
     * document root. Error out if we cannot get either one,
     * or if the current working directory is not in the docroot.
     * Use chdir()s and getcwd()s to avoid problems with symlinked
     * directories.  Yuck.
     */
    if (getcwd(cwd, SULSPHP_MAXPATH) == NULL) {
        starter_log_error(s, errno, "%s uid:(%u/%s); gid:(%u/%s); getcwd failed", prefix,
                          target_uid, actual_uname, target_gid, actual_gname );
        dl_clean_all_lve();
        exit(126);
    }

    if (((chdir(SULSPHP_DOC_ROOT)) != 0) ||
        ((getcwd(dwd, SULSPHP_MAXPATH)) == NULL) ||
        ((chdir(cwd)) != 0)) {

        starter_log_error(s, -1, "%s uid:(%u/%s); gid:(%u/%s); cannot get docroot information (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          SULSPHP_DOC_ROOT);
        dl_clean_all_lve();
        exit(127);
    }

    /*
     * Stat the cwd, or error out.
     */
    if (lstat(cwd, &dir_info) != 0) {
        starter_log_error(s, errno, "%s uid:(%u/%s); gid:(%u/%s); cannot stat cwd: (%s)", prefix, 
                         target_uid, actual_uname, target_gid, actual_gname, 
                          cwd);
        dl_clean_all_lve();
        exit(128);
    }

    /*
     * Verify the cwd is a directory, or error out.
     */
    if (!(S_ISDIR(dir_info.st_mode))) {
        starter_log_error(s, -1, "%s uid:(%u/%s); gid:(%u/%s); cwd is not a dir: (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          cwd);
        dl_clean_all_lve();
        exit(129);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
        starter_log_error(s, -1, "%s uid:(%u/%s); gid:(%u/%s); cwd is writable by group or others: (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          cwd);
        dl_clean_all_lve();
        exit(130);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if (stat(spawn_info->cmd, &prg_info) != 0) {
        starter_log_error(s, errno, "%s uid:(%u/%s); gid:(%u/%s); cannot stat program: (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          spawn_info->cmd);
        dl_clean_all_lve();
        exit(131);
    }

    /*
     * Error out if the program is writable by others.
     */
    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP)) {
        starter_log_error(s, -1, "%s uid:(%u/%s); gid:(%u/%s); program is writable by group or others: (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          spawn_info->cmd);
        dl_clean_all_lve();
        exit(132);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
        starter_log_error(s, -1, "%s  uid:(%u/%s); gid:(%u/%s); program is either setuid or setgid: (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          spawn_info->cmd);
        dl_clean_all_lve();
        exit(133);
    }

    /*
     * Error out if the program is not executable for the user.
     * Otherwise, she won't find any error in the logs except for
     * "[error] Premature end of script headers: ..."
     */
    if (!(prg_info.st_mode & S_IXUSR)) {
        starter_log_error(s, -1, "%s  uid:(%u/%s); gid:(%u/%s); program has no execute permission: (%s)", prefix, 
                          target_uid, actual_uname, target_gid, actual_gname, 
                          spawn_info->cmd);
        dl_clean_all_lve();
        exit(134);
    }

    for(char *ptr = spawn_info->cmd+1; *ptr; ptr++) {
        if(*ptr == '/') {
            *ptr = '\0';
            if( (stat(spawn_info->cmd, &dir_info) != 0) || !(S_ISDIR(dir_info.st_mode))
               || (dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP) ) {

                starter_log_error(s, -1, "%s  uid:(%u/%s); gid:(%u/%s); path to program is writable by group or others: (%s)", 
                                  prefix, 
                                  target_uid, actual_uname, target_gid, actual_gname, 
                                  spawn_info->cmd);
                dl_clean_all_lve();
                exit(135);
            }
            *ptr = '/';
        }
    }

    starter_log_error(s, 0, "%s uid:(%u/%s); gid:(%u/%s); %s suexec mode; cmd:(%s)", prefix,
                    target_uid, actual_uname, target_gid, actual_gname, 
                    spawn_info->use_suexec ? "with" : "without", spawn_info->cmd);

    /*
        Such a tricky method needed to make LVE memory limits work properly.
    */
    pid_t pid = fork();
    if(pid < 0) {
        starter_log_error(s, errno, "%s fork failed", prefix);
        dl_clean_all_lve();
        exit(136);
    }

    if(pid > 0) {
        dl_clean_all_lve();
        exit(0);
    }

    setsid();

    execl(spawn_info->cmd, spawn_info->cmd, NULL);
    starter_log_error(s, errno, "%s execl(%s) failed", prefix, spawn_info->cmd);
    /* It very seems that log is already closed, so write also into stderr */
    fprintf(stderr, "execl(%s) failed: %d(%s)\n", spawn_info->cmd, errno, strerror(errno));
    dl_clean_all_lve();
    environ = oldEnv; // to supress compiler warning only
    exit(137);
}
