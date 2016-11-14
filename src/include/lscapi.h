/*
 * Copyright 2014-2015 Cloud Linux Zug GmbH
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * The part the support library for lsapi & proxy_lsapi Apache modules
 * author Alexander Demeshko <ademeshko@cloudlinux.com>
 *
 * Here you define exportable functions for libscapi clients.
 */

#ifndef _LSCAPI_H_
#define _LSCAPI_H_

#ifdef LSCAPI_DEFAULT_SOCKET_PATH
#undef LSCAPI_DEFAULT_SOCKET_PATH
#endif
#ifdef LSCAPI_DEFAULT_SOCKET_BASE
#undef LSCAPI_DEFAULT_SOCKET_BASE
#endif
#ifdef LSCAPI_DEFAULT_SOCKET_DIR
#undef LSCAPI_DEFAULT_SOCKET_DIR
#endif

#define LSCAPI_DEFAULT_SOCKET_BASE "/var/run"
#define LSCAPI_DEFAULT_SOCKET_DIR "mod_lsapi"
#define LSCAPI_DEFAULT_SOCKET_PATH LSCAPI_DEFAULT_SOCKET_BASE "/" LSCAPI_DEFAULT_SOCKET_DIR

#include <sys/uio.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <lsapidef.h>
#include <lscapi_config.h>

#include <sha1.h>

#define LSCAPI_SECRET_SIZE 16
#define LSCAPI_SALT_SIZE 16
#define LSCAPI_SHA1_SIGN_SIZE (LSCAPI_SALT_SIZE + SHA1_DIGEST_SIZE)
#define LSCAPI_ENCODED_SHA1_SIGN_SIZE (2*LSCAPI_SHA1_SIGN_SIZE + 1)
#define LSCAPI_ENCODED_SHA1_SIGN_WITHOUT_SALT_SIZE (2*SHA1_DIGEST_SIZE + 1)

enum {
    PFL_RESEND_IF_CRASHED = 0,

    PFL_SOCKET_FAILED,

    PFL_BACKEND_CONNECT_FATAL_ERROR,
    PFL_BACKEND_WARM_CONNECT,
    PFL_BACKEND_WARM_CONNECT_MS,
    PFL_BACKEND_COLD_CONNECT,
    PFL_BACKEND_COLD_CONNECT_MS,
    PFL_BACKEND_CONNECT_FAILED,

    PFL_BACKEND_SPAWN_FAILED,
    PFL_BACKEND_SPAWN_SUCCESS,
    PFL_BACKEND_SPAWN_DELAYED,


/*
    PFL_MODLS_NORM_REQ_MS,          // 0
    PFL_MODLS_NORM_REQ_NUM,         // 0
    PFL_MODLS_REQ_HAS_BODY_MS,      // 0
    PFL_MODLS_REQ_HAS_BODY_NUM,     // 0
    PFL_MODLS_REQ_WO_BODY_MS,       // 0
    PFL_MODLS_REQ_WO_BODY_NUM,      // 0
*/
    PFL_LAST
};

#ifdef WITH_LIBPERFLOG
#include <perf_log.h>

extern pfl_handle_t* lsapi_perf_handle;
void lsapi_init_libperflog(void);

static inline void lsapi_perf_inc(int event_id)
{
    perf_inc(lsapi_perf_handle, event_id);
}

static inline void lsapi_perf_add(int event_id, pfl_event_count_t diff)
{
    perf_add(lsapi_perf_handle, event_id, diff);
}

#else //WITH_LIBPERFLOG

#define lsapi_perf_inc(event_id)
#define lsapi_perf_add(event_id, diff)

#endif //WITH_LIBPERFLOG


// lsapi structs
typedef struct lsapi_req_header lsapi_req_header_t;
typedef struct lsapi_http_header_index lsapi_http_header_index_t;
typedef struct lsapi_header_offset lsapi_header_offset_t;
typedef struct lsapi_packet_header lsapi_packet_header_t;
typedef struct lsapi_resp_info lsapi_resp_info;

// lscapi opaque structures
struct lscapi_rec;
struct lsphp_conn_t;

typedef struct lscapi_rec lscapi_rec;
typedef struct lsphp_conn_t lsphp_conn_t;

// allocator function pointer type
typedef void *(*lscapi_alloc_fn)(size_t size, void *user_data);

typedef long (*lscapi_user_get_body_fn)(char *buf, size_t bufLen, void *user_data);

typedef int (*lscapi_should_get_block_fn)(void *user_data);

typedef void (*lscapi_log_fn)(const char *file, int line, int level, int errcode,
                                const void *user_data, const char *fmt, ...);

typedef void (*lscapi_random_fn)(void *buf, size_t size);

typedef void* (*lscapi_lve_alloc_t)(size_t sz, void* user_data);
typedef void (*lscapi_lve_register_t)(void* user_data, void* data, int (*destroy_fn)());


struct lscapi_var_t {
    const char *key;
    int keyLen;
    const char *val;
    int valLen;
    int perdir;
};
typedef struct lscapi_var_t lscapi_var_t;


struct lscapi_header_index_t {
    unsigned keyOff;
    unsigned keyLen;
    unsigned valOff;
    unsigned valLen;
};
typedef struct lscapi_header_index_t lscapi_header_index_t;


struct lscapi_resphdr_info_t {
    char buf[LSAPI_MAX_DATA_PACKET_LEN];
    size_t dataLen;
    uint16_t *hdrSizes;
    int hdrNum;
    int respStatus;
};
typedef struct lscapi_resphdr_info_t lscapi_resphdr_info_t;


struct lscapi_backend_info_t {
    uint32_t connect_tries;
    uint32_t connect_timeout;

    uint32_t backend_children;
    uint32_t backend_pgrp_max_idle;
    uint32_t backend_max_idle;
    uint32_t backend_max_process_time;
    uint32_t backend_max_reqs;

    uint32_t poll_timeout;

    unsigned backend_coredump: 1;
    unsigned dump_backend_debug_info: 1;
    unsigned use_suexec: 1;
    unsigned per_user: 1;

    unsigned backend_coredump_was_set: 1;
    unsigned dump_backend_debug_info_was_set: 1;
    unsigned use_suexec_was_set: 1;
    unsigned per_user_was_set: 1;

    /*
        Define these fields unconditionally though they will be used in fact 
        only when compiled with -DWITH_CRIU flag
    */
    unsigned use_criu: 1;
    unsigned use_criu_was_set: 1;
    
    unsigned use_own_log: 1;
    unsigned use_own_log_was_set: 1;

    uint32_t max_resend_buffer_kb;
    unsigned max_resend_buffer_was_set: 1;
};
typedef struct lscapi_backend_info_t lscapi_backend_info_t;


#define LSCAPI_PATH_MAX 64
/*
 struct sockaddr_un in <sys/un.h> contains integer constant
 instead of promised by unix(7) UNIX_PATH_MAX
 So we will use our own macro.
*/
#define LSCAPI_SOCKET_MAX 108
typedef struct spawn_info_t {
    unsigned backend_children;
    unsigned backend_pgrp_max_idle;
    unsigned backend_max_idle;
    unsigned backend_max_process_time;
    unsigned backend_max_reqs;
    uid_t uid;
    gid_t gid;
    unsigned backend_coredump: 1;
    unsigned dump_backend_debug_info: 1;
    unsigned use_suexec: 1;
    unsigned backend_accept_notify: 1;
    unsigned use_own_log: 1;
    /*
        Define these fields unconditionally though they will be used in fact 
        only when compiled with -DWITH_CRIU flag
    */
    unsigned use_criu: 1;
    char phprc[LSCAPI_PATH_MAX];
    char cmd[LSCAPI_PATH_MAX];
    char socket_name[LSCAPI_SOCKET_MAX];
    /*
        Define these fields unconditionally though they will be used in fact 
        only when compiled with -DWITH_CRIU flag
    */
    char criu_socket_name[LSCAPI_SOCKET_MAX];
    char criu_images_dir[LSCAPI_PATH_MAX];
} spawn_info_t;


typedef pid_t (*lscapi_spawn_backend_fn)(const spawn_info_t *spawn_info,
                                         void *user_data, int force_start);

// Event masks
#define LSCAPI_BACKEND_LOG_RECEIVED    (1u << 0)
#define LSCAPI_RESPONSE_FINISHED       (1u << 1)
#define LSCAPI_BACKEND_LOG_FATAL       (1u << 2)
#define LSCAPI_SENDREQ_INTERNAL_ERROR  (1u << 3)
#define LSCAPI_SENDREQ_BACKEND_ERROR   (1u << 4)
#define LSCAPI_SENDREQ_CLIENT_ERROR    (1u << 5)

enum lscapi_create_flags {
	LSCAPI_CREATE_WITH_LVE	= 1 << 0,
	LSCAPI_OUT_ALREADY_INSIDE_LVE	= 1 << 16,
	LSCAPI_OUT_RESOURCE_LIMIT_LVE	= 1 << 17,
};

int lscapi_init(char *errbuf, size_t errlen);
void lscapi_child_init(lscapi_alloc_fn user_alloc, void *user_data);

const char* lscapi_get_backend(const char *handler);

/**
 * create opaque structure to store connection to lsphp on logical level
 * args:
 * user_alloc = pointer to allocator function
 * user_data = arbitrary user data to pass to allocator function
 * uid = uid for suexec and lve
 * gid = gid for suexec and lve
 * flags =
 * errbuf = buffer to store error description on error
 * errlen = length of the error buffer
 * return codes:
 * allocated and initialized structure = on success, NULL on error
 */
lscapi_rec *lscapi_create(lscapi_alloc_fn user_alloc,
                          lscapi_log_fn user_log,
                            void *user_data,
                            uint32_t uid, uint32_t gid,
                            unsigned *flagsPtr,
                            char *errbuf, unsigned errlen);


/**
 * close connection to lsphp on logical level
 * args:
 * lscapi = opaque structure created with lscapi_create
 */
void lscapi_destroy(lscapi_rec *lscapi);

/**
 * return codes:
 * 0 = on success, -1 on error and sets appropriate flag on eventMaskPtr
 */
int lscapi_send_request(lsphp_conn_t *conn, unsigned *eventMaskPtr,
                        char *errbuf, unsigned errlen);

void lscapi_set_socket_path(lscapi_rec *lscapi, char *socket_path);
void lscapi_set_phprc(lscapi_rec *lscapi, const char *phprc);

void lscapi_set_user_body_info(lscapi_rec *lscapi, size_t body_len,
                               lscapi_user_get_body_fn user_get_body,
                               lscapi_should_get_block_fn user_should_get_block);

void lscapi_set_use_request_scope_buffer(lscapi_rec *lscapi, bool value);

size_t lscapi_get_body_len(lscapi_rec *lscapi);

void lscapi_set_header_info(lscapi_rec *lscapi,
                            lsapi_http_header_index_t *hdrIndexPtr,
                            lsapi_header_offset_t *hdrOffsets,
                            size_t hdrOffsetsNum,
                            char *httpHeader,
                            size_t httpHeaderLen);

void lscapi_set_envs(lscapi_rec *lscapi, lscapi_var_t *envs, int envNum);
void lscapi_set_special_envs(lscapi_rec *lscapi, lscapi_var_t *specialEnvs, int specialEnvNum);

void lscapi_set_backend_path(lscapi_rec *lscapi,
                             const char *handler,
                             const char *backend_path);

void lscapi_set_debug_enabled(lscapi_rec *lscapi, int debug_enabled);

void lscapi_set_error(lscapi_rec *lscapi);
void lscapi_set_recoverable_error(lscapi_rec *lscapi);
bool lscapi_get_error(const lscapi_rec *lscapi, bool *outIsRecoverableError);
void lscapi_reset_internal_error_state(lscapi_rec *lscapi);

void lscapi_set_random(lscapi_rec *lscapi, lscapi_random_fn get_random_bytes);

void lscapi_set_user_spawn_backend(lscapi_rec *lscapi, lscapi_spawn_backend_fn user_spawn_backend);

void lscapi_set_accept_notify(lscapi_rec *lscapi, int accept_notify);

void lscapi_set_domain(lscapi_rec *lscapi,
                        const char *domain);

void lscapi_set_tmpdir(lscapi_rec *lscapi, const char *tmpdir);

/*
DEPRECATED
*/
const char* lscapi_get_backend_log(lscapi_rec *lscapi);

// lsphp stuff

void lscapi_init_backend_info(lscapi_backend_info_t *infoPtr);
void lscapi_merge_backend_info(lscapi_backend_info_t *base, lscapi_backend_info_t *cur, lscapi_backend_info_t *merged);

lsphp_conn_t* lscapi_acquire_lsphp_conn(lscapi_rec *lscapi, char *errbuf, unsigned errlen);

void lscapi_release_lsphp_conn(lsphp_conn_t *conn);

/*
   This function creates a safe environment for spawning new lsphp process.
   Memory for this is allocated with call to calloc and calls to strdup.
   So this function is intended to be called just after call to fork from within a child process and just before call to exec.
   DO NOT USE it otherwise to avoid memory leaks.
*/
/* DEPRECATED */
int lscapi_prepare_env_for_lsphp(spawn_info_t *spawn_info, const char *customEnv, int envLen, int envNum, const char *safePath, char *errbuf, unsigned errlen);

/*
   This function creates a safe environment for spawning new lsphp process.
   Memory for this is allocated with call to calloc and calls to strdup.
   So this function is intended to be called just after call to fork from within a child process and just before call to exec.
   DO NOT USE it otherwise to avoid memory leaks.
*/
char** lscapi_prepare_env(spawn_info_t *spawn_info, const char *customEnv, int envLen, int envNum, const char *safePath, char *errbuf, unsigned errlen);

int lscapi_lsphp_conn_get_socket(lsphp_conn_t *conn);

int lscapi_is_socket_closed(int sock);


/*
    DEPRECATED
    Do nothing. For compatibility with mod_lsapi ver. 0.2 only.
*/
void lscapi_set_userdir(lscapi_rec *lscapi, int userdir);

/*
    DEPRECATED
    Do nothing. For compatibility with mod_lsapi ver. 0.2 only.
*/
void lscapi_set_backend_coredump(lscapi_rec *lscapi, int coredump_enabled);

/*
    DEPRECATED
    Do nothing. For compatibility with mod_lsapi ver. 0.2 only.
*/
void lscapi_terminate_backends(void);


/*
    DEPRECATED
*/
int lscapi_determine_conn_lsphp(lsphp_conn_t *conn,
                                lscapi_backend_info_t *backendInfoPtr,
                                char *errbuf, unsigned errlen);

int lscapi_determine_conn_lsphp_ex(lsphp_conn_t *conn,
                                    lscapi_backend_info_t *backendInfoPtr,
                                    const char *sockName,
                                    char *errbuf, unsigned errlen);

int lscapi_connect_lsphp(lsphp_conn_t *conn, char *errbuf, unsigned errlen);

const char *lscapi_conn_get_socket_name(lsphp_conn_t *conn);

void lscapi_lsphp_use_sock(lsphp_conn_t *conn, int sock, char *errbuf, unsigned errlen);

int lscapi_receive_response_header(lsphp_conn_t *conn,
                                   lscapi_resphdr_info_t *hdrInfoPtr,
                                   unsigned *eventMaskPtr,
                                   char *errbuf, unsigned errlen);

int lscapi_receive_response_chunk(lsphp_conn_t *conn,
                                  char *buf, size_t *lenPtr,
                                  unsigned *eventMaskPtr,
                                  char *errbuf, unsigned errlen);

// lve.c
/**
 * load LVE library by dlopen and initialize it
 * args:
 * lve_alloc = pointer to function to allocate memory
 * lve_register = pointer to function to register allocated block
 * lve_user_data = user data for lve_alloc and lve_register calls
 * errbuf = buffer to store error description on error
 * errlen = length of the error buffer
 * return codes:
 * 0 = on success, -1 on error
 */
int lscapi_load_lve(lscapi_lve_alloc_t lve_alloc,
                    lscapi_lve_register_t lve_register,
                    void *lve_user_data,
                    char *errbuf, int errlen);

/**
 * check whether lscapi_load_lve was successfully called previously
 * return codes:
 * 1 = in case of success, 0 otherwise
 */
int lscapi_is_lve_loaded(void);


/*
    socket_path - sockets with patterns lsapi_*.sock in this directory will be deleted after stop of backends
*/
void lscapi_terminate_backends_ex(const char *socket_path);


#ifdef WITH_CRIU
/*
    socket_path - sockets matched to pattern lsapi_*.sock in this directory will be deleted after stop of backends
    criu_imgs_dir_path - subdirectories matched to pattern lsapi_*_criu_imgs in this directory will be deleted after stop of backends
*/
void lscapi_terminate_backends_criu(const char *socket_path, const char *criu_imgs_dir_path);
#endif

void lscapi_sign_uidgid_md5(lscapi_rec *lscapi, const uint32_t ids[2],
                            const uint8_t salt[LSCAPI_SALT_SIZE],
                            unsigned char sign[32]);

void lscapi_sign_uidgid_sha1(lscapi_rec *lscapi, const uint32_t ids[2],
                             const uint8_t salt[LSCAPI_SALT_SIZE],
                             uint8_t sign[LSCAPI_SHA1_SIGN_SIZE]);

void lscapi_sign_string_sha1(lscapi_rec *lscapi, const char *to_sign,
                             const uint8_t salt[LSCAPI_SALT_SIZE],
                             uint8_t sign[LSCAPI_SHA1_SIGN_SIZE]);

void lscapi_encode_bytes(const uint8_t *bytes, size_t len, char *buf);

void lscapi_encode_sha1_sign_without_salt(const uint8_t sign[LSCAPI_SHA1_SIGN_SIZE], char *buf);


#ifdef WITH_CRIU
void lscapi_set_criu_socket_path(lscapi_rec *lscapi, char *criu_socket_path);
void lscapi_set_criu_imgs_dir_path(lscapi_rec *lscapi, char *criu_imgs_dir_path);

pid_t lscapi_restore(spawn_info_t *spawn_info, char *errbuf, unsigned errlen);
int lscapi_prepare_dump(spawn_info_t *spawn_info, char *errbuf, unsigned errlen);
void lscapi_dump(void);
#endif //WITH_CRIU


#define LSCAPI_PROC_CREATE_EXPORTED
pid_t lscapi_proc_create(const char * const *args,
                         const char * const *env );


/*
#define PROFILE_ENABLED
#ifndef PROFILE_LOG
#define PROFILE_LOG
#endif
*/

#ifdef PROFILE_ENABLED

#include <sys/time.h>
#include <sys/resource.h>

extern __thread int PROFILE_counter;
extern char *PROFILE_margins[];
#ifdef PROFILE_LOG

#define PROFILE_START(pr) \
    static __thread struct timeval pr##_U##__LINE__, pr##_S##__LINE__; \
    static __thread int32_t pr##_CUMU##__LINE__, pr##_CUMS##__LINE__; \
    static __thread int pr##_CNT##__LINE__; \
    static __thread int pr##_ENTERED##__LINE__; \
do { \
    struct rusage ruse; \
    getrusage(RUSAGE_THREAD, &ruse); \
    pr##_U##__LINE__ = ruse.ru_utime; \
    pr##_S##__LINE__ = ruse.ru_stime; \
    (pr##_CNT##__LINE__)++; \
    if(!((pr##_CNT##__LINE__) % 100))  {  \
        fprintf(stderr, "%s%s.%d: " #pr ": ENTER\n", \
                PROFILE_margins[PROFILE_counter], __FUNCTION__, __LINE__ ); \
        PROFILE_counter++; \
        pr##_ENTERED##__LINE__ = 1; \
    } \
} while(0)

#define PROFILE_STOP(pr) do { \
    struct rusage ruse; \
    struct timeval res_utime, res_stime; \
    getrusage(RUSAGE_THREAD, &ruse); \
    timersub(&ruse.ru_utime, &(pr##_U##__LINE__), &res_utime); \
    timersub(&ruse.ru_stime, &(pr##_S##__LINE__), &res_stime); \
    pr##_CUMU##__LINE__ += res_utime.tv_sec * 1000000 + res_utime.tv_usec; \
    pr##_CUMS##__LINE__ += res_stime.tv_sec * 1000000 + res_stime.tv_usec; \
    if(pr##_ENTERED##__LINE__) { \
        pr##_ENTERED##__LINE__ = 0; \
        PROFILE_counter--; \
        double u = pr##_CUMU##__LINE__; u /= pr##_CNT##__LINE__; \
        double s = pr##_CUMS##__LINE__; s /= pr##_CNT##__LINE__; \
        fprintf(stderr, "%s%s.%d: " #pr ": u:%g; s:%g; cnt %d\n", \
                PROFILE_margins[PROFILE_counter], __FUNCTION__, __LINE__, u, s, pr##_CNT##__LINE__ ); \
    } \
} while(0)

#else // PROFILE_LOG

#define PROFILE_START(pr)
#define PROFILE_STOP(pr)

#endif // PROFILE_LOG

#else // PROFILE_ENABLED

#define PROFILE_START(pr)
#define PROFILE_STOP(pr)


#endif // PROFILE_ENABLED


#endif // _LSCAPI_H_
