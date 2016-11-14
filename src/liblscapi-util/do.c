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

#include <util_script.h>
#include <http_request.h>
#include <httpd.h>

#include <apr_lib.h>
#include <apr_date.h>

struct hdrs_flags {
    int content_type_found;
    int content_type_event_stream;
    int x_accel_buffering_found;
    int x_accel_buffering_no;
    int www_authenticate_found;
};

struct hdrs_context {
    const lscapi_resphdr_info_t *hdrsInfoPtr;
    int curNum;
    int curHdrSize;
    apr_off_t curOff;
    request_rec *r;
    lsapi_svr_conf_t *svrcfg;
    lsapi_dir_conf_t *dircfg;
    int cgi_status;
    const char *status_line;
    struct hdrs_flags *hdrsFlagsPtr;
};

static int getsfunc_HDRBUF(char *w, int len, struct hdrs_context *c) {

    if(c->curNum >= c->hdrsInfoPtr->hdrNum) { // normal exit
        w[0] = '\0';
        return 1;
    }

    if(c->curOff > c->hdrsInfoPtr->dataLen) {
        if(c->svrcfg->debug_enabled) {
            lscapi_rlog(APLOG_NOTICE, 0, c->r,
                        "Wrong packet format: offset %" APR_OFF_T_FMT " is more than datalen %"APR_SIZE_T_FMT,
                        c->curOff, c->hdrsInfoPtr->dataLen);
        }
        return -1;
    }

    if(!c->curHdrSize) {
        c->curHdrSize = c->hdrsInfoPtr->hdrSizes[c->curNum];
    }

    if(c->hdrsFlagsPtr->content_type_found == 0) {
        if(strncasecmp(c->hdrsInfoPtr->buf + c->curOff, "Content-Type:", 13) == 0) {
            c->hdrsFlagsPtr->content_type_found = 1;
            const char *ptr = c->hdrsInfoPtr->buf + c->curOff + 13;
            if(*ptr == ' ') ptr++;
            if(strncasecmp(ptr, "text/event-stream", 17) == 0) {
                c->hdrsFlagsPtr->content_type_event_stream = 1;
            }
        }
    }

    if(c->hdrsFlagsPtr->x_accel_buffering_found == 0) {
        if(strncasecmp(c->hdrsInfoPtr->buf + c->curOff, "X-Accel-Buffering:", 18) == 0) {
            c->hdrsFlagsPtr->x_accel_buffering_found = 1;
            const char *ptr = c->hdrsInfoPtr->buf + c->curOff + 18;
            if(*ptr == ' ') ptr++;
            if(strncasecmp(ptr, "no", 2) == 0) {
                c->hdrsFlagsPtr->x_accel_buffering_no = 1;
            }
        }
    }

    if(c->hdrsFlagsPtr->www_authenticate_found == 0) {
        if(strncasecmp(c->hdrsInfoPtr->buf + c->curOff, "WWW-Authenticate:", 17) == 0) {
            c->hdrsFlagsPtr->www_authenticate_found = 1;
        }
    }

    if(c->curHdrSize < len) {
        memcpy(w, c->hdrsInfoPtr->buf + c->curOff, c->curHdrSize);
        c->curNum++;
        c->curOff += c->curHdrSize;
        c->curHdrSize = 0;
    } else {
        memcpy(w, c->hdrsInfoPtr->buf + c->curOff, len-1);
        w[len-1] = '\0';

        c->curOff += len-1;
        c->curHdrSize -= len-1;
    }

    return 1;
}

#ifdef LSCAPI_WITH_DUMP_HEADER
/*
static void DumpHeaders(request_rec *r, const lscapi_resphdr_info_t *hdrsInfoPtr) {
    static unsigned long serialNo;
    char fname[256];


    snprintf(fname, sizeof fname, "/tmp/%s-%08lu.log", r->hostname, serialNo);
    serialNo++;

    FILE *fptr = fopen(fname, "wb");
    if(fptr) {
        lscapi_rlog(APLOG_ERR, 0, r,
                    "Dump headers into (%s)", fname);
        fwrite(hdrsInfoPtr->buf, 1, hdrsInfoPtr->dataLen, fptr);
        fclose(fptr);
    }
}
*/
#endif


// As RESPONSE_CODES in Apache 2.4 but should be the same also for Apache 2.2
#define LSAPI_RESPONSE_CODES 83

/*
http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
*/
static const char * const status_lines[LSAPI_RESPONSE_CODES+1] =  // 1 for UNKNOWN
{
    "100 Continue",
    "101 Switching Protocols",
    "102 Processing",
#define LEVEL_200  3
    "200 OK",
    "201 Created",
    "202 Accepted",
    "203 Non-Authoritative Information",
    "204 No Content",
    "205 Reset Content",
    "206 Partial Content",
    "207 Multi-Status",
    "208 Already Reported",
    NULL, /* 209 */
    NULL, /* 210 */
    NULL, /* 211 */
    NULL, /* 212 */
    NULL, /* 213 */
    NULL, /* 214 */
    NULL, /* 215 */
    NULL, /* 216 */
    NULL, /* 217 */
    NULL, /* 218 */
    NULL, /* 219 */
    NULL, /* 220 */
    NULL, /* 221 */
    NULL, /* 222 */
    NULL, /* 223 */
    NULL, /* 224 */
    NULL, /* 225 */
    "226 IM Used",
#define LEVEL_300 30
    "300 Multiple Choices",
    "301 Moved Permanently",
    "302 Moved Temporarily",    // instead of Apache "302 Found",
    "303 See Other",
    "304 Not Modified",
    "305 Use Proxy",
    NULL, /* 306 */
    "307 Temporary Redirect",
    "308 Permanent Redirect",
#define LEVEL_400 39
    "400 Bad Request",
    "401 Unauthorized",
    "402 Payment Required",
    "403 Forbidden",
    "404 Not Found",
    "405 Method Not Allowed",
    "406 Not Acceptable",
    "407 Proxy Authentication Required",
    "408 Request Timeout",
    "409 Conflict",
    "410 Gone",
    "411 Length Required",
    "412 Precondition Failed",
    "413 Request Entity Too Large",
    "414 Request-URI Too Long",
    "415 Unsupported Media Type",
    "416 Requested Range Not Satisfiable",
    "417 Expectation Failed",
    NULL, /* 418 */
    NULL, /* 419 */
    NULL, /* 420 */
    "421 Misdirected Request",
    "422 Unprocessable Entity",
    "423 Locked",
    "424 Failed Dependency",
    NULL, /* 425 */
    "426 Upgrade Required",
    NULL, /* 427 */
    "428 Precondition Required",
    "429 Too Many Requests",
    NULL, /* 430 */
    "431 Request Header Fields Too Large",
#define LEVEL_500 71
    "500 Internal Server Error",
    "501 Not Implemented",
    "502 Bad Gateway",
    "503 Service Unavailable",
    "504 Gateway Timeout",
    "505 HTTP Version Not Supported",
    "506 Variant Also Negotiates",
    "507 Insufficient Storage",
    "508 Loop Detected",
    NULL, /* 509 */
    "510 Not Extended",
    "511 Network Authentication Required",
#define LSAPI_RESPONSE_CODE_UNKNOWN 83
    "UKNOWN"
};

static int lsapi_index_of_response(int status, int with_unknown)
{
    static int shortcut[6] = {0, LEVEL_200, LEVEL_300, LEVEL_400,
    LEVEL_500, LSAPI_RESPONSE_CODES};
    int i, pos;

    if (status < 100) {               /* Below 100 is illegal for HTTP status */
        return LEVEL_500;
    }

    for (i = 0; i < 5; i++) {
        status -= 100;
        if (status < 100) {
            pos = (status + shortcut[i]);
            if (pos < shortcut[i + 1] && status_lines[pos] != NULL) {
                return pos;
            }
            else {
                /* status unknown (falls in gap) */
                return with_unknown ? LSAPI_RESPONSE_CODE_UNKNOWN : LEVEL_500;
            }
        }
    }
    return LEVEL_500;                         /* 600 or above is also illegal */
}

static const char* lsapi_get_status_line(int status)
{
    return status_lines[lsapi_index_of_response(status, 0)];
}

static const char* lsapi_get_status_line_with_null(int status)
{
    int n = lsapi_index_of_response(status, 1);
    return n == LSAPI_RESPONSE_CODE_UNKNOWN ? NULL : status_lines[n];
}


static void lsapi_print_backend_log(lscapi_rec *lscapi, request_rec *r, unsigned eventMask)
{
    const char *prefix;
    const char *log;
    int logLevel;
    if(eventMask & LSCAPI_BACKEND_LOG_FATAL)
    {
        prefix = "Backend fatal error";
        logLevel = APLOG_ERR;
    } else
    {
        prefix = "Backend log";
        logLevel = APLOG_NOTICE;
    }
    
    while(1)
    {
        log = lscapi_get_backend_log(lscapi);
        if(!log || log[0] == '\0')
            break;
        lscapi_rlog(logLevel, 0, r, "%s: %s", prefix, log );
    }

}

#define SET_STATUS_WITH_LINE(r, st)  do { (r)->status = (st); (r)->status_line = lsapi_get_status_line((r)->status); } while(0)

static int read_from_backend(lscapi_rec *lscapi, lsphp_conn_t *backend, request_rec *r,
                             lsapi_svr_conf_t *svrcfg, lsapi_dir_conf_t *dircfg,
                             int drain, 
                             const struct hdrs_flags *hdrsFlagsPtr, 
                             char *errbuf, size_t errlen) {
    int rc;
    char buf[LSAPI_MAX_DATA_PACKET_LEN];
    unsigned eventMask;
    apr_bucket_brigade *ob = NULL;

    if(!drain) {
        ob = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    }

    while(1) {

        size_t bufLen = LSAPI_MAX_DATA_PACKET_LEN;
        eventMask = 0;
        rc = lscapi_receive_response_chunk(backend, buf, &bufLen, &eventMask, errbuf, errlen);
        if(rc != 0) {
            lscapi_rlog(APLOG_ERR, 0, r, "Error receiving response: %s", errbuf);
            lscapi_set_error(lscapi);
            // TODO: it is too late to change status here, as header is already processed. But what we have to do?
            if(!drain) {
                SET_STATUS_WITH_LINE(r, dircfg->err_backend_recvrsp);  //HTTP_SERVICE_UNAVAILABLE
            }
            return -1;
        }

        if(eventMask & LSCAPI_BACKEND_LOG_RECEIVED) {
            lsapi_print_backend_log(lscapi, r, eventMask);
        }

        if(eventMask & LSCAPI_RESPONSE_FINISHED) {
            if(!drain) {
                apr_bucket *eosB = apr_bucket_eos_create(r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ob, eosB);
                ap_pass_brigade(r->output_filters, ob);
            }
            break;
        }

        if(!drain) {
            apr_bucket *b = apr_bucket_transient_create(buf, bufLen, r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ob, b);
            ap_pass_brigade(r->output_filters, ob);

            if(hdrsFlagsPtr->x_accel_buffering_no || hdrsFlagsPtr->content_type_event_stream) {
                APR_BRIGADE_INSERT_TAIL(ob, apr_bucket_flush_create(r->connection->bucket_alloc));
                ap_pass_brigade(r->output_filters, ob);
            }

        }

    } //while(!done)

    if(!drain) {
        //apr_brigade_cleanup(ib);
        apr_brigade_cleanup(ob);
    }
    return 0;
}

static int 
lscapi_set_cookie(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

#define HTTP_UNSET (-HTTP_OK)

static int 
lscapi_scan_script_header_err_core(request_rec *r, char *buffer,
                                    int (*getsfunc) (char *, int, struct hdrs_context *),
                                    struct hdrs_context *c)
{
    char *w, *l;
    int p;
    apr_table_t *merge;
    apr_table_t *cookie_table;
    int first_header = 1;

    *buffer = '\0';
    w = buffer;

    /* temporary place to hold headers to merge in later */
    merge = apr_table_make(r->pool, 10);

    cookie_table = apr_table_make(r->pool, 2);
    apr_table_do(lscapi_set_cookie, cookie_table, r->err_headers_out, "Set-Cookie", NULL);

    c->cgi_status = HTTP_UNSET;
    while (1) {

        int rv = (*getsfunc) (w, MAX_STRING_LEN - 1, c);
        if (rv == 0) {
            if (first_header) {
                lscapi_rlog(APLOG_ERR, 0, r, "End of script output before headers: %s",
                            apr_filepath_name_get(r->filename));
                return c->dircfg->err_backend_nohdrs; // HTTP_SERVICE_UNAVAILABLE
            } else {
                lscapi_rlog(APLOG_ERR, 0, r, "Premature end of script headers: %s",
                            apr_filepath_name_get(r->filename));
                return c->dircfg->err_backend_endhdrs; // HTTP_SERVICE_UNAVAILABLE
            }
        }
        else if (rv == -1) {
            lscapi_rlog(APLOG_ERR, 0, r,
                          "Script timed out before returning headers: %s",
                          apr_filepath_name_get(r->filename));
            return HTTP_GATEWAY_TIME_OUT;
        }

        /* Delete terminal (CR?)LF */

        p = strlen(w);
        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == CR) {
                w[p - 2] = '\0';
            }
            else {
                w[p - 1] = '\0';
            }
        }

        if (w[0] == '\0') {
            if ((c->cgi_status == HTTP_UNSET) && (r->method_number == M_GET)) {
                int cond_status = ap_meets_conditions(r);
                if(cond_status != OK) {
                    c->cgi_status = cond_status;
                    c->status_line = lsapi_get_status_line(c->cgi_status);
                }
            }
            apr_table_overlap(r->err_headers_out, merge,
                APR_OVERLAP_TABLES_MERGE);
            if (!apr_is_empty_table(cookie_table)) {
                /* the cookies have already been copied to the cookie_table */
                apr_table_unset(r->err_headers_out, "Set-Cookie");
                r->err_headers_out = apr_table_overlay(r->pool,
                    r->err_headers_out, cookie_table);
            }
            if(c->svrcfg->debug_enabled) {
                lscapi_rlog(APLOG_NOTICE, 0, r, "lscapi_scan_script_header finishing: cgi_status %d; status_line(%s)", c->cgi_status, c->status_line);
            }
            return OK;
        }

        if(c->svrcfg->debug_enabled) {
            lscapi_rlog(APLOG_NOTICE, 0, r, "lscapi_scan_script_header: next line(%s)", w);
        }
        
        /* if we see a bogus header don't ignore it. Shout and scream */
        if (!(l = strchr(w, ':'))) {

            /* Response status in format "HTTP/x.x nnn ..." is acceptable though */
            unsigned major, minor;
            char code_str[4];
            if(sscanf(w, "HTTP/%1u.%1u %3s", &major, &minor, code_str) == 3) {
                c->cgi_status = atoi(code_str);
                c->status_line = apr_pstrdup(r->pool, w+9); // skip "HTTP/1.1 " prefix
                if(c->svrcfg->debug_enabled) {
                    lscapi_rlog(APLOG_NOTICE, 0, r, "lscapi_scan_script_header: ROW header found: set cgi_status to %d; and status_line to (%s)", c->cgi_status, c->status_line);
                }
            }
            continue;
        }

        *l++ = '\0';
        while (*l && apr_isspace(*l)) {
            ++l;
        }

        if (!strcasecmp(w, "Content-type")) {
            char *tmp;

            /* Nuke trailing whitespace */

            char *endp = l + strlen(l) - 1;
            while (endp > l && apr_isspace(*endp)) {
                *endp-- = '\0';
            }

            tmp = apr_pstrdup(r->pool, l);
            ap_content_type_tolower(tmp);
            ap_set_content_type(r, tmp);
        }
        /*
         * If the script returned a specific status, that's what
         * we'll use - otherwise we assume 200 OK.
         */
        else if (!strcasecmp(w, "Status")) {
            c->cgi_status = atoi(l);
            c->status_line = apr_pstrdup(r->pool, l);
            if(c->svrcfg->debug_enabled) {
                lscapi_rlog(APLOG_NOTICE, 0, r, "lscapi_scan_script_header: ROW header found: Status header found: set r->status and cgi_status to %d; and status_line to (%s)", c->cgi_status, c->status_line);
            }
        }
        else if (!strcasecmp(w, "Location")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Length")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Range")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Transfer-Encoding")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "ETag")) {
            apr_table_set(r->headers_out, w, l);
        }
        /*
         * If the script gave us a Last-Modified header, we can't just
         * pass it on blindly because of restrictions on future values.
         */
        else if (!strcasecmp(w, "Last-Modified")) {
            ap_update_mtime(r, apr_date_parse_http(l));
            ap_set_last_modified(r);
        }
        else if (!strcasecmp(w, "Set-Cookie")) {
            apr_table_add(cookie_table, w, l);
        }
        else {
            apr_table_add(merge, w, l);
        }
        first_header = 0;
    }
    /* never reached - we leave this function within the while loop above */
    return OK;
}

apr_status_t lscapi_do_request(lscapi_rec *lscapi, lsphp_conn_t *backend, request_rec *r,
                               lsapi_svr_conf_t *svrcfg, lsapi_dir_conf_t *dircfg)
{
    char errbuf[256];
    int rc;
    unsigned eventMask;

    eventMask = 0;
    PROFILE_START(lscapi_send_request);
    rc = lscapi_send_request(backend, &eventMask, errbuf, sizeof errbuf);
    PROFILE_STOP(lscapi_send_request);
    if (rc != 0) {
        if(eventMask & LSCAPI_SENDREQ_INTERNAL_ERROR) {
            lscapi_rlog(APLOG_ERR, 0, r, "Internal error on sending request(%s); uri(%s) content-length(%s): %s",
                        r->the_request, r->unparsed_uri, apr_table_get(r->headers_in, "Content-Length"), errbuf);
            SET_STATUS_WITH_LINE(r, dircfg->err_lsapi_internal); //HTTP_SERVICE_UNAVAILABLE
        } else if(eventMask & LSCAPI_SENDREQ_BACKEND_ERROR) {
            lscapi_rlog(APLOG_ERR, 0, r, "Backend error on sending request(%s); uri(%s) content-length(%s) (lsphp is killed?): %s",
                        r->the_request, r->unparsed_uri, apr_table_get(r->headers_in, "Content-Length"), errbuf);
            SET_STATUS_WITH_LINE(r, dircfg->err_backend_sendreq); //HTTP_SERVICE_UNAVAILABLE
        } else if(eventMask & LSCAPI_SENDREQ_CLIENT_ERROR) {
            lscapi_rlog(APLOG_ERR, 0, r, "Client error on sending request(%s); uri(%s) content-length(%s): %s",
                        r->the_request, r->unparsed_uri, apr_table_get(r->headers_in, "Content-Length"), errbuf);
            SET_STATUS_WITH_LINE(r, HTTP_BAD_REQUEST);
        } else {
            // Unknown error?
            lscapi_rlog(APLOG_ERR, 0, r, "Error on sending request(%s); uri(%s) content-length(%s): %s",
                        r->the_request, r->unparsed_uri, apr_table_get(r->headers_in, "Content-Length"), errbuf);
            SET_STATUS_WITH_LINE(r, dircfg->err_lsapi_internal); //HTTP_SERVICE_UNAVAILABLE
        }
        lscapi_set_error(lscapi);
        return r->status;
    }

    if(dircfg->measure_time)
    {
        lscapi_write_measured_time(r, LSCAPI_MEASURE_REQUEST_SENT);
    }

    if(eventMask & LSCAPI_BACKEND_LOG_RECEIVED) {
        lsapi_print_backend_log(lscapi, r, eventMask);
    }

    lscapi_resphdr_info_t hdrsInfo;

    eventMask = 0;
    rc = lscapi_receive_response_header(backend, &hdrsInfo, &eventMask, errbuf, sizeof errbuf);
    if(rc != 0) {
        lscapi_rlog(APLOG_ERR, 0, r, "Error receiving response header (lsphp is killed?): %s", errbuf);
        lscapi_set_recoverable_error(lscapi);
        SET_STATUS_WITH_LINE(r, dircfg->err_backend_recvhdr);  //HTTP_SERVICE_UNAVAILABLE
        return r->status;
    }
    if(dircfg->measure_time)
    {
        lscapi_write_measured_time(r, LSCAPI_MEASURE_HEADER_GOT);
    }

    if(eventMask & LSCAPI_BACKEND_LOG_RECEIVED) {
        lsapi_print_backend_log(lscapi, r, eventMask);
    }

    char scan_buffer[MAX_STRING_LEN];
    struct hdrs_flags hdrsFlags;
    memset(&hdrsFlags, 0, sizeof(hdrsFlags));
    
    struct hdrs_context context;
    context.hdrsInfoPtr = &hdrsInfo;
    context.curHdrSize = 0;
    context.curOff = sizeof(lsapi_resp_info) + sizeof(uint16_t) * hdrsInfo.hdrNum;
    context.curNum = 0;
    context.svrcfg = svrcfg;
    context.dircfg = dircfg;
    context.r = r;
    context.hdrsFlagsPtr = &hdrsFlags;
    context.cgi_status = OK;
    context.status_line = NULL;
    
    if(svrcfg->debug_enabled) {
        lscapi_rlog(APLOG_NOTICE, 0, r, "lscapi_do_request: response header received: response status %d", hdrsInfo.respStatus);
    }
    

    rc = lscapi_scan_script_header_err_core(r, scan_buffer, getsfunc_HDRBUF, (void *) &context);

    if (rc != OK)
    {
        SET_STATUS_WITH_LINE(r, rc);
        if(svrcfg->debug_enabled) {
            lscapi_rlog(APLOG_NOTICE, 0, r, "lscapi_scan_script_header failed: %d: use standard header(%s)", rc, r->status_line);
        }
        read_from_backend(lscapi, backend, r, svrcfg, dircfg, 1, &hdrsFlags, errbuf, sizeof errbuf);  // discard output
        return rc;
    }

/*
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", r->method);

*/

    if(hdrsInfo.respStatus != OK) {
        if(hdrsInfo.respStatus == HTTP_OK) {
            if(svrcfg->debug_enabled) {
                lscapi_rlog(APLOG_NOTICE, 0, r, "leave status blank as response status is HTTP_OK: %d", hdrsInfo.respStatus);
            }
        } else {
            r->status = hdrsInfo.respStatus;
            if(svrcfg->debug_enabled) {
                lscapi_rlog(APLOG_NOTICE, 0, r, "set status to response status %d", r->status);
            }
            const char *status_line = lsapi_get_status_line_with_null(r->status);
            if(status_line) {
                r->status_line = status_line;
                if(svrcfg->debug_enabled) {
                    lscapi_rlog(APLOG_NOTICE, 0, r, "... and set status line to standard one (%s) as status is known", r->status_line);
                }
            } else if(context.cgi_status == r->status) { 
                r->status_line = context.status_line;
                if(svrcfg->debug_enabled) {
                    lscapi_rlog(APLOG_NOTICE, 0, r, "... and set status line to context one (%s) as status is unknown", r->status_line);
                }
            } else {
                char buf[8];
                snprintf(buf, sizeof buf, "%3d ", r->status);
                r->status_line = apr_pstrdup(r->pool, buf);
                if(svrcfg->debug_enabled) {
                    lscapi_rlog(APLOG_NOTICE, 0, r, "... and set status line to pseudo one (%s) as status is unknown and we cannot use context one", r->status_line);
                }
            }
        }
        
        
    } else if(hdrsFlags.www_authenticate_found == 1) {
        SET_STATUS_WITH_LINE(r, HTTP_UNAUTHORIZED);
        if(svrcfg->debug_enabled) {
            lscapi_rlog(APLOG_NOTICE, 0, r, "set status to %d as WWW-Authenticate header found; standard line (%s)", r->status, r->status_line);
        }
    } else if(context.cgi_status != HTTP_UNSET) {
        r->status = context.cgi_status;
        r->status_line = context.status_line;
        if(svrcfg->debug_enabled) {
            lscapi_rlog(APLOG_NOTICE, 0, r, "set status to %d using cgi_status and line(%s)", r->status, r->status_line);
        }
    } else {
        if(svrcfg->debug_enabled) {
            lscapi_rlog(APLOG_NOTICE, 0, r, "nor response code %d, nor cgi_status %d - leave status blank", hdrsInfo.respStatus, context.cgi_status);
        }
    }

    const char *location = apr_table_get(r->headers_out, "Location");
    if (location && location[0] == '/' && r->status == HTTP_OK)
    {
        read_from_backend(lscapi, backend, r, svrcfg, dircfg, 1, &hdrsFlags, errbuf, sizeof errbuf);  // discard output
        r->method = "GET";
        r->method_number = M_GET;
        apr_table_unset(r->headers_in, "Content-Length");

        ap_internal_redirect_handler(location, r);
        return OK;
    }
    else if (location && r->status == HTTP_OK)
    {
        read_from_backend(lscapi, backend, r, svrcfg, dircfg, 1, &hdrsFlags, errbuf, sizeof errbuf);  // discard output
        return HTTP_MOVED_TEMPORARILY;
    }

    rc = read_from_backend(lscapi, backend, r, svrcfg, dircfg, 0, &hdrsFlags, errbuf, sizeof errbuf); // send output to browser through filters
    if(rc != 0) {
        return r->status;
    }
    if(dircfg->measure_time)
    {
        lscapi_write_measured_time(r, LSCAPI_MEASURE_RESPONSE_GOT);
    }

    return OK;
}

void lscapi_reset_http_error_state(request_rec *r)
{
    SET_STATUS_WITH_LINE(r, HTTP_OK);
}


const char LSCAPI_MEASURE_REQUEST_GOT[] = "lscapi-measure-request-got";
const char LSCAPI_MEASURE_CONN_ESTABLISHED[] = "lscapi-measure-conn-established";
const char LSCAPI_MEASURE_REQUEST_SENT[] = "lscapi-measure-request-sent";
const char LSCAPI_MEASURE_HEADER_GOT[] = "lscapi-measure-header-got";
const char LSCAPI_MEASURE_RESPONSE_GOT[] = "lscapi-measure-response-got";

void lscapi_write_measured_time(request_rec *r, const char *key)
{
    struct timeval *tv = apr_palloc(r->pool, sizeof(struct timeval));
    gettimeofday(tv, NULL);
    apr_table_setn(r->notes, key, (char*)tv);
}

apr_status_t lscapi_get_measured_timedelta(request_rec *r, 
                                           const char *key_from, const char *key_to, 
                                           struct timeval *tv_delta)
{
    struct timeval *tv_from = (struct timeval *) apr_table_get(r->notes, key_from);
    struct timeval *tv_to = (struct timeval *) apr_table_get(r->notes, key_to);
    if(!tv_from || !tv_to)
    {
        return APR_ENOTIME;
    }
    timersub(tv_to, tv_from, tv_delta);
    return APR_SUCCESS;
}
