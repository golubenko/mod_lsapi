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

#define MAX_HEADERS 256


static const char * const standardHeaders[] =
{
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Authorization",

    "Connection",
    "Content-Type",
    "Content-Length",
    "Cookie",
    "Cookie2",

    "Host",
    "Pragma",
    "Referer",
    "User-Agent",
    "Cache-Control",

    "If-Modified-Since",
    "If-Match",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",

    "Keep-Alive",
    "Range",
    "X-Forwarded-For",
    "Via",
    "Transfer-Encoding"
};


static int findStandardHeaderIndex(const char *key, int keyLen) {
    int retVal;

    switch(keyLen) {

    case 3: // H_VIA
        if(!strcasecmp(key, standardHeaders[H_VIA]))
            retVal = H_VIA;
        else
            retVal = -1;
    break;

    case 4: // H_HOST
        if(!strcasecmp(key, standardHeaders[H_HOST]))
            retVal = H_HOST;
        else
            retVal = -1;
    break;

    case 5: // H_RANGE
        if(!strcasecmp(key, standardHeaders[H_RANGE]))
            retVal = H_RANGE;
        else
            retVal = -1;
    break;

    case 6: // H_ACCEPT H_COOKIE H_PRAGMA
        if(!strcasecmp(key, standardHeaders[H_ACCEPT]))
            retVal = H_ACCEPT;
        else if(!strcasecmp(key, standardHeaders[H_COOKIE]))
            retVal = H_COOKIE;
        else if(!strcasecmp(key, standardHeaders[H_PRAGMA]))
            retVal = H_PRAGMA;
        else
            retVal = -1;
    break;

    case 7: // H_REFERER H_COOKIE2
        if(!strcasecmp(key, standardHeaders[H_REFERER]))
            retVal = H_REFERER;
        else if(!strcasecmp(key, standardHeaders[H_COOKIE2]))
            retVal = H_COOKIE2;
        else
            retVal = -1;
    break;

    case 8: // H_IF_MATCH H_IF_RANGE
        if(!strcasecmp(key, standardHeaders[H_IF_MATCH]))
            retVal = H_IF_MATCH;
        else if(!strcasecmp(key, standardHeaders[H_IF_RANGE]))
            retVal = H_IF_RANGE;
        else
            retVal = -1;
    break;

    case 10: // H_CONNECTION H_USERAGENT H_KEEP_ALIVE
        if(!strcasecmp(key, standardHeaders[H_CONNECTION]))
            retVal = H_CONNECTION;
        else if(!strcasecmp(key, standardHeaders[H_USERAGENT]))
            retVal = H_USERAGENT;
        else if(!strcasecmp(key, standardHeaders[H_KEEP_ALIVE]))
            retVal = H_KEEP_ALIVE;
        else
            retVal = -1;
    break;

    case 12: // H_CONTENT_TYPE
        if(!strcasecmp(key, standardHeaders[H_CONTENT_TYPE]))
            retVal = H_CONTENT_TYPE;
        else
            retVal = -1;
    break;

    case 13: // H_AUTHORIZATION H_CACHE_CTRL H_IF_NO_MATCH
        if(!strcasecmp(key, standardHeaders[H_AUTHORIZATION]))
            retVal = H_AUTHORIZATION;
        else if(!strcasecmp(key, standardHeaders[H_CACHE_CTRL]))
            retVal = H_CACHE_CTRL;
        else if(!strcasecmp(key, standardHeaders[H_IF_NO_MATCH]))
            retVal = H_IF_NO_MATCH;
        else
            retVal = -1;
    break;

    case 14: // H_ACC_CHARSET H_CONTENT_LENGTH
        if(!strcasecmp(key, standardHeaders[H_ACC_CHARSET]))
            retVal = H_ACC_CHARSET;
        else if(!strcasecmp(key, standardHeaders[H_CONTENT_LENGTH]))
            retVal = H_CONTENT_LENGTH;
        else
            retVal = -1;
    break;

    case 15: // H_X_FORWARDED_FOR H_ACC_ENCODING H_ACC_LANG
        if(!strcasecmp(key, standardHeaders[H_X_FORWARDED_FOR]))
            retVal = H_X_FORWARDED_FOR;
        else if(!strcasecmp(key, standardHeaders[H_ACC_ENCODING]))
            retVal = H_ACC_ENCODING;
        else if(!strcasecmp(key, standardHeaders[H_ACC_LANG]))
            retVal = H_ACC_LANG;
        else
            retVal = -1;
    break;

    case 17: // H_TRANSFER_ENCODING H_IF_MODIFIED_SINCE
        if(!strcasecmp(key, standardHeaders[H_TRANSFER_ENCODING]))
            retVal = H_TRANSFER_ENCODING;
        else if(!strcasecmp(key, standardHeaders[H_IF_MODIFIED_SINCE]))
            retVal = H_IF_MODIFIED_SINCE;
        else
            retVal = -1;
    break;

    case 19: // H_IF_UNMOD_SINCE
        if(!strcasecmp(key, standardHeaders[H_IF_UNMOD_SINCE]))
            retVal = H_IF_UNMOD_SINCE;
        else
            retVal = -1;
    break;

    default:
            retVal = -1;
    }
    return retVal;
}


struct lscapi_http_hdrs_t {
    request_rec *r;
    int hdrNum;
    int overallLen;
    lscapi_var_t hdrs[MAX_HEADERS];
};

static int processHdrs(struct lscapi_http_hdrs_t *hdrs, const char *key, const char *value) {
    if(hdrs->hdrNum >= MAX_HEADERS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, hdrs->r,
                      "Cannot process all http headers -- MAX_HEADERS is too small %d", MAX_HEADERS);
        return 0;
    }

    /*
      MODLS-231
      https://httpoxy.org 
      https://www.apache.org/security/asf-httpoxy-response.txt
*/
    if(strcasecmp(key, "Proxy") == 0
      || strcasecmp(key, "Proxy-Authorization") == 0
      || strcasecmp(key, "Authorization") == 0 ) return 1;

    hdrs->hdrs[hdrs->hdrNum].key = key;
    hdrs->hdrs[hdrs->hdrNum].val = value;
    hdrs->hdrs[hdrs->hdrNum].keyLen = strlen(key);
    hdrs->hdrs[hdrs->hdrNum].valLen = strlen(value);
    //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, hdrs->r, "processHdrs: (%s)->(%s)", key, value);

    hdrs->overallLen += hdrs->hdrs[hdrs->hdrNum].keyLen + hdrs->hdrs[hdrs->hdrNum].valLen;
    hdrs->hdrNum++;
    return 1;
}


void lscapi_recreate_http_header(request_rec *r,
                                lsapi_http_header_index_t **hdrIndexPtr,
                                lsapi_header_offset_t **hdrOffsetsPtr, 
                                size_t *hdrOffsetsNumPtr,
                                size_t *contentLengthPtr,
                                char **bufPtr, size_t *bufLenPtr) {
    struct lscapi_http_hdrs_t hdrs;
    memset(&hdrs, 0, sizeof hdrs);
    hdrs.r = r;

    apr_table_do((apr_table_do_callback_fn_t*)processHdrs, &hdrs, r->headers_in, NULL);

    apr_size_t bufLen;

    bufLen = sizeof(lsapi_header_offset_t) * (hdrs.hdrNum ? hdrs.hdrNum : 1);
    lsapi_header_offset_t *hdrOffsets = apr_pcalloc(r->pool, bufLen);

    lsapi_http_header_index_t *hdrIndex = apr_pcalloc(r->pool, sizeof *hdrIndex);

    size_t reqLen = strlen(r->the_request);
    // 1 - for "\n" after request; 4 - for " : " and "\n" for each header; 3 - for finishing "\n\0"
    bufLen = reqLen + 1 + hdrs.overallLen + hdrs.hdrNum * 4 + 2;
    char *buf = apr_pcalloc(r->pool, bufLen);

    memcpy(buf, r->the_request, reqLen);
    size_t curOff = reqLen;
    //buf[curOff++] = '\r';
    buf[curOff++] = '\n';

    apr_size_t unknownHdrNum = 0;
    int contentLengthFound = 0;
    int i = 0;
    for(i = 0; i < hdrs.hdrNum; i++) {
        const char *keyPtr;
        int stdIndex = findStandardHeaderIndex(hdrs.hdrs[i].key, hdrs.hdrs[i].keyLen);

        if(stdIndex >= 0) {

            // treat this header as a standard one
            keyPtr = standardHeaders[stdIndex]; // use normalized keyword
            hdrIndex->m_headerLen[stdIndex] = hdrs.hdrs[i].valLen;
            hdrIndex->m_headerOff[stdIndex] = curOff + hdrs.hdrs[i].keyLen + 3;
            if(!contentLengthFound && stdIndex == H_CONTENT_LENGTH) {
                *contentLengthPtr = atoi(hdrs.hdrs[i].val);
                contentLengthFound = 1;
            }
            //ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, LSCAPI_APLOGNO
             //             "%d: treat key(%s) as standard one. index %d; key(%s)-(%s); ", (unsigned long)bufLen);
        } else {

            // treat this header as unknown one
            keyPtr = hdrs.hdrs[i].key; // use keyword as is
            hdrOffsets[unknownHdrNum].nameLen = hdrs.hdrs[i].keyLen;
            hdrOffsets[unknownHdrNum].nameOff = curOff;
            hdrOffsets[unknownHdrNum].valueLen = hdrs.hdrs[i].valLen;
            hdrOffsets[unknownHdrNum].valueOff = curOff + hdrs.hdrs[i].keyLen + 3;
            unknownHdrNum++;
        }

        memcpy(buf + curOff, keyPtr, hdrs.hdrs[i].keyLen); curOff += hdrs.hdrs[i].keyLen;
        memcpy(buf + curOff, " : ", 3); curOff += 3;
        memcpy(buf + curOff, hdrs.hdrs[i].val, hdrs.hdrs[i].valLen); curOff += hdrs.hdrs[i].valLen;
        //buf[curOff++] = '\r';
        buf[curOff++] = '\n';
    }
    //buf[curOff++] = '\r';
    buf[curOff++] = '\n';
    buf[curOff] = '\0';
    if(!contentLengthFound) {
        *contentLengthPtr = 0;
    }


    *hdrOffsetsNumPtr = unknownHdrNum;
    *hdrOffsetsPtr = hdrOffsets;
    *bufPtr = buf;
    *bufLenPtr = bufLen-1; // trailing null is not a part of http header
    *hdrIndexPtr = hdrIndex;
}
