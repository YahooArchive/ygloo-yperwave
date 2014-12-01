/**
 * Copyright 2013 Yahoo! Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License. See accompanying LICENSE file.
 */

#ifndef _YPERWAVE_HTTPREQUEST_H
#define	_YPERWAVE_HTTPREQUEST_H


#define YPERWAVE_HTTP_GET 0
#define YPERWAVE_HTTP_POST 1
#define YPERWAVE_HTTP_POST_FORM 2

#define YPERWAVE_TELEMETRYLEVEL_NONE 0
#define YPERWAVE_TELEMETRYLEVEL_BASIC 1
#define YPERWAVE_TELEMETRYLEVEL_FULL 128

/**
 * @file httprequest.h
 * yperwave http requests are encapsulated in a private struct. this file
 * provides API consumers with the necessary functions to manipulate and
 * query the struct.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct HttpRequestStruct HttpRequest;


/**
 * Telemetry data gathered during an HTTP request
 */
YOSAL_OBJECT_DECLARE(HttpRequestTelemetry)
YOSAL_OBJECT_BEGIN
  uint32_t time_total_ms; /** total time in milliseconds */
  uint32_t time_queued_ms; /** time waiting in queue milliseconds */
  uint32_t time_dns_ms; /** time to dns in milliseconds */
  uint32_t time_connect_ms; /** time to connect in milliseconds */
  uint32_t time_firstbyte_ms; /** time to first byte in milliseconds */
  uint32_t speed_upload_Bps; /** upload speed in bytes/s */
  uint32_t speed_download_Bps; /** download speed in bytes/s */
  uint32_t uploaded_bytes; /** number of uploaded bytes */
  uint32_t downloaded_bytes; /** number of downloaded bytes */
  uint32_t time_ssl_ms; /** time to SSL handshake completed */
YOSAL_OBJECT_END
YOSAL_OBJECT_EXPORT(HttpRequestTelemetry)

#include "yperwave/httppool.h"

 typedef enum {
  HttpRequestPriority_Normal = 0,
  HttpRequestPriority_High = 1,
} HttpRequestPriority;

/**
 * Create a new request to query the given URL. The request will have to
 * be attached to a pool for execution.
 * @param url to be called
 * @return the newly created HTTP request
 */
HttpRequest* httprequest_create(const char *url);

/**
 * Mark the request as completed, and release it
 * @param request completed
 * @return 0 on success or 1 on failure
 */
int httprequest_completed(HttpRequest *request);

/**
 * Release all memory currently held by the given request. Releasing an
 * already releasing request will result in an error being returned.
 * @param request to be destroyed
 * @return 0 on success or 1 on failure
 */
int httprequest_release(HttpRequest *request);

int httprequest_finalize(HttpRequest *req);

/**
 * Cancel pending requests immediately, and active requests as soon as possible.
 */
int httprequest_cancel(HttpRequest* req);

/**
 * Cancel pending requests immediately, and active requests optionally.
 * Active requests will be allowed to finish if the remaining bytes to transfer
 * is less than the threshold bytes, up to a hard timeout.
 *
 * @param thresholdbytes If a positive number, then the number of bytes
 *   permitted to complete.  If 0, then the timeout is used alone.  If -1,
 *   then cancellation is immediate.
 * @param timeoutms The max time allowed for the request to complete prior
 *    to cancelling, in milliseconds.  If 0, then cancellation will happen
 *    based on thresholdbytes.  If -1, then cancellation is immediate.
 */
int httprequest_cancelifcostly(HttpRequest *req, int thresholdbytes, int timeoutms);

/**
 * Query whether a cancel has been requested for a request.
 *
 * @return 1 if a cancel is requested.
 */
int httprequest_isCancelRequested(HttpRequest* req);

/**
 * Query whether a request completed due to cancellation.
 *
 * @return 1 if the request completed due to a cancellation.
 */
int httprequest_cancelled(HttpRequest* req);

int httprequest_setConnectTimeout(HttpRequest *req, int timeout);

/**
 * Set minimum speed
 * @param req
 * @param speed Minimum speed in kilobyte/second
 * @param seconds Sample interval
 */
int httprequest_setMinSpeed(HttpRequest *req, int speed, int seconds);


int httprequest_status(HttpRequest *req);
int httprequest_fromcache(HttpRequest *req);

/**
 * Shorthand to determine if a request was processed successfully
 */
int httprequest_success(HttpRequest *req);

int httprequest_setUploadFile(HttpRequest* ctx, const char* key, const char* filename, Ychannel* filestream, int autorelease);

/**
 * @return number of bytes already posted to server
 */
size_t httprequest_getpostprogress(HttpRequest* ctx);

/**
 * @return number of total bytes scheduled to be posted to server
 */
size_t httprequest_getpostlength(HttpRequest* ctx);

/**
 * @return number of bytes of the response downloaded
 */
size_t httprequest_getresponseprogress(HttpRequest* ctx);

/**
 * @return number of total bytes of the response
 */
size_t httprequest_getresponselength(HttpRequest* ctx);

int httprequest_failedfileread(HttpRequest *req);

UrlParams* httprequest_getParams(HttpRequest* ctx);

int httprequest_getMethod(HttpRequest* ctx);
int httprequest_setMethod(HttpRequest* ctx, int method);

int httprequest_setcallback(HttpRequest *handle, int (*cb)(HttpRequest*));
int httprequest_setprivate(HttpRequest *handle, void *privdata);
void* httprequest_getprivate(HttpRequest *handle);

int httprequest_setsslverify(HttpRequest *handle, int value);
int httprequest_getsslverify(HttpRequest *handle);

int httprequest_settag(HttpRequest *handle, int tag);
int httprequest_gettag(HttpRequest *handle);

int httprequest_addheaderline(HttpRequest* handle, const char *header);

int httprequest_collectresponseheaders(HttpRequest *handle);
const char* httprequest_getresponseheaderline(HttpRequest *handle, int index);

/**
 * Set the instrumentation level
 * YPERWAVE_TELEMETRYLEVEL_OFF: none
 * YPERWAVE_TELEMETRYLEVEL_BASIC: basic (time to DNS, first byte, speed)
 * other levels TBD
 * YPERWAVE_TELEMETRYLEVEL_FULL: everything, could be very expensive
 */
int httprequest_settelemetrylevel(HttpRequest *handle, int instrument);
int httprequest_gettelemetrylevel(HttpRequest *handle);

HttpRequestTelemetry* httprequest_gettelemetry(HttpRequest *handle);

Ychannel*
httprequest_setchannel(HttpRequest *handle,
                       Ychannel *channel, int release);
const char*
httprequest_outputfile(HttpRequest *handle, const char *outfile);

char* httprequest_geturl(HttpRequest *handle);
int httprequest_getcode(HttpRequest *handle);
size_t httprequest_getlength(HttpRequest *handle);
char* httprequest_getcontent(HttpRequest *handle, int *datalen);

/**
 * Convenient helper when fetching data synchronously is acceptable
 * @param httppool
 * @param request
 * @param datalen
 * @return
 */
char* httprequest_getRequest(HttpPool *httppool, HttpRequest *request,
                             int *datalen);

void httprequest_setcachehints(HttpRequest *req, int hints);
int httprequest_getcachehints(HttpRequest *req);

int httprequest_setcacheresponsedata(HttpRequest *req, CacheData *cachedata);
CacheData *httprequest_getcacheresponsedata(HttpRequest *handle);

#ifdef	__cplusplus
}
#endif

#endif	/* _YPERWAVE_HTTPREQUEST_H */

