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

#ifndef _YPERWAVE_HTTPPOOL_H
#define _YPERWAVE_HTTPPOOL_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HttpPoolStruct HttpPool;

#include "yperwave/httpcache.h"
#include "yperwave/httprequest.h"
#include "yperwave/httppoollooper.h"


/*
 * Global initializer / finalizer. Intiializer is automatically called when a new
 * httppool is created, so it's not required for customer for this API to call it
 */
int httppool_init();
int httppool_fini();

HttpPool* httppool_create();
int httppool_release(HttpPool *httppool);

int httppool_lock(HttpPool *httppool);
int httppool_unlock(HttpPool *httppool);

int httppool_add(HttpPool *httppool, HttpRequest *request);
int httppool_insert(HttpPool *httppool, HttpRequest *request, HttpRequestPriority priority);
void httppool_runcache(HttpPool *httppool);
int httppool_pop(HttpPool *httppool);

int httppool_looper_attached(HttpPool* httppool, HttpPoolLooper* looper);
int httppool_looper_detached(HttpPool* httppool);

uint32_t httppool_timeout(HttpPool* httppool);

/**
 * Check if an http pool is empty, returns true if there are
 * no queued and pending requests. Caller must lock the given
 * httppool before calling this function to ensure an accurate result.
 *
 * @param httppool
 */
int httppool_empty(HttpPool* httppool);

int httppool_prepare (HttpPool *httppool);
int httppool_perform(HttpPool* httppool);
int httppool_iowait(HttpPool* httppool);
int httppool_io(HttpPool *httppool);
int httppool_cleancancelled(HttpPool *httppool);

int httppool_step(HttpPool *httppool, int maxiters);


/**
 * Cancel all requests that match a given tag.
 * @param httppool
 * @param tag
 * @return -1 on error or number of cancelled requests
 */
int httppool_canceltag(HttpPool *httppool, int tag);

/**
 * Cancel all requests that match a given tag,
 * It cancels pending requests immediately, but active requests only if
 * the remaining bytes to transfer exceeds the threshold bytes, up to a
 * hard timeout.
 * @param httppool
 * @param tag
 * @param thresholdbytes If a positive number, then the number of bytes
 *   permitted to complete.  If 0, then the timeout is used alone.  If -1,
 *   then cancellation is immediate.
 * @param timeoutms The max time allowed for the request to complete prior
 *   to cancelling, in milliseconds.  If 0, then cancellation will happen
 *   based on thresholdbytes.  If -1, then cancellation is immediate.
 * @return -1 on error or number of cancelled requests
 */
int httppool_canceltagifcostly(HttpPool *httppool, int tag, int thresholdbytes, int timeoutms);

int
httppool_setmaxhostconnections(HttpPool* httppool, int maxhostconnections);

/**
 * Set the maximum number of concurrent requests. If pipelining is disabled, the
 * actual number of concurrent requests will be limited by the maximum number of
 * concurrent connections.  But if pipelining is enabled, then multiple requests
 * can share a connection, and the number of concurrent requests can exceed the
 * number of concurrect connections.  The default is 50.
 *
 * @param httppool
 * @param maxreqs
 *
 * @return YPERWAVE_OK on success
 */
int httppool_setmaxrequests(HttpPool* httppool, int maxreqs);

/**
 * Set the maximum number of concurrent connections. More concurrent connections
 * allow you to better utilize fast connections (WiFi, LTE). The default is 10.
 *
 * @param httppool
 * @param maxconnections
 *
 * @return YPERWAVE_OK on success
 */
int
httppool_setmaxconnections(HttpPool* httppool, int maxconnections);

/**
 * Set the maximum number of cached connections that are being kept alive. You
 * should aim for a number that allows you to cache several connections to hosts
 * that are being called concurrently. For example if your pool connects to 10
 * different hosts you should use at least a pool size of 30 to cache 3 connections
 * per host.
 *
 * @param httppool
 * @param keepalivepool new size of the keep alive pool
 *
 * @return YPERWAVE_OK on success
 */
int httppool_setkeepalivepoolsize(HttpPool* httppool, int keepalivepool);

/**
 *  Set the timeout for DNS entries, in seconds.
 *
 *  @param httppool
 *  @param seconds A value of 0 disables the cache, while a value of -1 causes
 *    entries to be retained forever.
 *
 *  @return YPERWAVE_OK on success.
 */
int httppool_setdnscachetimeout(HttpPool *httppool, int seconds);

/**
 *  Get the timeout for DNS entries, in seconds.
 *
 *  @return The timeout in seconds.  If 0, then caching is disabled.
 *    If -1, then entries are never evicted.
 */
int httppool_getdnscachetimeout(HttpPool *httppool);

/**
 *  Enable SSL false start for this HTTP pool.
 *  It is disabled by default.
 *
 *  @return YPERWAVE_OK on success.
 */
int httppool_setsslfalsestart(HttpPool *httppool, YBOOL enabled);

/**
 * Return whether SSL false start is enabled.
 *
 * @return YTRUE if enabled.
 */
YBOOL httppool_getsslfalsestart(HttpPool *httppool);

/**
 * Enable/disable HTTP pipelining.
 *
 * @param httppool
 * @param enabled
 * @param threshold The response-size threshold at which to stop pipelining,
 *   in bytes.  If a response is smaller, then it pipelines, but if a response
 *   is larger, the pending request uses a different socket.  If the size is
 *   0, then pipelining will always be used.
 *
 *  @return YPERWAVE_OK on success.
 */
int httppool_setpipelining(HttpPool *httppool, YBOOL enabled, int threshold);

/**
 * Query whether HTTP pipelining is enabled for this pool.
 *
 * @return YTRUE if enabled.
 */
YBOOL httppool_getpipelining(HttpPool *httppool);

/**
 * Query the HTTP pipelining threshold.
 *
 * @return The theshold in bytes, or 0 if pipelining is always used.
 */
int httppool_getpipeliningthreshold(HttpPool *httppool);

/**
 * Set a default user agent for all requests.
 *
 * @param useragent The string to send as the User-Agent header.
 * @return YPERWAVE_OK on success.
 */
int httppool_setuseragent(HttpPool *httppool, const char *useragent);

/**
 * Get the default user agent.
 *
 * @return The string sent as the User-Agent header.
 */
const char *httppool_getuseragent(HttpPool *httppool);

int httppool_setcacher(HttpPool *httppool, Cacher *cacher);

#ifdef __cplusplus
};
#endif

#endif /* _YPERWAVE_HTTPPOOL_H */
