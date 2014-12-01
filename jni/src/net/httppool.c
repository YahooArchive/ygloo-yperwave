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

#define LOG_TAG "yperwave::httppool"
#include "yperwave/yperwave.h"
#include "yperwave_priv.h"
#include "yosal/ycheck.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifndef WIN32
#  include <unistd.h>
#  include <fcntl.h>
#endif

#include <curl/multi.h>


struct HttpPoolStruct {
  /* mutex that locks http pool when requests are inserted or dequeued,
     also when the http pool is shut down */
  pthread_mutex_t lockmutex;

  CURLM *cm;
  CURLSH *curlshare;
  Cacher *cacher;
  /* Cache queue as linked list. */
  HttpRequest *cacheFirst;
  HttpRequest *cacheLast;
  /* List of in-flight cache requests. */
  Yhashmap *cacheProgress;
  /* Wait queue as linked list */
  HttpRequest *first;
  HttpRequest *last;
  /* List of in-flight requests */
  Yhashmap *inProgress;
  /* List of completed requests as linked list. */
  HttpRequest *finishedFirst;
  HttpRequest *finishedLast;
  /* Total number of requests pushed into the pool */
  int total;
  int caching;
  int running;
  int queued;

  /* maximum concurrent requests */
  int maxreqs;
  int maxconnections;
  int maxhostconnections;

  /* size of keep alive pool */
  int keepalivepool;

  const char *useragent;
  int dnscachetimeout;
  YBOOL sslfalsestart;
  YBOOL pipelining;
  int pipeliningThreshold;

  YArray *cancelledRequests;

  HttpPoolLooper* looper;

  uint64_t totalsize;
};

static int gHttpPool_ready = -1;
static pthread_mutex_t gHttpPool_mutex = PTHREAD_MUTEX_INITIALIZER;

int
httppool_init()
{
  CURLcode rc;

  /* Initialize http pool */
  if (gHttpPool_ready < 0) {
    pthread_mutex_lock(&gHttpPool_mutex);
    if (gHttpPool_ready < 0) {
      rc = curl_global_init_mem(CURL_GLOBAL_DEFAULT,
				Ymem_malloc,
				Ymem_free,
				Ymem_realloc,
				Ymem_strdup,
				Ymem_calloc);
      if (rc != CURLE_OK) {
	/* No http/https support available */
	gHttpPool_ready = 1;
      } else {
        /* Initialize seed for future random call */
        Yosal_init();
        /* Get sure JSON decoder uses our custom memory allocator */
        json_set_alloc_funcs(Ymem_malloc, Ymem_free);
        /* Ready */
	gHttpPool_ready = 0;
      }
    }
    pthread_mutex_unlock(&gHttpPool_mutex);
  }

  return gHttpPool_ready;
}

int
httppool_fini()
{
  if (gHttpPool_ready >= 0) {
    pthread_mutex_lock(&gHttpPool_mutex);
    if (gHttpPool_ready >= 0) {
      curl_global_cleanup();

      gHttpPool_ready = -1;
    }
    pthread_mutex_unlock(&gHttpPool_mutex);
  }

  return 0;
}

HttpPool*
httppool_create()
{
  HttpPool *httppool;

  if (httppool_init() != 0) {
    return NULL;
  }

  httppool = Ymem_malloc(sizeof(HttpPool));
  if (httppool == NULL) {
    return NULL;
  }

  if (pthread_mutex_init(&httppool->lockmutex, NULL) != 0) {
    Ymem_free(httppool);
    return NULL;
  }

  httppool->cancelledRequests = YArray_create();
  if (httppool->cancelledRequests == NULL) {
    httppool_release(httppool);
    return NULL;
  }

  httppool->cacher = NULL;
  httppool->cm = NULL;
  httppool->curlshare = NULL;
  httppool->cacheFirst = NULL;
  httppool->cacheLast = NULL;
  httppool->first = NULL;
  httppool->last = NULL;
  httppool->finishedFirst = NULL;
  httppool->finishedLast = NULL;
  httppool->total = 0;
  httppool->caching = 0;
  httppool->running = 0;
  httppool->queued = 0;
  httppool->maxreqs = 50;
  httppool->maxconnections = 10;
  httppool->maxhostconnections = 3;
  httppool->totalsize = 0;
  httppool->looper = NULL;
  httppool->cacheProgress = NULL;
  httppool->inProgress = NULL;
  httppool->keepalivepool = 30;
  httppool->useragent = NULL;
  httppool->dnscachetimeout = 60;
  httppool->sslfalsestart = YFALSE;
  httppool->pipelining = 0;
  httppool->pipeliningThreshold = 0;

  httppool->cacheProgress = Yhashmap_create(httppool->maxreqs);
  if (httppool->cacheProgress == NULL) {
    httppool_release(httppool);
    return NULL;
  }

  httppool->inProgress = Yhashmap_create(httppool->maxreqs);
  if (httppool->inProgress == NULL) {
    httppool_release(httppool);
    return NULL;
  }

  return httppool;
}

int
httppool_release(HttpPool *httppool)
{
  if (httppool == NULL) {
    return 0;
  }

  pthread_mutex_destroy(&httppool->lockmutex);

  if (httppool->cancelledRequests != NULL) {
    YArray_release(httppool->cancelledRequests);
  }

  if (httppool->inProgress) {
    Yhashmap_release(httppool->inProgress);
  }
  if (httppool->cacheProgress) {
    Yhashmap_release(httppool->cacheProgress);
  }
  if (httppool->curlshare) {
    curl_share_cleanup(httppool->curlshare);
  }
  if (httppool->useragent != NULL) {
    Ymem_free((void*)httppool->useragent);
  }

  curl_multi_cleanup(httppool->cm);

  Ymem_free(httppool);

  return 0;
}

int
httppool_setmaxrequests(HttpPool* httppool, int maxreqs)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  httppool_lock(httppool);
  httppool->maxreqs = maxreqs;
  httppool_unlock(httppool);

  return YPERWAVE_OK;
}

int
httppool_setdnscachetimeout(HttpPool *httppool, int seconds)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  } else {
    httppool->dnscachetimeout = seconds;
    return YPERWAVE_OK;
  }
}

int
httppool_getdnscachetimeout(HttpPool *httppool)
{
  if (httppool == NULL) {
    return 0;
  } else {
    return httppool->dnscachetimeout;
  }
}

int
httppool_setsslfalsestart(HttpPool *httppool, YBOOL enabled)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  } else {
    httppool->sslfalsestart = enabled;
    return YPERWAVE_OK;
  }
}

YBOOL
httppool_getsslfalsestart(HttpPool *httppool)
{
  if (httppool == NULL) {
    return YFALSE;
  } else {
    return httppool->sslfalsestart;
  }
}

int
httppool_setpipelining(HttpPool *httppool, YBOOL enabled, int threshold)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  } else {
    httppool->pipelining = enabled;
    httppool->pipeliningThreshold = threshold;
    return YPERWAVE_OK;
  }
}

YBOOL
httppool_getpipelining(HttpPool *httppool)
{
  if (httppool == NULL) {
    return YFALSE;
  } else {
    return httppool->pipelining;
  }
}

int
httppool_getpipeliningthreshold(HttpPool *httppool)
{
  if (httppool == NULL) {
    return 0;
  } else {
    return httppool->pipeliningThreshold;
  }
}

int
httppool_setmaxconnections(HttpPool* httppool, int maxconnections)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  httppool_lock(httppool);
  httppool->maxconnections = maxconnections;
  if (httppool->cm != NULL) {
    curl_multi_setopt(httppool->cm, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long) httppool->maxconnections);
  }
  httppool_unlock(httppool);

  return YPERWAVE_OK;
}

int
httppool_setmaxhostconnections(HttpPool* httppool, int maxhostconnections)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  httppool_lock(httppool);
  httppool->maxhostconnections = maxhostconnections;
  if (httppool->cm != NULL) {
    curl_multi_setopt(httppool->cm, CURLMOPT_MAX_HOST_CONNECTIONS, (long) httppool->maxhostconnections);
  }
  httppool_unlock(httppool);

  return YPERWAVE_OK;
}

int
httppool_setkeepalivepoolsize(HttpPool* httppool, int keepalivepool)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  httppool_lock(httppool);
  httppool->keepalivepool = keepalivepool;
  if (httppool->cm != NULL) {
    curl_multi_setopt(httppool->cm, CURLMOPT_MAXCONNECTS, (long) httppool->keepalivepool);
  }
  httppool_unlock(httppool);

  return YPERWAVE_OK;
}

int
httppool_setuseragent(HttpPool *httppool, const char *useragent)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  if (httppool->useragent != NULL) {
    Ymem_free((void*)httppool->useragent);
  }
  httppool->useragent = Ymem_strdup(useragent);

  if ((useragent == NULL) || (httppool->useragent != NULL)) {
    return YPERWAVE_OK;
  } else {
    return YPERWAVE_ERROR;
  }
}

const char *
httppool_getuseragent(HttpPool *httppool)
{
  if (httppool == NULL) {
    return NULL;
  } else {
    return httppool->useragent;
  }
}

int
httppool_setcacher(HttpPool *httppool, Cacher *cacher)
{
  if (httppool != NULL) {
    if (httppool_lock(httppool) == YPERWAVE_OK) {
      httppool->cacher = cacher;
      httppool_unlock(httppool);
      return YPERWAVE_OK;
    }
  }

  return YPERWAVE_ERROR;
}

CURLSH*
httppool_getsharedresources(HttpPool *httppool)
{
  if (httppool != NULL) {
    return httppool->curlshare;
  } else {
    return NULL;
  }
}

int
httppool_prepare (HttpPool *httppool)
{
  CURLM *cm;

  if (httppool->cm != NULL) {
    return YPERWAVE_OK;
  }

  cm = curl_multi_init();
  if (cm == NULL) {
    ALOGE("multi init failed\n");
    return YPERWAVE_ERROR;
  }

  httppool->cm = cm;

  httppool_setmaxconnections(httppool, httppool->maxconnections);
  httppool_setmaxhostconnections(httppool, httppool->maxhostconnections);
  httppool_setkeepalivepoolsize(httppool, httppool->keepalivepool);

  if (httppool->pipelining) {
    curl_multi_setopt(cm, CURLMOPT_PIPELINING, (long) 1);
    curl_multi_setopt(cm, CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE, (long) httppool->pipeliningThreshold);
    curl_multi_setopt(cm, CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE, (long) httppool->pipeliningThreshold);
  } else {
    curl_multi_setopt(cm, CURLMOPT_PIPELINING, (long) 0);
  }

  httppool->curlshare = curl_share_init();
  if (httppool->curlshare != NULL) {
    curl_share_setopt(httppool->curlshare, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
    curl_share_setopt(httppool->curlshare, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    curl_share_setopt(httppool->curlshare, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
  }

  return YPERWAVE_OK;
}

int
httppool_lock(HttpPool *httppool)
{
  int rc = YPERWAVE_OK;

  if (httppool != NULL) {
    if (pthread_mutex_lock(&httppool->lockmutex) != 0) {
      rc = YPERWAVE_ERROR;
    }
  }

  return rc;
}

int
httppool_unlock(HttpPool *httppool)
{
  int rc = YPERWAVE_OK;

  if (httppool != NULL) {
    if (pthread_mutex_unlock(&httppool->lockmutex) != 0) {
      rc = YPERWAVE_ERROR;
    }
  }

  return rc;
}

static void
listAppend(HttpRequest *handle, HttpRequest **first, HttpRequest **last)
{
  handle->next = NULL;
  if (*last != NULL) {
    (*last)->next = handle;
  }
  *last = handle;
  if (*first == NULL) {
    *first = handle;
  }
}

static void
listPrepend(HttpRequest *handle, HttpRequest **first, HttpRequest **last)
{
  handle->next = *first;
  *first = handle;
  if (*last == NULL) {
    *last = handle;
  }
}

static void
waitlistInsert(HttpPool *httppool, HttpRequest *handle)
{
  httprequest_setpool(handle, httppool);
  httprequest_finalize(handle);
  httprequest_setcacher(handle, httppool->cacher);

  if (handle->priority == HttpRequestPriority_Normal) {
    listAppend(handle, &httppool->first, &httppool->last);
  } else {
    listPrepend(handle, &httppool->first, &httppool->last);
  }
}

static void
cachelistInsert(HttpPool *httppool, HttpRequest *handle)
{
  if (handle->priority == HttpRequestPriority_Normal) {
    listAppend(handle, &httppool->cacheFirst, &httppool->cacheLast);
  } else {
    listPrepend(handle, &httppool->cacheFirst, &httppool->cacheLast);
  }
}

static void
finishedlistInsert(HttpPool *httppool, HttpRequest *handle)
{
  if (handle->priority == HttpRequestPriority_Normal) {
    listAppend(handle, &httppool->finishedFirst, &httppool->finishedLast);
  } else {
    listPrepend(handle, &httppool->finishedFirst, &httppool->finishedLast);
  }
}

int
httppool_add(HttpPool *httppool, HttpRequest *handle)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }
  if (handle == NULL) {
    return YPERWAVE_ERROR;
  }
  if (httppool_lock(httppool) != 0) {
    return YPERWAVE_ERROR;
  }

  httprequest_setactive(handle);
  int method = httprequest_getMethod(handle);
  if ((method == YPERWAVE_HTTP_GET) && (httppool->cacher != NULL) && (httppool->cacher->cachelookup != NULL)) {
    cachelistInsert(httppool, handle);
  } else {
    waitlistInsert(httppool, handle);
  }

  httppool->queued++;
  httppool->total++;

  httppool_unlock(httppool);

  if (httppool->looper != NULL) {
    httppoollooper_nudge(httppool->looper);
  }

  return 0;
}

int httppool_insert(HttpPool *httppool, HttpRequest *request, HttpRequestPriority priority)
{
  if (request != NULL) {
    httprequest_setpriority(request, priority);
  }
  return httppool_add(httppool, request);
}

static int
cancelHashmapTag(Yhashmap *hashmap, int tag, int thresholdbytes, int timeoutms)
{
  int cancelled = 0;
  YhashmapSearch search;
  YhashmapEntry *entry;

  Yhashmap_lock(hashmap);
  entry = Yhashmap_first(hashmap, &search);
  while (entry != NULL) {
    HttpRequest *r = *((HttpRequest**) Yhashmap_key(entry, NULL));

    if (r->tag == tag) {
      httprequest_cancelifcostly(r, thresholdbytes, timeoutms);
      cancelled++;
    }

    entry = Yhashmap_next(&search);
  }
  Yhashmap_unlock(hashmap);

  return cancelled;
}

static int
cancelRequestList(HttpRequest *start, int tag, int thresholdbytes, int timeoutms)
{
  int cancelled = 0;
  HttpRequest *cur = start;

  while (cur != NULL) {
    if (cur->tag == tag) {
      httprequest_cancelifcostly(cur, thresholdbytes, timeoutms);
      cancelled++;
    }

    cur = cur->next;
  }

  return cancelled;
}

int
httppool_canceltag(HttpPool *httppool, int tag)
{
  return httppool_canceltagifcostly(httppool, tag, -1, -1);
}

int
httppool_canceltagifcostly(HttpPool *httppool, int tag, int thresholdbytes, int timeoutms)
{
  int cancelled = 0;

  if (httppool == NULL) {
    return -1;
  }

  if (tag < 0) {
    return -1;
  }
  if (httppool_lock(httppool) != 0) {
    return -1;
  }

  cancelled += cancelRequestList(httppool->cacheFirst, tag, thresholdbytes, timeoutms);
  cancelled += cancelRequestList(httppool->first, tag, thresholdbytes, timeoutms);

  cancelled += cancelHashmapTag(httppool->cacheProgress, tag, thresholdbytes, timeoutms);
  cancelled += cancelHashmapTag(httppool->inProgress, tag, thresholdbytes, timeoutms);

  httppool_unlock(httppool);

  if (httppool->looper != NULL) {
    httppoollooper_nudge(httppool->looper);
  }

  return cancelled;
}

static void
cacheLookupCallback(HttpRequest *handle, int cancelled, void *cbdata)
{
  YDCHECK(handle != NULL);
  YDCHECK(cbdata != NULL);
  if ((handle == NULL) || (cbdata == NULL)) {
    return;
  }

  // This callback might oneday run on a different thread.
  HttpPool *httppool = (HttpPool*)cbdata;
  if (httppool_lock(httppool) != 0) {
    return;
  }

  Yhashmap_lock(httppool->cacheProgress);
  YDCHECK(Yhashmap_contain(httppool->cacheProgress, &handle, sizeof(HttpRequest*)));
  Yhashmap_removekey(httppool->cacheProgress, &handle, sizeof(HttpRequest*));
  Yhashmap_unlock(httppool->cacheProgress);
  YDCHECK(httppool->caching > 0);
  httppool->caching--;

  if (cancelled) {
    httppool->queued++;
    cachelistInsert(httppool, handle);
  } else if (httprequest_status(handle) == HTTPREQUEST_STATUS_NONE) {
    if ((httprequest_getcachehints(handle) & CacheHint_CacheOnly) == CacheHint_CacheOnly) {
      httprequest_setstatus(handle, HTTPREQUEST_STATUS_FAILED);
      finishedlistInsert(httppool, handle);
    } else {
      httppool->queued++;
      waitlistInsert(httppool, handle);

      if ((httppool->cacher != NULL) && (httppool->cacher->cacheupdate != NULL)) {
        httppool->cacher->cacheupdate(httppool->cacher, handle, CacherUpdatePhase_Start, NULL, 0);
      }
    }
  } else {
    finishedlistInsert(httppool, handle);
  }

  httppool_unlock(httppool);

  if (httppool->looper != NULL) {
    httppoollooper_nudge(httppool->looper);
  }
}

void
httppool_runcache(HttpPool *httppool)
{
  HttpRequest *handle;

  if (httppool == NULL) {
    return;
  }
  if (httppool_lock(httppool) != 0) {
    return;
  }

  while (httppool->cacheFirst != NULL) {
    // Pop the first cache request from the list.
    handle = httppool->cacheFirst;
    httppool->cacheFirst = handle->next;
    handle->next = NULL;
    if (httppool->cacheLast == handle) {
      httppool->cacheLast = NULL;
    }

    if (httprequest_isCancelRequested(handle)) {
      YArray_append(httppool->cancelledRequests, handle);
    } else {
      httppool->caching++;
      Yhashmap_lock(httppool->cacheProgress);
      Yhashmap_put(httppool->cacheProgress, &handle, sizeof(HttpRequest*), NULL);
      Yhashmap_unlock(httppool->cacheProgress);

      httppool_unlock(httppool);
      httppool->cacher->cachelookup(httppool->cacher, handle, cacheLookupCallback, httppool);
      if (httppool_lock(httppool) != 0) {
        return;
      }
    }
    httppool->queued--;
  }

  httppool_unlock(httppool);
}

int
httppool_pop(HttpPool *httppool)
{
  int nreqs = 0;
  HttpRequest *handle;

  if (httppool == NULL) {
    return nreqs;
  }

  if (httppool_lock(httppool) != 0) {
    return nreqs;
  }

  /* Transfer as many requests as possible from queue to running */
  while (httppool->running < httppool->maxreqs && httppool->first != NULL) {
    handle = httppool->first;
    httppool->first = handle->next;
    handle->next = NULL;

    if (httppool->last == handle) {
      httppool->last = NULL;
    }

    // ALOGD("PROF url=%s ADD %p ", handle->url, handle->curl);

    if (httprequest_isCancelRequested(handle)) {
      YArray_append(httppool->cancelledRequests, handle);
    } else {
      Yhashmap_lock(httppool->inProgress);
      Yhashmap_put(httppool->inProgress, &handle, sizeof(HttpRequest*), NULL);
      Yhashmap_unlock(httppool->inProgress);

      if ((httppool->cacher != NULL) && (httppool->cacher->cacheupdate != NULL)) {
        httppool->cacher->cacheupdate(httppool->cacher, handle, CacherUpdatePhase_Start, NULL, 0);
      }

      curl_multi_add_handle(httppool->cm, handle->curl);
      httppool->running++;
      nreqs++;
    }
    httppool->queued--;
  }

#if 0
  printf("pushed %d requests first=%p\n", nreqs, httppool->first);
#endif

  httppool_unlock(httppool);

  return nreqs;
}

int
httppool_looper_attached(HttpPool* httppool, HttpPoolLooper* looper)
{
  if (httppool == NULL || looper == NULL) {
    return YPERWAVE_ERROR;
  }

  if (httppool->looper != NULL) {
    return YPERWAVE_ERROR;
  }

  httppool->looper = looper;
  return YPERWAVE_OK;
}

int
httppool_looper_detached(HttpPool* httppool)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  httppool->looper = NULL;
  return YPERWAVE_OK;
}

int
httppool_fdset(HttpPool* httppool, fd_set *R, fd_set *W, fd_set *E, int *M)
{
  if (httppool == NULL) {
    return YPERWAVE_ERROR;
  }

  if (curl_multi_fdset(httppool->cm, R, W, E, M) != CURLM_OK) {
    return YPERWAVE_ERROR;
  }

  return YPERWAVE_OK;
}

uint32_t httppool_timeout(HttpPool* httppool)
{
  long t=0;

  if (httppool == NULL) {
    return -1;
  }

  if (curl_multi_timeout(httppool->cm, &t) != CURLM_OK) {
    return -1;
  }

  return t;
}

int httppool_empty(HttpPool* httppool)
{
  int retval = 1;

  if (httppool == NULL) {
    return -1;
  }

  if (httppool->first != NULL) {
    retval = 0;
  }

  if (httppool->cacheFirst != NULL) {
    retval = 0;
  }

  if (httppool->cacheProgress != NULL) {
    if (Yhashmap_size(httppool->cacheProgress) > 0) {
      retval = 0;
    }
  }

  if (httppool->inProgress != NULL) {
    if (Yhashmap_size(httppool->inProgress) > 0) {
      retval = 0;
    }
  }

  if (httppool->finishedFirst != NULL) {
    retval = 0;
  }

  return retval;
}

int
httppool_perform(HttpPool* httppool)
{
  int U;
  CURLMcode mrc;

  mrc = curl_multi_perform(httppool->cm, &U);
  if (mrc != CURLM_OK) {
    fprintf(stderr, "curl_multi_perform failed: %s\n",
            curl_multi_strerror(mrc));
    return -1;
  }

#if DEBUG_CURL
  ALOGD("U=%d TOTAL=%d QUEUED=%d RUNNING=%d CACHING=%d",
        U, httppool->total, httppool->queued, httppool->running, httppool->caching);
#endif

  return U;
}

int
httppool_iowait(HttpPool* httppool)
{
  long L;
  fd_set R, W, E;
  int M = -1;
  struct timeval T;

  FD_ZERO(&R);
  FD_ZERO(&W);
  FD_ZERO(&E);

  if (curl_multi_fdset(httppool->cm, &R, &W, &E, &M)) {
    // fprintf(stderr, "E: curl_multi_fdset\n");
    return YPERWAVE_ERROR;
  }

  if (curl_multi_timeout(httppool->cm, &L)) {
    //fprintf(stderr, "E: curl_multi_timeout\n");
    return YPERWAVE_ERROR;
  }
  if (L == -1) {
    L = 100;
  }

  if (M == -1) {
#ifdef WIN32
    Sleep(L);
#else
    sleep(L / 1000);
#endif
  } else {
    T.tv_sec = L/1000;
    T.tv_usec = (L%1000)*1000;

    if (select(M+1, &R, &W, &E, &T) < 0) {
      // fprintf(stderr, "E: select(%i,,,,%li): %i: %s\n",
      //    M+1, L, errno, strerror(errno));
      return YPERWAVE_ERROR;
    }

    httppool_pop(httppool);
  }

  return YPERWAVE_OK;
}

int
httppool_io(HttpPool *httppool)
{
  CURLMsg *msg;
  int Q;

  while ((msg = curl_multi_info_read(httppool->cm, &Q))) {
    if (msg->msg == CURLMSG_DONE) {
      CURL *curl = msg->easy_handle;
      HttpRequest *handle = NULL;

      /* Counter for active number of request must be decremented before
       calling user callback, so it can push new requests into the pool */
      httppool->running--;

      if (curl != NULL) {
        curl_multi_remove_handle(httppool->cm, curl);

        curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char**) &handle);
        if (handle != NULL) {
          Yhashmap_lock(httppool->inProgress);
          YDCHECK(Yhashmap_contain(httppool->inProgress, &handle, sizeof(HttpRequest*)));
          Yhashmap_removekey(httppool->inProgress, &handle, sizeof(HttpRequest*));
          Yhashmap_unlock(httppool->inProgress);

          if (msg->data.result == CURLE_OK) {
            httprequest_setstatus(handle, HTTPREQUEST_STATUS_SUCCESS);
          } else {
            const char* errstr = curl_easy_strerror(msg->data.result);
            ALOGE("cURL error: %s", errstr);

            // if a callback aborts, it sets the status already
            if (msg->data.result != CURLE_ABORTED_BY_CALLBACK) {
              httprequest_setstatus(handle, HTTPREQUEST_STATUS_FAILED);
            }
          }

          if ((httppool->cacher != NULL) && (httppool->cacher->cacheupdate != NULL)) {
            httppool->cacher->cacheupdate(httppool->cacher, handle,
                                          httprequest_status(handle) == HTTPREQUEST_STATUS_CANCELLED ?
                                            CacherUpdatePhase_Cancel : CacherUpdatePhase_Complete, NULL, 0);
          }
          httprequest_completed(handle);
        }
      }
    }
    else {
      ALOGE("CURLMsg (%d)", msg->msg);
    }
  }

  if (httppool_lock(httppool) != 0) {
    return YPERWAVE_ERROR;
  }
  while (httppool->finishedFirst != NULL) {
    HttpRequest *handle = httppool->finishedFirst;
    httppool->finishedFirst = handle->next;
    handle->next = NULL;
    if (httppool->finishedLast == handle) {
      httppool->finishedLast = NULL;
    }

    httppool_unlock(httppool);
    httprequest_completed(handle);
    if (httppool_lock(httppool) != 0) {
      return YPERWAVE_ERROR;
    }
  }
  httppool_unlock(httppool);

  return YPERWAVE_OK;
}

int
httppool_cleancancelled(HttpPool *httppool)
{
  int i;

  for (i=0; i<YArray_length(httppool->cancelledRequests); i++) {
    HttpRequest* req = (HttpRequest*) YArray_detach(httppool->cancelledRequests, i);

    if (req == NULL) {
      continue;
    }

    if (!req->completed) {
      httprequest_setstatus(req, HTTPREQUEST_STATUS_CANCELLED);
      if ((httppool->cacher != NULL) && (httppool->cacher->cacheupdate != NULL)) {
        httppool->cacher->cacheupdate(httppool->cacher, req, CacherUpdatePhase_Cancel, NULL, 0);
      }
      httprequest_completed(req);
    }
  }
  YArray_reset(httppool->cancelledRequests);

  return YPERWAVE_OK;
}

int
httppool_step(HttpPool *httppool, int maxiters)
{
  int niters = 0;
  int U;

  if (httppool == NULL) {
    return 0;
  }

  // temporary for backwards compatibility
  if (httppool->cm == NULL) {
    httppool_prepare(httppool);
  }

  httppool_runcache(httppool);
  httppool_pop(httppool);

  while ((httppool->running > 0) || (httppool->caching > 0)) {
    niters++;
    if (maxiters >= 0 && niters > maxiters) {
      break;
    }

    U = httppool_perform(httppool);

    if (U > 0) {
      httppool_iowait(httppool);
    }

    httppool_io(httppool);
  }

  httppool_cleancancelled(httppool);

  return httppool->running;
}
