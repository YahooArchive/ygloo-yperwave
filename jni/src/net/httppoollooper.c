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

#define LOG_TAG "yperwave::httppoollooper"

#include "yperwave/yperwave.h"
#include "yperwave_priv.h"

#include <pthread.h>
#include <fcntl.h>

#define LOOPER_FALLBACK_WAIT_TIME 0.1*1000000
#define LOOPER_SELECT_MIN_TIMEOUT_MS 1
#define LOOPER_SELECT_MIN_TIMEOUT_STEP_MS 1

#if !defined(NDEBUG)
// Disable verbose logging.
#undef ALOGV
#define ALOGV(...) ((void)0)
#endif

#ifdef MAX
#undef MAX
#endif
#define MAX(a,b) ((a) > (b) ? (a) : (b))

#ifdef MIN
#undef MIN
#endif
#define MIN(a,b) ((a) < (b) ? (a) : (b))


struct HttpPoolLooperStruct {
  Yhashmap* pools;
  HttpPool** pools_dense;
  int num_pools;

  pthread_t worker;
  int worker_started;

  pthread_mutex_t mut;
  int pipe[2];
  int stop_requested;
  int softstop_requested;

  int sleep_backoff;
};


HttpPoolLooper*
httppoollooper_create()
{
  HttpPoolLooper *looper;
  int flags;

  looper = Ymem_malloc(sizeof(HttpPoolLooper));
  if (looper == NULL) {
    return NULL;
  }

  looper->pools = Yhashmap_create(8);
  if (looper->pools == NULL) {
    httppoollooper_release(looper);
    return NULL;
  }

  pthread_mutex_init(&looper->mut, NULL);

  looper->stop_requested = 0;
  looper->softstop_requested = 0;
  looper->worker_started = 0;
  looper->sleep_backoff = LOOPER_SELECT_MIN_TIMEOUT_MS;

  looper->pools_dense = NULL;

  if (pipe(looper->pipe) != 0) {
    httppoollooper_release(looper);
    return NULL;
  }

  flags = fcntl(looper->pipe[0], F_GETFL);
  if (flags == -1) {
    httppoollooper_release(looper);
    return NULL;
  }

  if (fcntl(looper->pipe[0], F_SETFL, flags|O_NONBLOCK) == -1) {
    httppoollooper_release(looper);
    return NULL;
  }

  flags = fcntl(looper->pipe[1], F_GETFL);
  if (flags == -1) {
    httppoollooper_release(looper);
    return NULL;
  }

  if (fcntl(looper->pipe[1], F_SETFL, flags|O_NONBLOCK) == -1) {
    httppoollooper_release(looper);
    return NULL;
  }

  return looper;
}

int
httppoollooper_release(HttpPoolLooper* looper)
{
  if (looper == NULL) {
    return YPERWAVE_OK;
  }

  if (looper->pools != NULL) {
    Yhashmap_release(looper->pools);
  }

  if (looper->pools_dense != NULL) {
    Ymem_free(looper->pools_dense);
  }

  pthread_mutex_destroy(&looper->mut);

  close(looper->pipe[0]);
  close(looper->pipe[1]);

  Ymem_free(looper);
  return YPERWAVE_OK;
}

static void*
background(void *arg)
{
  char c[5];
  int i;
  HttpPoolLooper *looper = (HttpPoolLooper*)arg;
  fd_set R, W, E;
  int maxM;
  uint32_t min_timeout;
  int total_inflight;
  int num_empty;

  struct timeval T;


  for (i=0; i<looper->num_pools; i++) {
    httppool_prepare(looper->pools_dense[i]);
  }

  while (1) {
    pthread_mutex_lock(&looper->mut);

    if (looper->stop_requested) {
      pthread_mutex_unlock(&looper->mut);
      break;
    }

    while (read(looper->pipe[0], c, 5) > 0);
    pthread_mutex_unlock(&looper->mut);

    total_inflight = 0;
    for (i=0; i<looper->num_pools; i++) {
      httppool_runcache(looper->pools_dense[i]);
      httppool_pop(looper->pools_dense[i]);
      total_inflight += httppool_perform(looper->pools_dense[i]);
      httppool_io(looper->pools_dense[i]);
      httppool_cleancancelled(looper->pools_dense[i]);
    }

    maxM = -1;
    min_timeout = -1;
    FD_ZERO(&R); FD_ZERO(&W); FD_ZERO(&E);
    for (i=0; i<looper->num_pools; i++) {
      int M = -1;
      uint32_t timeout;

      httppool_fdset(looper->pools_dense[i], &R, &W, &E, &M);
      maxM = MAX(M, maxM);

      timeout = httppool_timeout(looper->pools_dense[i]);
      ALOGV("timeout: %d", timeout);

      if (min_timeout == -1) {
        min_timeout = timeout;
      } else {
        min_timeout = MIN(timeout, min_timeout);
      }
    }

    /* upper bound for select timeout, to allow cURL to do call progress callbacks,
     * do abort checks, etc. at least once per second */
    if (min_timeout > 1000) {
      min_timeout = 1000;
    }

    ALOGV("min timeout: %d", min_timeout);
    ALOGV("max M: %d", maxM);

    ALOGV("R fd_set:");
    int y;
    if (maxM > 0) {
      for (y=0; y<=maxM+1; y++) {
        ALOGV("%d - %d", y, FD_ISSET(y, &R));
      }
    }

    if (maxM == -1) {
      min_timeout = looper->sleep_backoff;
      looper->sleep_backoff += LOOPER_SELECT_MIN_TIMEOUT_STEP_MS;
      if (total_inflight <= 0) {
        pthread_mutex_lock(&looper->mut);
        if (looper->softstop_requested == 1) {
          pthread_mutex_unlock(&looper->mut);
          break;
        }

        for (i=0; i<looper->num_pools; i++) {
          httppool_lock(looper->pools_dense[i]);
        }

        num_empty = 0;
        for (i=0; i<looper->num_pools; i++) {
          if (httppool_empty(looper->pools_dense[i])) {
            num_empty++;
          }
        }

        if (num_empty == looper->num_pools) {
          ALOGV("looper going to deep sleep");
          min_timeout = 60*1000;
          looper->sleep_backoff = LOOPER_SELECT_MIN_TIMEOUT_MS;
        }

        for (i=0; i<looper->num_pools; i++) {
          httppool_unlock(looper->pools_dense[i]);
        }
        pthread_mutex_unlock(&looper->mut);
      }
    } else {
      looper->sleep_backoff = LOOPER_SELECT_MIN_TIMEOUT_MS;
    }

    maxM = MAX(looper->pipe[0], maxM);
    FD_SET(looper->pipe[0], &R);

    T.tv_sec = min_timeout/1000;
    T.tv_usec = (min_timeout%1000)*1000;

    ALOGV("selecting");
    if (select(maxM+1, &R, &W, &E, &T) < 0) {
      usleep(LOOPER_FALLBACK_WAIT_TIME);
    }
    ALOGV("return from select");
  }

  pthread_exit(NULL);
  return NULL;
}

int
httppoollooper_running(HttpPoolLooper* looper)
{
  if (looper == NULL) {
    return 0;
  }
  return looper->worker_started;
}

int
httppoollooper_start(HttpPoolLooper* looper)
{
  YhashmapSearch search;
  YhashmapEntry *entry;
  int i;


  if (looper == NULL) {
    return YPERWAVE_ERROR;
  }
  if (looper->worker_started) {
    ALOGE("looper already started");
    return YPERWAVE_ERROR;
  }

  Yhashmap_lock(looper->pools);

  if (looper->pools_dense != NULL) {
    Ymem_free(looper->pools_dense);
  }

  looper->pools_dense = Ymem_malloc(sizeof(HttpPool*) * Yhashmap_size(looper->pools));
  entry = Yhashmap_first(looper->pools, &search);
  i = 0;
  while (entry != NULL) {
    HttpPool *p = *((HttpPool**) Yhashmap_key(entry, NULL));
    looper->pools_dense[i] = p;
    i++;
    entry = Yhashmap_next(&search);
  }
  looper->num_pools = i;
  Yhashmap_unlock(looper->pools);

  if (pthread_create(&looper->worker, NULL, background, looper) != 0) {
    return YPERWAVE_ERROR;
  }
  looper->worker_started = 1;

  return YPERWAVE_OK;
}

int
httppoollooper_stop(HttpPoolLooper* looper, int blocking)
{
  if (looper == NULL) {
    return YPERWAVE_ERROR;
  }
  if (!looper->worker_started) {
    ALOGE("looper not started");
    return YPERWAVE_ERROR;
  }

  if (pthread_mutex_lock(&looper->mut) != 0) {
    return YPERWAVE_ERROR;
  }

  looper->stop_requested = 1;
  pthread_mutex_unlock(&looper->mut);

  httppoollooper_nudge(looper);

  if (blocking) {
    if (pthread_join(looper->worker, NULL) != 0) {
      looper->stop_requested = 0;
      return YPERWAVE_ERROR;
    }
    looper->worker_started = 0;
  }

  looper->stop_requested = 0;
  return YPERWAVE_OK;
}

int
httppoollooper_softstop(HttpPoolLooper* looper)
{
  if (looper == NULL) {
    return YPERWAVE_ERROR;
  }
  if (!looper->worker_started) {
    ALOGE("looper not started");
    return YPERWAVE_ERROR;
  }

  if (pthread_mutex_lock(&looper->mut) != 0) {
    return YPERWAVE_ERROR;
  }

  looper->softstop_requested = 1;

  pthread_mutex_unlock(&looper->mut);

  httppoollooper_nudge(looper);

  if (pthread_join(looper->worker, NULL) != 0) {
    looper->softstop_requested = 0;
    return YPERWAVE_ERROR;
  }
  looper->worker_started = 0;

  looper->softstop_requested = 0;
  return YPERWAVE_OK;
}

int
httppoollooper_nudge(HttpPoolLooper* looper)
{
  int retval = YPERWAVE_ERROR;

  if (looper == NULL) {
    return YPERWAVE_ERROR;
  }

  ALOGV("waking up looper");

  pthread_mutex_lock(&looper->mut);
  if (write(looper->pipe[1], "a", 1) >= 1) {
    retval = YPERWAVE_OK;
  }
  pthread_mutex_unlock(&looper->mut);

  return retval;
}

int
httppoollooper_addPool(HttpPoolLooper* looper, HttpPool* pool)
{
  if (looper == NULL || pool == NULL) {
    return YPERWAVE_ERROR;
  }

  if (Yhashmap_lock(looper->pools) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  if (httppool_looper_attached(pool, looper) != YPERWAVE_OK) {
    Yhashmap_unlock(looper->pools);
    return YPERWAVE_ERROR;
  }
  Yhashmap_put(looper->pools, &pool, sizeof(HttpPool*), NULL);

  Yhashmap_unlock(looper->pools);
  return YPERWAVE_OK;
}

int
httppoollooper_removePool(HttpPoolLooper* looper, HttpPool* pool)
{
  if (looper == NULL || pool == NULL) {
    return YPERWAVE_ERROR;
  }

  if (Yhashmap_lock(looper->pools) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  if (httppool_looper_detached(pool) != YPERWAVE_OK) {
    Yhashmap_unlock(looper->pools);
    return YPERWAVE_ERROR;
  }
  Yhashmap_removekey(looper->pools, &pool, sizeof(HttpPool*));

  Yhashmap_unlock(looper->pools);
  return YPERWAVE_OK;
}
