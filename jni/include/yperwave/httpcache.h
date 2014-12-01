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

#ifndef _YPERWAVE_HTTPCACHE_H
#define _YPERWAVE_HTTPCACHE_H 1

#ifdef __cplusplus
extern "C" {
#endif


// The cache hints decrease the importance of the cache entry.
// The entry's hints are the union of the hints from the original request,
// and the hints from all later requests.  Thus later requests can increase
// the importance of a cache entry.
typedef enum {
  CacheHint_None = 0x0,
  CacheHint_Streaming = 0x1,
  CacheHint_BypassLookup = 0x2,
  CacheHint_BypassSave = 0x4,
  CacheHint_CacheOnly = 0x8,
} CacheHints;

YOSAL_OBJECT_DECLARE(CacheData)
YOSAL_OBJECT_BEGIN
  void *data;
  unsigned datalen;
YOSAL_OBJECT_END
YOSAL_OBJECT_EXPORT(CacheData)

CacheData *cachedata_create();

#include "yperwave/httprequest.h"

typedef struct CacheTelemetryStruct CacheTelemetry;
struct CacheTelemetryStruct {
  uint32_t reqsCancelled; /** Number of HTTP requests cancelled. */
  uint32_t reqsFailed; /** Number of HTTP requests failed. */
  uint32_t reqsMerged; /** Number of overlapping HTTP requests merged into single request. */

  uint32_t compulsaryMisses; /** Number of compulsary misses in the memory cache. */
  uint32_t capacityMisses; /** Number of capacity misses in the memory cache. */
  uint32_t hits; /** Number of hits in the memory cache. */

  uint32_t totStreamEvictions; /** Number of streaming images evicted. */
  uint32_t totEvictions; /** Number of total images evicted. */
  uint32_t totCorruptEvictions; /** Number of images deleted due to corruption or error. */

  uint32_t totAddedItems; /** Number of items added into the memory cache over time. */
  uint32_t activeItems; /** Number of items currently in the memory cache. */
  uint32_t activeHistoryItems; /** Number of history items currently in the memory cache. */

  uint32_t activeBytes; /** Number of bytes currently in the memory cache. */
  uint32_t maxBytes; /** Number of bytes currently allowed in the memory cache. */

  uint64_t totAddedBytes; /** Number of bytes added into the cache over time. */
  uint64_t totEvictedBytes; /** Number of bytes evicted from the cache over time. */
  uint64_t totEvictedStreamBytes; /** Number of streaming bytes evicted from the cache over time. */
  uint64_t totEvictedCorruptBytes; /** Number of bytes evicted due to corruption or error. */
};

typedef enum {
  CacherUpdatePhase_Start = 0,
  CacherUpdatePhase_Data,
  CacherUpdatePhase_Complete,
  CacherUpdatePhase_Cancel
} CacherUpdatePhase;

typedef void (*CacherCBFunc)(HttpRequest *request, int cancelled, void *cbdata);

typedef struct CacherStruct Cacher;
struct CacherStruct
{
  void (*cachelookup)(Cacher *cacher, HttpRequest *request,
                      CacherCBFunc callback, void *cbdata);
  void (*cacheupdate)(Cacher *cacher, HttpRequest *request, CacherUpdatePhase phase,
                      void *optdata, int optdatalen);
};


#ifdef __cplusplus
};
#endif

#endif // _YPERWAVE_HTTPCACHE_H
