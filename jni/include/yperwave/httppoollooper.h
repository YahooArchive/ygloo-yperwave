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

#ifndef _YPERWAVE_HTTPPOOLLOOPER_H
#define _YPERWAVE_HTTPPOOLLOOPER_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HttpPoolLooperStruct HttpPoolLooper;

HttpPoolLooper*
httppoollooper_create();
int
httppoollooper_release(HttpPoolLooper* looper);

int
httppoollooper_running(HttpPoolLooper* looper);

int
httppoollooper_start(HttpPoolLooper* looper);

/**
 * Stop the looper immediately, cancel all pending requests.
 *
 * @param looper
 * @param blocking call blocks until looper is shut down
 */
int
httppoollooper_stop(HttpPoolLooper* looper, int blocking);

/**
 * Stop the looper after all currently pending and queued requests are completed,
 * blocks until looper has shut down.
 * This is best effort and request completion is likely, but not guaranteed. Only
 * use this method if you have have "unlimited" time left. Never use it when the OS
 * allocates you a limited amount of time to perform lifecycle operations.
 *
 * @param looper
 */
int
httppoollooper_softstop(HttpPoolLooper* looper);

/**
 * Wake the looper (background thread) from any sleep or blocking operation
 * it might perform.
 *
 * @param looper
 */
int
httppoollooper_nudge(HttpPoolLooper* looper);

/**
 * Add given pool to the given looper. This method can only be used
 * on stopped HttpPoolLoopers. One pool can only be attached to at most one
 * looper.
 * @param looper
 * @param pool
 * @return YPERWAVE_OK on success
 */
int
httppoollooper_addPool(HttpPoolLooper* looper, HttpPool* pool);

/**
 * Detach a pool from the given looper. This method can only be used
 * on stopped HttpPoolLoopers.
 * @param looper
 * @param pool
 * @return YPERWAVE_OK on success
 */
int
httppoollooper_removePool(HttpPoolLooper* looper, HttpPool* pool);

#ifdef __cplusplus
};
#endif

#endif /* _YPERWAVE_HTTPPOOLLOOPER_H */
