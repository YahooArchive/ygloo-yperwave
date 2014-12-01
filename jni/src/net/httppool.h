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

#ifndef YPERWAVE_HTTPPOOL_PRIV_H
#define	YPERWAVE_HTTPPOOL_PRIV_H


#ifdef	__cplusplus
extern "C" {
#endif

int httppool_fdset(HttpPool* httppool, fd_set *R, fd_set *W, fd_set *E, int *M);

CURLSH* httppool_getsharedresources(HttpPool *httppool);

#ifdef	__cplusplus
}
#endif

#endif	/* YPERWAVE_HTTPPOOL_PRIV_H */