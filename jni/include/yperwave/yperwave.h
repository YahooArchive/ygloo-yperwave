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

#ifndef _YPERWAVE_H
#define _YPERWAVE_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "yosal/yosal.h"

#define YPERWAVE_OK    ((int)  0)
#define YPERWAVE_ERROR ((int) -1)

#include "yperwave/urlparams.h"
#include "yperwave/httputils.h"
#include "yperwave/httppool.h"
#include "yperwave/httppoollooper.h"
#include "yperwave/httpcache.h"
#include "yperwave/httprequest.h"
#include "yperwave/httpsettings.h"
#include "yperwave/yauth.h"
#include "yperwave/oauth.h"

#ifdef __cplusplus
};
#endif

#endif /* _YPERWAVE_H */
