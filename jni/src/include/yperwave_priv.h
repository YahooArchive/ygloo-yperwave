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

#ifndef _YPERWAVE_PRIV_H
#define _YPERWAVE_PRIV_H 1

/* Public API */
#include "yperwave/yperwave.h"

#include "yperwave_config.h"

/* Standard Posix headers required for private APIs */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifndef WIN32
#  include <unistd.h>
#endif

#include "jansson.h"
#include "curl/curl.h"

/* Private API */
#include "net/httprequest.h"
#include "net/httppool.h"
#include "auth/oauth.h"
#include "auth/yauth.h"


#define YPERWAVE_DEFAULT_URL_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
};
#endif

#endif /* _YPERWAVE_PRIV_H */
