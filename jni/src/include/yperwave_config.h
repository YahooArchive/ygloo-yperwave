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

#ifndef _YPERWAVE_CONFIG_H
#define _YPERWAVE_CONFIG_H 1

/* Default values */
#ifndef HAVE_JSON
#define HAVE_JSON 0
#endif

#if defined(HAVE_JSON) && !HAVE_JSON
#undef HAVE_JSON
#endif

#if defined(YPERWAVE_DEBUG) && !YPERWAVE_DEBUG
#undef YPERWAVE_DEBUG
#endif

/* Transitive dependencies */
#if defined(HAVE_YQL) && !defined(HAVE_JSON)
#define HAVE_YQL 1
#endif

#if defined(YPERWAVE_DEBUG)
#define YPERWAVE_DEBUG_JSON 1
#define YPERWAVE_DEBUG_HTTP 1
#endif

#endif /* _YPERWAVE_CONFIG_H */
