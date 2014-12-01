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

#ifndef _YPERWAVE_URLPARAMS_H
#define	_YPERWAVE_URLPARAMS_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct UrlParamsStruct UrlParams;

int
urlparams_encode(Ybuffer *buffer, const char *inbuf, int inlen);
int
urlparams_decode(Ybuffer *buffer, const char *inbuf, int inlen);

UrlParams*
urlparams_create();

int
urlparams_release(UrlParams *params);

int
urlparams_addBlob(UrlParams *params,
                  const char *key, int keylen, int keystatic,
                  const char *value, int valuelen, int valuestatic);

int
urlparams_add(UrlParams *params, const char *key, const char *value);

int
urlparams_addint(UrlParams *params, const char *key, int ivalue);

int
urlparams_addint64(UrlParams *params, const char *key, uint64_t ivalue);

int
urlparams_adddouble(UrlParams *params, const char *key, double dvalue);

int
urlparams_merge(UrlParams *params, UrlParams *in);

int
urlparams_length(UrlParams *params);

const char*
urlparams_key(UrlParams *params, int n, int *keylen);

const char*
urlparams_value(UrlParams *params, int n, int *valuelen);

int
urlparams_sort(UrlParams *params);
int
urlparams_append(UrlParams *params, Ybuffer *buffer);
char*
urlparams_format(UrlParams *params);

#ifdef	__cplusplus
}
#endif

#endif	/* _YPERWAVE_URLPARAMS_H */

