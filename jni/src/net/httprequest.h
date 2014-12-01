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

#ifndef HTTPREQUEST_PRIV_H
#define	HTTPREQUEST_PRIV_H

#ifdef	__cplusplus
extern "C" {
#endif

#define HTTPREQUEST_STATUS_NONE 0
#define HTTPREQUEST_STATUS_INIT 1
#define HTTPREQUEST_STATUS_SUCCESS 2
#define HTTPREQUEST_STATUS_PENDING 3
#define HTTPREQUEST_STATUS_IDLE 4
#define HTTPREQUEST_STATUS_RUNNING 5
#define HTTPREQUEST_STATUS_TIMEOUT 6
#define HTTPREQUEST_STATUS_CANCELLED 7
#define HTTPREQUEST_STATUS_FAILED 8
#define HTTPREQUEST_STATUS_FAILED_FILE_READ 9

struct HttpRequestStruct {
  int method;
  char *url;
  UrlParams *urlparams;

  char* paramsstr;
  int paramsstrlen;

  int cancelRequested;
  nsecs_t cancelRequestedTimeoutNs;

  int connectTimeout;
  int minSpeed;
  int minSpeedInterval;

  int tag;

  char* uploadfilekey;
  char* uploadfilename;
  Ychannel* uploadfile;
  int uploadfile_autorelease;
  size_t uploadlength;
  size_t uploadcount;

  size_t postlength;
  size_t postprogress;
  size_t downloadlength;
  size_t downloadprogress;

  int (*callback)(HttpRequest*);
  void *privatedata;

  CURL *curl;
  struct curl_httppost* argsform;
  struct curl_slist* headers;

  HttpPool *httppool;

  int sslverify;

  Cacher *cacher;
  int cachehints;

  char* proxyhost;
  char* proxyuser;
  char* proxypwd;

  /* Output vbuffer to store the payload into */
  Ybuffer *vbuffer;
  char *rawdata;
  int rawlen;

  /* Output buffer to store a payload from the cache. */
  CacheData *cachedata;

  /* Output filename to save the payload into */
  char *outfile;
  /* Output filename to save the payload as it gets downloaded */
  char *partfile;
  /* Private output channel used to write into output file */
  Ychannel *outchannel;

  /* Output vchannel to write the payload into */
  Ychannel *vchannel;
  int vchannelrelease;

  /* Total number of (decoded) bytes received */
  size_t datalen;

  int completed;
  int status;
  YArray *responseHeaders;

  int instrument;
  HttpRequestTelemetry *telemetry;
  nsecs_t queuedtime;

  HttpRequestPriority priority;

  /* Implement simple queue directly into structure to avoid allocating
     lot of small chunks */
  HttpRequest *next;
};

int
httprequest_setactive(HttpRequest *req);

int
httprequest_setstatus(HttpRequest *req, int status);

void
httprequest_setpriority(HttpRequest *req, HttpRequestPriority priority);

void
httprequest_setcacher(HttpRequest *req, Cacher *cacher);

void
httprequest_setpool(HttpRequest *req, HttpPool *httppool);

#ifdef	__cplusplus
}
#endif

#endif	/* HTTPREQUEST_PRIV_H */

