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

#define LOG_TAG "yperwave::httprequest"

#include "yperwave/yperwave.h"
#include "yperwave_priv.h"

#include <string.h>

#if defined(USE_OPENSSL) && USE_OPENSSL
#include <openssl/ssl.h>
#endif

#define DEBUG_CURL 0

/*
  libcurl examples:
  http://curl.haxx.se/libcurl/c/simplessl.html

  For most efficient concurrent crawler, see hiperfifo.c
 */

static size_t
ResponseCallback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  HttpRequest *handle = (HttpRequest*) stream;
  CURL *curl = NULL;
  size_t nbytes = 0;

  if (handle == NULL) {
    return nbytes;
  }

  curl = handle->curl;
  if (curl == NULL) {
    return nbytes;
  }
#if 0
  ALOGD("got response for %p (%ld records of %ld bytes)", handle,
          (long) nmemb, (long) size);
#endif
  if (size > 0 && nmemb > 0) {
    nbytes = size * nmemb;

    if ((handle->cacher != NULL) && (handle->cacher->cacheupdate != NULL)) {
      handle->cacher->cacheupdate(handle->cacher, handle, CacherUpdatePhase_Data, ptr, nbytes);
    }

    if (handle->datalen == 0) {
      FILE *f = NULL;
      char *outfile;
      if (handle->outfile != NULL) {
        if (handle->partfile != NULL) {
          outfile = handle->partfile;
        } else {
          outfile = handle->outfile;
        }
        f = fopen(outfile, "wb");
        if (f != NULL) {
          Ychannel *ochannel = YchannelInitFile(f, 1);
          if (ochannel != NULL) {
            if (handle->outchannel != NULL) {
              YchannelRelease(handle->outchannel);
            }
            handle->outchannel = ochannel;
         }
        }
      }
    }

    if (handle->vchannel != NULL) {
      YchannelWrite(handle->vchannel, ptr, nbytes);
    } else if (handle->outchannel != NULL) {
      YchannelWrite(handle->outchannel, ptr, nbytes);
    } else {
      if (handle->vbuffer == NULL) {
        const double safemax = 2*1024*1024;
        double contentlen = -1;
        if (curl_easy_getinfo(handle->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &contentlen) != CURLE_OK) {
          contentlen = -1;
        }
        if (contentlen <= 0) {
          contentlen = 32*1024;
        } else if (contentlen > safemax) {
          contentlen = safemax;
        }
        handle->vbuffer = Ybuffer_init(contentlen);
      }
      if (handle->vbuffer != NULL) {
        Ybuffer_append(handle->vbuffer, ptr, nbytes);
      }
    }

    handle->datalen += nbytes;
  }

  return nbytes;
}

static int
ProgressCallback(void *p,
                 curl_off_t dltotal, curl_off_t dlnow,
                 curl_off_t ultotal, curl_off_t ulnow)
{
  HttpRequest *handle = (HttpRequest*) p;
  CURL *curl = NULL;
  YBOOL cancelNow = YFALSE;
  //double curtime = 0;

  if (handle == NULL) {
    return 1;
  }

  curl = handle->curl;
  if (curl == NULL) {
    return 1;
  }

  //ALOGD("progress callback for %s which is cancelled:%d", handle->url, handle->cancelRequested);

  handle->postlength = ultotal;
  handle->postprogress = ulnow;
  handle->downloadlength = dltotal;
  handle->downloadprogress = dlnow;

  if (handle->cancelRequested != 0) {
    cancelNow = handle->cancelRequested == -1;
    if (!cancelNow) {
      if (dlnow > dltotal) {
        // The server didn't send a correct content length, so for safety, cancel the request.
        cancelNow = YTRUE;
      } else if (dltotal > 0) {
        // We know the content length.  Compare remaining bytes to the cancel threshold.
        double remainingBytes = dltotal - dlnow;
        if (remainingBytes > handle->cancelRequested) {
            cancelNow = YTRUE;
        }
      }
    }
  }

  if (!cancelNow && (handle->cancelRequestedTimeoutNs != 0)) {
    if (Ytime(YTIME_CLOCK_MONOTONIC) >= handle->cancelRequestedTimeoutNs) {
      // We've waited too long since the cancel was requested.
      cancelNow = YTRUE;
    }
  }

  if (cancelNow) {
    handle->status = HTTPREQUEST_STATUS_CANCELLED;
    return -1;
  }

  //curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &curtime);

  /* under certain circumstances it may be desirable for certain functionality
     to only run every N seconds, in order to do this the transaction time can
     be used */
/*#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL 1.0f
#define STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES -1.0f

  if ((curtime - handle->lastruntime) >= MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL) {
    handle->lastruntime = curtime;
  }

  if (STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES >= 0.0f && dlnow >= STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES) {
    return 1;
  }*/

  return 0;
}

#if DEBUG_CURL
static int
DebugCallback(CURL *curl, curl_infotype infotype, char *msg, size_t msglen, void *data)
{
  switch (infotype) {
    case CURLINFO_TEXT:
      // The data is informational text.
      ALOGI("curl text: %.*s", (int) msglen, msg);
      break;
    case CURLINFO_HEADER_IN:
      // The data is header (or header-like) data received from the peer.
      ALOGI("curl header_in: %.*s", (int) msglen, msg);
      break;
    case CURLINFO_HEADER_OUT:
      // The data is header (or header-like) data sent to the peer.
      ALOGI("curl header_out: %.*s", (int) msglen, msg);
      break;
    case CURLINFO_DATA_IN:
      // The data is protocol data received from the peer.
      ALOGI("curl data_in: %.*s", (int) msglen, msg);
      break;
    case CURLINFO_DATA_OUT:
      //The data is protocol data sent to the peer.
      ALOGI("curl data_out: %.*s", (int) msglen, msg);
      break;
    default:
      ALOGI("curl unknown: %.*s", (int) msglen, msg);
      break;
  }

  return 0;
}
#endif

static size_t
HeaderCallback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  HttpRequest *request = (HttpRequest*)stream;

  if (request->responseHeaders != NULL) {
    // Note: ptr is a char array --- not always a zero-terminated string.
    int totlen = size*nmemb;
    const char *src = ptr;

    // Drop the HTTP line separator.
    while ((totlen > 0) && ((src[totlen-1] == '\r') || (src[totlen-1] == '\n') || (src[totlen-1] == '\0'))) {
      totlen--;
    }

    if (totlen > 0) {
      char *dst = Ymem_malloc(totlen + 1);
      if (dst != NULL) {
        memcpy(dst, src, totlen);
        dst[totlen] = '\0';
        if (YArray_append(request->responseHeaders, dst) == YOSAL_ERROR) {
          Ymem_free(dst);
        }
      }
    }
  }

  return size*nmemb;
}

static CURLcode
SslCtxCallback(CURL *curl, void *sslctx, void *parm)
{
  HttpRequest *request = (HttpRequest*)parm;

  if (httppool_getsslfalsestart(request->httppool)) {
#if defined(USE_OPENSSL) && USE_OPENSSL
    // Enable SSL false start.
    SSL_CTX_set_mode(sslctx, SSL_CTX_get_mode(sslctx) | SSL_MODE_HANDSHAKE_CUTTHROUGH);
#endif
  }

  return CURLE_OK;
}

UrlParams*
httprequest_getParams(HttpRequest* ctx)
{
  if (ctx->urlparams == NULL) {
    ctx->urlparams = urlparams_create();
  }

  return ctx->urlparams;
}

int
httprequest_setConnectTimeout(HttpRequest *req, int timeout)
{
  if (req == NULL) {
    return YOSAL_ERROR;
  }

  if (timeout <= 0) {
    timeout = 15;
  }

  req->connectTimeout = timeout;
  return YOSAL_OK;
}

int
httprequest_setMinSpeed(HttpRequest *req, int speed, int seconds)
{
  if (req == NULL) {
    return YOSAL_ERROR;
  }

  if (speed <= 0) {
    speed = 1024;
  }

  if (seconds <= 0) {
    seconds = 15;
  }

  req->minSpeed = speed;
  req->minSpeedInterval = seconds;
  return YOSAL_OK;
}

int
httprequest_setstatus(HttpRequest *req, int status)
{
  req->status = status;
  return YPERWAVE_OK;
}

int
httprequest_setUploadFile(HttpRequest* ctx,
                          const char* key, const char* filename, Ychannel* filestream, int autorelease)
{
  if (ctx->uploadfilekey != NULL) {
    Ymem_free(ctx->uploadfilekey);
    ctx->uploadfilekey = NULL;
  }
  if (ctx->uploadfilename != NULL) {
    Ymem_free(ctx->uploadfilename);
    ctx->uploadfilename = NULL;
  }
  if (ctx->uploadfile != NULL) {
    if (ctx->uploadfile_autorelease) {
      YchannelRelease(ctx->uploadfile);
    }
    ctx->uploadfile = NULL;
  }

  if (key != NULL) {
    ctx->uploadfilekey = Ymem_strdup(key);
  }
  if (filename != NULL) {
    ctx->uploadfilename = Ymem_strdup(filename);
  }
  if (filestream != NULL) {
    ctx->uploadfile = filestream;
  }

  ctx->uploadfile_autorelease = autorelease;

  ctx->uploadlength = 0;
  ctx->uploadcount = 0;

  return 0;
}

int
httprequest_addheaderline(HttpRequest* req, const char *header)
{
  if ((req != NULL) && (header != NULL)) {
    req->headers = curl_slist_append(req->headers, header);
    return (req->headers == NULL) ? YPERWAVE_ERROR : YPERWAVE_OK;
  } else {
    return YPERWAVE_ERROR;
  }
}

size_t
httprequest_getpostprogress(HttpRequest* ctx)
{
  if (ctx != NULL) {
    return ctx->postprogress;
  } else {
    return 0;
  }
}

size_t
httprequest_getpostlength(HttpRequest* ctx)
{
  if (ctx != NULL) {
    return ctx->postlength;
  } else {
    return 0;
  }
}

size_t
httprequest_getresponseprogress(HttpRequest* ctx)
{
  if (ctx != NULL) {
    return ctx->downloadprogress;
  } else {
    return 0;
  }
}

size_t
httprequest_getresponselength(HttpRequest* ctx)
{
  if (ctx != NULL) {
    return ctx->downloadlength;
  } else {
    return 0;
  }
}

int httprequest_cancel(HttpRequest* req)
{
  if (req == NULL) {
    return YOSAL_ERROR;
  } else {
    req->cancelRequested = -1;
    req->cancelRequestedTimeoutNs = 0;
    return YOSAL_OK;
  }
}

int httprequest_cancelifcostly(HttpRequest* req, int thresholdbytes, int timeoutms)
{
  if (req == NULL) {
    return YOSAL_ERROR;
  } else {
    if ((thresholdbytes < 0) || (timeoutms < 0)) {
      req->cancelRequested = -1;
      req->cancelRequestedTimeoutNs = 0;
    } else {
      req->cancelRequested = thresholdbytes;
      if (timeoutms == 0) {
        req->cancelRequestedTimeoutNs = 0;
      } else {
        req->cancelRequestedTimeoutNs = Ytime(YTIME_CLOCK_MONOTONIC) + ((nsecs_t)timeoutms)*YOSAL_NS_PER_MS;
      }
    }
    return YOSAL_OK;
  }
}

int httprequest_isCancelRequested(HttpRequest* req)
{
  if (req == NULL) {
    return 0;
  } else {
    return req->cancelRequested != 0;
  }
}

int httprequest_getMethod(HttpRequest* ctx)
{
  return ctx->method;
}

int httprequest_setMethod(HttpRequest* ctx, int method)
{
  int prevmethod = YPERWAVE_HTTP_GET;
  if (ctx != NULL) {
    prevmethod = ctx->method;
    ctx->method = method;
  }

  return prevmethod;
}

static int curlWithDefaults(HttpRequest* ctx)
{
  CURL *curl;
  int sslverify;

  curl = curl_easy_init();
  if (curl == NULL) {
    return -1;
  }
  ctx->curl = curl;

  if (ctx->httppool != NULL) {
    curl_easy_setopt(curl, CURLOPT_SHARE, httppool_getsharedresources(ctx->httppool));
    curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, httppool_getdnscachetimeout(ctx->httppool));
    curl_easy_setopt(curl, CURLOPT_USERAGENT, httppool_getuseragent(ctx->httppool));
  }

  sslverify = httprequest_getsslverify(ctx);

  /*
   * If you want to connect to a site who isn't using a certificate that is
   * signed by one of the certs in the CA bundle you have, you can skip the
   * verification of the server's certificate. This makes the connection
   * A LOT LESS SECURE.
   *
   * If you have a CA cert for the server stored someplace else than in the
   * default bundle, then the CURLOPT_CAPATH option might come handy for
   * you.
   */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (sslverify ? 1L : 0L));

  /*
   * If the site you're connecting to uses a different host name that what
   * they have mentioned in their server certificate's commonName (or
   * subjectAltName) fields, libcurl will refuse to connect. You can skip
   * this check, but this will make the connection less secure.
   */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (sslverify ? 2L : 0L));

  // Disable SSL versions prior to TLSv1.
  curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

  curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
  curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, ProgressCallback);
  curl_easy_setopt(curl, CURLOPT_XFERINFODATA, (void*) ctx);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ResponseCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*) ctx);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, (void*) ctx);
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "deflate;q=1.0, gzip;q=0.7, identity;q=0.5");
  curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, SslCtxCallback);
  curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, ctx);

  // only allow N seconds to establish a connection
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long) ctx->connectTimeout);

  // detect stale connections by imposing a minimum speed
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, (long) ctx->minSpeed);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, (long) ctx->minSpeedInterval);

#if DEBUG_CURL
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugCallback);
#else
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, NULL);
#endif

  /* Start the cookie engine */
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

  if (ctx->responseHeaders) {
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*) ctx);
  }

  ctx->status = HTTPREQUEST_STATUS_INIT;

  return 0;
}

/**
 * This function gets called by libcurl as soon as it needs to read data in order to send
 * it to the peer. The data area pointed at by the pointer ptr may be filled with at
 * most size multiplied with nmemb number of bytes. Your function must return the
 * actual number of bytes that you stored in that memory area. Returning 0 will signal
 * end-of-file to the library and cause it to stop the current transfer.
 *
 * http://curl.haxx.se/libcurl/c/curl_easy_setopt.html#CURLOPTREADFUNCTION
 *
 * @param ptr
 * @param size
 * @param nmemb
 * @param userdata
 * @return
 */
static size_t postYchannelCurlRead(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  size_t max = size*nmemb;
  HttpRequest* req = (HttpRequest*) userdata;
  Ychannel* in;
  int read;

  ALOGD("requested %ld bytes", (long) max);

  if (req == NULL) {
    return CURL_READFUNC_ABORT;
  }
  in = req->uploadfile;

  if (req->uploadcount+max > req->uploadlength) {
    max = req->uploadlength - req->uploadcount;
  }

  read = YchannelRead(in, ptr, max);

  if (read < 0) {
    req->status = HTTPREQUEST_STATUS_FAILED_FILE_READ;
    return CURL_READFUNC_ABORT;
  }

  if (read == 0 &&
          req->uploadcount != req->uploadlength) {
    ALOGE("aborting request due to insufficient POST data");
    req->status = HTTPREQUEST_STATUS_FAILED_FILE_READ;
    return CURL_READFUNC_ABORT;
  }

  req->uploadcount += read;


  ALOGD("read %ld/%ld", (long) read, (long) max);

  return read;
}

int httprequest_setactive(HttpRequest *req)
{
  if (req == NULL) {
    return YPERWAVE_ERROR;
  } else {
    req->queuedtime = Ytime(YTIME_CLOCK_REALTIME);
    return YPERWAVE_OK;
  }
}

int httprequest_finalize(HttpRequest *req)
{
  HttpRequest* handle = req;
  char* cabundle;

  int method = req->method;

  int curl_proxytype;

  if (handle->vbuffer != NULL) {
    Ymem_free(handle->vbuffer);
  }
  handle->vbuffer = NULL;

  if (curlWithDefaults(req) != 0) {
    return -1;
  }

  cabundle = httpsettings_cabundle();
  if (cabundle != NULL) {
    curl_easy_setopt(handle->curl, CURLOPT_CAINFO, cabundle);
    Ymem_free(cabundle);
  }

  if (httpsettings_proxy_type() != YPERWAVE_PROXY_TYPE_NONE) {
    handle->proxyhost = httpsettings_proxy_hostname();
    if (handle->proxyhost != NULL) {
      curl_easy_setopt(handle->curl, CURLOPT_PROXY, handle->proxyhost);
      curl_easy_setopt(handle->curl, CURLOPT_PROXYPORT, httpsettings_proxy_port());

      switch (httpsettings_proxy_type()) {
        case YPERWAVE_PROXY_TYPE_HTTP:
          curl_proxytype = CURLPROXY_HTTP;
          break;
        case YPERWAVE_PROXY_TYPE_SOCKS4:
          curl_proxytype = CURLPROXY_SOCKS4;
          break;
        case YPERWAVE_PROXY_TYPE_SOCKS5:
          curl_proxytype = CURLPROXY_SOCKS5;
          break;
        case YPERWAVE_PROXY_TYPE_NONE:
        default:
          curl_proxytype = CURLPROXY_HTTP;
          break;
      }

      curl_easy_setopt(handle->curl, CURLOPT_PROXYTYPE, curl_proxytype);
    }

    handle->proxyuser = httpsettings_proxy_username();
    if (handle->proxyuser != NULL) {
      curl_easy_setopt(handle->curl, CURLOPT_PROXYUSERNAME, handle->proxyuser);
    }

    handle->proxypwd = httpsettings_proxy_password();
    if (handle->proxypwd != NULL) {
      curl_easy_setopt(handle->curl, CURLOPT_PROXYPASSWORD, handle->proxypwd);
    }


  }

  if (method == YPERWAVE_HTTP_GET) {
    Ybuffer* vurl = Ybuffer_init(256);
    char* vurlc;

    Ybuffer_append(vurl, req->url, -1);

    if (urlparams_length(req->urlparams) > 0) {
      Ybuffer_append(vurl, "?", 1);
      urlparams_append(req->urlparams, vurl);
    }

    vurlc = Ybuffer_detach(vurl, NULL);
    ALOGD("URL: %s\n", vurlc);

    curl_easy_setopt(handle->curl, CURLOPT_URL, vurlc);
    Ymem_free(vurlc);

  } else if (method == YPERWAVE_HTTP_POST) {
    curl_easy_setopt(handle->curl, CURLOPT_URL, req->url);
    curl_easy_setopt(handle->curl, CURLOPT_POST, 1);

    if (req->uploadfile != NULL) {
      // Send parameters as part of the URL.
      Ybuffer* vurl = Ybuffer_init(256);
      char* vurlc;

      Ybuffer_append(vurl, req->url, -1);

      if (urlparams_length(req->urlparams) > 0) {
        Ybuffer_append(vurl, "?", 1);
        urlparams_append(req->urlparams, vurl);
      }

      vurlc = Ybuffer_detach(vurl, NULL);
      ALOGD("URL: %s\n", vurlc);

      curl_easy_setopt(handle->curl, CURLOPT_URL, vurlc);
      Ymem_free(vurlc);

      // And send the file as the post data.
      req->uploadlength = YchannelGetLength(req->uploadfile);
      curl_easy_setopt(handle->curl, CURLOPT_READFUNCTION, postYchannelCurlRead);
      curl_easy_setopt(handle->curl, CURLOPT_READDATA, req);
    } else if (urlparams_length(req->urlparams) > 0) {
      req->paramsstr = urlparams_format(req->urlparams);
      req->paramsstrlen = strlen(req->paramsstr);

      curl_easy_setopt(handle->curl, CURLOPT_POSTFIELDS, req->paramsstr);
      curl_easy_setopt(handle->curl, CURLOPT_POSTFIELDSIZE, req->paramsstrlen);

      // Disable the expect-continue header, for speedup.
      handle->headers = curl_slist_append(handle->headers, "Expect:");
    }

  } else if (method == YPERWAVE_HTTP_POST_FORM) {
    static const char *empty = "";
    struct curl_httppost* post = NULL;
    struct curl_httppost* last = NULL;
    int i = 0;
    int nparams = urlparams_length(req->urlparams);

    for (i = 0; i < nparams; i++) {
      int keylen = 0;
      int valuelen = 0;
      const char *key = urlparams_key(req->urlparams, i, &keylen);
      const char *value = urlparams_value(req->urlparams, i, &valuelen);

      if (key == NULL) {
        key = empty;
        keylen = 0;
      }
      if (value == NULL) {
        value = empty;
        valuelen = 0;
      }
      curl_formadd(&post, &last,
                   CURLFORM_COPYNAME, key, CURLFORM_NAMELENGTH, keylen,
                   CURLFORM_COPYCONTENTS, value, CURLFORM_CONTENTSLENGTH, valuelen,
                   CURLFORM_END);
    }

    if (req->uploadfile != NULL && req->uploadfilekey != NULL) {
      req->uploadlength = YchannelGetLength(req->uploadfile);

      curl_easy_setopt(handle->curl, CURLOPT_READFUNCTION, postYchannelCurlRead);
      curl_formadd(&post, &last,
                   CURLFORM_COPYNAME, req->uploadfilekey,
                   CURLFORM_FILENAME, (req->uploadfilename != NULL) ? req->uploadfilename : req->uploadfilekey,
                   CURLFORM_STREAM, req,
                   CURLFORM_CONTENTSLENGTH, req->uploadlength,
                   CURLFORM_END);
    } else {
      // Disable the expect-continue header, for speedup.
      handle->headers = curl_slist_append(handle->headers, "Expect:");
    }

    curl_easy_setopt(handle->curl, CURLOPT_URL, req->url);
    curl_easy_setopt(handle->curl, CURLOPT_POST, 1);
    curl_easy_setopt(handle->curl, CURLOPT_HTTPPOST, post);
    req->argsform = post;
  }

  if (handle->headers != NULL) {
    curl_easy_setopt(handle->curl, CURLOPT_HTTPHEADER, handle->headers);
  }

  return 0;
}


HttpRequest* httprequest_create(const char *url)
{
  HttpRequest *handle;

  if (url == NULL || url[0] == '\0') {
    return NULL;
  }

  handle = Ymem_malloc(sizeof (HttpRequest));
  if (handle == NULL) {
    return NULL;
  }

  handle->method = YPERWAVE_HTTP_GET;
  handle->url = Ymem_strdup(url);
  handle->urlparams = NULL;
  handle->paramsstr = NULL;
  handle->paramsstrlen = 0;
  handle->argsform = NULL;
  handle->headers = NULL;
  handle->uploadfilekey = NULL;
  handle->uploadfilename = NULL;
  handle->uploadfile = NULL;
  handle->uploadfile_autorelease = 0;
  handle->postlength = 0;
  handle->postprogress = 0;
  handle->downloadlength = 0;
  handle->downloadprogress = 0;
  handle->callback = NULL;
  handle->privatedata = NULL;
  handle->curl = NULL;
  handle->httppool = NULL;
  handle->sslverify = 1;
  handle->cancelRequested = 0;
  handle->cancelRequestedTimeoutNs = 0;
  handle->completed = 0;
  handle->status = HTTPREQUEST_STATUS_NONE;
  handle->tag = -1;
  handle->instrument = YPERWAVE_TELEMETRYLEVEL_NONE;
  handle->telemetry = NULL;
  handle->queuedtime = 0;
  handle->cachehints = CacheHint_None;
  handle->priority = HttpRequestPriority_Normal;
  handle->cachedata = NULL;
  handle->cacher = NULL;
  handle->proxyhost = NULL;
  handle->proxyuser = NULL;
  handle->proxypwd = NULL;
  handle->responseHeaders = NULL;

  httprequest_setConnectTimeout(handle, 0);
  httprequest_setMinSpeed(handle, 0, 0);

  /* Output vbuffer to store the payload into */
  handle->vbuffer = NULL;
  handle->rawdata = NULL;
  handle->rawlen = 0;

  /* Output filename to save the payload into */
  handle->outfile = NULL;
  handle->partfile = NULL;
  handle->outchannel = NULL;

  /* Output vchannel to write the payload into */
  handle->vchannel = NULL;
  handle->vchannelrelease = 0;

  /* Total number of (decoded) bytes received */
  handle->datalen = (size_t) 0;

  handle->next = NULL;

  return handle;
}

int httrequest_process_metrics(HttpRequest *handle) {
  double tmp;
  nsecs_t now;

  if (handle == NULL) {
    return YPERWAVE_ERROR;
  }

  if ((handle->curl == NULL) && !httprequest_fromcache(handle)) {
    return YPERWAVE_ERROR;
  }

  if (!handle->instrument) {
    return YPERWAVE_OK;
  }

  handle->telemetry = (HttpRequestTelemetry*) yobject_create(sizeof(HttpRequestTelemetry), Ymem_free);
  if (handle->telemetry == NULL) {
    return YPERWAVE_ERROR;
  }
  yobject_retain((yobject*)handle->telemetry);

  handle->telemetry->time_total_ms = 0;
  handle->telemetry->time_queued_ms = 0;
  handle->telemetry->time_dns_ms = 0;
  handle->telemetry->time_connect_ms = 0;
  handle->telemetry->time_firstbyte_ms = 0;
  handle->telemetry->speed_upload_Bps = 0;
  handle->telemetry->speed_download_Bps = 0;
  handle->telemetry->uploaded_bytes = 0;
  handle->telemetry->downloaded_bytes = 0;
  handle->telemetry->time_ssl_ms = 0;

  if (handle->curl != NULL) {
    if (curl_easy_getinfo(handle->curl, CURLINFO_TOTAL_TIME, &tmp) == CURLE_OK) {
      handle->telemetry->time_total_ms = (uint32_t) (tmp*1000.0);
    } else {
      ALOGE("Telemetry Error: failed to obtain total time");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_NAMELOOKUP_TIME, &tmp) == CURLE_OK) {
      handle->telemetry->time_dns_ms = (uint32_t) (tmp*1000.0);
    } else {
      ALOGE("Telemetry Error: failed to obtain DNS lookup time");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_CONNECT_TIME, &tmp) == CURLE_OK) {
      handle->telemetry->time_connect_ms = (uint32_t) (tmp*1000.0);
    } else {
      ALOGE("Telemetry Error: failed to obtain connect time");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_STARTTRANSFER_TIME, &tmp) == CURLE_OK) {
      handle->telemetry->time_firstbyte_ms = (uint32_t) (tmp*1000.0);
    } else {
      ALOGE("Telemetry Error: failed to obtain time to first byte");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_SPEED_UPLOAD, &tmp) == CURLE_OK) {
      handle->telemetry->speed_upload_Bps = (uint32_t) tmp;
    } else {
      ALOGE("Telemetry Error: failed to obtain upload speed");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_SPEED_DOWNLOAD, &tmp) == CURLE_OK) {
      handle->telemetry->speed_download_Bps = (uint32_t) tmp;
    } else {
      ALOGE("Telemetry Error: failed to obtain upload speed");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_SIZE_UPLOAD, &tmp) == CURLE_OK) {
      handle->telemetry->uploaded_bytes = (uint32_t) tmp;
    } else {
      ALOGE("Telemetry Error: failed to obtain upload size");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_SIZE_DOWNLOAD, &tmp) == CURLE_OK) {
      handle->telemetry->downloaded_bytes = (uint32_t) tmp;
    } else {
      ALOGE("Telemetry Error: failed to obtain download size");
    }

    if (curl_easy_getinfo(handle->curl, CURLINFO_APPCONNECT_TIME, &tmp) == CURLE_OK) {
      handle->telemetry->time_ssl_ms = (uint32_t) (tmp*1000.0);
    } else {
      ALOGE("Telemetry Error: failed to obtain time to SSL handshake");
    }
  }

  now = Ytime(YTIME_CLOCK_REALTIME);
  if (handle->queuedtime == 0) {
    handle->queuedtime = now - handle->telemetry->time_total_ms*YOSAL_NS_PER_MS;
  }
  handle->telemetry->time_queued_ms = (now - handle->queuedtime)/YOSAL_NS_PER_MS - handle->telemetry->time_total_ms;

  return YPERWAVE_OK;
}

#if ALOG_DEBUG
static void
httprequest_logtelemetry(HttpRequest *req)
{
  Ybuffer *entry;
  char *line;
  nsecs_t nowNs;
  nsecs_t startTimeNs;

  entry = Ybuffer_init(160);
  if (entry == NULL) {
    return;
  }

  nowNs = Ytime(YTIME_CLOCK_REALTIME);
  if (req->queuedtime > 0) {
    startTimeNs = req->queuedtime;
  } else {
    startTimeNs = nowNs;
  }
  Ybuffer_append_format(entry, " startMs=%llu", startTimeNs / YOSAL_NS_PER_MS);

  // Connection info.
  if (req->curl != NULL) {
    char *tmpStr;
    long localPort;

    // Optional.
    if (curl_easy_getinfo(req->curl, CURLINFO_PRIMARY_IP, &tmpStr) == CURLE_OK) {
      Ybuffer_append_format(entry, " server=%s", tmpStr);
    }
    // Optional.
    if (curl_easy_getinfo(req->curl, CURLINFO_LOCAL_PORT, &localPort) == CURLE_OK) {
      Ybuffer_append_format(entry, " conn=%u", (uint32_t)localPort);
    }
  }

  if (nowNs > startTimeNs) {
    Ybuffer_append_format(entry, " timeMs=%llu", (unsigned long long)(nowNs - startTimeNs)/YOSAL_NS_PER_MS);
  } else {
    Ybuffer_append_format(entry, " timeMs=0");
  }

  switch (req->method) {
    case YPERWAVE_HTTP_GET:
      Ybuffer_append_format(entry, " method=GET");
      break;
    case YPERWAVE_HTTP_POST:
    case YPERWAVE_HTTP_POST_FORM:
      Ybuffer_append_format(entry, " method=POST");
      break;
  }
  if (req->url != NULL) {
    Ybuffer_append_format(entry, " url=%s", req->url);
  }

  if (req->curl != NULL) {
    long responseCode;
    if (curl_easy_getinfo(req->curl, CURLINFO_RESPONSE_CODE, &responseCode) == CURLE_OK) {
      Ybuffer_append_format(entry, " status=%ld", responseCode);
    }
  } else if (req->cachedata != NULL) {
    Ybuffer_append_format(entry, " status=200");
    Ybuffer_append_format(entry, " cacheBytes=%u", req->cachedata->datalen);
  }
  if (httprequest_cancelled(req)) {
    Ybuffer_append_format(entry, " cancelled");
  }

  if (req->telemetry != NULL) {
    Ybuffer_append_format(entry, " upBytes=%u", req->telemetry->uploaded_bytes);
    Ybuffer_append_format(entry, " downBytes=%u", req->telemetry->downloaded_bytes);
    Ybuffer_append_format(entry, " contentBytes=%llu", (unsigned long long)req->downloadprogress);
    Ybuffer_append_format(entry, " postBytes=%llu", (unsigned long long)req->postprogress);
    Ybuffer_append_format(entry, " queuedMs=%u", req->telemetry->time_queued_ms);
    if (req->telemetry->time_dns_ms == 0) {
      Ybuffer_append_format(entry, " dnsMs=0");
    } else {
      Ybuffer_append_format(entry, " dnsMs=%u", req->telemetry->time_dns_ms);
    }
    if (req->telemetry->time_connect_ms == 0) {
      Ybuffer_append_format(entry, " connectMs=0");
    } else {
      Ybuffer_append_format(entry, " connectMs=%u", req->telemetry->time_connect_ms - req->telemetry->time_dns_ms);
    }
    if (req->telemetry->time_ssl_ms == 0) {
      Ybuffer_append_format(entry, " sslMs=0");
    } else {
      Ybuffer_append_format(entry, " sslMs=%u", req->telemetry->time_ssl_ms - req->telemetry->time_connect_ms);
    }
    if (req->telemetry->time_firstbyte_ms == 0) {
      Ybuffer_append_format(entry, " firstByteMs=0");
    } else {
      Ybuffer_append_format(entry, " firstByteMs=%u", req->telemetry->time_firstbyte_ms - req->telemetry->time_ssl_ms);
    }
    if (req->telemetry->time_total_ms == 0) {
      Ybuffer_append_format(entry, " receiveMs=0");
    } else {
      Ybuffer_append_format(entry, " receiveMs=%u", req->telemetry->time_total_ms - req->telemetry->time_firstbyte_ms);
    }
  }

  if ((req->urlparams != NULL) && (urlparams_length(req->urlparams)) > 0) {
    Ybuffer_append(entry, " params=", -1);
    urlparams_append(req->urlparams, entry);
  }

  line = Ybuffer_detach(entry, NULL);
  ALOGD("(stats) %s", line);
  Ymem_free(line);
}
#endif

int httprequest_completed(HttpRequest *handle)
{
  if (handle == NULL) {
    return YPERWAVE_ERROR;
  }

  if (handle->instrument >= YPERWAVE_TELEMETRYLEVEL_BASIC) {
    httrequest_process_metrics(handle);
  }

  handle->completed = 1;

#if ALOG_DEBUG
  httprequest_logtelemetry(handle);
#endif

  return httprequest_release(handle);
}

int
httprequest_fromcache(HttpRequest *handle)
{
  return (handle != NULL) && (handle->cachedata != NULL);
}

int
httprequest_status(HttpRequest *handle)
{
  if (handle == NULL) {
    return HTTPREQUEST_STATUS_NONE;
  }

  return handle->status;
}

int
httprequest_cancelled(HttpRequest *req) {
  return (httprequest_status(req) == HTTPREQUEST_STATUS_CANCELLED);
}

int
httprequest_failedfileread(HttpRequest *req) {
  return (httprequest_status(req) == HTTPREQUEST_STATUS_FAILED_FILE_READ);
}

int
httprequest_success(HttpRequest *req)
{
  return (httprequest_status(req) == HTTPREQUEST_STATUS_SUCCESS);
}

int httprequest_release(HttpRequest *handle)
{
#ifdef YPERWAVE_DEBUG_HTTP
  ALOGD("http request release");
#endif
  if (handle == NULL) {
    return 1;
  }

  if (handle->vchannel != NULL) {
    YchannelFlush(handle->vchannel);
  }

  if (handle->completed) {
    if (handle->outchannel != NULL) {
      YchannelFlush(handle->outchannel);
      YchannelRelease(handle->outchannel);

      if (handle->partfile != NULL && handle->outfile != NULL) {
        if (access(handle->outfile, F_OK) == 0) {
          /* Target file exists */
        }  else {
          if (rename(handle->partfile, handle->outfile) != 0) {
            /* Rename failed */
          } else {
            /* Have payload into outfile */
          }
        }
      }
    }
  }

  /* Invoke user callback */
  if (handle->callback != NULL) {
    (*(handle->callback))(handle);
  }

  /* Clean up */
  httprequest_setchannel(handle, NULL, 0);
  httprequest_outputfile(handle, NULL);
  httprequest_setUploadFile(handle, NULL, NULL, NULL, 0);

  if (handle->curl != NULL) {
    curl_easy_cleanup(handle->curl);
  }
  if (handle->argsform != NULL) {
    curl_formfree(handle->argsform);
  }
  if (handle->headers != NULL) {
    curl_slist_free_all(handle->headers);
  }
  if (handle->vbuffer != NULL) {
    Ybuffer_fini(handle->vbuffer);
  }
  if (handle->rawdata != NULL) {
    Ymem_free(handle->rawdata);
  }
  if (handle->url != NULL) {
    Ymem_free(handle->url);
  }
  if (handle->urlparams != NULL) {
    urlparams_release(handle->urlparams);
  }
  if (handle->paramsstr != NULL) {
    Ymem_free(handle->paramsstr);
  }
  if (handle->telemetry != NULL) {
    yobject_release((yobject*)handle->telemetry);
  }
  if (handle->cachedata != NULL) {
    yobject_release((yobject*)handle->cachedata);
  }
  if (handle->proxyhost != NULL) {
    Ymem_free(handle->proxyhost);
  }
  if (handle->proxyuser != NULL) {
    Ymem_free(handle->proxyuser);
  }
  if (handle->proxypwd != NULL) {
    Ymem_free(handle->proxypwd);
  }
  if (handle->responseHeaders != NULL) {
    YArray_release(handle->responseHeaders);
  }

  Ymem_free(handle);

  return 0;
}

int
httprequest_setcallback(HttpRequest *handle, int (*cb)(HttpRequest*))
{
  if (handle != NULL) {
    handle->callback = cb;
  }

  return 0;
}

int
httprequest_settelemetrylevel(HttpRequest *handle, int instrument)
{
  if (handle == NULL) {
    return YPERWAVE_ERROR;
  }

  handle->instrument = instrument;
  return YPERWAVE_OK;
}

int
httprequest_gettelemetrylevel(HttpRequest *handle)
{
  if (handle == NULL) {
    return YPERWAVE_ERROR;
  }

  return handle->instrument;
}

HttpRequestTelemetry*
httprequest_gettelemetry(HttpRequest *handle)
{
  return (HttpRequestTelemetry*) yobject_retain((yobject*) handle->telemetry);
}

void
httprequest_setcachehints(HttpRequest *handle, int hints)
{
  if (handle != NULL) {
    handle->cachehints = hints;
  }
}

int
httprequest_getcachehints(HttpRequest *handle)
{
  CacheHints hints = CacheHint_None;
  if (handle != NULL) {
    hints = handle->cachehints;
  }
  return hints;
}

void
httprequest_setpriority(HttpRequest *handle, HttpRequestPriority priority)
{
  if (handle != NULL) {
    handle->priority = priority;
  }
}

void
httprequest_setcacher(HttpRequest *handle, Cacher *cacher)
{
  if (handle != NULL) {
    handle->cacher = cacher;
  }
}

void
httprequest_setpool(HttpRequest *req, HttpPool *pool)
{
  if (req != NULL) {
    req->httppool = pool;
  }
}

int
httprequest_setprivate(HttpRequest *handle, void *privdata)
{
  if (handle != NULL) {
    handle->privatedata = privdata;
  }

  return 0;
}

void*
httprequest_getprivate(HttpRequest *handle)
{
  if (handle != NULL) {
    return handle->privatedata;
  }

  return NULL;
}

int
httprequest_setsslverify(HttpRequest *handle, int value)
{
  int result = 0;

  if (handle != NULL) {
    result = handle->sslverify;
    handle->sslverify = (value == 0 ? 0 : 1);
  }

  /* Return previous value of SSL verification flag */
  return result;
}

int
httprequest_getsslverify(HttpRequest *handle)
{
  if (handle != NULL) {
    return handle->sslverify;
  }

  return 0;
}

Ychannel*
httprequest_setchannel(HttpRequest *handle,
                       Ychannel *channel, int release)
{
  Ychannel *prevchannel = NULL;

  if (handle == NULL) {
    return NULL;
  }

  if (handle->vchannel != NULL) {
    YchannelFlush(handle->vchannel);
    if (handle->vchannelrelease) {
      YchannelRelease(handle->vchannel);
    } else {
      prevchannel = handle->vchannel;
    }
  }

  if (channel == NULL) {
    release = 0;
  }

  handle->vchannel = channel;
  handle->vchannelrelease = release;

  return prevchannel;
}

int
httprequest_gettag(HttpRequest *handle)
{
  if (handle == NULL) {
    return -1;
  }

  return handle->tag;
}

int
httprequest_settag(HttpRequest *handle, int tag)
{
  if (handle == NULL) {
    return YPERWAVE_ERROR;
  }

  handle->tag = tag;
  return YPERWAVE_OK;
}


const char*
httprequest_outputfile(HttpRequest *handle, const char *outfile)
{
  if (handle == NULL) {
    return NULL;
  }

  if (handle->outfile != NULL) {
    Ymem_free(handle->outfile);
  }
  if (handle->partfile != NULL) {
    Ymem_free(handle->partfile);
  }

  handle->outfile = NULL;
  handle->partfile = NULL;
  if (outfile != NULL) {
    int l = strlen(outfile);

    handle->outfile = Ymem_malloc(l+1);
    if (handle->outfile != NULL) {
      handle->partfile = Ymem_malloc(l+5+1);
      if (handle->partfile == NULL) {
        Ymem_free(handle->outfile);
        handle->outfile = NULL;
      } else {
        memcpy(handle->outfile, outfile, l);
        handle->outfile[l] = '\0';

        memcpy(handle->partfile, outfile, l);
        memcpy(handle->partfile+l, ".part", 5);
        handle->partfile[l+5] = '\0';
      }
    }
  }

  return handle->outfile;
}

char* httprequest_geturl(HttpRequest *handle)
{
  if (handle == NULL) {
    return NULL;
  }

  return handle->url;
}

int httprequest_getcode(HttpRequest *handle)
{
  int rc = YPERWAVE_ERROR;

  if (handle == NULL) {
    return rc;
  }

  if (!httprequest_success(handle)) {
    return rc;
  }

  if (handle->curl != NULL) {
    long l;

    curl_easy_getinfo(handle->curl, CURLINFO_RESPONSE_CODE, &l);
    if (l >= 0 && l <= 65535) {
      rc = (int) l;
    }
  } else if (handle->cachedata != NULL) {
    rc = 200;
  }

  return rc;
}

size_t httprequest_getlength(HttpRequest *handle)
{
  size_t l = 0;

  if (handle != NULL) {
    l = (size_t) handle->datalen;
  }

  return l;
}

char*
httprequest_getcontent(HttpRequest *handle, int *datalen)
{
  char *data = NULL;
  int l = 0;

  if (handle != NULL) {
    if (handle->vbuffer != NULL) {
      data = Ybuffer_detach(handle->vbuffer, &l);
      handle->vbuffer = NULL;
      handle->rawdata = data;
      handle->rawlen = l;
    } else if (handle->rawdata != NULL) {
      data = handle->rawdata;
      l = handle->rawlen;
    } else if (handle->cachedata != NULL) {
      data = handle->cachedata->data;
      l = handle->cachedata->datalen;
    }
  }

  if (datalen != NULL) {
    *datalen = l;
  }
  return data;
}

int
httprequest_collectresponseheaders(HttpRequest *handle)
{
  int result = YPERWAVE_OK;

  if ((handle != NULL) && (handle->responseHeaders == NULL)) {
    handle->responseHeaders = YArray_createLength(10);
    if (handle->responseHeaders == NULL) {
      result = YPERWAVE_ERROR;
    } else {
      YArray_setElementReleaseFunc(handle->responseHeaders, (YArrayElementReleaseFunc)Ymem_free);
    }
  }

  return result;
}

const char*
httprequest_getresponseheaderline(HttpRequest *handle, int index)
{
  const char *value = NULL;

  if ((handle != NULL) && (handle->responseHeaders != NULL)) {
    if (index < YArray_length(handle->responseHeaders)) {
      value = YArray_get(handle->responseHeaders, index);
    }
  }

  return value;
}

int
httprequest_setcacheresponsedata(HttpRequest *handle, CacheData *cachedata)
{
  if (handle == NULL) {
    return YPERWAVE_OK;
  }
  if ((handle->vbuffer != NULL) || (handle->rawdata != NULL) || (handle->vchannel != NULL) ||
      (handle->outchannel != NULL) || (handle->outfile != NULL) || (handle->partfile != NULL)) {
    return YPERWAVE_ERROR;
  }

  handle->status = HTTPREQUEST_STATUS_SUCCESS;
  handle->cachedata = (CacheData*)yobject_retain((yobject*)cachedata);
  handle->datalen = cachedata->datalen;

  return YPERWAVE_OK;
}

CacheData *
httprequest_getcacheresponsedata(HttpRequest *handle)
{
  CacheData *cachedata = NULL;
  if (handle != NULL) {
    cachedata = handle->cachedata;
  }
  return cachedata;
}

int httprequest_getcookies(HttpRequest *handle)
{
  int rc = -1;
  struct curl_slist *cookies;

  if (handle != NULL && handle->curl != NULL) {
    CURLcode res;

    res = curl_easy_getinfo(handle->curl, CURLINFO_COOKIELIST, &cookies);
    if (res == CURLE_OK) {
      struct curl_slist *current = cookies;
      rc = 0;
      while (current != NULL) {
        current = current->next;
        rc++;
      }
      curl_slist_free_all(cookies);
    }
  }

  return rc;
}

/* Simple API, synchronous */
char* httprequest_getRequest(HttpPool *httppool, HttpRequest *request,
                             int *datalen)
{
  CURLcode status;
  long code;
  char *result = NULL;
  int poollocal = 0;

  /* Create a temporary pool just for this request */
  if (httppool == NULL) {
    httppool = httppool_create();
    if (httppool == NULL) {
      return NULL;
    }
    poollocal = 1;
  }

  httprequest_finalize(request);

  if (request != NULL) {
    CURL *curl = request->curl;

    status = curl_easy_perform(curl);
    if (status != 0) {
      ALOGE("error: unable to request data from %s",
              httprequest_geturl(request));
      ALOGE("curl error: %s", curl_easy_strerror(status));
    } else {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
      if (code == 200) {
        result = httprequest_getcontent(request, datalen);
      } else {
        ALOGD("error: server responded with code %ld\n", code);
      }
    }
  }

  if (poollocal) {
    httppool_release(httppool);
  }

  return result;
}
