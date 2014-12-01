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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "yperwave/yperwave.h"
#include "yperwave_priv.h"
#include "net/httprequest_json.h"

#include "yosal/ytest.h"

#ifndef __BIONIC__
#include <pwd.h>
#include <unistd.h>
#define HAVE_GETPASS
#define MKDTEMP mkdtemp
#else
#define MKDTEMP mktemp
#endif


static HttpPool *httppool = NULL;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int pending = 0;

static void pendingAdd(int n)
{
  pthread_mutex_lock(&mut);
  pending += n;
  pthread_mutex_unlock(&mut);
  pthread_cond_broadcast(&cond);
}

static int downloadCB(HttpRequest *handle)
{
  size_t datalen = httprequest_getlength(handle);

  printf("download callback: %ld bytes\n", (long) datalen);

  HttpRequestTelemetry *tele = httprequest_gettelemetry(handle);
  if (tele != NULL) {
    printf("Telemetry:\n");
    printf("time total: %d, dns: %d, connect: %d, ssl: %d, firstbyte: %d\n", tele->time_total_ms,
           tele->time_dns_ms, tele->time_connect_ms, tele->time_ssl_ms, tele->time_firstbyte_ms);
    printf("size up: %dbytes, down %dbytes\n", tele->uploaded_bytes, tele->downloaded_bytes);
    printf("speed up: %fkb/s, down %fkb/s\n", tele->speed_upload_Bps/1024.0, tele->speed_download_Bps/1024.0);
    yobject_release((yobject*) tele);
  }

  if (datalen > 0) {
    YTEST_ASSERT_EQ(httprequest_status(handle), HTTPREQUEST_STATUS_SUCCESS);
    YTEST_ASSERT_EQ(httprequest_getcode(handle), 200);
  }

  HttpPool *httppool = (HttpPool*)httprequest_getprivate(handle);
  YTEST_ASSERT_NE(httppool, NULL);
  YTEST_ASSERT_TRUE(httppool_empty(httppool));

  pendingAdd(-1);
  return 0;
}

static int jsonCB(HttpRequest *req)
{
  printf("json callback\n");

  json_t *root = httprequest_get_json(req);
  json_decref(root);

  printf("json callback done\n");

  pendingAdd(-1);
  return 0;
}

static int genericCB(HttpRequest *req)
{
  int datalen;
  char* data;
  int rc;

  printf("HTTP request for %s finished...", req->url);

  if (httprequest_success(req)) {
    printf("successfully\n");
    rc = httprequest_getcode(req);
  } else {
    // UNDEFINED, only for test/development
    rc = httprequest_getcode(req);
    printf("but failed\n");
  }

  HttpRequestTelemetry *tele = httprequest_gettelemetry(req);
  if (tele != NULL) {
    printf("Telemetry:\n");
    printf("time total: %d, dns: %d, connect: %d, ssl: %d, firstbyte: %d\n", tele->time_total_ms,
           tele->time_dns_ms, tele->time_connect_ms, tele->time_ssl_ms, tele->time_firstbyte_ms);
    printf("size up: %dbytes, down %dbytes\n", tele->uploaded_bytes, tele->downloaded_bytes);
    printf("speed up: %fkb/s, down %fkb/s\n", tele->speed_upload_Bps/1024.0, tele->speed_download_Bps/1024.0);
    yobject_release((yobject*) tele);
  }

  printf("response code: %d\n", rc);

  data = httprequest_getcontent(req, &datalen);
  if (datalen > 100) {
    datalen = 100;
  }
  printf("DATA:\n%.*s\n---\n", datalen, data);

  pendingAdd(-1);
  return 0;
}

static int usage()
{
  fprintf(stderr, "usage: yperwave [-proxy-socks|-proxy-http] runtests|demoget|demooauth|democancel|demotimeout|jsonasync|downloadasync\n");
  return 0;
}

static int testurlencode()
{
  printf("Testing yperwave::urlencode\n");

  char* s = "+ANLJuRXYrxLbybh/CiSL4NGg1E=";
  int encodedsize = http_urlencode(s, NULL, 0);
  char* encodedstr = Ymem_malloc(encodedsize+1);
  http_urlencode(s, encodedstr, encodedsize+1);
  YTEST_EXPECT_STREQ(encodedstr, "%2BANLJuRXYrxLbybh%2FCiSL4NGg1E%3D");
  Ymem_free(encodedstr);

  s = "z=xCx/RBB7x/RB4U9rIUYmajMNjE2TgY1TjUwNDROME5PNTE3Tk&a=YAE&sk=DAAJDoMxGRGamv&ks=EAAxeV5xg_hjzK6sVyukkSARQ--~E&d=c2wBTVRZeE9RRXlPVEkzTXpNNU56azRNall3T1RrME9RLS0BYQFZQUUBZwFWRVRYSVBZWU9RTURQMjc1MlVCTDZPUUJGNAFzY2lkATJxWGkybEVzSlMxaTA0R2xiQm9Zb3VsUDlncy0BYWMBQUF5eXlBTkJTUmxlAW9rAVpXMC0Bc2MBZmxpY2tybnNjAXp6AXhDeC9SQjhBQQFjcwFmbGlja3Juc2MBdGlwAVJQb1B6Qg--&af=QXdBQjFDQXpBQlJSJnRzPTEzNzU2NzA0NDkmcHM9dG52NWZ0dmg0VWdpLlpYM1FCUmY4QS0t";
  encodedsize = http_urlencode(s, NULL, 0);
  encodedstr = Ymem_malloc(encodedsize+1);
  http_urlencode(s, encodedstr, encodedsize+1);

  YTEST_EXPECT_STREQ(encodedstr, "z%3DxCx%2FRBB7x%2FRB4U9rIUYmajMNjE2TgY1TjUwNDROME5PNTE3Tk%26a%3DYAE%26sk%3DDAAJDoMxGRGamv%26ks%3DEAAxeV5xg_hjzK6sVyukkSARQ--~E%26d%3Dc2wBTVRZeE9RRXlPVEkzTXpNNU56azRNall3T1RrME9RLS0BYQFZQUUBZwFWRVRYSVBZWU9RTURQMjc1MlVCTDZPUUJGNAFzY2lkATJxWGkybEVzSlMxaTA0R2xiQm9Zb3VsUDlncy0BYWMBQUF5eXlBTkJTUmxlAW9rAVpXMC0Bc2MBZmxpY2tybnNjAXp6AXhDeC9SQjhBQQFjcwFmbGlja3Juc2MBdGlwAVJQb1B6Qg--%26af%3DQXdBQjFDQXpBQlJSJnRzPTEzNzU2NzA0NDkmcHM9dG52NWZ0dmg0VWdpLlpYM1FCUmY4QS0t");
  Ymem_free(encodedstr);

  return 0;
}

static void sethttpproxy()
{
  httpsettings_set_proxy_hostname("localhost");
  httpsettings_set_proxy_port(8888);
  httpsettings_set_proxy_type(YPERWAVE_PROXY_TYPE_HTTP);
  //httpsettings_set_proxy_username("userfoo");
  //httpsettings_set_proxy_password("passbar");
  printf("using http proxy\n");
}

static void setsocksproxy()
{
  httpsettings_set_proxy_hostname("localhost");
  httpsettings_set_proxy_port(8889);
  httpsettings_set_proxy_type(YPERWAVE_PROXY_TYPE_SOCKS4);
  printf("using socks proxy\n");
}

static int testoauth()
{
  char* url = "http://photos.example.net/photos";
  char* secret = "kd94hf93k423kf44&pfkkdhi9sl3r4s00";
  UrlParams *params;
  Ybuffer* sigbase;
  char* sigbasec;
  char *hmac;

  printf("Testing yperwave::oauth signature base string\n");

  params = urlparams_create();

  urlparams_add(params, "size", "original");
  urlparams_add(params, "file", "vacation.jpg");
  urlparams_add(params, OAUTH_SIGNATURE_METHOD, OAUTH_HMAC_SHA1);
  urlparams_add(params, OAUTH_VERSION, OAUTH_VERSION_1_0);
  urlparams_add(params, OAUTH_NONCE, "kllo9940pd9333jh");
  urlparams_add(params, OAUTH_TIMESTAMP, "1191242096");
  urlparams_add(params, OAUTH_CONSUMER_KEY, "dpf43f3p2l4k3l03");
  urlparams_add(params, OAUTH_TOKEN, "nnch734d00sl2jdk");

  sigbase = buildSignatureBase(url, YPERWAVE_HTTP_GET, params);
  sigbasec = Ybuffer_detach(sigbase, NULL);

  urlparams_release(params);

  YTEST_EXPECT_STREQ(sigbasec, "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal");

  sigbase = Ybuffer_init(128);
  Ybuffer_append(sigbase, sigbasec, strlen(sigbasec));
  Ymem_free(sigbasec);

  printf("Test yperwave::oauth HMAC-SHA1 computation\n");
  hmac = computeSignature(sigbase, YOSAL_DIGEST_MODE_HMAC_SHA1, secret);

  YTEST_EXPECT_STREQ(hmac, "tR3+Ty81lMeYAr/Fid0kMTYa/WM=");

  Ymem_free(hmac);
  return 0;
}

int testappendurlparams() {
  UrlParams *params;

  printf("Testing yperwave::urlparams append\n");

  params = urlparams_create();

  urlparams_add(params, "Han", "Solo");
  urlparams_add(params, "Captain", "Kirk");
  urlparams_add(params, "Battlestar", "Galactica");
  urlparams_add(params, "Millenium", "Falcon");

  YTEST_EXPECT_EQ(urlparams_length(params), 4);

  YTEST_EXPECT_STREQ(urlparams_key(params, 0, NULL), "Han");
  YTEST_EXPECT_STREQ(urlparams_value(params, 0, NULL), "Solo");

  YTEST_EXPECT_STREQ(urlparams_key(params, 1, NULL), "Captain");
  YTEST_EXPECT_STREQ(urlparams_value(params, 1, NULL), "Kirk");

  YTEST_EXPECT_STREQ(urlparams_key(params, 2, NULL), "Battlestar");
  YTEST_EXPECT_STREQ(urlparams_value(params, 2, NULL), "Galactica");

  YTEST_EXPECT_STREQ(urlparams_key(params, 3, NULL), "Millenium");
  YTEST_EXPECT_STREQ(urlparams_value(params, 3, NULL), "Falcon");

  urlparams_release(params);

  return 0;
}

int testsorturlparams()
{
  UrlParams *params;

  printf("Testing yperwave::urlparams sort\n");

  params = urlparams_create();

  urlparams_add(params, "Han", "Solo");
  urlparams_add(params, "Captain", "Kirk");
  urlparams_add(params, "ABCD", "second one");
  urlparams_add(params, "ABC", "first one");

  urlparams_sort(params);

  YTEST_EXPECT_EQ(urlparams_length(params), 4);

  YTEST_EXPECT_STREQ(urlparams_key(params, 0, NULL), "ABC");
  YTEST_EXPECT_STREQ(urlparams_key(params, 1, NULL), "ABCD");
  YTEST_EXPECT_STREQ(urlparams_key(params, 2, NULL), "Captain");
  YTEST_EXPECT_STREQ(urlparams_key(params, 3, NULL), "Han");

  urlparams_release(params);

  return 0;
}


int main(int argc, char *argv[])
{
  int carg;
  YBOOL sslverify = YFALSE;

  if (argc <= 1 || strcmp(argv[1], "help") == 0) {
    usage();
    return 1;
  }

  //ALOG_SET_LOGLEVEL(ANDROID_LOG_VERBOSE);
  carg = 1;
  if (argv[carg][0] == '-') {
    httpsettings_init();
    if (strcmp(argv[carg], "-proxy-socks") == 0) {
      setsocksproxy();
    } else if (strcmp(argv[carg], "-proxy-http") == 0) {
      sethttpproxy();
    } else if (strcmp(argv[carg], "-cabundle") == 0) {
      carg++;
      httpsettings_set_cabundle(argv[carg]);
      sslverify = YTRUE;
    } else {
      usage();
      return 1;
    }
    carg++;
  }

  if (strcmp(argv[carg], "runtests") == 0) {
    int i;
    int iterations = 1;

    if (argc > 2) {
      iterations = atoi(argv[carg+1]);
    }

    for (i=0; i<iterations; i++) {
      testoauth();
      testurlencode();
      testappendurlparams();
      testsorturlparams();
    }
    return 0;
  }

  if (strcmp(argv[carg], "demooauth") == 0) {
    char* data;
    int datalen = 0;
    HttpRequest* req;
    UrlParams *params;

    req = httprequest_create("http://term.ie/oauth/example/request_token.php");
    httprequest_setsslverify(req, sslverify);
    httprequest_setMethod(req, YPERWAVE_HTTP_POST);
    httprequest_oauthSign(req, "key", "secret", NULL, NULL);
    data = httprequest_getRequest(NULL, req, &datalen);
    printf("Request1 Data: %s\n", data);
    httprequest_release(req);

    req = httprequest_create("http://term.ie/oauth/example/access_token.php");
    httprequest_setsslverify(req, sslverify);
    httprequest_setMethod(req, YPERWAVE_HTTP_POST);
    httprequest_oauthSign(req, "key", "secret", "requestkey", "requestsecret");
    data = httprequest_getRequest(NULL, req, &datalen);
    printf("Request2 Data: %s\n", data);
    httprequest_release(req);

    req = httprequest_create("http://term.ie/oauth/example/echo_api.php");
    httprequest_setsslverify(req, sslverify);

    params = httprequest_getParams(req);

    urlparams_add(params, "Unforeseen", "Consequences");
    urlparams_add(params, "Black", "Mesa");
    urlparams_add(params, "Frankenstein", "percent%ampersand&");

    httprequest_setMethod(req, YPERWAVE_HTTP_POST);
    httprequest_oauthSign(req, "key", "secret", "accesskey", "accesssecret");

    data = httprequest_getRequest(NULL, req, &datalen);
    printf("Request3 Data: %s\n", data);
    httprequest_release(req);

    return 0;
  }

  /* Async Demos */
  httppool = httppool_create();
  HttpPoolLooper* looper = httppoollooper_create();
  httppoollooper_addPool(looper, httppool);

  if (strcmp(argv[carg], "demoget") == 0) {
    char* url;
    HttpRequest *getRequest;

    httppoollooper_start(looper);

    if (argc < 3) {
      url = "http://www.yahoo.com/";
    } else {
      url = argv[carg+1];
    }

    getRequest = httprequest_create(url);
    httprequest_setsslverify(getRequest, sslverify);
    httprequest_setcallback(getRequest, genericCB);
    httppool_add(httppool, getRequest);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "democancel") == 0) {
    int n;
    HttpRequest* cancelBeforeAdd;
    HttpRequest* cancelInFlight;
    HttpRequest* cancelTag;

    httppoollooper_start(looper);

    cancelBeforeAdd = httprequest_create("http://localhost:8000/sleep?t=9999991");
    httprequest_setsslverify(cancelBeforeAdd, sslverify);
    httprequest_setcallback(cancelBeforeAdd, genericCB);
    httprequest_cancel(cancelBeforeAdd);
    httppool_add(httppool, cancelBeforeAdd);
    pendingAdd(1);

    cancelInFlight = httprequest_create("http://localhost:8000/sleep?t=9999992");
    httprequest_setsslverify(cancelInFlight, sslverify);
    httprequest_setcallback(cancelInFlight, genericCB);
    httppool_add(httppool, cancelInFlight);
    pendingAdd(1);

    cancelTag = httprequest_create("http://localhost:8000/sleep?t=9999993");
    httprequest_setsslverify(cancelTag, sslverify);
    httprequest_setcallback(cancelTag, genericCB);
    httprequest_settag(cancelTag, 99);
    httppool_add(httppool, cancelTag);
    pendingAdd(1);

    n = httppool_canceltag(httppool, 99);
    printf("cancelled %d requests by valid tag\n", n);

    n = httppool_canceltag(httppool, 1);
    printf("cancelled %d requests by invalid tag\n", n);

    usleep(0.5 * 1000000);
    httprequest_cancel(cancelInFlight);
  }

  if (strcmp(argv[carg], "demosleepwake") == 0) {
    HttpRequest *request = httprequest_create("http://localhost:8000/sleep?t=100");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);

    httppoollooper_start(looper);
    httppool_add(httppool, request);
    pendingAdd(1);

    usleep(5.0*1000000.0);
    request = httprequest_create("http://localhost:8000/sleep?t=501");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(httppool, request);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demotelemetry") == 0) {
    HttpRequest *request1 = httprequest_create("http://www.yahoo.com/");
    httprequest_setsslverify(request1, sslverify);
    httprequest_setcallback(request1, genericCB);
    httprequest_settelemetrylevel(request1, YPERWAVE_TELEMETRYLEVEL_BASIC);

    httppoollooper_start(looper);
    httppool_add(httppool, request1);
    pendingAdd(1);

    usleep(1.0*1000000.0);

    HttpRequest *request2 = httprequest_create("http://www.yahoo.com/");
    httprequest_setsslverify(request2, sslverify);
    httprequest_setcallback(request2, genericCB);
    httprequest_settelemetrylevel(request2, YPERWAVE_TELEMETRYLEVEL_BASIC);

    httppool_add(httppool, request2);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demorestart") == 0) {
    HttpRequest *request = httprequest_create("http://localhost:8000/echo?d=MyFirstRequest");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);

    httppoollooper_start(looper);
    httppool_add(httppool, request);
    pendingAdd(1);

    usleep(0.2*1000000.0);
    httppoollooper_stop(looper, 1);
    httppoollooper_start(looper);

    request = httprequest_create("http://localhost:8000/echo?d=MySecondRequest");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(httppool, request);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demoserial") == 0) {
    HttpRequest *request = httprequest_create("http://localhost:8000/sleep?t=1000");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);

    httppool_setkeepalivepoolsize(httppool, 1);
    httppool_setmaxrequests(httppool, 1);

    httppoollooper_start(looper);
    httppool_add(httppool, request);
    pendingAdd(1);

    request = httprequest_create("http://localhost:8000/echo?d=MySecondRequest");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(httppool, request);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demoparallel") == 0) {
    HttpRequest *request = httprequest_create("http://localhost:8000/sleep?t=1000");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);

    httppool_setkeepalivepoolsize(httppool, 2);
    httppool_setmaxrequests(httppool, 2);

    httppoollooper_start(looper);
    httppool_add(httppool, request);
    pendingAdd(1);

    request = httprequest_create("http://localhost:8000/echo?d=MySecondRequest");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(httppool, request);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demomultiloop") == 0) {
    HttpPool *pool2;
    HttpRequest *request;

    pool2 = httppool_create();
    httppoollooper_addPool(looper, pool2);
    httppoollooper_start(looper);

    request = httprequest_create("http://www.yahoo.com/");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(httppool, request);
    pendingAdd(1);

    request = httprequest_create("http://news.yahoo.com/");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(pool2, request);
    pendingAdd(1);

    request = httprequest_create("http://ipv4.download.thinkbroadband.com/10MB.zip");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(httppool, request);
    pendingAdd(1);

    usleep(1.0*1000000.0);

    request = httprequest_create("http://localhost:8000/sleep?t=3002");
    httprequest_setsslverify(request, sslverify);
    httprequest_setcallback(request, genericCB);
    httppool_add(pool2, request);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demominspeed") == 0) {
    HttpRequest* timeout;
    httppoollooper_start(looper);

    timeout = httprequest_create("http://localhost:8000/slow");
    httprequest_setsslverify(timeout, sslverify);
    httprequest_setcallback(timeout, genericCB);
    httppool_add(httppool, timeout);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "demotimeout") == 0) {
    HttpRequest* timeout;
    httppoollooper_start(looper);

    printf("This test assumes that you can't send SYN packets to localhost:7777\n");
    printf("Ensure this on your Mac using: $ sudo ipfw add 5050 deny tcp from 127.0.0.1 any to 127.0.0.1 7777 in\n");
    timeout = httprequest_create("http://localhost:7777/");
    httprequest_setsslverify(timeout, sslverify);
    httprequest_setcallback(timeout, genericCB);
    httppool_add(httppool, timeout);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "jsonasync") == 0) {
    HttpRequest* req = httprequest_create("http://searchx.query.yahoo.com/v1/public/yql?q=desc%20yql.storage&format=json");
    httprequest_setsslverify(req, sslverify);
    httppoollooper_start(looper);
    httprequest_setcallback(req, jsonCB);

    httppool_add(httppool, req);
    pendingAdd(1);
  }

  if (strcmp(argv[carg], "downloadasync") == 0) {
    const char *url = NULL;
    HttpRequest *request;
    httppoollooper_start(looper);

    // Test image
    url = "http://upload.wikimedia.org/wikipedia/commons/8/85/Recurvirostra_novaehollandiae_in_flight_-_Lake_Joondalup.jpg";
    // Large, used to verify memory usage
    // url = "http://releases.ubuntu.com/14.04/ubuntu-14.04-desktop-amd64.iso";

    request = httprequest_create(url);
    httprequest_setsslverify(request, sslverify);
    httprequest_settelemetrylevel(request, YPERWAVE_TELEMETRYLEVEL_BASIC);
    httprequest_setcallback(request, downloadCB);
    httprequest_setprivate(request, httppool);
    httprequest_outputfile(request, "download.out");

    httppool_add(httppool, request);
    pendingAdd(1);
  }

  while (1) {
    pthread_mutex_lock(&mut);
    if (pending <= 0) {
      pthread_mutex_unlock(&mut);
      break;
    }
    pthread_cond_wait(&cond, &mut);
    pthread_mutex_unlock(&mut);
  }

  pthread_mutex_destroy(&mut);
  pthread_cond_destroy(&cond);

  httppoollooper_stop(looper, 1);
  httppoollooper_removePool(looper, httppool);
  httppool_release(httppool);
  httppoollooper_release(looper);

  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  return 0;
}

