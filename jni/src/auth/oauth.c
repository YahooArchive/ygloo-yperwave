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

#define LOG_TAG "yperwave::oauth"

#include "yosal/yosal.h"

#include "yperwave_priv.h"

#include "oauth.h"

#include <time.h>

#ifdef MAX
#undef MAX
#endif
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define YOSAL_DIGEST_LENGTH MAX(YOSAL_DIGEST_MD5, YOSAL_DIGEST_SHA1)

#define NONCE_LENGTH (16+1)

#define YPERWAVE_OAUTH_DEBUG


/**
 * Compute signature for given base
 * see https://dev.twitter.com/docs/auth/creating-signature
 *
 * @param base the signature base
 * @param digestmode digest to use, supported MD5 or SHA1
 * @param secret HMAC secret (usually client_secret&token_secret for oauth)
 * @return
 */
char* computeSignature(Ybuffer* base, int digestmode, const char* secret)
{
  char sig[YOSAL_DIGEST_LENGTH];

  Ydigest* digest = Ydigest_create_mac(digestmode, secret, strlen(secret));
  int len;
  char* basec = Ybuffer_detach(base, &len);

#ifdef YPERWAVE_OAUTH_DEBUG
  ALOGD("base: %s\n", basec);
#endif

  Ydigest_update(digest, basec, len);
  Ydigest_final(digest);
  Ydigest_digest(digest, sig);

  char* b64 = Ybase64_encode(sig, YOSAL_DIGEST_SHA1);

  Ydigest_release(digest);
  Ymem_free(basec);

  return b64;
}

/**
 * Build signature base string for oAuth, format:
 * urlencode(METHOD)&urlencode(BASEURL)&urlencode(PARAMS)
 *
 * Gotchas:
 * 1. Parameter values are double encoded in the end, because "value" in oAuth lingo
 * is "value as it is sent to the server" and values are sent to the server URL encoded.
 *
 * @param url base URL
 * @param args HTTP arguments
 * @param nargs number of arguments
 * @return
 */
Ybuffer*
buildSignatureBase(const char* url, int method, UrlParams *params)
{
  Ybuffer *base;
  Ybuffer *penc;
  char *pencstr;
  int penclen;

  base = Ybuffer_init(128);
  if (base == NULL) {
    return NULL;
  }

  /* Method */
  switch (method) {
  case YPERWAVE_HTTP_POST:
  case YPERWAVE_HTTP_POST_FORM:
    Ybuffer_append(base, "POST", -1);
    Ybuffer_append(base, "&", 1);
    break;
  case YPERWAVE_HTTP_GET:
    Ybuffer_append(base, "GET", -1);
    Ybuffer_append(base, "&", 1);
    break;
  default:
    Ybuffer_fini(base);
    return NULL;
  }

  /* Base url */
  if (url != NULL) {
    urlparams_encode(base, url, strlen(url));
    Ybuffer_append(base, "&", 1);
  }

  /* Generate url encoded string for all arguments */
  urlparams_sort(params);
  penc = Ybuffer_init(32);
  urlparams_append(params, penc);

  /* Append it encoded again */
  pencstr = Ybuffer_detach(penc, &penclen);
  urlparams_encode(base, pencstr, penclen);
  Ymem_free(pencstr);

  return base;
}

int
httprequest_oauthSign(HttpRequest* req,
                      const char* consumer_key, const char* consumer_secret,
                      const char* token, const char* token_secret) {


  char nonce[NONCE_LENGTH];
  char timestamp[24];
  UrlParams *params;
  Ybuffer* combined_secret;
  char* combined_secretc;
  Ybuffer* signature_base;
  char* sigb64;
  unsigned long t = Ytime_epoch();

  Yrandom_hexstring(nonce, NONCE_LENGTH);
  snprintf(timestamp, sizeof(timestamp), "%lu" , t);

  params = httprequest_getParams(req);

  urlparams_add(params, OAUTH_SIGNATURE_METHOD, OAUTH_HMAC_SHA1);
  urlparams_add(params, OAUTH_VERSION, OAUTH_VERSION_1_0);
  urlparams_add(params, OAUTH_NONCE, nonce);
  urlparams_add(params, OAUTH_TIMESTAMP, timestamp);
  if (consumer_key != NULL) {
    urlparams_add(params, OAUTH_CONSUMER_KEY, consumer_key);
  }
  if (token != NULL) {
    urlparams_add(params, OAUTH_TOKEN, token);
  }

  signature_base = buildSignatureBase(req->url, req->method, params);

  combined_secret = Ybuffer_init(128);
  if (token_secret != NULL) {
    int lentoken = strlen(token_secret);

    /* TODO: shouldn't consumer and token be url encoded? */
    if (consumer_secret != NULL) {
      int lenconsumer = strlen(consumer_secret);
      Ybuffer_append(combined_secret, consumer_secret, lenconsumer);
    }
    Ybuffer_append(combined_secret, "&", 1);
    Ybuffer_append(combined_secret, token_secret, lentoken);
  } else {
    if (consumer_secret != NULL) {
      int len = strlen(consumer_secret);
      Ybuffer_append(combined_secret, consumer_secret, len);
      Ybuffer_append(combined_secret, "&", 1);
    }
  }

  combined_secretc = Ybuffer_detach(combined_secret, NULL);

  sigb64 = computeSignature(signature_base, YOSAL_DIGEST_MODE_HMAC_SHA1, combined_secretc);
  Ymem_free(combined_secretc);

  urlparams_add(params, OAUTH_SIGNATURE, sigb64);
  Ymem_free(sigb64);

  return YPERWAVE_OK;
}
