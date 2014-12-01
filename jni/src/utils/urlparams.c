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

#define LOG_TAG "yperwave::httpparams"

#include "inttypes.h"

#include "yperwave/yperwave.h"
#include "yperwave_priv.h"

#ifdef MIN
#undef MIN
#endif
#define MIN(a,b) ((a) < (b) ? (a) : (b))

typedef struct {
  char *key;
  int keylen;
  int keystatic;
  char *value;
  int valuelen;
  int valuestatic;
} UrlParameter;

struct UrlParamsStruct {
  int nparams;
  int size;
  UrlParameter* plist;
};

int
urlparams_encode(Ybuffer *buffer, const char *inbuf, int inlen)
{
  static const char* hex = "0123456789ABCDEF";
  unsigned char *inc;
  unsigned char c;
  char encbuf[3];
  int olen;
  int i;

  if (inbuf == NULL || inlen <= 0) {
    return 0;
  }

  inc = (unsigned char*) inbuf;

  olen = 0;
  for (i = 0; i < inlen; i++) {
    c = inc[0];
    inc++;

    /* see http://tools.ietf.org/html/rfc5849#section-3.6 (oauth hard requirement) */
    if ( ( c >= '0' && c <= '9') ||
         ( c >= 'a' && c <= 'z') ||
         ( c >= 'A' && c <= 'Z') ||
         ( c == '-' || c == '.' || c == '_' || c == '~') ) {
      /* Valid url character, don't encode it */
      if (buffer != NULL) {
        Ybuffer_append(buffer, (char*) &c, 1);
      }
      olen++;
    } else {
      /* Character has to be escaped */
      encbuf[0] = '%';
      encbuf[1] = hex[(c >> 4) & 0xf];
      encbuf[2] = hex[(c >> 0) & 0xf];
      if (buffer != NULL) {
        Ybuffer_append(buffer, encbuf, 3);
      }
    }
  }

  return olen;
}

static int
getHexNibble(char c)
{
  if (c >= '0' && c <= '9') {
    return (int) (c - '0');
  } else if (c >= 'a' && c <= 'f') {
    return (int) (10 + (c - 'a'));
  } else if (c >= 'A' && c <= 'F') {
    return (int) (10 + (c - 'A'));
  } else {
    return (int) -1;
  }
}

static int
getHexByte(const char *c)
{
  int nhigh, nlow;

  nhigh = getHexNibble(c[0]);
  if (nhigh >= 0) {
    nlow = getHexNibble(c[1]);
    if (nlow >= 0) {
      return (unsigned char) ((nhigh << 4) | nlow);
    }
  }

  return -1;
}

int
urlparams_decode(Ybuffer *buffer, const char *inbuf, int inlen)
{
  unsigned char *inc;
  unsigned char c;
  int dec;
  int i;
  int olen;

  if (inbuf == NULL || inlen <= 0) {
    return 0;
  }

  inc = (unsigned char*) inbuf;

  olen = 0;
  for (i = 0; i < inlen; i++) {
    c = inc[0];
    inc++;

    if (c == '%' && i + 2 < inlen) {
      dec = getHexByte((const char*) inc);
      if (dec >= 0) {
        inc += 2;
        i += 2;
        c = (unsigned char) dec;
      }
    }

    if (buffer != NULL) {
      Ybuffer_append(buffer, (char*) &c, 1);
    }
    olen++;
  }

  return olen;
}

UrlParams*
urlparams_create()
{
  UrlParams *params;

  params = Ymem_malloc(sizeof(UrlParams));
  if (params == NULL) {
    return NULL;
  }

  params->nparams = 0;
  params->size = 0;
  params->plist = NULL;

  return params;
}

int
urlparams_release(UrlParams *params)
{
  int i;
  UrlParameter *p;

  if (params == NULL) {
    return YPERWAVE_OK;
  }

  if (params->plist != NULL) {
    for (i = 0; i < params->nparams; i++) {
      p = &(params->plist[i]);
      if (p->key != NULL && !p->keystatic) {
        Ymem_free(p->key);
      }
      if (p->value != NULL && !p->valuestatic) {
        Ymem_free(p->value);
      }
    }
    Ymem_free(params->plist);
  }

  Ymem_free(params);

  return YPERWAVE_OK;
}

int
urlparams_addBlob(UrlParams *params,
                  const char *key, int keylen, int keystatic,
                  const char *value, int valuelen, int valuestatic)
{
  UrlParameter *p;

  if (key == NULL || keylen < 0) {
    key = NULL;
    keylen = 0;
    keystatic = 1;
  }
  if (value == NULL || valuelen < 0) {
    value = NULL;
    valuelen = 0;
    valuestatic = 1;
  }

  if (keylen <= 0 && valuelen <= 0) {
    /* Empty key/value, ignore */
    return YPERWAVE_OK;
  }

  if (params->nparams >= params->size) {
    /* No more allocated space, need to reallocate */
    int newsize = params->size + 16;
    if (params->plist == NULL) {
      params->plist = Ymem_malloc(newsize * sizeof(UrlParameter));
      if (params->plist == NULL) {
        return YPERWAVE_ERROR;
      }
    } else {
      UrlParameter *newplist =
        Ymem_realloc(params->plist, newsize * sizeof(UrlParameter));
      if (newplist == NULL) {
        return YPERWAVE_ERROR;
      }
      params->plist = newplist;
    }

    params->size = newsize;
  }

  p = &(params->plist[params->nparams]);

  if (keystatic) {
    p->key = (char*) key;
    p->keylen = keylen;
    p->keystatic = 1;
  } else {
    if (keylen < 0) {
      p->key = NULL;
    } else {
      p->key = Ymem_malloc(keylen+1);
      if (p->key == NULL) {
        return YPERWAVE_ERROR;
      }
      memcpy(p->key, key, keylen);
      /* Null-terminate key for convenience during debugging and zero-size strings get allocated */
      p->key[keylen] = '\0';
    }

    p->keylen = keylen;
    p->keystatic = 0;
  }

  if (valuestatic) {
    p->value = (char*) value;
    p->valuelen = valuelen;
    p->valuestatic = 1;
  } else {
    if (valuelen < 0) {
      p->value = NULL;
    } else {
      p->value = Ymem_malloc(valuelen+1);
      if (p->value == NULL) {
        if (p->key != NULL && !p->keystatic) {
          Ymem_free(p->key);
          p->key = NULL;
        }
        return YPERWAVE_ERROR;
      }
      memcpy(p->value, value, valuelen);
      /* Null-terminate key for convenience during debugging and zero-size strings get allocated */
      p->value[valuelen] = '\0';
    }

    p->valuelen = valuelen;
    p->valuestatic = valuestatic;
  }

  params->nparams++;

  return YPERWAVE_OK;
}

int
urlparams_add(UrlParams *params, const char *key, const char *value)
{
  int keylen = 0;
  int valuelen = 0;

  if (key != NULL) {
    keylen = strlen(key);
  }
  if (value != NULL) {
    valuelen = strlen(value);
  }

  return urlparams_addBlob(params, key, keylen, 0, value, valuelen, 0);
}

int
urlparams_addint(UrlParams *params, const char *key, int ivalue)
{
  /* Buffer is large enough for any 32 or 64 (or even 128) bits integer */
  char value[40];

  snprintf(value, sizeof(value), "%d", ivalue);

  return urlparams_add(params, key, value);
}

int
urlparams_addint64(UrlParams *params, const char *key, uint64_t ivalue)
{
  /* Buffer is large enough for any 32 or 64 (or even 128) bits integer */
  char value[40];

  snprintf(value, sizeof(value), "%"PRId64, ivalue);

  return urlparams_add(params, key, value);
}

int
urlparams_adddouble(UrlParams *params, const char *key, double dvalue)
{
  char value[50];

  snprintf(value, sizeof(value), "%lf", dvalue);

  return urlparams_add(params, key, value);
}

int
urlparams_merge(UrlParams *params, UrlParams *opt)
{
  int n = 0;
  int nopt;
  int i;
  const char *key;
  int keylen = -1;
  const char *value;
  int valuelen = -1;

  nopt = urlparams_length(opt);
  if (params == NULL || nopt <= 0) {
    return n;
  }

  for (i = 0; i < nopt; i++) {
    key = urlparams_key(opt, i, &keylen);
    value = urlparams_value(opt, i, &valuelen);

    urlparams_addBlob(params, key, keylen, 0, value, valuelen, 0);
    n++;
  }

  return n;
}

int
urlparams_length(UrlParams *params)
{
  if (params == NULL) {
    return 0;
  }

  return params->nparams;
}

const char*
urlparams_key(UrlParams *params, int n, int *keylen)
{
  UrlParameter *p;

  if (params == NULL) {
    return NULL;
  }
  if (n < 0 || n >= params->nparams) {
    return NULL;
  }

  p = &(params->plist[n]);
  if (keylen != NULL) {
    *keylen = p->keylen;
  }
  return p->key;
}

const char*
urlparams_value(UrlParams *params, int n, int *valuelen)
{
  UrlParameter *p;

  if (params == NULL) {
    return NULL;
  }
  if (n < 0 || n >= params->nparams) {
    return NULL;
  }

  p = &(params->plist[n]);
  if (valuelen != NULL) {
    *valuelen = p->valuelen;
  }
  return p->value;
}

static int
UrlParameterCompare(const void *v1, const void *v2)
{
  const UrlParameter *p1 = (UrlParameter*) v1;
  const UrlParameter *p2 = (UrlParameter*) v2;
  int c;

  if (p1->key == NULL) {
    if (p2->key == NULL) {
      return 0;
    }
    return -1;
  }
  if (p2->key == NULL) {
    return 1;
  }

  c = memcmp(p1->key, p2->key, MIN(p1->keylen, p2->keylen));
  if (c == 0) {
    /* Don't use subtraction, so this works even if keylen is unsigned */
    if (p1->keylen < p2->keylen) {
      c = -1;
    } else if (p1->keylen > p2->keylen) {
      c = 1;
    }
  }

  return c;
}

int
urlparams_sort(UrlParams *params)
{
  int nparams;

  nparams = urlparams_length(params);
  if (nparams > 0) {
    qsort(params->plist, nparams, sizeof(UrlParameter), UrlParameterCompare);
  }

  return nparams;
}

int
urlparams_append(UrlParams *params, Ybuffer *buffer)
{
  int nparams;
  const char *key;
  int keylen = -1;
  const char *value;
  int valuelen = -1;
  int i;
  int n;

  nparams = urlparams_length(params);
  if (nparams <= 0) {
    return 0;
  }

  n = 0;
  for (i = 0; i < nparams; i++) {
    key = urlparams_key(params, i, &keylen);
    value = urlparams_value(params, i, &valuelen);

    if (i > 0) {
      if (buffer != NULL) {
        Ybuffer_append(buffer, "&", 1);
      }
      n++;
    }
    if (key != NULL) {
      if (keylen > 0) {
        n += urlparams_encode(buffer, key, keylen);
      }
    }
    if (value != NULL) {
      Ybuffer_append(buffer, "=", 1);
      n++;
      if (valuelen > 0) {
        n += urlparams_encode(buffer, value, valuelen);
      }
    }
  }

  return n;
}

char*
urlparams_format(UrlParams *params)
{
  Ybuffer *buffer;
  char *result;
  int nparams;
  int n;

  nparams = urlparams_length(params);
  if (nparams <= 0) {
    return NULL;
  }

  buffer = Ybuffer_init(32);
  if (buffer == NULL) {
    return NULL;
  }

  n = urlparams_append(params, buffer);
  if (n <= 0) {
    result = NULL;
    Ybuffer_fini(buffer);
  } else {
    result = Ybuffer_detach(buffer, NULL);
  }

  return result;
}
