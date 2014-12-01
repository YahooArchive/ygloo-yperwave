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

#include "yperwave/yperwave.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifndef WIN32
#  include <unistd.h>
#endif

#define HTTP_ENCODE_URL  0
#define HTTP_ENCODE_JSON 1


// TODO: more convenient implementation that encodes into a Ybuffer that is expanded
// on the fly
static int
encode(const char *str, char *outbuf, int n, int fmt)
{
  static const char* hex = "0123456789ABCDEF";
  unsigned char *inc;
  unsigned char *outc;
  unsigned char c;
  int olen;

  if (str == NULL) {
    return 0;
  }

  inc = (unsigned char*) str;
  if (n <= 0) {
    outc = NULL;
    n = 0;
  } else {
    outc = (unsigned char*) outbuf;
  }

  olen = 0;
  while (inc[0] != '\0') {
    c = inc[0];
    inc++;

    if (fmt == HTTP_ENCODE_URL) {
      /* see http://tools.ietf.org/html/rfc5849#section-3.6 (oauth hard requirement) */
      if ( ( c >= '0' && c <= '9') ||
	   ( c >= 'a' && c <= 'z') ||
	   ( c >= 'A' && c <= 'Z') ||
	   ( c == '-' || c == '.' || c == '_' || c == '~') ) {
	/* Valid url character, don't encode it */
	if (outc != NULL && olen + 1 <= n) {
	  *outc++ = c;
	}
	olen++;
      } else {
	/* Character has to be escaped */
	if (outc != NULL && olen + 3 <= n) {
	  *outc++ = '%';
	  *outc++ = hex[(c >> 4) & 0xf];
	  *outc++ = hex[(c >> 0) & 0xf];
	}
	olen+=3;
      }
    } else {
      if ( c == '"' || c == '{' || c == '}') {
	/* Character has to be escaped */
	if (outc != NULL && olen + 2 <= n) {
	  *outc++ = '\\';
	  *outc++ = c;
	}
	olen+=2;
      } else {
	/* Valid url character, don't encode it */
	if (outc != NULL && olen + 1 <= n) {
	  *outc++ = c;
	}
	olen++;
      }
    }
  }

  if (outc != NULL && olen + 1 <= n) {
    *outc++ = '\0';
  }

  return olen;
}

int
http_urlencode(const char *str, char *outbuf, int n)
{
  return encode(str, outbuf, n, HTTP_ENCODE_URL);
}

int
http_jsonencode(const char *str, char *outbuf, int n)
{
  return encode(str, outbuf, n, HTTP_ENCODE_JSON);
}
