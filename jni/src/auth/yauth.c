#define LOG_TAG "yperwave::yauth"

#include "yperwave/yperwave.h"

#include "yperwave_priv.h"

static const char* YAUTH_LOGIN_SERVER = "login.yahoo.com";

#define YPERWAVE_AUTH_DEBUG

HttpRequest*
httprequest_yauth_build_token_request(const char *login, const char *password,
                                      const char *partner_name)
{
  char *url;
  Ybuffer *vurl;
  HttpRequest *request;
  UrlParams *params;

  vurl = Ybuffer_init(YPERWAVE_DEFAULT_URL_SIZE);
  if (vurl == NULL) {
    return NULL;
  }

  Ybuffer_append(vurl, "https://", -1);
  Ybuffer_append(vurl, YAUTH_LOGIN_SERVER, -1);
  Ybuffer_append(vurl, "/config/pwtoken_get", -1);

  url = Ybuffer_detach(vurl, NULL);
  if (url == NULL) {
    return NULL;
  }

#ifdef YPERWAVE_AUTH_DEBUG
  ALOGD("GET TOKEN URL = %s\n", url);
#endif

  request = httprequest_create(url);
  Ymem_free(url);

  if (request == NULL) {
    return NULL;
  }

  params = httprequest_getParams(request);
  urlparams_add(params, "login", login);
  urlparams_add(params, "passwd", password);
  urlparams_add(params, "src", partner_name);
  urlparams_add(params, "v", "2");

  return request;
}


char* httprequest_yauth_token_extract(const char* data, int len, const char* partner_name)
{
  char *authtoken = NULL;
  int avail = len;
  const char *nextline;
  const char *eol;
  const char *bol;

  if (len <= 0) {
    return NULL;
  }

  /* First line must be integer (0 if success) */
  nextline = data;
  if (avail >= 3 &&
      nextline[0] == '0' &&
      nextline[1] == '\r' && nextline[2] == '\n') {
#ifdef YPERWAVE_AUTH_DEBUG
    ALOGD("TOKEN REQUEST SUCCESS\n");
#endif
  } else {
    return NULL;
  }

  avail -= 3;
  nextline += 3;

  int partnerlen = strlen(partner_name);
  if (avail > partnerlen + 1 &&
          memcmp(nextline, partner_name, partnerlen) == 0 &&
          nextline[partnerlen] == '=') {

    bol = nextline + partnerlen + 1;
    avail -= partnerlen + 1;

#ifdef YPERWAVE_AUTH_DEBUG
    ALOGD("PARTNER TOKEN OK\n");
#endif

    /* Find end of line */
    eol = bol;
    while (avail > 0 && eol[0] != '\r') {
      eol++;
      avail--;
    }

    authtoken = Ymem_malloc(eol - bol + 1);
    memcpy(authtoken, bol, eol - bol);
    authtoken[eol - bol] = '\0';

#ifdef YPERWAVE_AUTH_DEBUG
    ALOGD("Token Data:\n---\n%.*s\n---\n", len, data);
    ALOGD("token: '%s'\n", authtoken);
#endif
  }

  return authtoken;
}

HttpRequest* httprequest_yauth_build_yt_request(const char* partner_name, const char* user_token)
{
  Ybuffer *vurl;
  UrlParams *params;
  char *url;
  HttpRequest *request;

  vurl = Ybuffer_init(YPERWAVE_DEFAULT_URL_SIZE);
  if (vurl == NULL) {
    return NULL;
  }

  Ybuffer_append(vurl, "https://", -1);
  Ybuffer_append(vurl, YAUTH_LOGIN_SERVER, -1);
  Ybuffer_append(vurl, "/config/pwtoken_login", -1);

  url = Ybuffer_detach(vurl, NULL);
  if (url == NULL) {
    return NULL;
  }

  request = httprequest_create(url);
  Ymem_free(url);

  if (request == NULL) {
    return NULL;
  }

  params = httprequest_getParams(request);
  urlparams_add(params, "src", partner_name);
  urlparams_add(params, "token", user_token);
  urlparams_add(params, "persistent", "1");
  urlparams_add(params, "v", "2");

  return request;
}

YTPair* httprequest_yauth_yt_extract(const char* data, int len)
{
  const char* line;
  int avail=len;

  const char* cookie_start;
  const char* cookie_end;
  int cookie_length;

  YTPair* ytpair = Ymem_malloc(sizeof(YTPair));

  /*
   * Response:
   * 0
   * Y=XXXX; some foobar
   * T=YYY; some foobar
   * B=ZZZ; some foobar
   * PH=AAA; some foobar
   * AO=BBB; some foobar
   */

  /* First line must be integer (0 if success) */
  line = data;
  if (len >= 3 &&
          line[0] == '0' &&
          line[1] == '\r' && line[2] == '\n') {

#ifdef YPERWAVE_AUTH_DEBUG
    ALOGD("YT REQUEST SUCCESS\n");
#endif
  } else {
    return NULL;
  }

  // move cursor to 2nd line
  avail -= 3;
  line += 3;

  cookie_start = line+2;
  cookie_end = strchr(line, ';');
  cookie_length = cookie_end - cookie_start;

  ytpair->Y = Ymem_malloc(cookie_length+1);
  memcpy(ytpair->Y, cookie_start, cookie_length);
  ytpair->Y[cookie_length] = '\0';

#ifdef YPERWAVE_AUTH_DEBUG
  ALOGD("extracted Y cookie: %s\n", ytpair->Y);
#endif

  line += (2+cookie_length);
  avail -= (2+cookie_length);

  // move cursor to next line
  while (*line != '\n') {
    line++;
    avail--;
  }
  line++; avail--;

  cookie_start = line+2;
  cookie_end = strchr(line, ';');
  cookie_length = cookie_end - cookie_start;
  ytpair->T = Ymem_malloc(cookie_length+1);
  memcpy(ytpair->T, cookie_start, cookie_length);
  ytpair->T[cookie_length] = '\0';

#ifdef YPERWAVE_AUTH_DEBUG
  ALOGD("extracted T cookie: %s\n", ytpair->T);
#endif

  return ytpair;
}
