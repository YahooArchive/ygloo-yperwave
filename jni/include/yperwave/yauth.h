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

#ifndef _YPERWAVE_YAUTH_H
#define _YPERWAVE_YAUTH_H

#include "httprequest.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct YTPairStruct YTPair;
struct YTPairStruct {
  char* Y;
  char* T;
};

/**
 * Build a request to exchange Yahoo username and password for a token. The returned request
 * has to be attached to an HttpPool and executed. Afterwards, httprequest_yauth_token_extract
 * can be used to extract the token from the response.
 * @param login Yahoo username
 * @param password Corresponding password
 * @param partner_name Identifier of the calling application
 * @return  A requet
 */
HttpRequest* httprequest_yauth_build_token_request(const char *login, const char *password, const char *partner_name);
/**
 * Extract a token from a request that was created using httprequest_yauth_build_token_request.
 * The returned token will remain valid until the user changes his or her password.
 * @param data Response of the request.
 * @param len Length of data
 * @param partner_name Identifier of the calling application
 * @return
 */
char* httprequest_yauth_token_extract(const char* data, int len, const char* partner_name);

/**
 * Build a request to exchange a Yahoo user token (see httprequest_yauth_build_token_request)
 * for a Y/T cookie pair. The returned request has to be attached to an HttpPool and executed.
 * Afterwards, httprequest_yauth_yt_extract can be used to extract the Y/T cookie pair
 * from the response
 * @param partner_name Identifier of the calling application
 * @param user_token Token obtained using httprequest_yauth_build_token_request
 */
HttpRequest* httprequest_yauth_build_yt_request(const char* partner_name, const char* user_token);
/**
 * Extract a Y/T pair from a request created with httprequest_yauth_build_yt_request.
 * @param data Response of the request
 * @param len Length of data
 */
YTPair* httprequest_yauth_yt_extract(const char* data, int len);

#ifdef	__cplusplus
}
#endif

#endif	/* _YPERWAVE_YAUTH_H */

