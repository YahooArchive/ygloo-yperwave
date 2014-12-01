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

#ifndef _YPERWAVE_OAUTH_H
#define _YPERWAVE_OAUTH_H

#ifdef	__cplusplus
extern "C" {
#endif

int httprequest_oauthSign(HttpRequest* req,
                          const char* consumer_key, const char* consumer_secret,
                          const char* token, const char* token_secret);


#ifdef	__cplusplus
}
#endif

#endif	/* _YPERWAVE_OAUTH_H */

