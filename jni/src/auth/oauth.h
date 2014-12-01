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

#ifndef _YPERWAVE_OAUTH_PRIV_H
#define	_YPERWAVE_OAUTH_PRIV_H

/* OAuth constants */
#define OAUTH_CONSUMER_KEY "oauth_consumer_key"
#define OAUTH_TOKEN "oauth_token"
#define OAUTH_TOKEN_SECRET "oauth_token_secret"
#define OAUTH_SIGNATURE_METHOD "oauth_signature_method"
#define OAUTH_SIGNATURE "oauth_signature"
#define OAUTH_TIMESTAMP "oauth_timestamp"
#define OAUTH_NONCE "oauth_nonce"
#define OAUTH_VERSION "oauth_version"

#define OAUTH_VERSION_1_0 "1.0"

#define OAUTH_HMAC_MD5 "HMAC-MD5"
#define OAUTH_HMAC_SHA1 "HMAC-SHA1"

#ifdef	__cplusplus
extern "C" {
#endif

Ybuffer* buildSignatureBase(const char* url, int method, UrlParams *params);
char* computeSignature(Ybuffer* base, int digestmode, const char* secret);

#ifdef	__cplusplus
}
#endif

#endif	/* _YPERWAVE_OAUTH_PRIV_H */
