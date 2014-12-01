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

#ifndef HTTPREQUEST_JSON_H
#define	HTTPREQUEST_JSON_H

#ifdef	__cplusplus
extern "C" {
#endif


/**
 * Retrieve an HTTP response directly as JSON
 * @param req The HTTP request whose response is to be retrieved
 * @return Root of parsed JSON data (see: http://www.digip.org/jansson/doc/2.2/apiref.html)
 */
json_t* httprequest_get_json(HttpRequest* req);


/**
 * Traverse JSON tree starting at root and output its contents.
 * @param root starting point
 * @return 0 on success
 */
int httprequest_json_dump(json_t *root);

#ifdef	__cplusplus
}
#endif

#endif	/* HTTPREQUEST_JSON_H */

