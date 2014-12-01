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

#ifndef _YPERWAVE_HTTPSETTINGS_H
#define _YPERWAVE_HTTPSETTINGS_H

#ifdef	__cplusplus
extern "C" {
#endif


enum proxy_type_enum {
  YPERWAVE_PROXY_TYPE_NONE,
  YPERWAVE_PROXY_TYPE_HTTP,
  YPERWAVE_PROXY_TYPE_SOCKS4,
  YPERWAVE_PROXY_TYPE_SOCKS5,
};
typedef enum proxy_type_enum proxy_type_t;

YOSAL_OBJECT_EXPORT(HttpSettings)

int httpsettings_init();

int httpsettings_set_proxy_hostname(const char* hostname);
int httpsettings_set_proxy_port(uint16_t port);
int httpsettings_set_proxy_type(proxy_type_t type);
int httpsettings_set_proxy_username(const char* username);
int httpsettings_set_proxy_password(const char* password);
int httpsettings_set_cabundle(const char* cabundle);

char* httpsettings_proxy_hostname();
uint16_t httpsettings_proxy_port();
proxy_type_t httpsettings_proxy_type();
char* httpsettings_proxy_username();
char* httpsettings_proxy_password();
char* httpsettings_cabundle();

#ifdef	__cplusplus
}
#endif

#endif	/* _YPERWAVE_HTTPSETTINGS_H */

