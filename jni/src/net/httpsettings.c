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

#define LOG_TAG "yperwave::httpsettings"

#include "yperwave/yperwave.h"
#include <pthread.h>

YOSAL_OBJECT_DECLARE(HttpSettings)
YOSAL_OBJECT_BEGIN
  proxy_type_t proxy_type;
  char* proxy_hostname;
  uint16_t proxy_port;
  char* proxy_username;
  char* proxy_password;
  char* cabundle;
YOSAL_OBJECT_END

static HttpSettings* settings = NULL;
static pthread_mutex_t settings_mutex = PTHREAD_MUTEX_INITIALIZER;

static void
release(void *ptr)
{
  HttpSettings *set = (HttpSettings*) ptr;

  if (set->proxy_hostname != NULL) {
    Ymem_free(set->proxy_hostname);
  }

  if (set->proxy_username != NULL) {
    Ymem_free(set->proxy_username);
  }

  if (set->proxy_password != NULL) {
    Ymem_free(set->proxy_password);
  }

  if (set->cabundle != NULL) {
    Ymem_free(set->cabundle);
  }

  Ymem_free(settings);
}

int
httpsettings_init()
{
  HttpSettings* set = NULL;

  pthread_mutex_lock(&settings_mutex);

  if (settings == NULL) {
    set = (HttpSettings*) yobject_create(sizeof(HttpSettings), release);
    if (set == NULL) {
      pthread_mutex_unlock(&settings_mutex);
      return YPERWAVE_ERROR;
    }

    set->proxy_hostname = NULL;
    set->proxy_port = 0;
    set->proxy_type = YPERWAVE_PROXY_TYPE_NONE;
    set->proxy_username = NULL;
    set->proxy_password = NULL;
    set->cabundle = NULL;
    settings = set;
  }

  pthread_mutex_unlock(&settings_mutex);
  return YPERWAVE_OK;
}


int
httpsettings_set_proxy_hostname(const char* hostname)
{
  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  if (settings->proxy_hostname != NULL) {
    Ymem_free(settings->proxy_hostname);
  }

  settings->proxy_hostname = Ymem_strdup(hostname);

  yobject_unlock((yobject*) settings);
  return YPERWAVE_OK;
}

int
httpsettings_set_proxy_port(uint16_t port)
{
  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  settings->proxy_port = port;

  yobject_unlock((yobject*) settings);
  return YPERWAVE_OK;
}

int
httpsettings_set_proxy_type(proxy_type_t type)
{
  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  settings->proxy_type = type;

  yobject_unlock((yobject*) settings);
  return YPERWAVE_OK;
}

int
httpsettings_set_proxy_username(const char* username)
{
  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  if (settings->proxy_username != NULL) {
    Ymem_free(settings->proxy_username);
  }

  settings->proxy_username = Ymem_strdup(username);

  yobject_unlock((yobject*) settings);
  return YPERWAVE_OK;
}

int
httpsettings_set_proxy_password(const char* password)
{
  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  if (settings->proxy_password != NULL) {
    Ymem_free(settings->proxy_password);
  }

  settings->proxy_password = Ymem_strdup(password);

  yobject_unlock((yobject*) settings);
  return YPERWAVE_OK;
}

int
httpsettings_set_cabundle(const char* cabundle)
{
  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return YPERWAVE_ERROR;
  }

  if (settings->cabundle != NULL) {
    Ymem_free(settings->cabundle);
  }

  settings->cabundle = Ymem_strdup(cabundle);

  yobject_unlock((yobject*) settings);
  return YPERWAVE_OK;
}

char*
httpsettings_proxy_hostname()
{
  char *retval = NULL;

  if (settings == NULL) {
    return retval;
  }

  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return NULL;
  }

  retval = Ymem_strdup(settings->proxy_hostname);
  yobject_unlock((yobject*) settings);

  return retval;
}

uint16_t
httpsettings_proxy_port()
{
  uint16_t retval = 0;

  if (settings == NULL) {
    return retval;
  }

  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return retval;
  }

  retval = settings->proxy_port;
  yobject_unlock((yobject*) settings);

  return retval;
}

proxy_type_t
httpsettings_proxy_type()
{
  proxy_type_t retval = YPERWAVE_PROXY_TYPE_NONE;

  if (settings == NULL) {
    return retval;
  }

  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return retval;
  }

  retval = settings->proxy_type;
  yobject_unlock((yobject*) settings);

  return retval;
}

char*
httpsettings_proxy_username()
{
  char *retval = NULL;

  if (settings == NULL) {
    return retval;
  }

  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return NULL;
  }

  retval = Ymem_strdup(settings->proxy_username);
  yobject_unlock((yobject*) settings);

  return retval;
}

char*
httpsettings_proxy_password()
{
  char *retval = NULL;

  if (settings == NULL) {
    return retval;
  }

  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return NULL;
  }

  retval = Ymem_strdup(settings->proxy_password);
  yobject_unlock((yobject*) settings);

  return retval;
}

char*
httpsettings_cabundle()
{
  char *retval = NULL;

  if (settings == NULL) {
    return retval;
  }

  if (yobject_lock((yobject*) settings) != YOSAL_OK) {
    return NULL;
  }

  retval = Ymem_strdup(settings->cabundle);
  yobject_unlock((yobject*) settings);

  return retval;
}
