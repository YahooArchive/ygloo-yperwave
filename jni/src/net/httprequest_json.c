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

#define LOG_TAG "yperwave:httprequest"

#include "yperwave_priv.h"
#include "httprequest_json.h"

#define YPERWAVE_JSON_DEBUG

json_t* httprequest_get_json(HttpRequest* req)
{
  char* data;
  int datalen;
  json_error_t jerror;

  if (req == NULL) {
    ALOGE("error: request is null");
    return NULL;
  }

  data = httprequest_getcontent(req, &datalen);
  if (data == NULL || datalen == 0) {
    ALOGE("error: data is null or zero length");
    return NULL;
  }


  json_t* root = json_loadb(data, datalen, 0, &jerror);
  if (root == NULL) {
    ALOGE("error: on line %d: %s\n", jerror.line, jerror.text);
    return NULL;
  }

#ifdef YPERWAVE_JSON_DEBUG
  httprequest_json_dump(root);
#endif

  return root;
}


#ifdef YPERWAVE_JSON_DEBUG

static int printTab(FILE *f, int depth)
{
  int i;
  const char tab[2] = "  ";

  for (i = 0; i < depth; i++) {
    fwrite(tab, sizeof (tab), 1, f);
  }

  return depth;
}

static int json_dump(json_t *root, const char *prefix, int depth)
{
  const char *key;
  json_t *value;
  int valuetype;
  void *iter;
  int i;

  if (root == NULL) {
    fprintf(stderr, "error: root is null\n");
    return -1;
  }

  if (!json_is_object(root)) {
    fprintf(stderr, "error: root is not an object\n");
    return -1;
  }

  // Handcrafted iterator. More verbose than using the json_object_foreach()
  // macro, but makes actual processing less opaque
  iter = json_object_iter(root);
  while (iter) {
    key = json_object_iter_key(iter);
    value = json_object_iter_value(iter);

    if (value == NULL) {
      valuetype = JSON_NULL;
    } else {
      valuetype = json_typeof(value);
    }

    printTab(stderr, depth);
    switch (valuetype) {
      case JSON_OBJECT:
        fprintf(stderr, "Obj:%s -> <object>\n", key);
        json_dump(value, prefix, depth + 1);
        break;
      case JSON_ARRAY:
        fprintf(stderr, "Arr:%s -> <array>\n", key);
        for (i = 0; i < json_array_size(value); i++) {
          json_t *element;

          element = json_array_get(value, i);
          printTab(stderr, depth);
          fprintf(stderr, "#%d\n", i);
          json_dump(element, prefix, depth + 1);
        }
        break;
      case JSON_STRING:
        fprintf(stderr, "Str:%s -> %s\n",
                key, json_string_value(value));
        break;
      case JSON_INTEGER:
        fprintf(stderr, "Int:%s -> %ld\n",
                key, (long) json_integer_value(value));
        break;
      case JSON_REAL:
        fprintf(stderr, "Flt:%s -> %f\n",
                key, json_real_value(value));
        break;
      case JSON_TRUE:
        fprintf(stderr, "Boo:%s -> true\n", key);
        break;
      case JSON_FALSE:
        fprintf(stderr, "Boo:%s -> false\n", key);
        break;
      case JSON_NULL:
        fprintf(stderr, "Ptr:%s -> NULL\n", key);
        break;
      default:
        fprintf(stderr, "Unk:%s ->", key);
        break;
    }

    iter = json_object_iter_next(root, iter);
  }

  return 0;
}


int httprequest_json_dump(json_t *root) {
  return json_dump(root, NULL, 0);
}
#endif
