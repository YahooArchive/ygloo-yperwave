#define LOG_TAG "yperwave:cache"
#include "yperwave/yperwave.h"

void cachedata_release(void *yobject)
{
  CacheData *cachedata = (CacheData *)yobject;
  if (cachedata == NULL) {
    return;
  }

  if (cachedata->data != NULL) {
    Ymem_free(cachedata->data);
  }

  Ymem_free(cachedata);
}

CacheData *cachedata_create()
{
  CacheData *cachedata = (CacheData *)yobject_create(sizeof(CacheData), cachedata_release);
  if (cachedata != NULL) {
    cachedata->data = NULL;
    cachedata->datalen = 0;
  }
  return cachedata;
}
