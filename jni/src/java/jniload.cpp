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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define  LOG_TAG    "yperwave::jni"

#include "jni.h"

#include "yperwave_config.h"
#include "java/jniutils.h"

extern "C" {
extern int register_Network(JNIEnv *env, const char *className);
};

const char* classNameNet =
  "com/yahoo/mobile/client/android/yperwave/Network";

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* _env = NULL;
    jint result = -1;
    jclass localClass;

    ALOGD("Register start");

    if (vm->GetEnv((void**) &_env, JNI_VERSION_1_4) != JNI_OK) {
        ALOGE("ERROR: GetEnv failed");
        goto bail;
    }

    /* Network */
    localClass = _env->FindClass(classNameNetwork);
    if (localClass != NULL) {
      if (register_Network(_env, classNameNetwork) < 0) {
        ALOGE("Network native registration failed");
        goto bail;
      }
    }

    /* Success, return JNI version */
    ALOGD("Register completed");
    result = JNI_VERSION_1_4;

bail:
    return result;
}
