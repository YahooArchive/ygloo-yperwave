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

#define LOG_TAG "yperwave::net"

#include "yperwave/yperwave.h"
#include "yperwave_priv.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

static volatile int gYwaveHttpPool_inited = -1;
static pthread_mutex_t gYwaveHttpPool_mutex = PTHREAD_MUTEX_INITIALIZER;

static JavaVM * g_vm;

static jclass gHttpPool_clazz = 0;
static jfieldID gHttpPool_nativeHandleFieldID = 0;
static jmethodID gHttpPool_onSuccessMethodID = 0;
static jmethodID gHttpPool_onFailureMethodID = 0;

static int
jni_httppool_init(JNIEnv *_env,  const char *classPathName)
{
    if (gYwaveHttpPool_inited < 0) {
        pthread_mutex_lock(&gYwaveHttpPool_mutex);
        if (gYwaveHttpPool_inited < 0) {
	  jclass clazz;

	  /* Resolve classes */
	  clazz = (*_env)->FindClass(_env, classPathName);
	  if (clazz != 0) {
	    gHttpPool_clazz = (*_env)->NewGlobalRef(_env, clazz);

	    gHttpPool_nativeHandleFieldID =
	      (*_env)->GetFieldID(_env, gHttpPool_clazz, "mNativeHandle", "J");
	    gHttpPool_onSuccessMethodID =
	      (*_env)->GetMethodID(_env, gHttpPool_clazz, "onSuccess", "(J)I");
	    gHttpPool_onFailureMethodID =
	      (*_env)->GetMethodID(_env, gHttpPool_clazz, "onFailure", "(JI)I");	  }
	  (*_env)->GetJavaVM(_env, &g_vm);

	  if ( (g_vm == 0) || (gHttpPool_clazz == 0) ||
	       (gHttpPool_nativeHandleFieldID == 0) ||
	       (gHttpPool_onSuccessMethodID == 0) ||
	       (gHttpPool_onFailureMethodID == 0) ) {
	    gYwaveHttpPool_inited = 0;
	  } else if (netclient_init() != 0) {
	    gYwaveHttpPool_inited = 0;
	  } else {
	    gYwaveHttpPool_inited = 1;
	  }
        }
        pthread_mutex_unlock(&gYwaveHttpPool_mutex);
    }

    return (gYwaveHttpPool_inited > 0);
}

static jlong convertPointerToJLong(void* ptr) {
    return (jlong) ((uintptr_t) ptr);
}

static void* convertJLongToPointer(jlong l) {
    return (void*) ((uintptr_t) l);
}

static jfieldID
getNativeHandleFieldID(JNIEnv* _env, jobject object)
{
    jfieldID fieldID = 0;

#if 1
    fieldID = gHttpPool_nativeHandleFieldID;
#else
    jclass clazz = (*_env)->GetObjectClass(_env, object);
    if (clazz != NULL) {
	fieldID = (*_env)->GetFieldID(_env, clazz, "mNativeHandle", "J");
    }
#endif

    return fieldID;
}

static NetclientEnv*
getNetclientEnv(JNIEnv* _env, jobject object)
{
    jlong l = 0;
    jfieldID fieldID = getNativeHandleFieldID(_env, object);

    if (fieldID != 0) {
	l = (*_env)->GetLongField(_env, object, fieldID);
    }

    return (NetclientEnv*) convertJLongToPointer(l);
}

static jlong
setNetclientEnv(JNIEnv* _env, jobject object, NetclientEnv *netenv)
{
    jfieldID fieldID = getNativeHandleFieldID(_env, object);
    jlong l = 0;

    if (fieldID != 0) {
	l = convertPointerToJLong(netenv);
	(*_env)->SetLongField(_env, object, fieldID, l);
    }

    return l;
}

static HttpPool*
getHttpPool(JNIEnv* _env, jobject object)
{
    NetclientEnv *netenv;

    netenv = getNetclientEnv(_env, object);
    if (netenv != NULL) {
	return netclient_pool(netenv);
    }

    return NULL;
}

JNIEXPORT jlong JNICALL
httppool_jni_create(JNIEnv* _env, jobject object)
{
    NetclientEnv *netenv;

    netenv = netclient_create();
    if (netenv == NULL) {
#ifdef YPERWAVE_DEBUG_NETAPI
	ALOGE("failed to create native object");
#endif
    } else {
#ifdef YPERWAVE_DEBUG_NETAPI
	ALOGI("created native object %p", netenv);
#endif
    }

    setNetclientEnv(_env, object, netenv);
    return convertPointerToJLong(netenv);
}

JNIEXPORT jint JNICALL
httppool_jni_release(JNIEnv* _env, jobject object)
{
    NetclientEnv *netenv;

    netenv = getNetclientEnv(_env, object);
    if (netenv != NULL) {
	netclient_release(netenv);
	setNetclientEnv(_env, object, NULL);
    }

    return 0;
}

typedef struct {
    jobject globalref;
    HttpRequest* request;
} callbackData;

static int
callbackRelease(JNIEnv* _env, callbackData *cbdata)
{
    if (cbdata != NULL) {
	if (cbdata->globalref != NULL) {
	    (*_env)->DeleteGlobalRef(_env, cbdata->globalref);
	    cbdata->globalref = NULL;
	}

	Ymem_free(cbdata);
    }

    return 0;
}

static callbackData*
callbackRegister(JNIEnv* _env, jobject object, HttpRequest *request)
{
    callbackData *cbdata;

    cbdata = (callbackData*) Ymem_malloc(sizeof(callbackData));
    if (cbdata == NULL) {
	return NULL;
    }

    /* Keep a global reference, since local one will expire
       after this method has returned */
    cbdata->globalref = (*_env)->NewGlobalRef(_env, object);
    if (cbdata->globalref == NULL) {
	callbackRelease(_env, cbdata);
	return NULL;
    }

    cbdata->request = request;

    return cbdata;
}

static int
callbackInvoke(HttpRequest *handle, callbackData *cbdata)
{
    int detach = 0;
    JNIEnv *g_env;
    int getEnvStat;
    int rc;

    if (handle == NULL || cbdata == NULL) {
	return 1;
    }

    getEnvStat = (*g_vm)->GetEnv(g_vm, (void **) &g_env, JNI_VERSION_1_6);
    if (getEnvStat == JNI_EDETACHED) {
	/* Need to attach current thread to env */
	if ((*g_vm)->AttachCurrentThread(g_vm, &g_env, NULL) == 0) {
	    detach = 1;
	} else {
	    /* Failed to attach */
	}
    } else if (getEnvStat == JNI_OK) {
    } else if (getEnvStat == JNI_EVERSION) {
	/* Invalid version */
    }

    rc = httprequest_getcode(handle);
    if (rc == 200) {
	(*g_env)->CallVoidMethod(g_env, cbdata->globalref, gHttpPool_onSuccessMethodID,
				 convertPointerToJLong(cbdata->request));
    } else {
	(*g_env)->CallVoidMethod(g_env, cbdata->globalref, gHttpPool_onFailureMethodID,
				 convertPointerToJLong(cbdata->request), rc);
    }

    if ((*g_env)->ExceptionCheck(g_env)) {
	(*g_env)->ExceptionDescribe(g_env);
    }

    if (detach) {
	(*g_vm)->DetachCurrentThread(g_vm);
    }

    return 0;
}

static int
requestCallback(HttpRequest *handle)
{
    char *data = NULL;
    int datalen = 0;
    callbackData *cbdata;

    data = httprequest_getcontent(handle, &datalen);
    cbdata = httprequest_getprivate(handle);

    if (data != NULL) {
#ifdef YPERWAVE_DEBUG_NETAPI
	ALOGI("Request %p completed (%d bytes)\n", handle, datalen);
#endif
    }

    /* Invoke Java callback */
    if (cbdata != NULL) {
	callbackInvoke(handle, cbdata);
    }

    return 0;
}

static int
callbackPush(JNIEnv* _env, jobject object, HttpPool *httppool, HttpRequest *request)
{
    callbackData *cbdata;

    if (request == NULL) {
	return -1;
    }

    cbdata = callbackRegister(_env, object, request);
    if (cbdata == NULL) {
	return -1;
    }

    httprequest_setprivate(request, (void*) cbdata);
    httprequest_setcallback(request, requestCallback);
    if (httppool_add(httppool, request) < 0) {
	return -1;
    }

    return 0;
}

JNIEXPORT jlong JNICALL
httppool_jni_add(JNIEnv* _env, jobject object, jstring jurl)
{
    HttpRequest *request = NULL;
    HttpPool *httppool;

    httppool = getHttpPool(_env, object);
    if (httppool == NULL) {
	return 0;
    }

    char const * url = (*_env)->GetStringUTFChars(_env, jurl, NULL);
    if (url != NULL) {
	request = httprequest_create(url);
	if (request != NULL) {
	    if (callbackPush(_env, object, httppool, request) < 0) {
		httprequest_release(request);
		request = NULL;
	    }
	}
	(*_env)->ReleaseStringUTFChars(_env, jurl, url);
    }
    return convertPointerToJLong(request);
}

JNIEXPORT jint JNICALL
httppool_jni_step(JNIEnv* _env, jobject object, jint nsteps)
{
    HttpPool *httppool;
    int rc;

    httppool = getHttpPool(_env, object);
    if (httppool == NULL) {
	return -1;
    }

    rc = httppool_step(httppool, nsteps);
    ALOGI("Step %d/%d into http pool %p", rc, nsteps, httppool);

    return rc;
}

JNIEXPORT jlong JNICALL
httppool_jni_login(JNIEnv* _env, jobject object,
		   jstring jappkey, jstring jappsecret,
		   jstring jlogin, jstring jpassword)
{
    HttpRequest *request = NULL;
#if 0
    NetclientEnv *netenv;

    // JNI bindings (if we need them) have to be rewritten to converge to new APIs
    netenv = getNetclientEnv(_env, object);
    if (netenv == NULL) {
	ALOGE("login failed to get netenv handle for object %p", object);
	return 0;
    }

    if (jappkey == NULL || jappsecret == NULL || jlogin == NULL || jpassword == NULL) {
	return 0;
    }

    char const * appkey = (*_env)->GetStringUTFChars(_env, jappkey, NULL);
    if (appkey != NULL) {
	char const * appsecret = (*_env)->GetStringUTFChars(_env, jappsecret, NULL);
	if (appsecret != NULL) {
	    char const * login = (*_env)->GetStringUTFChars(_env, jlogin, NULL);
	    if (login != NULL) {
		char const * password = (*_env)->GetStringUTFChars(_env, jpassword, NULL);
		if (password != NULL) {
		    request = yahoo_login(netenv, appkey, appsecret, login, password);
		    if (request != NULL) {
			if (callbackPush(_env, object, netclient_pool(netenv), request) < 0) {
			    httprequest_release(request);
			    request = NULL;
			}
		    }
		    (*_env)->ReleaseStringUTFChars(_env, jpassword, password);
		}
		(*_env)->ReleaseStringUTFChars(_env, jlogin, login);
	    }
	    (*_env)->ReleaseStringUTFChars(_env, jappsecret, appsecret);
	}
	(*_env)->ReleaseStringUTFChars(_env, jappkey, appkey);
    }
#endif

    return convertPointerToJLong(request);
}

JNIEXPORT jint JNICALL
httppool_jni_setToken(JNIEnv* _env, jobject object, jstring jtoken)
{
    NetclientEnv *netenv;

    netenv = getNetclientEnv(_env, object);
    if (netenv == NULL) {
	ALOGE("setToken failed to get netenv handle for object %p", object);
	return 0;
    }

    char const * token = (*_env)->GetStringUTFChars(_env, jtoken, NULL);
    if (token != NULL) {
	netclient_settoken(netenv, token);
	(*_env)->ReleaseStringUTFChars(_env, jtoken, token);
    }

    return 0;
}

JNIEXPORT jobject JNICALL
httppool_jni_getToken(JNIEnv* _env, jobject object)
{
    NetclientEnv *netenv;
    const char *authtoken;

    netenv = getNetclientEnv(_env, object);
    if (netenv == NULL) {
	ALOGE("getToken failed to get netenv handle for object %p", object);
	return NULL;
    }

    authtoken = netclient_gettoken(netenv);
    if (authtoken == NULL) {
	return NULL;
    }

    return (*_env)->NewStringUTF(_env, authtoken);
}

/* Dalvik VM type signatures */
static JNINativeMethod httppool_methods[] = {
    {   "native_poolCreate",
	"()J",
	(void*) httppool_jni_create
    },
    {   "native_poolRelease",
	"()I",
	(void*) httppool_jni_release
    },
    {   "native_poolAdd",
	"(Ljava/lang/String;)J",
	(void*) httppool_jni_add
    },
    {   "native_poolStep",
	"(I)I",
	(void*) httppool_jni_step
    },
    {   "native_login",
	"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)J",
	(void*) httppool_jni_login
    },
    {   "native_setToken",
	"(Ljava/lang/String;)I",
	(void*) httppool_jni_setToken
    },
    {   "native_getToken",
	"()Ljava/lang/String;",
	(void*) httppool_jni_getToken
    }
};

int register_Network(JNIEnv *_env, const char *classPathName)
{
    int rc;

    if (jni_httppool_init(_env, classPathName) <= 0) {
        return JNI_FALSE;
    }

    rc = jniutils_registerNativeMethods(_env, classPathName,
					httppool_methods, NELEM(httppool_methods));
    if (rc != JNI_TRUE) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}
