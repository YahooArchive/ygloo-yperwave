LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

include $(LOCAL_PATH)/../../../build/config/config.mk

ifeq ($(YPERWAVE_BUILD_SHARED),)
YPERWAVE_BUILD_SHARED:=true
ifeq ($(BUILD_HOST),true)
YPERWAVE_BUILD_SHARED:=false
endif
ifeq ($(BUILD_IOS),true)
YPERWAVE_BUILD_SHARED:=false
endif
endif

# Set to true to build a debuggable shared library
YPERWAVE_DEBUG_BUILD:=false
# Set to true to enable verbose logs
YPERWAVE_DEBUG_LOG:=false

ifneq ($(NDK_DEBUG),)
ifneq ($(NDK_DEBUG),0)
YPERWAVE_DEBUG_BUILD:=true
YPERWAVE_DEBUG_LOG:=true
endif
endif

ifneq ($(NDK_ROOT),)
# Native SDK dependencies
include $(YOSAL_ROOT)/Android.mk
##### Build 3rdparties static libraries
include $(ZLIB_ROOT)/Android.mk
ifeq ($(YCONFIG_OPTION_SSL),axtls)
include $(AXTLS_ROOT)/Android.mk
endif
ifeq ($(YCONFIG_OPTION_SSL),openssl)
include $(OPENSSL_ROOT)/Android.mk
endif
#include $(CARES_ROOT)/Android.mk
include $(CURL_ROOT)/Android.mk
include $(JANSSON_ROOT)/Android.mk
endif

YPERWAVE_MAIN_C_INCLUDES :=
YPERWAVE_MAIN_SRC_FILES :=
YPERWAVE_MAIN_CFLAGS :=
YPERWAVE_MAIN_LDFLAGS :=
YPERWAVE_MAIN_STATIC_LIBRARIES :=
YPERWAVE_MAIN_SHARED_LIBRARIES :=

ifeq ($(YPERWAVE_DEBUG_LOG),true)
YPERWAVE_MAIN_CFLAGS += -DYPERWAVE_DEBUG=1
endif

YPERWAVE_MAIN_CFLAGS += -Wall -Werror

ifeq ($(YCONFIG_OPTION_SSL),openssl)
# Introduced for OpenSSL's support for SSL false start.
YPERWAVE_MAIN_CFLAGS += -DUSE_OPENSSL=1
endif

YPERWAVE_MAIN_SRC_FILES += src/auth/oauth.c
YPERWAVE_MAIN_SRC_FILES += src/auth/yauth.c
YPERWAVE_MAIN_SRC_FILES += src/net/httpcache.c
YPERWAVE_MAIN_SRC_FILES += src/net/httppool.c
YPERWAVE_MAIN_SRC_FILES += src/net/httppoollooper.c
YPERWAVE_MAIN_SRC_FILES += src/net/httprequest.c
YPERWAVE_MAIN_SRC_FILES += src/net/httprequest_json.c
YPERWAVE_MAIN_SRC_FILES += src/net/httpsettings.c
YPERWAVE_MAIN_SRC_FILES += src/net/httputils.c
YPERWAVE_MAIN_SRC_FILES += src/utils/urlparams.c

# JNI wrapper 
# YPERWAVE_MAIN_SRC_FILES += src/java/netapi.c

# Public API
YPERWAVE_MAIN_C_INCLUDES += $(YPERWAVE_ROOT)/jni/include
# Private API
YPERWAVE_MAIN_C_INCLUDES += $(YPERWAVE_ROOT)/jni/src/include
YPERWAVE_MAIN_C_INCLUDES += $(YPERWAVE_ROOT)/jni/src

#YPERWAVE_MAIN_C_INCLUDES += $(CARES_ROOT)
#YPERWAVE_MAIN_STATIC_LIBRARIES += libyahoo_cares

ifeq ($(YCONFIG_OPTION_SSL),axtls)
YPERWAVE_MAIN_C_INCLUDES += $(AXTLS_ROOT)/include
endif
ifeq ($(YCONFIG_OPTION_SSL),openssl)
YPERWAVE_MAIN_C_INCLUDES += $(OPENSSL_ROOT)/include
endif
YPERWAVE_MAIN_C_INCLUDES += $(CURL_ROOT)/include
YPERWAVE_MAIN_C_INCLUDES += $(JANSSON_ROOT)/src
YPERWAVE_MAIN_C_INCLUDES += $(JANSSON_ROOT)/android
YPERWAVE_MAIN_C_INCLUDES += $(ZLIB_ROOT)

YPERWAVE_MAIN_C_INCLUDES += $(YOSAL_ROOT)/include

YPERWAVE_MAIN_STATIC_LIBRARIES := $(YPERWAVE_STATIC_LIBRARIES)

LOCAL_PATH:=$(YPERWAVE_ROOT)/jni
include $(CLEAR_VARS)

ifeq ($(YPERWAVE_DEBUG_BUILD),true)
LOCAL_CFLAGS += -DDEBUG -UNDEBUG -O0 -g
else
LOCAL_CFLAGS += -Os
LOCAL_CFLAGS += -fstrict-aliasing
# LOCAL_CFLAGS += -fprefetch-loop-arrays
endif

LOCAL_MODULE := libyahoo_yperwave_main
LOCAL_MODULE_TAGS := optional

LOCAL_C_INCLUDES := $(YPERWAVE_MAIN_C_INCLUDES)
LOCAL_SRC_FILES := $(YPERWAVE_MAIN_SRC_FILES)
LOCAL_CFLAGS := $(YPERWAVE_MAIN_CFLAGS)
LOCAL_LDFLAGS := $(YPERWAVE_MAIN_LDFLAGS)

include $(BUILD_STATIC_LIBRARY)

#### Build shared library (Android only)
ifeq ($(YPERWAVE_BUILD_SHARED),true)

LOCAL_PATH:=$(YPERWAVE_ROOT)/jni
include $(CLEAR_VARS)


LOCAL_C_INCLUDES := $(YPERWAVE_MAIN_C_INCLUDES)
LOCAL_SRC_FILES := $(YPERWAVE_MAIN_SRC_FILES)
LOCAL_CFLAGS := $(YPERWAVE_MAIN_CFLAGS)
LOCAL_LDFLAGS := $(YPERWAVE_MAIN_LDFLAGS)
LOCAL_STATIC_LIBRARIES := $(YPERWAVE_MAIN_STATIC_LIBRARIES)
LOCAL_SHARED_LIBRARIES := $(YPERWAVE_MAIN_SHARED_LIBRARIES)

ifeq ($(YPERWAVE_DEBUG_BUILD),true)
LOCAL_CFLAGS += -DDEBUG -UNDEBUG -O0 -g
else
LOCAL_CFLAGS += -Os
LOCAL_CFLAGS += -fstrict-aliasing
# LOCAL_CFLAGS += -fprefetch-loop-arrays
endif

LOCAL_LDLIBS += -llog

ifeq ($(NDK_ROOT),)
LOCAL_SHARED_LIBRARIES  += libcutils libutils
endif

LOCAL_MODULE := libyahoo_yperwave
LOCAL_MODULE_TAGS := optional

# If building with AOSP tree before ICS (NoOp for NDK build)
LOCAL_PRELINK_MODULE:=false

include $(BUILD_SHARED_LIBRARY)

# $(call import-module,android/cpufeatures)
endif
