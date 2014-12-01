YPERWAVE_TEST_ROOT := $(call my-dir)

###########################################
LOCAL_PATH:=$(YPERWAVE_TEST_ROOT)
include $(CLEAR_VARS)

include $(LOCAL_PATH)/../../../../../build/config/config.mk

LOCAL_CFLAGS += -Wall -Werror

LOCAL_C_INCLUDES += $(YPERWAVE_ROOT)/jni/include
LOCAL_C_INCLUDES += $(YOSAL_ROOT)/include

LOCAL_C_INCLUDES += $(YPERWAVE_ROOT)/jni/src/include
LOCAL_C_INCLUDES += $(YPERWAVE_ROOT)/jni/src

LOCAL_C_INCLUDES += $(JANSSON_ROOT)/src
LOCAL_C_INCLUDES += $(JANSSON_ROOT)/android

LOCAL_C_INCLUDES += $(CURL_ROOT)/include

LOCAL_SRC_FILES += test-yperwave.c

# LOCAL_STATIC_LIBRARIES += cpufeatures

LOCAL_STATIC_LIBRARIES := $(YPERWAVE_STATIC_LIBRARIES)

ifeq ($(BUILD_ANDROID),true)
LOCAL_LDLIBS += -llog
endif

# LOCAL_STATIC_LIBRARIES += cpufeatures
ifeq ($(NDK_ROOT),)
LOCAL_SHARED_LIBRARIES  += libcutils libutils
endif

LOCAL_MODULE := yperwave
LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)
