# Build static Java library
YPERWAVE_DIR := $(call my-dir)

# Build ymagine java library
LOCAL_PATH := $(YPERWAVE_DIR)
include $(CLEAR_VARS)

# Build all java files in the java subdirectory
LOCAL_SRC_FILES := $(call all-java-files-under, src)

# Any libraries that this library depends on
# LOCAL_JAVA_LIBRARIES := com.yahoo.mobile.client.android.yapps

# The name of the jar file to create
LOCAL_MODULE := com.yahoo.mobile.client.android.yperwave

# Build a static jar file.
include $(BUILD_STATIC_JAVA_LIBRARY)

# Build shared library
include $(YPERWAVE_DIR)/jni/Android.mk

ifeq ($(BUILD_SUPPORT_EXECUTABLE),true)
include $(call first-makefiles-under,$(YPERWAVE_DIR)/tests)
endif
