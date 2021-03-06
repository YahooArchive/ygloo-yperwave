YPERWAVE_JNI:=$(call my-dir)

# Features
YPERWAVE_CONFIG_JSON:=true

# SSL implementation to use (axtls or openssl)
YPERWAVE_CONFIG_SSL:=axtls

# Code layout
YPERWAVE_ROOT:=$(YPERWAVE_JNI)/..
YPERWAVE_3RDPARTIES:=$(YPERWAVE_ROOT)/../../external

# Local mirrors of 3rd parties modules
ZLIB_ROOT:=$(YPERWAVE_3RDPARTIES)/zlib
LZF_ROOT:=$(YPERWAVE_3RDPARTIES)/lzf
CARES_ROOT:=$(YPERWAVE_3RDPARTIES)/c-ares
AXTLS_ROOT:=$(YPERWAVE_3RDPARTIES)/axtls
OPENSSL_ROOT:=$(YPERWAVE_3RDPARTIES)/openssl
CURL_ROOT:=$(YPERWAVE_3RDPARTIES)/curl
JANSSON_ROOT:=$(YPERWAVE_3RDPARTIES)/jansson

# Core layout
YOSAL_ROOT:=$(YPERWAVE_ROOT)/../yosal

