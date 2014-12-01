# Helper makefile to build iOS library for all architectures
YPERWAVE_IOS_DIR:=$(shell pwd)
YPERWAVE_DIR:=$(YPERWAVE_IOS_DIR)/..
BUILDCONFIG_DIR:=$(YPERWAVE_DIR)/../..

all: libs/libyahoo_yperwave.a

libs/libyahoo_yperwave.a: $(BUILDCONFIG_DIR)/out/target/ios/libyahoo_yperwave.a
	@mkdir -p libs
	cp -f $< $@


$(BUILDCONFIG_DIR)/out/target/ios/libyahoo_yperwave.a:
	make -C $(BUILDCONFIG_DIR) all ios TARGET_ARCH=armv7
	make -C $(BUILDCONFIG_DIR) all ios TARGET_ARCH=armv7s
	make -C $(BUILDCONFIG_DIR) all ios TARGET_ARCH=i386
	make -C $(BUILDCONFIG_DIR) ios combo
