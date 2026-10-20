DEBUG = 0
FINALPACKAGE = 1
ARCHS = arm64
PACKAGE_VERSION = 0.2.2
TARGET := iphone:clang:16.5:13.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = YTLiteUnlock
$(TWEAK_NAME)_FRAMEWORKS = UIKit Foundation Security
$(TWEAK_NAME)_LDFLAGS = -lsubstrate
$(TWEAK_NAME)_CFLAGS = -fobjc-arc
$(TWEAK_NAME)_FILES = Tweak.x

include $(THEOS_MAKE_PATH)/tweak.mk
