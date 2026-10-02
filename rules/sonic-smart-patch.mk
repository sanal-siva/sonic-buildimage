# Optional lightweight host collector. Vulnerability scanners run centrally.
SONIC_SMART_PATCH_VERSION = 3.1.1-1
SONIC_SMART_PATCH = sonic-smart-patch_$(SONIC_SMART_PATCH_VERSION)_all.deb
$(SONIC_SMART_PATCH)_SRC_PATH = $(SRC_PATH)/sonic-smart-patch
$(SONIC_SMART_PATCH)_VERSION = $(SONIC_SMART_PATCH_VERSION)
$(SONIC_SMART_PATCH)_NAME = sonic-smart-patch
ifeq ($(INCLUDE_SONIC_SMART_PATCH),y)
SONIC_DPKG_DEBS += $(SONIC_SMART_PATCH)
SONIC_INSTALLER_EXTRA_DEBS += $(SONIC_SMART_PATCH)
endif
