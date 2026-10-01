# Optional lightweight host collector. Vulnerability scanners run centrally.
SONIC_GUARDIAN_VERSION = 2.0.0-4
SONIC_GUARDIAN = sonic-guardian_$(SONIC_GUARDIAN_VERSION)_all.deb
$(SONIC_GUARDIAN)_SRC_PATH = $(SRC_PATH)/sonic-guardian
$(SONIC_GUARDIAN)_VERSION = $(SONIC_GUARDIAN_VERSION)
$(SONIC_GUARDIAN)_NAME = sonic-guardian
ifeq ($(INCLUDE_SONIC_GUARDIAN),y)
SONIC_DPKG_DEBS += $(SONIC_GUARDIAN)
SONIC_INSTALLER_EXTRA_DEBS += $(SONIC_GUARDIAN)
endif
