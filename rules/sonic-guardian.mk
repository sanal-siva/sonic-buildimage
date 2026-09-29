# SONiC Guardian Build Rules
# Integrates SONiC Guardian module into sonic-buildimage build system

SONIC_GUARDIAN_VERSION = 1.0.0
SONIC_GUARDIAN_DEBS = sonic-guardian

# Build flags
SONIC_GUARDIAN_DEPENDS = python3 python3-pip grype

# Package target
SONIC_GUARDIAN_DEBIAN_PACKAGE = $(SONIC_GUARDIAN_MODULE)_$(SONIC_GUARDIAN_VERSION)_all.deb

# Conditional inclusion based on build flag
ifeq ($(INCLUDE_SONIC_GUARDIAN), y)
    $(info SONiC Guardian: ENABLED)
    SONIC_MODULES += sonic-guardian
    SONIC_PACKAGES += $(SONIC_GUARDIAN_DEBS)
    SONIC_DAEMON_PACKAGES += sonic-guardian
else
    $(info SONiC Guardian: disabled (use INCLUDE_SONIC_GUARDIAN=y to enable))
endif

# Build dependency
sonic-guardian-debs: $(SONIC_GUARDIAN_DEBIAN_PACKAGE)

$(SONIC_GUARDIAN_DEBIAN_PACKAGE):
	@echo "Building SONiC Guardian module..."
	make -C src/sonic-guardian sonic-guardian
	@echo "SONiC Guardian build complete"

# Clean dependency
sonic-guardian-clean:
	make -C src/sonic-guardian clean

.PHONY: sonic-guardian-debs sonic-guardian-clean
