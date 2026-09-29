# SONiC Guardian Module Makefile
# Build and package SONiC Guardian for sonic-buildimage

.PHONY: clean sonic-guardian

SONIC_GUARDIAN_VERSION = 1.0.0
SONIC_GUARDIAN_MODULE = sonic-guardian

# Build target
sonic-guardian:
	@echo "Building SONiC Guardian v$(SONIC_GUARDIAN_VERSION)..."
	cd $(SONIC_GUARDIAN_MODULE) && \
	dpkg-buildpackage -us -uc -b && \
	echo "Build complete"

# Verify build
verify-build:
	@if [ -f ../$(SONIC_GUARDIAN_MODULE)_$(SONIC_GUARDIAN_VERSION)_all.deb ]; then \
		echo "✓ SONiC Guardian package built successfully"; \
		dpkg -c ../$(SONIC_GUARDIAN_MODULE)_$(SONIC_GUARDIAN_VERSION)_all.deb | head -20; \
	else \
		echo "✗ Build failed - package not found"; \
		exit 1; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning SONiC Guardian build artifacts..."
	cd $(SONIC_GUARDIAN_MODULE) && \
	rm -rf build/ dist/ *.egg-info/ && \
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
	find . -type f -name "*.pyc" -delete && \
	rm -f ../$(SONIC_GUARDIAN_MODULE)_*.deb && \
	rm -f ../$(SONIC_GUARDIAN_MODULE)_*.build && \
	rm -f ../$(SONIC_GUARDIAN_MODULE)_*.changes && \
	echo "Clean complete"

# Install locally (for testing)
install-local:
	@echo "Installing SONiC Guardian locally..."
	sudo dpkg -i ../$(SONIC_GUARDIAN_MODULE)_$(SONIC_GUARDIAN_VERSION)_all.deb
	@echo "Installation complete. Start daemon with:"
	@echo "  sudo systemctl start sonic-guardian"
	@echo "  sudo systemctl enable sonic-guardian"

# Show version
version:
	@echo "SONiC Guardian v$(SONIC_GUARDIAN_VERSION)"
