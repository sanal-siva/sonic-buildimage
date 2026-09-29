"""Package remediation engine with intelligent dependency sequencing"""

import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime

from guardian.models import Package, PackageType, RemediationAction
from guardian.exceptions import RemediationError
from guardian.logging import setup_logging

logger = setup_logging(__name__)


class RemediationEngine:
    """Handles package updates with type-specific procedures"""

    def __init__(self):
        """Initialize remediation engine"""
        self.package_type_map = {
            "linux-image": PackageType.LINUX_KERNEL,
            "linux-headers": PackageType.LINUX_KERNEL,
            "frr": PackageType.FRR,
            "openssl": PackageType.OPENSSL,
        }

    def identify_package_type(self, package_name: str) -> PackageType:
        """Identify package type for special handling

        Args:
            package_name: Name of package

        Returns:
            PackageType enum value
        """
        for key, pkg_type in self.package_type_map.items():
            if key in package_name.lower():
                return pkg_type
        return PackageType.STANDARD

    def detect_dependencies(self, package_name: str) -> List[str]:
        """Detect package dependencies via apt

        Args:
            package_name: Package to analyze

        Returns:
            List of dependent package names
        """
        try:
            result = subprocess.run(
                ["apt-cache", "depends", "--recurse", "--no-recommends", package_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                dependencies = []
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line and not line.startswith(package_name):
                        dependencies.append(line)
                logger.debug(f"Dependencies for {package_name}: {dependencies}")
                return dependencies
        except Exception as e:
            logger.warning(f"Failed to detect dependencies: {e}")
        return []

    def sequence_remediations(
        self, packages: List[str]
    ) -> List[str]:
        """Order packages for remediation based on dependency graph

        Args:
            packages: List of package names to remediate

        Returns:
            Ordered list respecting kernel → services → standard hierarchy
        """
        kernel_packages = []
        service_packages = []
        standard_packages = []

        for pkg in packages:
            pkg_type = self.identify_package_type(pkg)
            if pkg_type == PackageType.LINUX_KERNEL:
                kernel_packages.append(pkg)
            elif pkg_type in [PackageType.FRR, PackageType.OPENSSL]:
                service_packages.append(pkg)
            else:
                standard_packages.append(pkg)

        return kernel_packages + service_packages + standard_packages

    def download_package(self, package_name: str) -> bool:
        """Download package from repository

        Args:
            package_name: Package to download

        Returns:
            True if successful
        """
        try:
            logger.info(f"Downloading {package_name}")
            result = subprocess.run(
                ["apt-get", "install", "--download-only", "-y", package_name],
                capture_output=True,
                timeout=300,
            )
            if result.returncode == 0:
                logger.info(f"Downloaded {package_name}")
                return True
            else:
                logger.error(f"Download failed: {result.stderr.decode()}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"Download timeout for {package_name}")
            return False
        except Exception as e:
            logger.error(f"Download error: {e}")
            return False

    def install_package(self, package_name: str) -> bool:
        """Install package with type-specific procedure

        Args:
            package_name: Package to install

        Returns:
            True if successful
        """
        pkg_type = self.identify_package_type(package_name)

        try:
            logger.info(f"Installing {package_name} (type: {pkg_type.value})")

            # Standard apt install
            result = subprocess.run(
                ["apt-get", "install", "-y", package_name],
                capture_output=True,
                timeout=600,
            )

            if result.returncode != 0:
                logger.error(f"Installation failed: {result.stderr.decode()}")
                return False

            # Type-specific post-install procedures
            if pkg_type == PackageType.LINUX_KERNEL:
                return self._post_kernel_install()
            elif pkg_type == PackageType.FRR:
                return self._post_frr_install()
            elif pkg_type == PackageType.OPENSSL:
                return self._post_openssl_install()

            logger.info(f"Installed {package_name}")
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"Installation timeout for {package_name}")
            return False
        except Exception as e:
            logger.error(f"Installation error: {e}")
            return False

    def _post_kernel_install(self) -> bool:
        """Post-install for Linux kernel"""
        try:
            logger.info("Configuring GRUB for kernel...")
            subprocess.run(["update-grub"], capture_output=True, timeout=30)
            logger.info("Kernel installation complete - reboot required")
            return True
        except Exception as e:
            logger.error(f"Kernel post-install failed: {e}")
            return False

    def _post_frr_install(self) -> bool:
        """Post-install for FRR"""
        try:
            logger.info("Restarting FRR daemon...")
            subprocess.run(["systemctl", "restart", "frr"], capture_output=True, timeout=30)
            logger.info("FRR restarted successfully")
            return True
        except Exception as e:
            logger.error(f"FRR post-install failed: {e}")
            return False

    def _post_openssl_install(self) -> bool:
        """Post-install for OpenSSL"""
        try:
            logger.info("Restarting services dependent on OpenSSL...")
            # Restart commonly affected services
            services = ["sshd", "telemetry", "snmpd"]
            for service in services:
                try:
                    subprocess.run(
                        ["systemctl", "restart", service],
                        capture_output=True,
                        timeout=10,
                    )
                except Exception as e:
                    logger.warning(f"Failed to restart {service}: {e}")
            logger.info("OpenSSL installation complete")
            return True
        except Exception as e:
            logger.error(f"OpenSSL post-install failed: {e}")
            return False
