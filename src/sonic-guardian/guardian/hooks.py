"""apt/dpkg hook handlers for real-time package change tracking"""

import sys
import os
from typing import Optional
from datetime import datetime

from guardian.metadata import MetadataManager
from guardian.remediation import RemediationEngine
from guardian.logging import setup_logging

logger = setup_logging(__name__)


class DPKGHookHandler:
    """Handles dpkg hooks for package change events"""

    def __init__(self):
        """Initialize hook handler"""
        self.metadata_mgr = MetadataManager()
        self.remediation_engine = RemediationEngine()

    def process_pre_install(self, package_name: str, package_version: str) -> None:
        """Handle pre-install hook

        Args:
            package_name: Package being installed
            package_version: Package version
        """
        try:
            logger.info(f"Pre-install hook: {package_name}={package_version}")
            # Can be used for pre-install validation if needed
        except Exception as e:
            logger.error(f"Pre-install hook failed: {e}")

    def process_post_install(self, package_name: str, package_version: str) -> None:
        """Handle post-install hook - updates delta metadata file

        Args:
            package_name: Package that was installed
            package_version: Installed package version
        """
        try:
            logger.info(f"Post-install hook: {package_name}={package_version}")

            # Identify package type
            pkg_type = self.remediation_engine.identify_package_type(package_name)

            # Update metadata delta file
            self.metadata_mgr.update_inventory(package_name, package_version, pkg_type.value)

            logger.debug(f"Updated delta metadata for {package_name}")
        except Exception as e:
            logger.error(f"Post-install hook failed: {e}")

    def process_pre_remove(self, package_name: str) -> None:
        """Handle pre-remove hook

        Args:
            package_name: Package being removed
        """
        try:
            logger.info(f"Pre-remove hook: {package_name}")
            # Can be used for pre-removal checks if needed
        except Exception as e:
            logger.error(f"Pre-remove hook failed: {e}")

    def process_post_remove(self, package_name: str) -> None:
        """Handle post-remove hook - updates delta metadata file

        Args:
            package_name: Package that was removed
        """
        try:
            logger.info(f"Post-remove hook: {package_name}")

            # Mark package as removed in delta metadata
            metadata = self.metadata_mgr.load()
            inventory = metadata.get("inventory", [])

            # Remove from inventory
            inventory = [p for p in inventory if p["name"] != package_name]
            metadata["inventory"] = inventory
            metadata["last_updated"] = datetime.utcnow().isoformat() + "Z"

            # Record removal in log
            metadata.setdefault("removal_log", []).append(
                {
                    "package_name": package_name,
                    "removed_at": datetime.utcnow().isoformat() + "Z",
                }
            )

            self.metadata_mgr.save(metadata)
            logger.debug(f"Updated delta metadata for removal: {package_name}")
        except Exception as e:
            logger.error(f"Post-remove hook failed: {e}")

    def process_pre_upgrade(self, package_name: str) -> None:
        """Handle pre-upgrade hook

        Args:
            package_name: Package being upgraded
        """
        try:
            logger.debug(f"Pre-upgrade hook: {package_name}")
        except Exception as e:
            logger.error(f"Pre-upgrade hook failed: {e}")

    def process_post_upgrade(
        self, package_name: str, old_version: str, new_version: str
    ) -> None:
        """Handle post-upgrade hook - updates delta metadata file

        Args:
            package_name: Package that was upgraded
            old_version: Previous version
            new_version: New version
        """
        try:
            logger.info(f"Post-upgrade hook: {package_name} {old_version} -> {new_version}")

            # Identify package type
            pkg_type = self.remediation_engine.identify_package_type(package_name)

            # Update metadata delta file
            metadata = self.metadata_mgr.load()
            inventory = metadata.get("inventory", [])

            # Find and update package entry
            for pkg in inventory:
                if pkg["name"] == package_name:
                    pkg["version"] = new_version
                    pkg["updated_at"] = datetime.utcnow().isoformat() + "Z"
                    pkg["update_history"] = pkg.get("update_history", [])
                    pkg["update_history"].append(
                        {
                            "from_version": old_version,
                            "to_version": new_version,
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                        }
                    )
                    break
            else:
                # Package not in inventory, add it
                inventory.append(
                    {
                        "name": package_name,
                        "version": new_version,
                        "type": pkg_type.value,
                        "installed_at": datetime.utcnow().isoformat() + "Z",
                    }
                )

            metadata["inventory"] = inventory
            metadata["last_updated"] = datetime.utcnow().isoformat() + "Z"
            self.metadata_mgr.save(metadata)

            logger.debug(f"Updated delta metadata for upgrade: {package_name}")
        except Exception as e:
            logger.error(f"Post-upgrade hook failed: {e}")


def main_hook_handler():
    """Main entry point for hook scripts

    Environment variables used:
    - HOOK_ACTION: install, remove, upgrade
    - DPKG_MAINTSCRIPT_NAME: pre or post
    - DPKG_MAINTSCRIPT_PACKAGE: package name
    """
    try:
        action = os.environ.get("HOOK_ACTION", "").lower()
        phase = os.environ.get("DPKG_MAINTSCRIPT_NAME", "").lower()
        package = os.environ.get("DPKG_MAINTSCRIPT_PACKAGE", "unknown")
        version = os.environ.get("DPKG_MAINTSCRIPT_PACKAGE_VERSION", "unknown")

        handler = DPKGHookHandler()

        if phase == "pre" and action == "install":
            handler.process_pre_install(package, version)
        elif phase == "post" and action == "install":
            handler.process_post_install(package, version)
        elif phase == "pre" and action == "remove":
            handler.process_pre_remove(package)
        elif phase == "post" and action == "remove":
            handler.process_post_remove(package)
        elif phase == "pre" and action in ["upgrade", "upgrade-from", "configure"]:
            handler.process_pre_upgrade(package)
        elif phase == "post" and action in ["upgrade", "upgrade-from", "configure"]:
            old_version = os.environ.get("DPKG_MAINTSCRIPT_PACKAGE_OLD_VERSION", "unknown")
            handler.process_post_upgrade(package, old_version, version)

        return 0
    except Exception as e:
        logger.error(f"Hook handler failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main_hook_handler())
