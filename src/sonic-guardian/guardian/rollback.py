"""Rollback mechanism for failed remediations"""

import subprocess
from typing import Dict, Any, Optional
from datetime import datetime

from guardian.validation import ValidationEngine
from guardian.exceptions import RollbackError
from guardian.logging import setup_logging

logger = setup_logging(__name__)


class RollbackEngine:
    """Handles automatic rollback of failed remediations"""

    def __init__(self):
        """Initialize rollback engine"""
        self.validation = ValidationEngine()

    def trigger_rollback(
        self, package_name: str, previous_version: str
    ) -> bool:
        """Execute rollback to previous package version

        Args:
            package_name: Package to rollback
            previous_version: Target version to restore

        Returns:
            True if rollback successful
        """
        try:
            logger.warning(f"Triggering rollback for {package_name} to {previous_version}")

            # Downgrade to previous version
            if not self._downgrade_package(package_name, previous_version):
                logger.error(f"Failed to downgrade {package_name}")
                return False

            # Re-validate system health
            logger.info("Re-validating system health after rollback...")
            all_passed, results = self.validation.run_health_checks()

            if all_passed:
                logger.info("Rollback successful - system health restored")
                return True
            else:
                failed_checks = [r.check_type for r in results if r.status != "PASS"]
                logger.error(f"Rollback completed but health checks failed: {failed_checks}")
                return False
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            raise RollbackError(f"Rollback execution failed: {e}")

    def _downgrade_package(self, package_name: str, target_version: str) -> bool:
        """Downgrade package to previous version

        Args:
            package_name: Package to downgrade
            target_version: Version to restore

        Returns:
            True if successful
        """
        try:
            logger.info(f"Downgrading {package_name} to {target_version}")

            result = subprocess.run(
                ["apt-get", "install", "-y", f"{package_name}={target_version}"],
                capture_output=True,
                timeout=600,
            )

            if result.returncode == 0:
                logger.info(f"Successfully downgraded {package_name}")
                return True
            else:
                logger.error(f"Downgrade failed: {result.stderr.decode()}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(f"Downgrade timeout for {package_name}")
            return False
        except Exception as e:
            logger.error(f"Downgrade error: {e}")
            return False

    def store_rollback_artifacts(
        self, package_name: str, version: str, remediation_id: str
    ) -> Dict[str, Any]:
        """Store information needed for rollback

        Args:
            package_name: Package name
            version: Current version before update
            remediation_id: Remediation action ID

        Returns:
            Rollback artifact metadata
        """
        artifacts = {
            "package_name": package_name,
            "original_version": version,
            "remediation_id": remediation_id,
            "rollback_timestamp": datetime.utcnow().isoformat() + "Z",
        }

        logger.debug(f"Storing rollback artifacts: {artifacts}")
        return artifacts
