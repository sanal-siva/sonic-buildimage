"""SONiC Guardian daemon entry point with autonomous remediation"""

import sys
import time
from datetime import datetime, timedelta

from guardian.config import ConfigManager
from guardian.metadata import MetadataManager
from guardian.scanner import VulnerabilityScanner
from guardian.intelligence import IntelligenceServiceClient
from guardian.remediation import RemediationEngine
from guardian.validation import ValidationEngine
from guardian.rollback import RollbackEngine
from guardian.logging import setup_logging

logger = setup_logging(__name__)

SCAN_INTERVAL = 3600  # 1 hour
REMEDIATION_CHECK_INTERVAL = 300  # 5 minutes


class GuardianDaemon:
    """SONiC Guardian daemon service"""

    def __init__(self):
        self.config_mgr = ConfigManager()
        self.metadata_mgr = MetadataManager()
        self.last_scan = None

    def run(self) -> int:
        """Main daemon event loop"""
        logger.info("SONiC Guardian daemon starting")

        try:
            logger.info("SONiC Guardian daemon started successfully")

            while True:
                try:
                    if not self.config_mgr.get_service_enabled():
                        time.sleep(60)
                        continue

                    if self._should_scan():
                        self._run_scan()

                    mode = self.config_mgr.get_operating_mode()
                    if mode == "autonomous":
                        self._check_autonomous_remediation()

                    time.sleep(REMEDIATION_CHECK_INTERVAL)
                except Exception as e:
                    logger.error(f"Daemon error: {e}")
                    time.sleep(60)

        except KeyboardInterrupt:
            logger.info("SONiC Guardian daemon shutting down")
        except Exception as e:
            logger.error(f"SONiC Guardian daemon fatal error: {e}")
            return 1

        logger.info("SONiC Guardian daemon stopped")
        return 0

    def _should_scan(self) -> bool:
        metadata = self.metadata_mgr.load()
        last_scan = metadata["scan_history"][-1] if metadata.get("scan_history") else None
        if not last_scan:
            return True
        last_scan_time = datetime.fromisoformat(
            last_scan.get("timestamp", "").replace("Z", "+00:00")
        )
        return datetime.utcnow() - last_scan_time > timedelta(seconds=SCAN_INTERVAL)

    def _run_scan(self) -> None:
        try:
            logger.info("Starting periodic vulnerability scan")
            sbom_source = self.config_mgr.get_sbom_source()
            scanner = VulnerabilityScanner(sbom_source, self.metadata_mgr)
            scanner.load_sbom()
            vulnerabilities = scanner.scan_packages()
            new_vulns, all_vulns = scanner.deduplicate_vulnerabilities(vulnerabilities)
            scan_result = {
                "cve_count": len(all_vulns),
                "new_cves": len(new_vulns),
                "severity_breakdown": {
                    "CRITICAL": sum(1 for v in all_vulns if v.severity.value == "CRITICAL"),
                    "HIGH": sum(1 for v in all_vulns if v.severity.value == "HIGH"),
                    "MEDIUM": sum(1 for v in all_vulns if v.severity.value == "MEDIUM"),
                    "LOW": sum(1 for v in all_vulns if v.severity.value == "LOW"),
                },
                "vulnerabilities": [v.to_dict() for v in all_vulns],
            }
            self.metadata_mgr.add_scan_result(scan_result)
            logger.info(f"Scan complete: {scan_result['cve_count']} CVEs")
            self.last_scan = scan_result
        except Exception as e:
            logger.error(f"Scan failed: {e}")

    def _check_autonomous_remediation(self) -> None:
        if not self.last_scan:
            return
        try:
            service_url = self.config_mgr.get_service_url()
            auth_token = self.config_mgr.get_auth_token()
            if not service_url or not auth_token:
                return
            client = IntelligenceServiceClient(service_url, auth_token)
            vulns = self.last_scan.get("vulnerabilities", [])
            recommendations = client.assess_vulnerabilities(vulns, "unknown")
            auto_heal_packages = set()
            for rec in recommendations:
                if rec.action_type == "auto_heal" and rec.confidence >= 0.8:
                    auto_heal_packages.add(rec.package_name)
            if auto_heal_packages:
                logger.info(f"Auto-healing {len(auto_heal_packages)} packages")
                self._remediate_packages(list(auto_heal_packages))
        except Exception as e:
            logger.debug(f"Autonomous remediation check failed: {e}")

    def _remediate_packages(self, packages: list) -> None:
        remediation_engine = RemediationEngine()
        validation_engine = ValidationEngine()
        rollback_engine = RollbackEngine()
        ordered_packages = remediation_engine.sequence_remediations(packages)
        for package in ordered_packages:
            try:
                logger.info(f"Auto-remediating {package}")
                if not remediation_engine.download_package(package):
                    continue
                if not remediation_engine.install_package(package):
                    continue
                all_passed, results = validation_engine.run_health_checks()
                if not all_passed:
                    logger.warning(f"Validation failed after {package}, rolling back")
                    rollback_engine.trigger_rollback(package, "previous")
                    continue
                logger.info(f"Successfully auto-remediated {package}")
                action = {
                    "package_name": package,
                    "initiated_by": "autonomous",
                    "status": "completed",
                }
                self.metadata_mgr.add_remediation_action(action)
            except Exception as e:
                logger.error(f"Failed to remediate {package}: {e}")


def main():
    """Main daemon entry point"""
    daemon = GuardianDaemon()
    return daemon.run()


if __name__ == "__main__":
    sys.exit(main())
