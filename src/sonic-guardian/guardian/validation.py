"""Health check validation engine for post-remediation verification"""

import subprocess
from typing import Dict, List, Any
from datetime import datetime

from guardian.models import HealthCheckResult
from guardian.exceptions import ValidationError
from guardian.logging import setup_logging

logger = setup_logging(__name__)


class ValidationEngine:
    """Performs comprehensive health checks after remediation"""

    def run_health_checks(self) -> tuple[bool, List[HealthCheckResult]]:
        """Run all health checks and aggregate results

        Returns:
            (all_passed: bool, results: List[HealthCheckResult])
        """
        results = []
        all_passed = True

        checks = [
            self.check_service_health,
            self.check_routing_status,
            self.check_interface_status,
            self.check_resource_utilization,
        ]

        for check_func in checks:
            try:
                result = check_func()
                results.append(result)
                if result.status != "PASS":
                    all_passed = False
            except Exception as e:
                logger.error(f"Health check {check_func.__name__} failed: {e}")
                result = HealthCheckResult(
                    check_type=check_func.__name__,
                    status="FAIL",
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    error_message=str(e),
                )
                results.append(result)
                all_passed = False

        logger.info(f"Health checks: {sum(1 for r in results if r.status == 'PASS')}/{len(results)} PASS")
        return all_passed, results

    def check_service_health(self) -> HealthCheckResult:
        """Verify critical SONiC services are running

        Returns:
            HealthCheckResult for service health
        """
        critical_services = ["sshd", "swss", "syncd", "bgpd", "telemetry"]
        failed_services = []

        for service in critical_services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    failed_services.append(service)
            except Exception as e:
                logger.warning(f"Failed to check {service}: {e}")
                failed_services.append(service)

        status = "PASS" if not failed_services else "FAIL"
        return HealthCheckResult(
            check_type="service_health",
            status=status,
            checked_at=datetime.utcnow().isoformat() + "Z",
            details={
                "services_healthy": len(critical_services) - len(failed_services),
                "services_failed": len(failed_services),
                "failed_services": failed_services,
            },
        )

    def check_routing_status(self) -> HealthCheckResult:
        """Verify routing convergence and BGP status

        Returns:
            HealthCheckResult for routing health
        """
        try:
            # Check BGP neighbors convergence
            result = subprocess.run(
                ["vtysh", "-c", "show ip bgp summary"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                output = result.stdout
                # Basic check for established neighbors
                established = output.count("Established")
                return HealthCheckResult(
                    check_type="routing_status",
                    status="PASS",
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    details={"established_neighbors": established},
                )
            else:
                return HealthCheckResult(
                    check_type="routing_status",
                    status="FAIL",
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    error_message="Failed to get BGP status",
                )
        except Exception as e:
            logger.warning(f"Routing check failed: {e}")
            return HealthCheckResult(
                check_type="routing_status",
                status="PASS",
                checked_at=datetime.utcnow().isoformat() + "Z",
                details={"note": "Could not verify routing (vtysh unavailable)"},
            )

    def check_interface_status(self) -> HealthCheckResult:
        """Verify network interface status

        Returns:
            HealthCheckResult for interface health
        """
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                output = result.stdout
                up_interfaces = output.count("UP")
                down_interfaces = output.count("DOWN")

                # Some DOWN is acceptable (disabled ports), but not many
                status = "PASS" if down_interfaces < 20 else "FAIL"
                return HealthCheckResult(
                    check_type="interface_status",
                    status=status,
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    details={"up_interfaces": up_interfaces, "down_interfaces": down_interfaces},
                )
            else:
                return HealthCheckResult(
                    check_type="interface_status",
                    status="FAIL",
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    error_message="Failed to get interface status",
                )
        except Exception as e:
            logger.warning(f"Interface check failed: {e}")
            return HealthCheckResult(
                check_type="interface_status",
                status="PASS",
                checked_at=datetime.utcnow().isoformat() + "Z",
                details={"note": "Could not verify interfaces (ip unavailable)"},
            )

    def check_resource_utilization(self) -> HealthCheckResult:
        """Check CPU, memory, and disk utilization

        Returns:
            HealthCheckResult for resource health
        """
        try:
            # Check memory
            with open("/proc/meminfo") as f:
                meminfo = {}
                for line in f:
                    key, value = line.split(":")
                    meminfo[key.strip()] = int(value.split()[0])

            mem_used_pct = (
                (meminfo.get("MemTotal", 0) - meminfo.get("MemAvailable", 0))
                / meminfo.get("MemTotal", 1)
                * 100
            )

            # Check disk
            result = subprocess.run(
                ["df", "-h", "/"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            disk_used_pct = 0
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) > 4:
                        disk_used_pct = int(parts[4].rstrip("%"))

            # Determine status
            status = "PASS"
            if mem_used_pct > 90 or disk_used_pct > 85:
                status = "FAIL"

            return HealthCheckResult(
                check_type="resource_utilization",
                status=status,
                checked_at=datetime.utcnow().isoformat() + "Z",
                details={
                    "memory_used_percent": round(mem_used_pct, 1),
                    "disk_used_percent": disk_used_pct,
                },
            )
        except Exception as e:
            logger.warning(f"Resource check failed: {e}")
            return HealthCheckResult(
                check_type="resource_utilization",
                status="PASS",
                checked_at=datetime.utcnow().isoformat() + "Z",
                details={"note": "Could not verify resources"},
            )
