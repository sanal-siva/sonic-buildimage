"""SONiC Guardian - Self-Healing Security Framework

A framework for continuous vulnerability discovery, intelligent risk assessment,
and autonomous remediation in SONiC network operating systems.
"""

__version__ = "1.0.0"
__author__ = "SONiC Contributors"
__license__ = "Apache 2.0"

from guardian.models import (
    SBOM,
    Package,
    PackageType,
    Vulnerability,
    VEXRecord,
    Recommendation,
    RemediationAction,
    HealthCheckResult,
    OperatingMode,
)

__all__ = [
    "SBOM",
    "Package",
    "PackageType",
    "Vulnerability",
    "VEXRecord",
    "Recommendation",
    "RemediationAction",
    "HealthCheckResult",
    "OperatingMode",
]
