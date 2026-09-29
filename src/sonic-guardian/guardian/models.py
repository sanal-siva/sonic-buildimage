"""Data model classes for SONiC Guardian"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import json


class PackageType(str, Enum):
    """Package type categories for remediation procedures"""

    LINUX_KERNEL = "linux-kernel"
    FRR = "frr"
    OPENSSL = "openssl"
    STANDARD = "standard"


class OperatingMode(str, Enum):
    """Operating modes for SONiC Guardian"""

    ADVISORY = "advisory"
    ASSISTED = "assisted"
    AUTONOMOUS = "autonomous"


class VulnerabilitySeverity(str, Enum):
    """CVE severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SBOM:
    """Software Bill of Materials"""

    format: str
    spec_version: str
    version: int
    components: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SBOM":
        return cls(**data)


@dataclass
class Package:
    """Installed software package"""

    name: str
    version: str
    package_type: PackageType
    install_date: Optional[str] = None
    criticality: str = "medium"
    service_dependencies: List[str] = field(default_factory=list)
    update_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "package_type": self.package_type.value,
        }


@dataclass
class Vulnerability:
    """Discovered vulnerability (CVE)"""

    cve_id: str
    package_name: str
    affected_version: str
    fixed_version: Optional[str]
    severity: VulnerabilitySeverity
    cvss_score: float
    discovered_at: str
    status: str = "open"
    vex_verdict: Optional[str] = None
    remediation_status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "severity": self.severity.value,
        }


@dataclass
class VEXRecord:
    """Vulnerability Exploitability Exchange document"""

    vulnerability_id: str
    package_name: str
    verdict: str
    impact_statement: str
    assessed_at: str
    rationale: str
    tool_confidence: float = 0.95

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Recommendation:
    """Intelligence Service recommendation"""

    cve_id: str
    package_name: str
    risk_score: float
    action_type: str
    confidence: float
    expected_downtime_minutes: int
    assessed_at: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationAction:
    """Executed or planned remediation"""

    id: str
    cve_id: str
    package_name: str
    package_type: PackageType
    from_version: str
    to_version: str
    initiated_at: str
    initiated_by: str
    pre_validation: Optional[Dict[str, Any]] = None
    post_validation: Optional[Dict[str, Any]] = None
    status: str = "pending"
    rollback_artifacts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "package_type": self.package_type.value,
        }


@dataclass
class HealthCheckResult:
    """System health validation result"""

    check_type: str
    status: str
    checked_at: str
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
