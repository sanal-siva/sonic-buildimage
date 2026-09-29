"""VEX (Vulnerability Exploitability Exchange) document management"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from uuid import uuid4

from guardian.models import VEXRecord
from guardian.logging import setup_logging

logger = setup_logging(__name__)

VEX_DIR = "/etc/sonic/vex"


class VEXManager:
    """Manages Vulnerability Exploitability Exchange documents"""

    def __init__(self, vex_dir: str = VEX_DIR):
        """Initialize VEX manager

        Args:
            vex_dir: Directory for VEX documents
        """
        self.vex_dir = Path(vex_dir)
        self.vex_dir.mkdir(parents=True, exist_ok=True)

    def create_vex_document(
        self, sonic_version: str, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create comprehensive VEX document for SONiC release

        Args:
            sonic_version: SONiC version string
            vulnerabilities: List of vulnerability data

        Returns:
            VEX document in NTIA CycloneDX format
        """
        vex_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "SONiC",
                        "name": "SONiC Guardian",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "bom-ref": f"sonic-{sonic_version}",
                    "type": "operating-system",
                    "name": "SONiC",
                    "version": sonic_version,
                },
            },
            "vulnerabilities": [],
        }

        for vuln in vulnerabilities:
            vex_entry = {
                "ref": f"CVE-{uuid4()}",
                "id": vuln.get("cve_id", "UNKNOWN"),
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id')}"},
                "ratings": [
                    {
                        "score": vuln.get("cvss_score", 0),
                        "method": "CVSSv3",
                    }
                ],
                "cwes": [],
                "status": "not_affected",
                "justification": "component_not_present",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "detail": vuln.get("rationale", "Assessed as non-impacted"),
            }
            vex_doc["vulnerabilities"].append(vex_entry)

        return vex_doc

    def record_non_impacted_cve(
        self, cve_id: str, package_name: str, rationale: str, tool_confidence: float = 0.95
    ) -> VEXRecord:
        """Record CVE as non-impacted with justification

        Args:
            cve_id: CVE identifier
            package_name: Affected package name
            rationale: Why this CVE is non-impacted
            tool_confidence: Confidence score (0-1)

        Returns:
            VEXRecord object
        """
        vex_record = VEXRecord(
            vulnerability_id=cve_id,
            package_name=package_name,
            verdict="not_affected",
            impact_statement=f"SONiC Guardian assessment: {package_name} not impacted by {cve_id}",
            assessed_at=datetime.utcnow().isoformat() + "Z",
            rationale=rationale,
            tool_confidence=tool_confidence,
        )

        logger.info(f"Recorded non-impacted CVE: {cve_id} in {package_name}")
        return vex_record

    def generate_vex_file(self, vex_doc: Dict[str, Any], filename: str = None) -> Path:
        """Write VEX document to file in NTIA CycloneDX format

        Args:
            vex_doc: VEX document data
            filename: Optional custom filename

        Returns:
            Path to written VEX file
        """
        if not filename:
            sonic_version = vex_doc["metadata"]["component"]["version"]
            filename = f"sonic-{sonic_version}-vex.json"

        vex_path = self.vex_dir / filename

        try:
            with open(vex_path, "w") as f:
                json.dump(vex_doc, f, indent=2)

            logger.info(f"VEX document written: {vex_path}")
            return vex_path
        except Exception as e:
            logger.error(f"Failed to write VEX document: {e}")
            raise

    def load_vex_records(self, sonic_version: str) -> List[VEXRecord]:
        """Load all VEX records for specific SONiC version

        Args:
            sonic_version: SONiC version string

        Returns:
            List of VEXRecord objects
        """
        vex_file = self.vex_dir / f"sonic-{sonic_version}-vex.json"

        if not vex_file.exists():
            logger.debug(f"No VEX records found for {sonic_version}")
            return []

        try:
            with open(vex_file) as f:
                vex_doc = json.load(f)

            records = []
            for vuln in vex_doc.get("vulnerabilities", []):
                if vuln.get("status") == "not_affected":
                    record = VEXRecord(
                        vulnerability_id=vuln.get("id"),
                        package_name="unknown",
                        verdict=vuln.get("justification", "component_not_present"),
                        impact_statement=vuln.get("impact_statement", ""),
                        assessed_at=vuln.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                        rationale=vuln.get("detail", ""),
                        tool_confidence=0.95,
                    )
                    records.append(record)

            logger.info(f"Loaded {len(records)} VEX records for {sonic_version}")
            return records
        except Exception as e:
            logger.error(f"Failed to load VEX records: {e}")
            return []

    def update_vex_document(self, vex_doc: Dict[str, Any], new_records: List[VEXRecord]) -> Dict[str, Any]:
        """Update VEX document with new non-impacted CVE records

        Args:
            vex_doc: Existing VEX document
            new_records: New VEX records to add

        Returns:
            Updated VEX document
        """
        existing_ids = {v["id"] for v in vex_doc.get("vulnerabilities", [])}

        for record in new_records:
            if record.vulnerability_id not in existing_ids:
                vex_entry = {
                    "ref": f"CVE-{uuid4()}",
                    "id": record.vulnerability_id,
                    "status": "not_affected",
                    "justification": record.verdict,
                    "timestamp": record.assessed_at,
                    "detail": record.rationale,
                    "impact_statement": record.impact_statement,
                }
                vex_doc["vulnerabilities"].append(vex_entry)
                logger.debug(f"Added VEX record: {record.vulnerability_id}")

        vex_doc["metadata"]["timestamp"] = datetime.utcnow().isoformat() + "Z"
        return vex_doc

    def export_vex_sbom(self, vex_records: List[VEXRecord]) -> Dict[str, Any]:
        """Export VEX records as SBOM with vulnerability status

        Args:
            vex_records: List of VEX records

        Returns:
            SBOM-compatible VEX export
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "vulnerabilities": [
                {
                    "ref": f"CVE-{uuid4()}",
                    "id": rec.vulnerability_id,
                    "source": {"name": "NVD"},
                    "status": "not_affected",
                    "justification": rec.verdict,
                    "detail": rec.rationale,
                    "timestamp": rec.assessed_at,
                }
                for rec in vex_records
            ],
        }
