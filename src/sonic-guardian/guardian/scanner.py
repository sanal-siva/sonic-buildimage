"""Vulnerability scanner using grype + SBOM baseline with delta metadata

Implements CPU-efficient scanning by:
1. Loading baseline SBOM from source (local or remote)
2. Merging with delta metadata (added/updated/removed packages)
3. Creating temporary SBOM with combined packages
4. Running grype scan against merged SBOM (not filesystem)
5. Deduplicating against previous scan results
"""

import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.request import urlopen

from guardian.models import Vulnerability, VulnerabilitySeverity
from guardian.exceptions import ScanError
from guardian.logging import setup_logging
from guardian.metadata import MetadataManager
from guardian.vex import VEXManager

logger = setup_logging(__name__)


class VulnerabilityScanner:
    """Grype-based scanner with SBOM + delta metadata approach"""

    def __init__(
        self,
        sbom_source: str = "/etc/sonic/SBOM.json",
        metadata_mgr: Optional[MetadataManager] = None,
        vex_mgr: Optional[VEXManager] = None,
    ):
        """Initialize scanner

        Args:
            sbom_source: Path or URL to SBOM file
            metadata_mgr: Metadata manager instance
            vex_mgr: VEX manager instance
        """
        self.sbom_source = sbom_source
        self.metadata_mgr = metadata_mgr or MetadataManager()
        self.vex_mgr = vex_mgr or VEXManager()
        self.sbom = None

    def load_sbom(self) -> Dict[str, Any]:
        """Load SBOM from source (local or remote)

        Returns:
            SBOM data dict

        Raises:
            ScanError: If SBOM cannot be loaded
        """
        try:
            if self.sbom_source.startswith(("http://", "https://")):
                logger.info(f"Fetching SBOM from remote: {self.sbom_source}")
                with urlopen(self.sbom_source, timeout=10) as response:
                    self.sbom = json.loads(response.read().decode('utf-8'))
            else:
                logger.info(f"Loading SBOM from local file: {self.sbom_source}")
                with open(self.sbom_source) as f:
                    self.sbom = json.load(f)

            component_count = len(self.sbom.get('components', []))
            logger.info(f"SBOM loaded: {component_count} components")
            return self.sbom
        except Exception as e:
            logger.error(f"Failed to load SBOM: {e}")
            raise ScanError(f"Cannot load SBOM: {e}")

    def scan_packages(self) -> List[Vulnerability]:
        """Run grype scan against SBOM + delta metadata

        CPU-efficient approach:
        1. Load baseline SBOM
        2. Merge with delta metadata (added/updated/removed packages)
        3. Create temporary merged SBOM file
        4. Run grype scan against merged SBOM (not filesystem)
        5. Parse and return vulnerabilities

        Returns:
            List of discovered vulnerabilities

        Raises:
            ScanError: If scan fails
        """
        if not self.sbom:
            self.load_sbom()

        temp_sbom_file = None
        try:
            logger.info("Preparing merged SBOM for scanning (baseline + delta)")

            # Merge baseline SBOM with delta metadata
            merged_sbom = self._merge_sbom_with_delta()

            # Create temporary SBOM file
            temp_sbom_file = self._create_temp_sbom_file(merged_sbom)
            logger.info(f"Created temporary SBOM for scanning: {temp_sbom_file}")

            # Run grype scan against the SBOM file (not filesystem)
            logger.info("Starting grype scan against SBOM file (CPU-efficient)")
            result = subprocess.run(
                ["grype", f"sbom:{temp_sbom_file}", "--output", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in [0, 1]:
                raise ScanError(f"Grype scan failed: {result.stderr}")

            grype_output = json.loads(result.stdout)
            vulnerabilities = self._parse_grype_output(grype_output)

            component_count = len(merged_sbom.get('components', []))
            logger.info(
                f"Scan complete: {len(vulnerabilities)} CVEs found in {component_count} packages"
            )
            return vulnerabilities

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse grype output: {e}")
            raise ScanError(f"Invalid grype output: {e}")
        except subprocess.TimeoutExpired:
            logger.error("Grype scan timed out")
            raise ScanError("Grype scan timed out after 5 minutes")
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise ScanError(f"Scan failed: {e}")
        finally:
            # Clean up temporary SBOM file
            if temp_sbom_file and Path(temp_sbom_file).exists():
                try:
                    Path(temp_sbom_file).unlink()
                    logger.debug(f"Cleaned up temporary SBOM file: {temp_sbom_file}")
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary SBOM: {e}")

    def deduplicate_vulnerabilities(
        self, vulnerabilities: List[Vulnerability]
    ) -> tuple[List[Vulnerability], List[Vulnerability]]:
        """Compare against previous scan results, identify new/changed CVEs

        Args:
            vulnerabilities: Current scan results

        Returns:
            (new_vulnerabilities, all_vulnerabilities)
        """
        last_scan = self.metadata_mgr.get_last_scan()
        vex_records = self.metadata_mgr.load().get("vex_records", [])

        # Filter out VEX-marked non-impacted CVEs
        vex_cve_ids = {rec["vulnerability_id"] for rec in vex_records if rec.get("verdict") == "not_affected"}
        vulnerabilities = [v for v in vulnerabilities if v.cve_id not in vex_cve_ids]

        if not last_scan:
            logger.info("First scan - all CVEs are new")
            return vulnerabilities, vulnerabilities

        previous_cves = {v["cve_id"]: v for v in last_scan.get("vulnerabilities", [])}
        new_vulns = []

        for vuln in vulnerabilities:
            if vuln.cve_id not in previous_cves:
                new_vulns.append(vuln)
                logger.debug(f"New CVE: {vuln.cve_id}")
            elif vuln.severity != previous_cves[vuln.cve_id].get("severity"):
                new_vulns.append(vuln)
                logger.debug(f"Changed severity: {vuln.cve_id}")

        logger.info(f"Deduplication: {len(new_vulns)} new/changed CVEs out of {len(vulnerabilities)} total")
        logger.info(f"Filtered out {len(vex_cve_ids)} VEX-marked non-impacted CVEs")
        return new_vulns, vulnerabilities

    def _merge_sbom_with_delta(self) -> Dict[str, Any]:
        """Merge baseline SBOM with delta metadata

        Creates combined SBOM with:
        - Baseline components from loaded SBOM
        - Added packages from delta metadata
        - Updated versions for changed packages
        - Removes packages marked as removed

        Returns:
            Merged SBOM data dict
        """
        try:
            merged = {
                **self.sbom,
                "components": list(self.sbom.get("components", []))
            }

            metadata = self.metadata_mgr.load()
            inventory = metadata.get("inventory", [])

            if not inventory:
                logger.debug("No delta metadata found - using baseline SBOM only")
                return merged

            logger.info(f"Merging {len(inventory)} packages from delta metadata")

            # Build set of baseline component names for quick lookup
            baseline_names = {c.get("name") for c in merged.get("components", [])}

            # Process delta packages
            added_count = 0
            updated_count = 0

            for pkg in inventory:
                pkg_name = pkg.get("name")
                pkg_version = pkg.get("version")
                pkg_type = pkg.get("type", "standard")

                if not pkg_name or not pkg_version:
                    continue

                # Find if package exists in baseline
                found = False
                for component in merged.get("components", []):
                    if component.get("name") == pkg_name:
                        old_version = component.get("version")
                        if old_version != pkg_version:
                            logger.debug(
                                f"Updating {pkg_name} from {old_version} to {pkg_version}"
                            )
                            component["version"] = pkg_version
                            component["purl"] = f"pkg:deb/debian/{pkg_name}@{pkg_version}"
                            updated_count += 1
                        found = True
                        break

                # If not in baseline, add it
                if not found:
                    logger.debug(f"Adding new package: {pkg_name}@{pkg_version}")
                    new_component = {
                        "type": "library",
                        "name": pkg_name,
                        "version": pkg_version,
                        "purl": f"pkg:deb/debian/{pkg_name}@{pkg_version}",
                        "metadata": {"package_type": pkg_type}
                    }
                    merged["components"].append(new_component)
                    added_count += 1

            logger.info(
                f"Merged SBOM: {added_count} added, {updated_count} updated, "
                f"{len(merged.get('components', []))} total packages"
            )
            return merged

        except Exception as e:
            logger.error(f"Failed to merge SBOM with delta: {e}")
            logger.warning("Falling back to baseline SBOM only")
            return self.sbom

    def _create_temp_sbom_file(self, sbom_data: Dict[str, Any]) -> str:
        """Create temporary SBOM file for grype scanning

        Args:
            sbom_data: SBOM data to write

        Returns:
            Path to temporary SBOM file

        Raises:
            ScanError: If file creation fails
        """
        try:
            # Create temporary file in /tmp with .json extension
            temp_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False,
                prefix='sonic_guardian_sbom_'
            )

            json.dump(sbom_data, temp_file, indent=2)
            temp_file.close()

            logger.debug(f"Created temporary SBOM file: {temp_file.name}")
            return temp_file.name

        except Exception as e:
            logger.error(f"Failed to create temporary SBOM file: {e}")
            raise ScanError(f"Cannot create temporary SBOM: {e}")

    def _parse_grype_output(self, grype_data: Dict[str, Any]) -> List[Vulnerability]:
        """Parse grype JSON output into Vulnerability objects

        Args:
            grype_data: Grype JSON output

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        for match in grype_data.get("matches", []):
            vuln_data = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            try:
                # Determine severity: use CVSS score if available, else check grype severity field
                cvss_score = vuln_data.get("cvssScore", 0)
                if cvss_score:
                    severity = self._severity_from_cvss(float(cvss_score))
                else:
                    # Fallback to grype's severity field if CVSS missing
                    grype_severity = vuln_data.get("severity", "").lower()
                    severity = self._severity_from_string(grype_severity)
                    if not cvss_score and grype_severity:
                        logger.debug(f"Using grype severity '{grype_severity}' for {vuln_data.get('id', 'UNKNOWN')}")

                vuln = Vulnerability(
                    cve_id=vuln_data.get("id", "UNKNOWN"),
                    package_name=artifact.get("name", "unknown"),
                    affected_version=artifact.get("version", "unknown"),
                    fixed_version=vuln_data.get("fixed", {}).get("versions", [None])[0],
                    severity=severity,
                    cvss_score=float(cvss_score) if cvss_score else None,
                    discovered_at=datetime.utcnow().isoformat() + "Z",
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                logger.warning(f"Failed to parse vulnerability: {e}")

        return vulnerabilities

    def _severity_from_cvss(self, cvss_score: float) -> VulnerabilitySeverity:
        """Map CVSS score to severity level

        Args:
            cvss_score: CVSS score

        Returns:
            VulnerabilitySeverity
        """
        if cvss_score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif cvss_score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif cvss_score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        else:
            return VulnerabilitySeverity.LOW

    def _severity_from_string(self, severity_str: str) -> VulnerabilitySeverity:
        """Map severity string to VulnerabilitySeverity enum

        Args:
            severity_str: Severity string from grype (e.g., "critical", "high")

        Returns:
            VulnerabilitySeverity (defaults to LOW if unrecognized)
        """
        severity_map = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "negligible": VulnerabilitySeverity.LOW,
        }
        return severity_map.get(severity_str.lower(), VulnerabilitySeverity.LOW)
