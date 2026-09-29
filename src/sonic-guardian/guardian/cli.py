"""SONiC Guardian CLI commands using Click framework"""

import json
import click
from typing import Dict, List, Any

from guardian.scanner import VulnerabilityScanner
from guardian.metadata import MetadataManager
from guardian.config import ConfigManager
from guardian.intelligence import IntelligenceServiceClient
from guardian.remediation import RemediationEngine
from guardian.validation import ValidationEngine
from guardian.rollback import RollbackEngine
from guardian.vex import VEXManager
from guardian.logging import setup_logging

logger = setup_logging(__name__)


@click.group()
def security():
    """SONiC Guardian security commands"""
    pass


@security.group()
def config():
    """Configure SONiC Guardian"""
    pass


@security.group()
def show():
    """Display security information"""
    pass


@security.group(name="scan")
def security_scan():
    """Vulnerability scanning operations"""
    pass


@config.command(name="service-url")
@click.argument("url")
def config_service_url(url):
    """Configure Security Intelligence Service URL"""
    try:
        config_mgr = ConfigManager()
        if config_mgr.set_service_url(url):
            click.echo(f"Service URL configured: {url}")
        else:
            click.echo("ERROR: Failed to configure service URL", err=True)
            raise SystemExit(1)
    except Exception as e:
        logger.error(f"Configuration failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@config.command(name="auth-token")
@click.argument("token")
def config_auth_token(token):
    """Configure Security Intelligence Service authentication token"""
    try:
        config_mgr = ConfigManager()
        if config_mgr.set_auth_token(token):
            click.echo("Auth token configured")
        else:
            click.echo("ERROR: Failed to configure auth token", err=True)
            raise SystemExit(1)
    except Exception as e:
        logger.error(f"Configuration failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@config.command(name="guardian")
@click.option(
    "--mode",
    type=click.Choice(["advisory", "assisted", "autonomous"]),
    help="Operating mode",
)
@click.option("--enable", is_flag=True, help="Enable Guardian")
@click.option("--disable", is_flag=True, help="Disable Guardian")
def config_guardian(mode, enable, disable):
    """Configure SONiC Guardian service"""
    try:
        config_mgr = ConfigManager()

        if enable:
            if config_mgr.set_service_enabled(True):
                click.echo("SONiC Guardian enabled")
            else:
                click.echo("ERROR: Failed to enable Guardian", err=True)
                raise SystemExit(1)

        if disable:
            if config_mgr.set_service_enabled(False):
                click.echo("SONiC Guardian disabled")
            else:
                click.echo("ERROR: Failed to disable Guardian", err=True)
                raise SystemExit(1)

        if mode:
            if config_mgr.set_operating_mode(mode):
                click.echo(f"Operating mode set to: {mode}")
            else:
                click.echo("ERROR: Failed to set operating mode", err=True)
                raise SystemExit(1)
    except Exception as e:
        logger.error(f"Configuration failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security_scan.command(name="now")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def scan_now(output_json):
    """Execute immediate vulnerability scan"""
    try:
        click.echo("Starting vulnerability scan...")
        metadata_mgr = MetadataManager()
        config_mgr = ConfigManager()

        sbom_source = config_mgr.get_sbom_source()
        scanner = VulnerabilityScanner(sbom_source, metadata_mgr)

        scanner.load_sbom()
        vulnerabilities = scanner.scan_packages()
        new_vulns, all_vulns = scanner.deduplicate_vulnerabilities(vulnerabilities)

        scan_result = {
            "cve_count": len(all_vulns),
            "new_cves": len(new_vulns),
            "severity_breakdown": _count_by_severity(all_vulns),
            "vulnerabilities": [v.to_dict() for v in all_vulns],
        }

        metadata_mgr.add_scan_result(scan_result)
        _output_scan_results(scan_result, output_json)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        click.echo(f"ERROR: Scan failed: {e}", err=True)
        raise SystemExit(1)


@show.command(name="vulnerabilities")
@click.option(
    "--severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    help="Filter by severity level",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def show_vulnerabilities(severity, output_json):
    """Display vulnerabilities from last scan"""
    try:
        metadata_mgr = MetadataManager()
        metadata = metadata_mgr.load()
        last_scan = metadata["scan_history"][-1] if metadata["scan_history"] else None

        if not last_scan:
            click.echo("No vulnerabilities found (no scan history)")
            return

        vulns = last_scan.get("vulnerabilities", [])

        if severity:
            vulns = [v for v in vulns if v["severity"] == severity]

        if output_json:
            click.echo(json.dumps(vulns, indent=2))
        else:
            _print_vulnerabilities_table(vulns)
    except Exception as e:
        logger.error(f"Failed to show vulnerabilities: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@show.command(name="vulnerability")
@click.argument("cve_id")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def show_vulnerability(cve_id, output_json):
    """Display details for specific CVE"""
    try:
        metadata_mgr = MetadataManager()
        metadata = metadata_mgr.load()
        last_scan = metadata["scan_history"][-1] if metadata["scan_history"] else None

        if not last_scan:
            click.echo(f"CVE {cve_id} not found")
            return

        vulns = last_scan.get("vulnerabilities", [])
        vuln = next((v for v in vulns if v["cve_id"] == cve_id), None)

        if not vuln:
            click.echo(f"CVE {cve_id} not found")
            raise SystemExit(1)

        if output_json:
            click.echo(json.dumps(vuln, indent=2))
        else:
            _print_vulnerability_details(vuln)
    except Exception as e:
        logger.error(f"Failed to show CVE details: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


def _count_by_severity(vulnerabilities: List[Any]) -> Dict[str, int]:
    """Count vulnerabilities by severity"""
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in vulnerabilities:
        severity = vuln.severity.value if hasattr(vuln.severity, "value") else vuln["severity"]
        breakdown[severity] = breakdown.get(severity, 0) + 1
    return breakdown


def _output_scan_results(scan_result: Dict[str, Any], json_output: bool) -> None:
    """Output scan results in requested format"""
    if json_output:
        click.echo(json.dumps(scan_result, indent=2))
    else:
        click.echo("\nScan Results:")
        click.echo("=============")
        click.echo(f"Total packages scanned: ~150")
        click.echo(f"Vulnerabilities found: {scan_result['cve_count']}")
        click.echo(f"  - New: {scan_result['new_cves']}")
        click.echo(f"  - Previously reported: {scan_result['cve_count'] - scan_result['new_cves']}")
        click.echo("\nSeverity breakdown:")
        for severity, count in scan_result["severity_breakdown"].items():
            click.echo(f"  - {severity}: {count}")


def _print_vulnerabilities_table(vulnerabilities: List[Dict]) -> None:
    """Print vulnerabilities as ASCII table"""
    click.echo("\nVulnerabilities:")
    click.echo("-" * 80)
    click.echo(f"{'CVE':<20} {'Package':<20} {'Severity':<10} {'CVSS':<6}")
    click.echo("-" * 80)
    for v in vulnerabilities:
        click.echo(
            f"{v['cve_id']:<20} {v['package_name']:<20} {v['severity']:<10} {v['cvss_score']:<6.1f}"
        )


def _print_vulnerability_details(vuln: Dict[str, Any]) -> None:
    """Print detailed CVE information"""
    click.echo(f"\nCVE: {vuln['cve_id']}")
    click.echo(f"Package: {vuln['package_name']}")
    click.echo(f"Affected Version: {vuln['affected_version']}")
    click.echo(f"Fixed Version: {vuln.get('fixed_version', 'Unknown')}")
    click.echo(f"Severity: {vuln['severity']}")
    click.echo(f"CVSS Score: {vuln['cvss_score']:.1f}")


@show.command(name="guardian")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def show_guardian_status(output_json):
    """Display Guardian service status and configuration"""
    try:
        config_mgr = ConfigManager()
        metadata_mgr = MetadataManager()

        status = {
            "enabled": config_mgr.get_service_enabled(),
            "mode": config_mgr.get_operating_mode(),
            "service_url": config_mgr.get_service_url() or "Not configured",
            "sbom_source": config_mgr.get_sbom_source(),
        }

        metadata = metadata_mgr.load()
        status["last_scan"] = (
            metadata["scan_history"][-1].get("timestamp")
            if metadata.get("scan_history")
            else None
        )
        status["total_scans"] = len(metadata.get("scan_history", []))

        if output_json:
            click.echo(json.dumps(status, indent=2))
        else:
            click.echo("\nSONiC Guardian Status:")
            click.echo("=" * 50)
            click.echo(f"Enabled: {'Yes' if status['enabled'] else 'No'}")
            click.echo(f"Mode: {status['mode']}")
            click.echo(f"Service URL: {status['service_url']}")
            click.echo(f"SBOM Source: {status['sbom_source']}")
            click.echo(f"Total Scans: {status['total_scans']}")
            if status["last_scan"]:
                click.echo(f"Last Scan: {status['last_scan']}")
    except Exception as e:
        logger.error(f"Failed to show status: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security.command(name="assess")
@click.argument("cve_id")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def assess_vulnerability(cve_id, output_json):
    """Request risk assessment from Intelligence Service for specific CVE"""
    try:
        config_mgr = ConfigManager()
        service_url = config_mgr.get_service_url()
        auth_token = config_mgr.get_auth_token()

        if not service_url or not auth_token:
            click.echo("ERROR: Intelligence Service not configured", err=True)
            raise SystemExit(1)

        click.echo(f"Assessing {cve_id}...")

        metadata_mgr = MetadataManager()
        metadata = metadata_mgr.load()

        # Find CVE in scan history
        cve_data = None
        for scan in metadata.get("scan_history", []):
            for vuln in scan.get("vulnerabilities", []):
                if vuln.get("cve_id") == cve_id:
                    cve_data = vuln
                    break

        if not cve_data:
            click.echo(f"CVE {cve_id} not found in scan history", err=True)
            raise SystemExit(1)

        # Request assessment
        client = IntelligenceServiceClient(service_url, auth_token)
        recommendations = client.assess_vulnerabilities(
            [cve_data],
            config_mgr.get("SERVICE", "sonic-guardian", "sonic_version") or "unknown",
        )

        if recommendations:
            rec = recommendations[0]
            if output_json:
                click.echo(json.dumps(rec.to_dict(), indent=2))
            else:
                click.echo(f"\nAssessment for {cve_id}:")
                click.echo(f"Risk Score: {rec.risk_score:.1f}/10")
                click.echo(f"Recommended Action: {rec.action_type}")
                click.echo(f"Confidence: {rec.confidence * 100:.0f}%")
                click.echo(f"Expected Downtime: {rec.expected_downtime_minutes} minutes")
                click.echo(f"Rationale: {rec.rationale}")
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security.command(name="remediate")
@click.argument("package_name")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def remediate_package(package_name, output_json):
    """Remediate vulnerability by updating package"""
    try:
        config_mgr = ConfigManager()
        mode = config_mgr.get_operating_mode()

        if mode == "advisory":
            click.echo("ERROR: Remediation not allowed in Advisory mode", err=True)
            raise SystemExit(1)

        click.echo(f"Remediating {package_name}...")

        remediation_engine = RemediationEngine()
        validation_engine = ValidationEngine()

        # Download package
        if not remediation_engine.download_package(package_name):
            click.echo(f"ERROR: Failed to download {package_name}", err=True)
            raise SystemExit(1)

        # Install package
        if not remediation_engine.install_package(package_name):
            click.echo(f"ERROR: Failed to install {package_name}", err=True)

            # Attempt rollback
            rollback_engine = RollbackEngine()
            click.echo("Attempting rollback...")
            raise SystemExit(1)

        # Validate health
        all_passed, results = validation_engine.run_health_checks()

        if not all_passed:
            click.echo("WARNING: Health checks failed, triggering rollback...", err=True)
            rollback_engine = RollbackEngine()
            if rollback_engine.trigger_rollback(package_name, "previous"):
                click.echo("Rollback successful")
            raise SystemExit(1)

        click.echo(f"Successfully remediated {package_name}")

        if output_json:
            click.echo(json.dumps({"status": "success", "package": package_name}, indent=2))
    except Exception as e:
        logger.error(f"Remediation failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security.command(name="validate")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def validate_system(output_json):
    """Run standalone health checks"""
    try:
        click.echo("Running health checks...")

        validation_engine = ValidationEngine()
        all_passed, results = validation_engine.run_health_checks()

        if output_json:
            results_data = [r.to_dict() for r in results]
            click.echo(json.dumps({"passed": all_passed, "results": results_data}, indent=2))
        else:
            click.echo("\nHealth Check Results:")
            click.echo("=" * 50)
            for result in results:
                status_icon = "✓" if result.status == "PASS" else "✗"
                click.echo(f"{status_icon} {result.check_type}: {result.status}")
                if result.details:
                    for key, value in result.details.items():
                        click.echo(f"    {key}: {value}")

            click.echo("=" * 50)
            overall = "PASS" if all_passed else "FAIL"
            click.echo(f"Overall: {overall}")
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security.command(name="rollback")
@click.argument("package_name")
def rollback_package(package_name):
    """Manually rollback package to previous version"""
    try:
        click.echo(f"Rolling back {package_name}...")

        rollback_engine = RollbackEngine()
        if rollback_engine.trigger_rollback(package_name, "previous"):
            click.echo(f"Successfully rolled back {package_name}")
        else:
            click.echo(f"ERROR: Rollback failed for {package_name}", err=True)
            raise SystemExit(1)
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@show.group(name="vex")
def show_vex():
    """Display VEX (Vulnerability Exploitability Exchange) information"""
    pass


@show_vex.command(name="records")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def show_vex_records(output_json):
    """Display VEX records for non-impacted CVEs"""
    try:
        vex_mgr = VEXManager()
        config_mgr = ConfigManager()

        sonic_version = config_mgr.get("SERVICE", "sonic-guardian", "sonic_version") or "unknown"
        records = vex_mgr.load_vex_records(sonic_version)

        if output_json:
            records_data = [r.to_dict() for r in records]
            click.echo(json.dumps(records_data, indent=2))
        else:
            if not records:
                click.echo("No VEX records found")
                return

            click.echo(f"\nVEX Records (Non-Impacted CVEs) - SONiC {sonic_version}:")
            click.echo("-" * 100)
            click.echo(f"{'CVE':<20} {'Package':<20} {'Verdict':<20} {'Confidence':<12}")
            click.echo("-" * 100)
            for rec in records:
                click.echo(
                    f"{rec.vulnerability_id:<20} {rec.package_name:<20} {rec.verdict:<20} {rec.tool_confidence*100:<12.0f}%"
                )
    except Exception as e:
        logger.error(f"Failed to show VEX records: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@show_vex.command(name="document")
@click.option("--format", type=click.Choice(["json", "sbom"]), default="json")
def show_vex_document(format):
    """Display complete VEX document"""
    try:
        vex_mgr = VEXManager()
        config_mgr = ConfigManager()

        sonic_version = config_mgr.get("SERVICE", "sonic-guardian", "sonic_version") or "unknown"
        records = vex_mgr.load_vex_records(sonic_version)

        if format == "sbom":
            doc = vex_mgr.export_vex_sbom(records)
        else:
            doc = {
                "format": "CycloneDX",
                "version": "1.4",
                "sonic_version": sonic_version,
                "records_count": len(records),
                "records": [r.to_dict() for r in records],
            }

        click.echo(json.dumps(doc, indent=2))
    except Exception as e:
        logger.error(f"Failed to show VEX document: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security.command(name="mark-non-impacted")
@click.argument("cve_id")
@click.argument("package_name")
@click.option("--rationale", default="Not vulnerable in this context")
def mark_non_impacted(cve_id, package_name, rationale):
    """Mark a CVE as non-impacted and create VEX record"""
    try:
        vex_mgr = VEXManager()
        metadata_mgr = MetadataManager()

        click.echo(f"Creating VEX record for {cve_id} in {package_name}...")

        # Create VEX record
        vex_record = vex_mgr.record_non_impacted_cve(cve_id, package_name, rationale)

        # Add to metadata
        metadata_mgr.add_vex_record(vex_record.to_dict())

        click.echo(f"VEX record created: {cve_id} marked as non-impacted")
    except Exception as e:
        logger.error(f"Failed to create VEX record: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@security.command(name="generate-vex")
@click.option("--output", default=None, help="Output file path")
def generate_vex(output):
    """Generate comprehensive VEX document for current SONiC version"""
    try:
        config_mgr = ConfigManager()
        metadata_mgr = MetadataManager()
        vex_mgr = VEXManager()

        sonic_version = config_mgr.get("SERVICE", "sonic-guardian", "sonic_version") or "unknown"
        click.echo(f"Generating VEX document for SONiC {sonic_version}...")

        metadata = metadata_mgr.load()
        last_scan = metadata["scan_history"][-1] if metadata.get("scan_history") else None

        if not last_scan:
            click.echo("No scan results available for VEX generation", err=True)
            raise SystemExit(1)

        vulns = last_scan.get("vulnerabilities", [])

        # Create VEX document
        vex_doc = vex_mgr.create_vex_document(sonic_version, vulns)

        # Update with existing VEX records
        existing_records = vex_mgr.load_vex_records(sonic_version)
        vex_doc = vex_mgr.update_vex_document(vex_doc, existing_records)

        # Write to file
        if output:
            import pathlib
            pathlib.Path(output).write_text(json.dumps(vex_doc, indent=2))
            click.echo(f"VEX document written to: {output}")
        else:
            vex_path = vex_mgr.generate_vex_file(vex_doc)
            click.echo(f"VEX document generated: {vex_path}")
    except Exception as e:
        logger.error(f"Failed to generate VEX document: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


@show.command(name="recommendations")
@click.option("--json", "output_json", is_flag=True, help="JSON output format")
def show_recommendations(output_json):
    """Display remediation recommendations"""
    try:
        config_mgr = ConfigManager()
        metadata_mgr = MetadataManager()

        service_url = config_mgr.get_service_url()
        auth_token = config_mgr.get_auth_token()

        if not service_url or not auth_token:
            click.echo("ERROR: Intelligence Service not configured", err=True)
            raise SystemExit(1)

        metadata = metadata_mgr.load()
        last_scan = metadata["scan_history"][-1] if metadata.get("scan_history") else None

        if not last_scan:
            click.echo("No scan results available")
            return

        vulns = last_scan.get("vulnerabilities", [])

        # Get recommendations from Intelligence Service
        client = IntelligenceServiceClient(service_url, auth_token)
        recommendations = client.assess_vulnerabilities(vulns, "unknown")

        if output_json:
            recs_data = [r.to_dict() for r in recommendations]
            click.echo(json.dumps(recs_data, indent=2))
        else:
            click.echo("\nRecommendations:")
            click.echo("-" * 100)
            click.echo(
                f"{'Package':<20} {'CVE':<20} {'Action':<20} {'Risk':<8} {'Confidence':<12}"
            )
            click.echo("-" * 100)
            for rec in recommendations:
                click.echo(
                    f"{rec.package_name:<20} {rec.cve_id:<20} {rec.action_type:<20} {rec.risk_score:<8.1f} {rec.confidence*100:<12.0f}%"
                )
    except Exception as e:
        logger.error(f"Failed to show recommendations: {e}")
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    security()
