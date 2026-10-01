"""Native and standalone Smart Patch CLI. Collection is read-only by default."""
import json
from datetime import datetime, timezone
import click
from smart_patch.agent import Agent
from smart_patch.config import ConfigManager, public_config
from smart_patch.storage import StateStore, read_public_state
from smart_patch.lifecycle import set_enabled, set_mode


def output(value):
    click.echo(json.dumps(value, indent=2, sort_keys=True))


def guarded(function):
    from functools import wraps
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (ValueError, OSError, RuntimeError) as error:
            raise click.ClickException(str(error))
    return wrapper


@click.group()
def security():
    """SONiC Smart Patch: inventory, evidence, findings and maintenance."""


@security.group()
def config():
    """Configure Smart Patch (persisted in ConfigDB and on disk)."""


@config.group(name="smart-patch", invoke_without_command=True)
@click.option("--enable", is_flag=True)
@click.option("--disable", is_flag=True)
@click.option("--mode", type=click.Choice(["advisory", "assisted", "autonomous"]))
@guarded
def configure_smart_patch(enable, disable, mode):
    if enable and disable:
        raise click.ClickException("Choose enable or disable")
    manager = ConfigManager()
    if enable or disable:
        set_enabled(enable, config=manager)
    if mode:
        set_mode(mode, config=manager)


@configure_smart_patch.command(name="enable")
@guarded
def enable_smart_patch():
    managed = set_enabled(True)
    click.echo("Smart Patch enabled; service started and enabled at boot" if managed else "Smart Patch enabled in standalone configuration")


@configure_smart_patch.command(name="disable")
@guarded
def disable_smart_patch():
    managed = set_enabled(False)
    click.echo("Smart Patch disabled; service stopped and disabled at boot" if managed else "Smart Patch disabled in standalone configuration")


@configure_smart_patch.command(name="mode")
@click.argument("mode", type=click.Choice(["advisory", "assisted", "autonomous"]))
@guarded
def smart_patch_mode(mode):
    set_mode(mode)
    click.echo("Smart Patch operating mode saved")


@config.command(name="service-url")
@click.argument("url")
@guarded
def service_url(url):
    ConfigManager().set_service_url(url)
    click.echo("Service URL saved")


@config.command(name="auth-token")
@click.option("--token-file", type=click.Path(exists=True, dir_okay=False))
@click.argument("token", required=False)
@guarded
def auth_token(token_file, token):
    from pathlib import Path
    value = Path(token_file).read_text().strip() if token_file else token or click.prompt("Device token", hide_input=True)
    ConfigManager().set_auth_token(value)
    click.echo("Device token stored in a root-only file")


@config.command(name="setting")
@click.argument("name", type=click.Choice(["ca_bundle", "sync_interval", "inventory_interval", "min_available_mb", "allow_http", "autonomous_allowlist", "maintenance_cpu_quota_percent", "maintenance_min_free_mib", "maintenance_checks_enabled", "validation_services", "validation_cpu_max_pct", "validation_memory_max_pct", "validation_disk_max_pct", "validation_disk_path", "validation_prefix_loss_pct", "validation_require_prefix_counts"]))
@click.argument("value")
@guarded
def setting(name, value):
    """Save a setting; maintenance checks default false, CPU 0 is unlimited, disk in MiB."""
    if name.endswith("interval") and not 10 <= int(value) <= 86400:
        raise ValueError("Interval must be between 10 and 86400 seconds")
    if name == "min_available_mb" and not 64 <= int(value) <= 65536:
        raise ValueError("Memory threshold must be between 64 and 65536 MiB")
    if name == "maintenance_cpu_quota_percent" and not 0 <= int(value) <= 100:
        raise ValueError("Maintenance CPU quota must be between 0 and 100 percent; 0 disables the quota")
    if name == "maintenance_min_free_mib" and not 1 <= int(value) <= 65536:
        raise ValueError("Maintenance free space must be between 1 and 65536 MiB")
    if name == "maintenance_checks_enabled" and value not in ("true", "false"):
        raise ValueError("Maintenance checks must be true or false")
    if name.endswith("_max_pct") and not 1 <= int(value) <= 100:
        raise ValueError("Validation percentage must be between 1 and 100")
    if name == "validation_prefix_loss_pct" and not 0 <= int(value) <= 100:
        raise ValueError("Prefix loss tolerance must be between 0 and 100")
    if name == "validation_require_prefix_counts" and value not in ("true", "false"):
        raise ValueError("Prefix count requirement must be true or false")
    if name == "validation_services":
        import re
        services = value.split(",")
        if not 1 <= len(services) <= 16 or any(not re.fullmatch(r"[A-Za-z0-9_.@:-]+", item) for item in services):
            raise ValueError("Supply 1-16 explicit systemd service names")
    if name == "allow_http" and value not in ("true", "false"):
        raise ValueError("allow_http must be true or false")
    ConfigManager().set("", "", name, value)
    click.echo("Setting saved")


@security.group()
def show():
    """Show measured state, current findings and collection coverage."""


@show.command(name="status")
@click.option("--json", "as_json", is_flag=True)
@guarded
def status(as_json):
    state = read_public_state()
    result = {key: state.get(key) for key in ("sync_status", "assessment_status", "assessment_revision", "last_sync", "collected_at", "error", "inventory_digest", "assessed_inventory_digest", "findings_total", "findings_truncated", "coverage", "clock_alignment", "cache_status", "retained_last_known_count", "cache_omitted_count", "expired_or_unverifiable_verdicts")}
    result.update(components=state.get("component_count", 0), findings=len(state.get("findings", [])), scopes=state.get("scopes", []))
    config = public_config()
    result["enabled"] = config["enabled"]
    result["mode"] = config["mode"]
    result["maintenance_checks_enabled"] = config["maintenance_checks_enabled"]
    result["fresh"] = False
    if state.get("last_sync"):
        age = (datetime.now(timezone.utc)-datetime.fromisoformat(state["last_sync"])).total_seconds()
        result["age_seconds"] = round(age)
        result["fresh"] = age < max(120, int(config["sync_interval"])*3) and state.get("sync_status") == "connected"
    output(result)


@show.command(name="findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], case_sensitive=False))
@click.option("--json", "as_json", is_flag=True)
@guarded
def findings(severity, as_json):
    state = read_public_state()
    items = state.get("findings", [])
    if severity:
        items = [item for item in items if item.get("severity", "").upper() == severity.upper()]
    if as_json:
        output(items)
        return
    click.echo("Assessment: %s; connection: %s; last sync: %s" % (state.get("assessment_status", "unassessed"), state.get("sync_status", "never_connected"), state.get("last_sync", "never")))
    if state.get("findings_truncated"):
        click.echo("Local cache contains %d rows; service reports %d current findings. Use the service for complete coverage." % (len(items), state.get("findings_total", len(items))))
    if state.get("retained_last_known_count"):
        click.echo("Last-known observations retained: %d; partial coverage does not establish their current applicability." % state["retained_last_known_count"])
    if not items:
        click.echo("No current findings available; inspect status and coverage before interpreting this result.")
    for item in items:
        click.echo("%s  %-18s %-10s %-20s %s %s [%s]" % (item.get("id", "?"), item.get("cve_id", "?"), item.get("severity", "unknown"), item.get("applicability", "under_investigation"), item.get("scope", "?"), item.get("package_name", "?"), item.get("cache_state", "unknown")))
        if item.get("decision_basis") == "inventory_advisory_match":
            click.echo("  Inventory/advisory match; build unverified; scoped operator review required before remediation.")


show.add_command(findings, "vulnerabilities")


@show.command(name="finding")
@click.argument("finding_id")
@guarded
def finding(finding_id):
    matches = [item for item in read_public_state().get("findings", []) if item.get("id") == finding_id or item.get("cve_id") == finding_id]
    if not matches:
        raise ValueError("Finding not present in the current local assessment")
    output(matches)


show.add_command(finding, "evidence")
show.add_command(finding, "vulnerability")


@show.command(name="inventory-drift")
@guarded
def drift():
    state = read_public_state()
    pending = state.get("pending_summary", {})
    output({"epoch": state.get("epoch"), "acknowledged_sequence": state.get("sequence"), "pending_kind": pending.get("kind"), "pending_upserts": pending.get("upserts", 0), "pending_removals": pending.get("removals", 0), "scopes": state.get("scopes", [])})


@show.command(name="resource-usage")
@guarded
def resources():
    output(read_public_state().get("resources", {}))


@security.group(name="scan")
def scan():
    """Request central assessment by syncing lightweight inventory."""


@scan.command(name="now")
@click.option("--json", "as_json", is_flag=True)
@guarded
def scan_now(as_json):
    result = Agent().sync(force=True)
    output(result)


@security.command(name="sync")
@click.option("--force", is_flag=True)
@guarded
def sync(force):
    output(Agent().sync(force=force))


@security.command(name="collect")
@guarded
def collect():
    from smart_patch.collector import InventoryCollector
    output(InventoryCollector().collect())


@security.group(name="maintenance")
def maintenance():
    """Create, stage and execute exact-version, scope-specific plans."""


@maintenance.command(name="plan")
@click.argument("finding_id")
@click.argument("target_version")
@guarded
def plan(finding_id, target_version):
    from smart_patch.remediation import RemediationEngine
    output(RemediationEngine().create_plan(finding_id, target_version))


@maintenance.command(name="stage")
@click.argument("plan_id")
@guarded
def stage(plan_id):
    from smart_patch.remediation import RemediationEngine
    output(RemediationEngine().stage(plan_id))


@maintenance.command(name="apply")
@click.argument("plan_id")
@click.option("--approve", is_flag=True, help="Approve this exact staged plan")
@guarded
def apply(plan_id, approve):
    from smart_patch.remediation import RemediationEngine
    output(RemediationEngine().apply(plan_id, approved=approve))


@maintenance.command(name="rollback")
@click.argument("plan_id")
@click.option("--approve", is_flag=True)
@guarded
def rollback(plan_id, approve):
    if not approve:
        raise ValueError("Explicit --approve is required for rollback")
    from smart_patch.remediation import RemediationEngine
    output(RemediationEngine().rollback(plan_id))


@security.command(name="export-vex")
@click.option("--output", "filename", default="smart-patch-vex.json")
@guarded
def export_vex(filename):
    from smart_patch.vex import VEXManager
    state = StateStore().load()
    manager = VEXManager()
    document = manager.create_vex_document(state.get("build_id", "unknown"), state.get("findings", []), clock_alignment=state.get("clock_alignment", {}))
    click.echo(str(manager.generate_vex_file(document, filename)))


if __name__ == "__main__":
    security()
