#!/usr/bin/python3
"""Root-run live acceptance helper. Only Smart Patch and named file-only fixtures mutate.

Transport supplies one base64 JSON request. No passwords/tokens are returned.
Every run snapshots configuration and restores it through the cleanup action.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone

os.environ.update(DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")
PACKAGES = {"sonic-smart-patch-testprobe", "smart-patch-testprobe"}


def command(argv, check=True, timeout=90):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Command failed: %s: %s" % (argv[0], result.stderr[-1200:]))
    return result


def version(package):
    result = command(["dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", package], check=False)
    return result.stdout.split(" ", 1)[1].strip() if result.returncode == 0 and result.stdout.startswith("installed ") else None


def package_inventory():
    output = command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n"]).stdout
    return {parts[0]: parts[1] for line in output.splitlines() if len(parts := line.split("\t")) == 3 and parts[2] == "installed"}


def state_summary():
    from smart_patch.storage import StateStore
    state = StateStore().load()
    pending = state.get("pending")
    from smart_patch.collector import digest
    return {key: state.get(key) for key in ("device_id", "epoch", "sequence", "inventory_digest", "last_sync", "sync_status", "assessment_status", "resources")} | {
        "pending_hash": digest(pending) if pending else None,
        "pending_kind": pending.get("kind") if pending else None,
        "pending_sequence": pending.get("sequence") if pending else None,
        "component_count": len(state.get("inventory", {})),
        "fixture_components": [item for item in state.get("inventory", {}).values() if item.get("name") in PACKAGES],
        "facts": [{key: fact.get(key) for key in ("fact_id", "collector", "scope", "status")} for fact in state.get("facts", [])]}


def sync(force=False):
    from smart_patch.agent import Agent
    result = Agent().sync(force=force)
    return {"ack_sequence":result.get("ack_sequence"), "resync_required":result.get("resync_required"),
            "assessment_status":result.get("assessment_status"), "state":state_summary()}


def resource_snapshot():
    properties = command(["systemctl", "show", "sonic-smart-patch", "-p", "MainPID", "-p", "MemoryCurrent", "-p", "MemoryPeak", "-p", "MemoryMax", "-p", "CPUQuotaPerSecUSec", "-p", "ControlGroup"]).stdout
    values = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
    group = values.get("ControlGroup", "")
    events = Path("/sys/fs/cgroup") / group.lstrip("/") / "memory.events"
    if group and events.exists():
        values["memory_events"] = dict(line.split() for line in events.read_text().splitlines())
    return values


def prepare(folder, request):
    from smart_patch.config import ConfigManager
    from smart_patch.storage import atomic_json
    if (folder / "backup.json").exists():
        raise ValueError("Run already prepared; use cleanup instead of overwriting recovery state")
    for package in PACKAGES:
        if version(package):
            raise ValueError("Fixture package already present: " + package)
    manager = ConfigManager()
    configuration = manager.directory / "config.json"
    backup = {"configuration":configuration.read_text() if configuration.exists() else None,
              "config_db":manager.config_db.get_entry(manager.namespace, "GLOBAL") if manager.config_db else None,
              "active":command(["systemctl", "is-active", "sonic-smart-patch"], check=False).stdout.strip() == "active",
              "packages":package_inventory(), "resources":resource_snapshot(), "created_at":time.time()}
    folder.mkdir(parents=True, mode=0o755)
    folder.parent.chmod(0o755)
    folder.chmod(0o755)
    atomic_json(folder / "backup.json", backup)
    command(["systemctl", "stop", "sonic-smart-patch"])
    archive = Path(request["archive"])
    with tarfile.open(archive, "r:gz") as source:
        for member in source.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
                raise ValueError("Unsafe fixture archive member")
        source.extractall(folder / "repo", filter="data")
    for path in (folder / "repo").rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    manifest = json.loads((folder / "repo/fixture-manifest.json").read_text())
    if manifest.get("contains_real_vulnerabilities") is not False or set(manifest.get("packages", [])) != PACKAGES:
        raise ValueError("Only labelled synthetic file-only packages are permitted")
    for relative, expected in manifest["sha256"].items():
        actual = hashlib.sha256((folder / "repo" / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError("Fixture digest mismatch")
    command(["gpgv", "--keyring", str(folder / "repo/fixture-key.gpg"), str(folder / "repo/InRelease")])
    source_list = Path("/etc/apt/sources.list.d") / (folder.name + ".list")
    source_list.write_text("deb [signed-by=%s] file:%s ./\n" % (folder / "repo/fixture-key.gpg", folder / "repo"))
    command(["apt-get", "-o", "Dir::Etc::sourcelist=" + str(source_list), "-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0", "update"], timeout=120)
    command(["apt-get", "check"])
    return {"prepared":True, "before":backup["resources"], "state":state_summary()}


def package_change(folder, request):
    package, action = request["package"], request["operation"]
    if package not in PACKAGES:
        raise ValueError("Only named synthetic fixture packages may change")
    dirty = Path("/var/lib/sonic-smart-patch/dirty")
    before = dirty.stat().st_mtime_ns if dirty.exists() else 0
    if action == "remove":
        command(["apt-get", "-y", "--no-auto-remove", "remove", package], timeout=120)
    elif action == "install":
        target = request["version"]
        if target not in ("1.0", "1.1"):
            raise ValueError("Unsupported fixture version")
        path = folder / "repo/pool" / f"{package}_{target}_all.deb"
        command(["apt-get", "-y", "--no-install-recommends", "--no-remove", "install", str(path)], timeout=120)
    else:
        raise ValueError("Unknown package fixture operation")
    after = dirty.stat().st_mtime_ns if dirty.exists() else 0
    result = sync(force=False)
    return {"installed_version":version(package), "apt_hook_observed":after > before, **result}


def yang_check(folder, request):
    from smart_patch.config import ConfigManager
    import sonic_yang
    import importlib.util
    registration_path = Path("/usr/share/sonic-smart-patch/install-yang.py")
    specification = importlib.util.spec_from_file_location("smart_patch_native_yang_registration", registration_path)
    registration = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(registration)
    model_dir = registration.native_yang_directory()
    if model_dir is None or not (model_dir / "sonic-smart-patch.yang").is_file():
        raise AssertionError("Smart Patch model is absent from native SONiC YANG directory")
    deployed_model = model_dir / "sonic-smart-patch.yang"
    expected = Path(request["model"])
    if hashlib.sha256(deployed_model.read_bytes()).digest() != hashlib.sha256(expected.read_bytes()).digest():
        raise AssertionError("Installed Smart Patch model does not match tested community source")
    manager = ConfigManager()
    actual = manager.config_db.get_entry("SONIC_SMART_PATCH", "GLOBAL")
    def check(data):
        try:
            model = sonic_yang.SonicYang(str(model_dir), print_log_enabled=False)
        except TypeError:
            model = sonic_yang.SonicYang(str(model_dir))
        model.loadYangModel()
        model.loadData({"SONIC_SMART_PATCH":{"GLOBAL":data}})
        model.validate_data_tree()
    check(actual)
    rejected = False
    try:
        check({**actual, "mode":"not-a-valid-mode"})
    except Exception:
        rejected = True
    if not rejected:
        raise AssertionError("SonicYang accepted invalid Smart Patch mode")
    return {"real_config_valid":True, "invalid_mode_rejected":True, "binding":sonic_yang.__file__, "native_model_directory":str(model_dir), "deployed_model":str(deployed_model.resolve())}


def offline(folder):
    from smart_patch.config import ConfigManager
    from smart_patch.agent import Agent
    manager = ConfigManager()
    original = manager.get_service_url()
    (folder / "offline-url.txt").write_text(original)
    manager.set_service_url("https://127.0.0.1:65432")
    failed = False
    try:
        Agent().sync(force=True)
    except Exception:
        failed = True
    if not failed:
        raise AssertionError("Offline endpoint unexpectedly accepted synchronization")
    result = state_summary()
    if not result["pending_hash"] or result["sync_status"] != "stale":
        raise AssertionError("Failed synchronization was not durably journaled")
    manager.set_service_url(original)
    return result


def recover():
    import requests
    from smart_patch.agent import Agent
    from smart_patch.collector import digest
    before = state_summary()
    class ObservedTransport(requests.Session):
        sent_hash = None
        def post(self, *args, **kwargs):
            self.sent_hash = digest(kwargs["json"])
            return super().post(*args, **kwargs)
    transport = ObservedTransport()
    Agent(session=transport).sync()
    if before["pending_hash"] != transport.sent_hash:
        raise AssertionError("Recovery changed the pending envelope")
    after = state_summary()
    if after["pending_hash"] or after["sync_status"] != "connected":
        raise AssertionError("Recovery was not acknowledged")
    return {"pending_hash":before["pending_hash"], "actual_sent_hash":transport.sent_hash, "state":after}


def low_memory_guard():
    from smart_patch.agent import Agent
    from smart_patch.config import ConfigManager
    manager = ConfigManager()
    original = manager.values()["min_available_mb"]
    available = next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")) // 1024
    try:
        manager.set("", "", "min_available_mb", str(available+1024))
        try:
            Agent().sync(force=True)
        except RuntimeError as error:
            if "memory" not in str(error):
                raise
            return {"deferred":True, "available_mb":available, "threshold_mb":available+1024, "memory_pressure_allocated":False}
        raise AssertionError("Collection did not honor memory threshold")
    finally:
        manager.set("", "", "min_available_mb", original)


def fixture_plan_state(folder, request):
    from smart_patch.storage import StateStore
    from smart_patch.remediation import RemediationEngine
    state = StateStore().load()
    remote_id = request["plan_id"]
    local_id = state.get("remote_plans", {}).get(remote_id)
    if not local_id:
        return {"local_plan_id":None}
    plan = RemediationEngine()._load(local_id)
    if plan.get("package") != "smart-patch-testprobe" or folder.name not in plan.get("finding_id", ""):
        raise ValueError("Plan is not this run's synthetic fixture")
    if request.get("rollback"):
        plan = RemediationEngine().rollback(local_id)
    return {"local_plan_id":local_id, "status":plan["status"], "package_version":version("smart-patch-testprobe"),
            "artifacts":{key:[{field:item[field] for field in ("package", "version", "sha256")} for item in value] for key,value in plan.get("artifacts", {}).items()},
            "post_validation":plan.get("post_validation"), "rollback_validation":plan.get("rollback_validation")}


def cleanup(folder):
    from smart_patch.config import ConfigManager
    from smart_patch.storage import StateStore, atomic_json
    from smart_patch.agent import Agent
    backup_path = folder / "backup.json"
    if not backup_path.exists():
        return {"restored":False, "reason":"No backup; prepare did not mutate switch"}
    backup = json.loads(backup_path.read_text())
    command(["systemctl", "stop", "sonic-smart-patch"], check=False)
    errors = []
    for package in PACKAGES:
        if version(package):
            try:
                command(["dpkg", "--purge", package], timeout=120)
            except Exception as error:
                errors.append(str(error))
    source = Path("/etc/apt/sources.list.d") / (folder.name + ".list")
    source.unlink(missing_ok=True)
    for path in Path("/var/lib/apt/lists").glob("*"+folder.name+"*"):
        if path.is_file():
            path.unlink()
    manager = ConfigManager()
    if manager.config_db:
        manager.config_db.set_entry(manager.namespace, "GLOBAL", None)
        if backup["config_db"]:
            manager.config_db.set_entry(manager.namespace, "GLOBAL", backup["config_db"])
    config_path = manager.directory / "config.json"
    if backup["configuration"] is None:
        config_path.unlink(missing_ok=True)
    else:
        config_path.write_text(backup["configuration"])
        config_path.chmod(0o600)
    store = StateStore()
    plan_dir = store.directory / "plans"
    local_fixture_ids = []
    if plan_dir.exists():
        for path in plan_dir.glob("*/plan.json"):
            plan = json.loads(path.read_text())
            if plan.get("package") in PACKAGES and folder.name in plan.get("finding_id", ""):
                local_fixture_ids.append(plan["id"])
                shutil.rmtree(path.parent)
    with store.transaction() as state:
        state["findings"] = [item for item in state.get("findings", []) if folder.name not in item.get("id", "")]
        state["plan_findings"] = {key:value for key,value in state.get("plan_findings", {}).items() if folder.name not in key}
        state["remote_plans"] = {key:value for key,value in state.get("remote_plans", {}).items() if value not in local_fixture_ids}
        state.pop("pending", None)  # A test endpoint may have left a retry pending; force a new epoch below.
        state.update(sequence=0, acknowledged_fingerprints={})
        import uuid
        state["epoch"] = str(uuid.uuid4())
    try:
        Agent().sync(force=True)
    except Exception as error:
        errors.append("Final inventory synchronization: " + str(error))
    if backup["active"]:
        command(["systemctl", "start", "sonic-smart-patch"])
    current = package_inventory()
    changed = {key:[value,current.get(key)] for key,value in backup["packages"].items() if current.get(key) != value}
    added = sorted(set(current)-set(backup["packages"]))
    if changed or added:
        errors.append("Non-fixture package inventory changed")
    report = {"restored":not errors, "errors":errors, "changed_packages":changed, "added_packages":added,
              "fixture_packages_absent":all(version(package) is None for package in PACKAGES),
              "state":state_summary(), "resources":resource_snapshot()}
    # Preserve cleanup result locally; archive it before deleting this directory.
    atomic_json(folder / "cleanup.json", report)
    shutil.rmtree(folder / "repo", ignore_errors=True)
    (Path("/var/lib/sonic-smart-patch/vex") / (folder.name+"-vex.json")).unlink(missing_ok=True)
    return report



def live_health():
    from smart_patch.validation import ValidationEngine
    engine = ValidationEngine()
    before = engine.snapshot()
    after = engine.snapshot()
    comparison = engine.compare(before, after)
    if comparison["status"] != "PASS":
        raise AssertionError("Real SONiC health validation failed: " + json.dumps(comparison))
    return {"before":before, "after":after, "comparison":comparison}


def scheduled_collection():
    from smart_patch.config import ConfigManager
    manager = ConfigManager()
    original = manager.values()
    try:
        manager.set_operating_mode("advisory")
        manager.set("", "", "sync_interval", "10")
        manager.set("", "", "inventory_interval", "10")
        command(["systemctl", "start", "sonic-smart-patch"])
        observed = []
        deadline = time.monotonic()+100
        while time.monotonic() < deadline:
            from smart_patch.storage import StateStore
            state = StateStore().load()
            value = state.get("last_collection")
            if value and value not in observed:
                observed.append(value)
                if len(observed) >= 3:
                    return {"collection_device_times":observed, "configured_interval_seconds":10,
                            "meaning":"actual scheduled metadata collection; central scanning is a separate job"}
            time.sleep(1)
        raise AssertionError("Scheduled Smart Patch collection did not occur twice after initial observation")
    finally:
        command(["systemctl", "stop", "sonic-smart-patch"], check=False)
        for key in ("sync_interval", "inventory_interval", "mode"):
            manager.set("", "", key, original[key])


def autonomous_fixture(folder, request):
    from smart_patch.config import ConfigManager
    from smart_patch.storage import StateStore
    from smart_patch.actions import AutonomousCoordinator
    from smart_patch.remediation import RemediationEngine
    manager, store = ConfigManager(), StateStore()
    original = manager.values()
    state = store.load()
    requested = request["finding_ids"]
    findings = [item for item in state.get("findings", []) if item.get("id") in requested]
    if len(findings) != 2 or any(folder.name not in item["id"] or item.get("scope") != "host" or item.get("package_name") not in PACKAGES for item in findings):
        raise ValueError("Autonomous acceptance requires both this run's scoped synthetic fixtures")
    if state.get("assessment_status") not in ("complete", "completed", "ready") or state.get("assessed_inventory_digest") != state.get("inventory_digest"):
        raise ValueError("Autonomous acceptance requires a real complete current assessment; it will not fake this state")
    if any(version(package) != "1.0" for package in PACKAGES):
        raise ValueError("Both harmless fixtures must start at 1.0")
    simulation = command(["apt-get", "-s", "--no-remove", "install", "smart-patch-testprobe=1.1"]).stdout
    changed = {line.split()[1].split(":",1)[0] for line in simulation.splitlines() if line.startswith("Inst ")}
    if changed != {"smart-patch-testprobe"} or any(line.startswith("Remv ") for line in simulation.splitlines()):
        raise ValueError("Fixture transaction would affect unrelated packages")
    results = {}
    try:
        manager.set("", "", "autonomous_allowlist", "host/smart-patch-testprobe,host/sonic-smart-patch-testprobe")
        for mode in ("advisory", "assisted"):
            manager.set_operating_mode(mode)
            if AutonomousCoordinator(store, manager).run_once() is not None or version("smart-patch-testprobe") != "1.0":
                raise AssertionError("Mode allowed an unexpected automatic install: "+mode)
            results[mode] = {"installed_version":"1.0", "automatic_action":False}
        protected = next(item for item in findings if item["package_name"] == "sonic-smart-patch-testprobe")
        plan = RemediationEngine(store, manager).create_plan(protected["id"], "1.1")
        if plan["impact"] != "image_maintenance":
            raise AssertionError("Protected SONiC package did not produce image-maintenance requirement")
        try:
            RemediationEngine(store, manager).stage(plan["id"])
        except ValueError:
            pass
        else:
            raise AssertionError("Protected package was stageable for hot patching")
        manager.set_operating_mode("autonomous")
        command(["systemctl", "start", "sonic-smart-patch"])
        deadline = time.monotonic()+300
        attempt = None
        while time.monotonic() < deadline:
            state = store.load()
            attempt = next((value for value in state.get("autonomous_attempts", {}).values()
                            if value.get("finding_id") in requested and value.get("package") == "smart-patch-testprobe"), None)
            if attempt and attempt.get("status") not in ("started", None):
                break
            time.sleep(1)
        command(["systemctl", "stop", "sonic-smart-patch"])
        if not attempt or attempt.get("status") != "pending_reassessment" or version("smart-patch-testprobe") != "1.1":
            raise AssertionError("Actual daemon autonomous fixture did not complete: "+json.dumps(attempt))
        if version("sonic-smart-patch-testprobe") != "1.0":
            raise AssertionError("Protected fixture was modified automatically")
        rollback = RemediationEngine(store, manager).rollback(attempt["plan_id"])
        if rollback["status"] != "rolled_back" or version("smart-patch-testprobe") != "1.0":
            raise AssertionError("Autonomous fixture rollback did not restore the marker")
        results["autonomous"] = {"daemon_executed":True, "attempt":attempt, "rollback_status":rollback["status"],
                                 "protected_package_unchanged":True, "maintenance_plan_id":plan["id"]}
        return results
    finally:
        command(["systemctl", "stop", "sonic-smart-patch"], check=False)
        manager.set("", "", "autonomous_allowlist", original.get("autonomous_allowlist", ""))
        manager.set_operating_mode(original["mode"])


def forced_health_rollback(folder, request):
    from smart_patch.storage import StateStore
    from smart_patch.remediation import RemediationEngine
    from smart_patch.validation import ValidationEngine
    store = StateStore()
    local_id = store.load().get("remote_plans", {}).get(request["plan_id"])
    engine = RemediationEngine(store)
    if not local_id:
        raise ValueError("An approved, staged fixture transaction is required")
    plan = engine._load(local_id)
    if plan["status"] != "staged" or plan["package"] != "smart-patch-testprobe" or folder.name not in plan["finding_id"]:
        raise ValueError("Only this run's harmless staged fixture can use fault injection")
    if {item["package"].split(":",1)[0] for item in plan["transaction"]} != {"smart-patch-testprobe"}:
        raise ValueError("Fault injection cannot affect unrelated dependency packages")
    class FailureOnce:
        def __init__(self):
            self.real = ValidationEngine()
            self.calls = 0
        def snapshot(self):
            result = self.real.snapshot()
            self.calls += 1
            if self.calls == 2:
                result["errors"].append("SYNTHETIC TEST: injected post-install validation failure; no routing/service fault created")
            return result
        compare = staticmethod(ValidationEngine.compare)
    injection = FailureOnce()
    engine.validation = injection
    started = time.monotonic()
    result = engine.apply(local_id, approved=True)
    if result["status"] != "rolled_back" or version("smart-patch-testprobe") != "1.0":
        raise AssertionError("Injected health failure did not trigger real retained-artifact rollback")
    if result.get("rollback_validation", {}).get("status") != "PASS":
        raise AssertionError("Real health did not recover after fixture rollback")
    return {"fixture":True, "fault_injection":"single test-only post-install validation error",
            "actual_package_restore":True, "validation_samples":injection.calls,
            "status":result["status"], "post_validation":result.get("post_validation"),
            "rollback_validation":result.get("rollback_validation"), "seconds":time.monotonic()-started}


def vex_fixture(folder, request):
    from smart_patch.storage import StateStore
    state = StateStore().load()
    finding = next((item for item in state.get("findings", []) if item.get("id") == request["finding_id"]), None)
    if not finding or folder.name not in finding["id"] or finding.get("package_name") != "smart-patch-testprobe":
        raise ValueError("Only this run's synthetic fixture can be asserted in the VEX test")
    if finding.get("applicability") != "not_affected":
        raise AssertionError("Service fixture exclusion did not reach the native cache")
    filename = folder.name+"-vex.json"
    output = command(["security", "export-vex", "--output", filename]).stdout.strip()
    expected = Path("/var/lib/sonic-smart-patch/vex") / filename
    if Path(output) != expected:
        raise AssertionError("Unexpected native VEX output path")
    document = json.loads(expected.read_text())
    matches = [item for item in document.get("vulnerabilities", []) if item.get("id") == finding["cve_id"]
               and {affected.get("ref") for affected in item.get("affects", [])} == {finding["component_id"]}]
    if len(matches) != 1 or matches[0].get("analysis", {}).get("state") != "not_affected":
        raise AssertionError("Native VEX did not preserve scoped fixture exclusion")
    if matches[0]["analysis"].get("justification") != "code_not_present":
        raise AssertionError("Native VEX justification was not mapped correctly")
    return {"fixture":True, "not_a_real_cve":True, "native_cli_executed":True,
            "bom_format":document.get("bomFormat"), "spec_version":document.get("specVersion"),
            "statement":matches[0], "file":str(expected)}


def main(request):
    run_id = request.get("run_id", "")
    if not re.fullmatch(r"smart-patch-acceptance-[0-9a-f]{12}", run_id):
        raise ValueError("Invalid run identifier")
    folder = Path("/var/lib/sonic-smart-patch-test") / run_id
    action = request["action"]
    if action == "prepare":
        return prepare(folder, request)
    if action == "cleanup":
        return cleanup(folder)
    if not (folder / "backup.json").exists():
        raise ValueError("Prepare and backup must succeed before mutations")
    if action == "sync":
        return sync(request.get("force", False))
    if action == "state":
        return state_summary()
    if action == "package":
        return package_change(folder, request)
    if action == "yang":
        return yang_check(folder, request)
    if action == "offline":
        return offline(folder)
    if action == "recover":
        return recover()
    if action == "low-memory":
        return low_memory_guard()
    if action == "resources":
        return resource_snapshot()
    if action == "health":
        return live_health()
    if action == "schedule":
        return scheduled_collection()
    if action == "autonomous-fixture":
        return autonomous_fixture(folder, request)
    if action == "forced-health-rollback":
        return forced_health_rollback(folder, request)
    if action == "vex-fixture":
        return vex_fixture(folder, request)
    if action == "mode":
        from smart_patch.config import ConfigManager
        if request["mode"] not in ("advisory", "assisted"):
            raise ValueError("Acceptance harness never enables autonomous mode")
        ConfigManager().set_operating_mode(request["mode"])
        return {"mode":request["mode"]}
    if action == "daemon":
        if request["operation"] not in ("start", "stop", "restart"):
            raise ValueError("Invalid daemon operation")
        command(["systemctl", request["operation"], "sonic-smart-patch"])
        return resource_snapshot()
    if action == "plan":
        return fixture_plan_state(folder, request)
    raise ValueError("Unknown acceptance operation")


if __name__ == "__main__":
    request = json.loads(base64.b64decode(sys.argv[1]))
    try:
        result = main(request)
        print("SMART_PATCH_RESULT="+json.dumps({"ok":True, "result":result}, separators=(",", ":")))
    except Exception as error:
        print("SMART_PATCH_RESULT="+json.dumps({"ok":False, "error":str(error)}, separators=(",", ":")))
        raise SystemExit(1)
