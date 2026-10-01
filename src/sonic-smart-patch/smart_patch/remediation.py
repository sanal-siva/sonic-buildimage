"""Exact-version maintenance transactions with optional operational checks.

Automated package changes require explicit deployment policy; image/kernel and
routing changes remain reviewed SONiC image maintenance operations.
"""
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from smart_patch.collector import run, digest
from smart_patch.config import ConfigManager
from smart_patch.storage import StateStore, atomic_json, now
from smart_patch.validation import ValidationEngine
from smart_patch.decision import current_finding, decision_validity
from smart_patch.maintenance_resources import MaintenanceCommandRunner

PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?$")
VERSION = re.compile(r"^[0-9A-Za-z.+:~_-]+$")
HIGH_IMPACT = re.compile(r"^(linux-|frr|libssl|openssl|libc6|systemd|docker|sonic-|swss|syncd)")

OPTIONAL_CHECKS = ["minimum_free_space", "installed_version", "inventory_freshness", "scope_coverage", "decision_expiry",
                   "dependency_policy", "artifact_hashes", "rollback_package_availability",
                   "pre_install_health", "post_install_health", "post_install_version"]


def maintenance_checks_enabled(config):
    value = config.values().get("maintenance_checks_enabled", "false")
    if value not in ("true", "false"):
        raise ValueError("maintenance_checks_enabled must be true or false")
    return value == "true"


def remediation_eligible(finding):
    """Inventory-only advisory matches need a scoped review before maintenance.

    Older services omit these fields, so their existing eligibility is preserved.
    An explicit approval of a plan does not replace review of its assessment.
    """
    return (finding.get("remediation_eligible") is not False
            and finding.get("decision_basis") != "inventory_advisory_match")


class RemediationEngine:
    def __init__(self, store=None, config=None, runner=run):
        self.store = store or StateStore()
        self.config = config or ConfigManager()
        self.runner = MaintenanceCommandRunner(self.config) if runner is run else runner
        self.directory = (self.store.directory / "plans").resolve()
        self.directory.mkdir(exist_ok=True)
        self.validation = ValidationEngine(self.runner, self.config)

    @contextmanager
    def _maintenance_lock(self):
        with (self.directory / "maintenance.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            previous = getattr(self, "_phase_checks", None)
            self._phase_checks = maintenance_checks_enabled(self.config)
            try:
                yield
            finally:
                self._phase_checks = previous

    def _checks_enabled(self):
        value = getattr(self, "_phase_checks", None)
        return maintenance_checks_enabled(self.config) if value is None else value

    def _check_free_space(self):
        try:
            minimum = int(self.config.values().get("maintenance_min_free_mib", "500"))
        except (TypeError, ValueError) as error:
            raise ValueError("maintenance_min_free_mib must be an integer between 1 and 65536") from error
        if not 1 <= minimum <= 65536:
            raise ValueError("maintenance_min_free_mib must be between 1 and 65536")
        if shutil.disk_usage(self.directory).free < minimum * 1024**2:
            raise ValueError("At least %d MiB of staging free space is required" % minimum)

    @staticmethod
    def _require_host(plan):
        if plan.get("scope") != "host":
            raise ValueError("Container packages require reviewed image maintenance; automatic staging and installation support host packages only")

    def _path(self, plan_id):
        if not re.fullmatch(r"[0-9a-f-]{36}", plan_id):
            raise ValueError("Invalid plan identifier")
        return self.directory / plan_id / "plan.json"

    def _save(self, plan):
        atomic_json(self._path(plan["id"]), plan)
        return plan

    def _load(self, plan_id):
        return json.loads(self._path(plan_id).read_text())

    def _prefix(self, scope):
        if scope == "host":
            return []
        if not re.fullmatch(r"container:[A-Za-z0-9][A-Za-z0-9_.-]*", scope):
            raise ValueError("Invalid remediation scope")
        return ["docker", "exec", scope.split(":", 1)[1]]

    def create_plan(self, finding_id, target_version):
        state = self.store.load()
        candidates = [item for item in state.get("findings", []) if item.get("id") == finding_id]
        if not candidates and finding_id in state.get("plan_findings", {}):
            candidates = [state["plan_findings"][finding_id]]
        if len(candidates) != 1:
            raise ValueError("An exact current finding ID is required")
        checks = self._checks_enabled()
        finding = current_finding(candidates[0], state.get("clock_alignment", {})) if checks else candidates[0]
        if finding.get("applicability") != "affected":
            raise ValueError("Only affected findings are eligible for remediation")
        if not remediation_eligible(finding):
            raise ValueError("Inventory-only advisory matches require scoped operator review before remediation")
        if target_version not in finding.get("fixed_versions", []):
            raise ValueError("Target must be an advisory-supported fixed version")
        name, scope = finding["package_name"], finding["scope"]
        if not PACKAGE.fullmatch(name) or not VERSION.fullmatch(target_version):
            raise ValueError("Invalid package/version")
        self._prefix(scope)
        if checks:
            try:
                self.runner(["dpkg", "--compare-versions", target_version, "gt", finding["affected_version"]], timeout=5)
            except Exception as error:
                raise ValueError("A maintenance update must select a newer Debian fixed version") from error
        plan = {"schema_version": 1, "id": str(uuid.uuid4()), "finding_id": finding_id,
                "scope": scope, "package": name, "from_version": finding["affected_version"], "target_version": target_version,
                "inventory_digest": state.get("inventory_digest"), "created_at": now(), "status": "planned",
                "impact": "image_maintenance" if HIGH_IMPACT.match(name) or scope != "host" else "package_update",
                "evidence": finding.get("evidence", []), "approval": None,
                "decision_valid_until":finding.get("decision_valid_until"),
                "required_checks": ["authorized exact target", "APT transaction resolution", "central reassessment"],
                "optional_checks": list(OPTIONAL_CHECKS), "maintenance_checks_enabled": checks}
        for key in ("decision_basis", "remediation_eligible"):
            if key in finding:
                plan[key] = finding[key]
        return self._save(plan)

    def _verify_current(self, plan):
        state = self.store.load()
        finding_id = plan.get("finding_id")
        findings = [item for item in state.get("findings", []) if item.get("id") == finding_id]
        if not findings and finding_id in state.get("plan_findings", {}):
            findings = [state["plan_findings"][finding_id]]
        if not remediation_eligible(plan) or any(not remediation_eligible(item) for item in findings):
            raise ValueError("Inventory-only advisory matches require scoped operator review before remediation")
        if not self._checks_enabled():
            return
        observed = self.runner(self._prefix(plan["scope"]) + ["dpkg-query", "-W", "-f=${Version}", plan["package"]]).strip()
        if observed != plan["from_version"]:
            raise ValueError("Installed package version differs from approved plan")
        if state.get("inventory_digest") != plan["inventory_digest"]:
            raise ValueError("Inventory changed after planning")
        if decision_validity(plan, state.get("clock_alignment", {})) not in ("not_time_limited", "current"):
            raise ValueError("Supporting assessment expired or its validity cannot be verified")

    def _transaction(self, plan):
        prefix = self._prefix(plan["scope"])
        target = plan["package"] + "=" + plan["target_version"]
        checks = self._checks_enabled()
        output = self.runner(prefix + ["apt-get", "-s"] + (["--no-remove"] if checks else []) + ["install", target], timeout=60, limit=1048576)
        changes = []
        removed = [line for line in output.splitlines() if line.startswith("Remv ")]
        if checks and removed:
            raise ValueError("Plan would remove packages")
        plan["transaction_removed"] = removed
        for line in output.splitlines():
            match = re.match(r"^Inst ([^ ]+)(?: \[([^]]+)\])? \(([^ ]+)", line)
            if match:
                name, old, new = match.groups()
                if not PACKAGE.fullmatch(name) or not VERSION.fullmatch(new):
                    raise ValueError("Invalid dependency transaction")
                # A newly installed dependency lacks a retained prior version and
                # needs an image transaction; package rollback must be complete.
                if checks and not old:
                    raise ValueError("New dependencies require reviewed image maintenance")
                changes.append({"package": name, "from_version": old, "to_version": new})
        if not changes:
            raise ValueError("APT simulation found no changes")
        if checks and any(HIGH_IMPACT.match(item["package"]) for item in changes):
            raise ValueError("Core/routing/kernel dependency requires reviewed SONiC image maintenance")
        return changes

    def _download(self, plan, change, direction):
        directory = self._path(plan["id"]).parent / direction
        directory.mkdir(exist_ok=True)
        version = change["to_version"] if direction == "forward" else change["from_version"]
        target = change["package"] + "=" + version
        if plan["scope"] == "host":
            # No shell interpretation; APT only downloads an exact version.
            try:
                self.runner(["apt-get", "download", target], cwd=directory, timeout=180, limit=1048576)
            except Exception as error:
                raise ValueError("Exact %s version download unavailable: %s; %s" % (direction, target, str(error)[:300])) from error
        else:
            name = plan["scope"].split(":", 1)[1]
            container_directory = "/var/tmp/sonic-smart-patch-" + plan["id"] + "/" + direction
            self.runner(["docker", "exec", name, "mkdir", "-p", container_directory])
            self.runner(["docker", "exec", "--workdir", container_directory, name, "apt-get", "download", target], timeout=180, limit=1048576)
            self.runner(["docker", "cp", name + ":" + container_directory + "/.", str(directory)], timeout=180)
        matches = []
        for artifact in directory.glob("*.deb"):
            fields = self.runner(["dpkg-deb", "-f", str(artifact), "Package", "Version"]).splitlines()
            info = dict(line.split(": ", 1) for line in fields if ": " in line)
            if info.get("Package") == change["package"].split(":")[0] and info.get("Version") == version:
                hasher = hashlib.sha256()
                with artifact.open("rb") as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        hasher.update(block)
                matches.append({"path": str(artifact), "sha256": hasher.hexdigest(), "package": change["package"], "version": version})
        if len(matches) != 1:
            raise ValueError("Exact downloaded package could not be verified")
        expected = plan.get("target_package_sha256")
        if self._checks_enabled() and expected and direction == "forward" and change["package"].split(":", 1)[0] == plan["package"].split(":", 1)[0]:
            if matches[0]["sha256"] != expected.removeprefix("sha256:").lower():
                raise ValueError("Downloaded target package differs from verified catalog SHA256")
            matches[0]["catalog_hash_verified"] = True
        return matches[0]

    def stage(self, plan_id):
        with self._maintenance_lock():
            return self._stage(plan_id)

    def _stage(self, plan_id):
        if self.config.get_operating_mode() == "advisory":
            raise ValueError("Advisory mode permits planning only; choose assisted to stage")
        plan = self._load(plan_id)
        self._require_host(plan)
        if plan["status"] != "planned":
            raise ValueError("Only planned maintenance can be staged")
        if plan["impact"] == "image_maintenance":
            raise ValueError("This plan requires a reviewed SONiC image maintenance procedure")
        checks = self._checks_enabled()
        plan.update(maintenance_checks_enabled=checks, staging_checks_enabled=checks,
                    checks_skipped=[] if checks else list(OPTIONAL_CHECKS))
        if checks:
            self._check_free_space()
        self._verify_current(plan)
        changes = self._transaction(plan)
        plan["transaction"] = changes
        # Forward packages are necessary to execute the requested operation.
        # Rollback availability is optional only when the local checks are off.
        plan["artifacts"] = {"forward": [self._download(plan, item, "forward") for item in changes], "rollback": []}
        plan["rollback_missing"] = []
        for item in changes:
            try:
                if not item.get("from_version"):
                    raise ValueError("New dependency has no previous package version")
                plan["artifacts"]["rollback"].append(self._download(plan, item, "rollback"))
            except Exception as error:
                if checks:
                    raise
                plan["rollback_missing"].append({"package": item["package"], "version": item.get("from_version"), "reason": str(error)[:500]})
        for item in plan.get("transaction_removed", []):
            plan["rollback_missing"].append({"package": item.split()[1], "version": None,
                "reason": "Transaction removes a package; automatic restoration of removals is not supported"})
        plan["rollback_available"] = self._rollback_available(plan)
        plan["transaction_digest"] = digest(changes)
        plan["status"] = "staged"
        plan["staged_at"] = now()
        return self._save(plan)

    def _install(self, plan, direction):
        artifacts = plan["artifacts"][direction]
        if not artifacts:
            raise ValueError("No staged %s package artifacts are available" % direction)
        checks = self._checks_enabled()
        if checks:
            for artifact in artifacts:
                hasher = hashlib.sha256()
                with open(artifact["path"], "rb") as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        hasher.update(block)
                if hasher.hexdigest() != artifact["sha256"]:
                    raise ValueError("Staged artifact digest changed")
        paths = [item["path"] for item in artifacts]
        prefix = self._prefix(plan["scope"])
        if prefix:
            name = plan["scope"].split(":", 1)[1]
            container_directory = "/var/tmp/sonic-smart-patch-" + plan["id"] + "/" + direction
            self.runner(prefix + ["mkdir", "-p", container_directory])
            paths = []
            for artifact in artifacts:
                target = container_directory + "/" + Path(artifact["path"]).name
                self.runner(["docker", "cp", artifact["path"], name + ":" + target], timeout=120)
                paths.append(target)
        cache_options = []
        if not prefix:
            # APT can prefer a configured repository record for a version even
            # when the same .deb is explicitly supplied. With --no-download,
            # that record must resolve in its archive cache. apt-get download
            # already gave these files canonical cache names (including encoded
            # epochs and the binary architecture); keep each direction isolated.
            cache_directory = (self._path(plan["id"]).parent / direction).resolve()
            if any(Path(path).resolve().parent != cache_directory for path in paths):
                raise ValueError("Staged artifacts must remain in this plan's %s directory" % direction)
            cache_options = ["-o", "Dir::Cache::Archives=" + str(cache_directory)]
        self.runner(prefix + ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "--no-download"]
                    + cache_options + (["--no-remove"] if checks else []) + ["--allow-downgrades", "install"] + paths, timeout=600, limit=2*1024*1024)
        if checks:
            for artifact in artifacts:
                observed = self.runner(prefix + ["dpkg-query", "-W", "-f=${Version}", artifact["package"]]).strip()
                if observed != artifact["version"]:
                    raise ValueError("Installed version failed verification for " + artifact["package"])

    @staticmethod
    def _rollback_available(plan):
        changes = plan.get("transaction", [])
        if not changes or plan.get("transaction_removed") or plan.get("rollback_missing"):
            return False
        artifacts = plan.get("artifacts", {}).get("rollback", [])
        return all(change.get("from_version") and any(a.get("package") == change["package"]
                    and a.get("version") == change["from_version"] and a.get("path")
                    and Path(a["path"]).is_file() for a in artifacts) for change in changes)

    def apply(self, plan_id, approved=False):
        with self._maintenance_lock():
            plan = self._load(plan_id)
            self._require_host(plan)
            mode = self.config.get_operating_mode()
            if mode == "advisory":
                raise ValueError("Advisory mode cannot apply maintenance")
            allowlist = self.config.values().get("autonomous_allowlist", "").split(",")
            policy_approved = mode == "autonomous" and plan["scope"] + "/" + plan["package"] in allowlist
            if not approved and not policy_approved:
                raise ValueError("Explicit approval or an exact scope/package autonomous policy is required")
            if plan["status"] != "staged":
                raise ValueError("A staged exact-version plan is required")
            checks = self._checks_enabled()
            plan.update(maintenance_checks_enabled=checks, checks_skipped=[] if checks else list(OPTIONAL_CHECKS))
            if checks:
                self._check_free_space()
            state = self.store.load()
            if checks and state.get("inventory_digest") != plan["inventory_digest"]:
                raise ValueError("Inventory changed after planning; create a new plan")
            self._verify_current(plan)
            plan["rollback_available"] = self._rollback_available(plan)
            if checks:
                if plan.get("staging_checks_enabled") is False:
                    raise ValueError("This plan was staged with maintenance checks disabled; create a fresh plan and stage it with checks enabled")
                if not plan["rollback_available"]:
                    raise ValueError("Complete rollback artifacts are required when maintenance checks are enabled; restage this plan")
                if digest(self._transaction(plan)) != plan["transaction_digest"]:
                    raise ValueError("Dependency transaction changed after staging")
                plan["pre_validation"] = self.validation.snapshot()
                if plan["pre_validation"]["errors"]:
                    raise ValueError("Cannot establish complete SONiC health baseline")
            else:
                plan["pre_validation"] = {"status": "SKIPPED", "errors": [], "reason": "maintenance_checks_enabled=false"}
            plan.update(status="applying", approval="operator" if approved else "autonomous_policy", started_at=now())
            self._save(plan)
            try:
                self._install(plan, "forward")
                if checks:
                    plan["post_validation"] = self.validation.compare(plan["pre_validation"], self.validation.snapshot())
                    if plan["post_validation"]["status"] != "PASS":
                        raise ValueError("Post-change SONiC health failed")
                else:
                    plan["post_validation"] = {"status": "SKIPPED", "reason": "maintenance_checks_enabled=false"}
                plan["status"] = "pending_reassessment"
                plan["completed_at"] = now()
                self._save(plan)
                (self.store.directory / "dirty").touch()
                return plan
            except Exception as error:
                if not plan["rollback_available"]:
                    plan.update(status="failed", error=str(error), rollback_error="Automatic rollback unavailable: complete previous-version artifacts were not staged")
                    plan["failed_at"] = now()
                    return self._save(plan)
                plan.update(status="rollback_required", error=str(error))
                self._save(plan)
                return self._rollback(plan_id)
            finally:
                # Even a failed transaction without rollback can change inventory.
                (self.store.directory / "dirty").touch()

    def rollback(self, plan_id):
        with self._maintenance_lock():
            return self._rollback(plan_id)

    def _rollback(self, plan_id):
        plan = self._load(plan_id)
        if plan["status"] not in ("applying", "rollback_required", "pending_reassessment", "rollback_failed"):
            raise ValueError("Plan is not eligible for rollback")
        if not self._rollback_available(plan):
            raise ValueError("Automatic rollback unavailable: complete previous-version artifacts were not staged")
        try:
            self._install(plan, "rollback")
            if self._checks_enabled() and plan.get("pre_validation", {}).get("status") != "SKIPPED":
                plan["rollback_validation"] = self.validation.compare(plan["pre_validation"], self.validation.snapshot())
                plan["status"] = "rolled_back" if plan["rollback_validation"]["status"] == "PASS" else "rollback_failed"
            else:
                plan["rollback_validation"] = {"status": "SKIPPED", "reason": "Maintenance health checks were disabled or no baseline was captured"}
                plan["status"] = "rolled_back"
        except Exception as error:
            plan.update(status="rollback_failed", rollback_error=str(error))
        plan["rollback_at"] = now()
        (self.store.directory / "dirty").touch()
        return self._save(plan)
