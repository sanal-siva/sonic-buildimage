"""Small remediation snapshots, offline CLI projection and outbound reporting.

Package work remains serialized by its maintenance lock. A separate reporting
thread can publish phase changes while the main sync waits for an APT command.
It never executes actions or changes inventory. Local plans remain the durable
outbox, and acknowledged report revisions are scoped to the enrollment epoch.
"""
import fcntl
import heapq
import json
import logging
import os
import re
import time
from pathlib import Path

import requests

from smart_patch.config import ConfigManager, public_config
from smart_patch.storage import StateStore, atomic_json, now, read_public_state

LOG = logging.getLogger("sonic-smart-patch")
MAX_PLANS = 256
MAX_REPORTS = 32
MAX_RESPONSE = 2 * 1024 * 1024
STATES = {"draft", "planned", "approved", "staging", "downloading", "downloaded", "staged",
          "installing", "installed", "restarting", "pending_reassessment", "failed", "staging_failed",
          "denied", "rollback_required", "rolling_back", "rolled_back", "rollback_failed",
          "rollback_unknown", "unknown", "cancelled", "expired"}
ROW_FIELDS = ("id", "device_id", "hostname", "origin", "plan_id", "local_plan_id", "finding_id",
              "finding_ids", "component_id", "package_name", "scope", "cve_id", "cve_ids",
              "from_version", "target_version", "observed_version", "current_version", "state",
              "status", "collector_state", "applicability", "finding_status", "current_matching_finding",
              "updated_at", "report_revision", "progress", "central_resolution", "reassessment", "rollback")


def _sanitize(value, credential="", depth=0):
    if depth > 6:
        return None
    if isinstance(value, str):
        value = value[:2048]
        if credential and len(credential) >= 8:
            value = value.replace(credential, "[redacted]")
        return re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
    if isinstance(value, dict):
        return {str(k)[:64]: _sanitize(v, credential, depth + 1) for k, v in list(value.items())[:64]
                if str(k) not in ("token", "auth_token", "password", "credentials", "path")}
    if isinstance(value, list):
        return [_sanitize(v, credential, depth + 1) for v in value[:100]]
    return value if value is None or isinstance(value, (bool, int, float)) else None


def _report(plan, credential=""):
    fields = {key: plan.get(key) for key in ("scope", "from_version", "target_version", "component_id",
              "inventory_digest", "inventory_epoch", "build_id", "created_at", "updated_at")}
    fields.update(local_plan_id=plan.get("id"), revision=plan.get("revision", 1),
                  origin=plan.get("origin", "cli"), package_name=plan.get("package", plan.get("package_name")),
                  architecture=plan.get("architecture") or "", finding_ids=plan.get("finding_ids") or [plan.get("finding_id")],
                  cve_ids=plan.get("cve_ids", []), status={"applying": "installing"}.get(plan.get("status"), plan.get("status")))
    if fields["status"] not in STATES:
        fields["status"] = "unknown"
    for key in ("service_plan_id", "request_id"):
        if plan.get(key):
            fields[key] = plan[key]
    if plan.get("container_identity"):
        fields["container_identity"] = plan["container_identity"]
    detail_keys = ("maintenance_checks_enabled", "checks_skipped", "rollback_available", "rollback_missing",
                   "container", "container_identity", "container_restart", "writable_layer_warning", "pre_validation",
                   "post_validation", "error", "rollback_error", "download_error")
    details = {key: plan[key] for key in detail_keys if key in plan}
    artifacts = plan.get("artifacts", {})
    retained = [{key: a[key] for key in ("package", "version", "architecture", "sha256", "source") if key in a}
                for a in artifacts.get("rollback", [])[:64]]
    fields["rollback"] = {"available": plan.get("rollback_available"),
                          "missing": plan.get("rollback_missing", []), "artifacts": retained}
    fields["progress"] = {"events": plan.get("history", [])[-32:], "details": details,
                          "forward_packages": [{k: a[k] for k in ("package", "version", "sha256", "source") if k in a}
                                               for a in artifacts.get("forward", [])[:64]]}
    if plan.get("transaction") or plan.get("staged_at") or plan.get("status") == "staged":
        fields["staging_result"] = {"status": "staged" if plan.get("staged_at") else plan.get("status"),
                                    "details": {**details, "rollback": fields["rollback"]}}
    if plan.get("started_at") or plan.get("completed_at"):
        fields["execution_result"] = {"status": fields["status"], "details": details}
    return _sanitize(fields, credential)


def publish_plan(plan, directory, config=None):
    """Publish a bounded public snapshot without acquiring the shared state lock."""
    if not re.fullmatch(r"[0-9a-f-]{36}", str(plan.get("id", ""))):
        return False
    try:
        credential = config.get_auth_token() if config else ""
        report = _report(plan, credential or "")
        path = Path(directory) / "remediation-public"
        if path.is_symlink():
            raise ValueError("Public remediation directory cannot be a symbolic link")
        path.mkdir(mode=0o755, exist_ok=True)
        # The daemon uses UMask=0077; the filtered public directory must remain
        # traversable by the unprivileged native show command.
        path.chmod(0o755)
        atomic_json(path / (plan["id"] + ".json"), report, mode=0o644)
        return True
    except (OSError, ValueError, TypeError) as error:
        # The authoritative private plan is already persisted. A display/cache
        # problem must never turn a successful installation into a rollback.
        LOG.warning("Remediation public snapshot deferred: %s", type(error).__name__)
        return False


def _newest_files(directory, public=False):
    path = Path(directory) / ("remediation-public" if public else "plans")
    if not path.is_dir():
        return []
    candidates = []
    for item in path.iterdir():
        target = item if public else item / "plan.json"
        try:
            if (item.is_symlink() or target.is_symlink() or not target.is_file() or
                    target.stat().st_size > 512 * 1024):
                continue
            candidates.append((target.stat().st_mtime_ns, str(target)))
        except OSError:
            continue
    return [Path(name) for _, name in heapq.nlargest(MAX_PLANS, candidates)]


def local_reports(store, config=None):
    credential = config.get_auth_token() if config else ""
    reports = []
    for path in _newest_files(store.directory):
        try:
            plan = json.loads(path.read_text())
            report = _report(plan, credential or "")
            # Legacy files without their original identity are useful locally,
            # but must never be relabelled as a newly enrolled device's action.
            required = ("local_plan_id", "scope", "package_name", "from_version", "target_version",
                        "component_id", "inventory_digest", "inventory_epoch", "build_id")
            if (any(not report.get(key) for key in required) or not report.get("cve_ids") or
                    not all(report.get("finding_ids", [])) or
                    (report["origin"] == "service" and (not report.get("service_plan_id") or not report.get("request_id")))):
                continue
            if len(json.dumps(report)) > 60000:
                report["progress"] = {"events": plan.get("history", [])[-8:], "details": {"report_truncated": True}}
                report.pop("staging_result", None)
                report.pop("execution_result", None)
            reports.append(report)
        except (OSError, ValueError, TypeError):
            continue
    return reports


def _local_rows(reports, device_id=None):
    rows = []
    for report in reports:
        for cve in report.get("cve_ids", []):
            rows.append({**report, "id": "local:" + report["local_plan_id"] + ":" + cve,
                         "device_id": device_id, "plan_id": report.get("service_plan_id"),
                         "state": report["status"], "cve_id": cve, "cve_ids": [cve],
                         "report_revision": report["revision"], "central_resolution": {}, "reassessment": {}})
    return rows


def _merge_rows(state, reports):
    rows = [{key: row[key] for key in ROW_FIELDS if key in row} for row in state.get("remediation_status", [])[:1000]]
    local = _local_rows(reports, state.get("device_id"))
    lookup = {(r.get("local_plan_id"), r.get("cve_id")): index for index, r in enumerate(rows)}
    for row in local:
        key = (row["local_plan_id"], row["cve_id"])
        index = lookup.get(key)
        if index is None:
            lookup[key] = len(rows)
            rows.append(row)
        elif row["report_revision"] > (rows[index].get("report_revision") or 0):
            rows[index] = row
    covered = {(row.get("component_id"), row.get("cve_id")) for row in rows}
    for finding in state.get("findings", [])[:1000]:
        if (finding.get("component_id"), finding.get("cve_id")) not in covered:
            rows.append({"id": finding.get("id"), "device_id": state.get("device_id"),
                         "origin": "inventory", "finding_id": finding.get("id"), "cve_id": finding.get("cve_id"),
                         "cve_ids": [finding.get("cve_id")], "component_id": finding.get("component_id"),
                         "package_name": finding.get("package_name"), "scope": finding.get("scope"),
                         "state": "no_plan", "status": "no_plan", "applicability": finding.get("applicability"),
                         "from_version": finding.get("affected_version"), "updated_at": finding.get("assessed_at")})
    planned = {(row.get("component_id"), row.get("cve_id")) for row in rows if row.get("origin") != "inventory"}
    return [row for row in rows if row.get("origin") != "inventory" or
            (row.get("component_id"), row.get("cve_id")) not in planned]


def _cached_status(directory, state):
    try:
        saved = json.loads((Path(directory) / "remediation-status.json").read_text())
        if saved.get("device_id") == state.get("device_id") and saved.get("epoch") == state.get("epoch"):
            state.update(saved)
    except (OSError, ValueError):
        pass
    return state


def get_status(store=None, config=None, cve=None, scope=None, status=None):
    directory = store.directory if store else Path(os.getenv("SMART_PATCH_STATE_DIR", "/var/lib/sonic-smart-patch"))
    if store is not None:
        state = store.load()
        reports = local_reports(store, config)
    else:
        state = read_public_state(directory)
        reports = []
        for path in _newest_files(directory, public=True):
            try:
                reports.append(json.loads(path.read_text()))
            except (OSError, ValueError):
                continue
    _cached_status(directory, state)
    values = config.values() if config else public_config()
    reports = [report for report in reports if not state.get("epoch") or report.get("inventory_epoch") == state["epoch"]]
    rows = _merge_rows(state, reports)
    rows = [row for row in rows if (not cve or cve.lower() in str(row.get("cve_id", "")).lower())
            and (not scope or row.get("scope") == scope) and (not status or row.get("state") == status)]
    rows.sort(key=lambda row: (row.get("updated_at") or "", str(row.get("id"))), reverse=True)
    return {"rows": rows[:1000], "maintenance_mode": values.get("maintenance_mode", "false") == "true",
            "sync_status": state.get("sync_status", "unknown"), "assessed_at": state.get("remediation_updated_at"),
            "truncated": len(rows) > 1000 or state.get("remediation_truncated", False)}


class RemediationReporter:
    def __init__(self, config=None, store=None, session=None):
        self.config = config or ConfigManager()
        self.store = store or StateStore()
        self.session = session or requests.Session()
        self._owns_session = session is None
        self._last_send = 0
        self._last_metadata = None

    def _identity(self):
        path = self.store.directory / "remediation-identity.json"
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            # Wait for a validated ordinary inventory ACK after upgrade. Never
            # contend with collection on the complete inventory's state lock.
            return {}

    def _containers(self):
        from smart_patch.collector import run
        from smart_patch.maintenance_resources import CONTAINER_FORMAT
        try:
            ids = run(["docker", "ps", "--format", "{{.ID}}"], timeout=5, limit=16384).splitlines()[:128]
            if not ids or any(not re.fullmatch(r"[0-9a-f]{12,64}", ident) for ident in ids):
                return {}
            lines = run(["docker", "inspect", "--format", CONTAINER_FORMAT] + ids,
                        timeout=8, limit=128 * 1024).splitlines()
            result = {}
            for line in lines[:128]:
                value = json.loads(line)
                name = str(value.get("name", "")).lstrip("/")
                if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) and value.get("running") is True
                        and isinstance(value.get("pid"), int) and value["pid"] > 0
                        and re.fullmatch(r"[0-9a-f]{64}", str(value.get("id", "")))
                        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("image", "")))):
                    result["container:" + name] = {key: value[key] for key in ("id", "image", "name", "running", "pid")}
            return result
        except (OSError, ValueError, RuntimeError, KeyError):
            # Missing identity never enables container maintenance centrally.
            return {}

    def report_once(self):
        values = self.config.values()
        if values.get("enabled") != "true":
            return {"disabled": True}
        with (self.store.directory / "remediation-report.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state = self._identity()
            required = ("device_id", "epoch", "build_id", "acknowledged_digest")
            if any(not state.get(key) for key in required):
                return {"waiting_for_inventory": True}
            token = self.config.get_auth_token()
            url = values.get("service_url")
            if not token or not url:
                return {"unconfigured": True}
            if not url.startswith("https://") and values.get("allow_http") != "true":
                raise ValueError("HTTPS is required for remediation reporting")
            endpoint = url.rstrip("/") + ("" if url.rstrip("/").endswith("/api/v1") else "/api/v1") + "/agents/remediation"
            identity = (state["device_id"], state["epoch"], state["build_id"])
            journal_path = self.store.directory / "remediation-reporter.json"
            try:
                journal = json.loads(journal_path.read_text())
            except (OSError, ValueError):
                journal = {}
            acknowledgement = journal.get("ack", {}) if journal.get("identity") == list(identity) else {}
            all_reports = local_reports(self.store, self.config)
            reports = [r for r in all_reports
                       if r["inventory_epoch"] == state["epoch"] and r["build_id"] == state["build_id"]
                       and r["revision"] > acknowledgement.get(r["local_plan_id"], 0)][:MAX_REPORTS]
            from smart_patch.maintenance_resources import container_maintenance_available
            container_capability = int(container_maintenance_available())
            metadata = {"device_id": identity[0], "epoch": identity[1], "build_id": identity[2],
                    "inventory_digest": state["acknowledged_digest"],
                    "maintenance_mode": values.get("maintenance_mode", "false") == "true",
                    "capabilities": {"container_package_update": container_capability, "local_plan_reporting": 1}}
            active = any(r["status"] in ("staging", "downloading", "installing", "installed", "restarting", "pending_reassessment")
                         for r in all_reports)
            if (not reports and metadata == self._last_metadata and
                    time.monotonic() - self._last_send < (5 if active else 30)):
                return {"unchanged": True}
            body = {**metadata, "containers": self._containers() if container_capability else {}, "reports": reports}
            response = self.session.post(endpoint, json=body, headers={"Authorization": "Bearer " + token},
                                         timeout=(3, 10), verify=values.get("ca_bundle") or True,
                                         allow_redirects=False, stream=True)
            try:
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_content(65536):
                    data.extend(chunk)
                    if len(data) > MAX_RESPONSE:
                        raise ValueError("Remediation status response exceeds the collector budget")
                result = json.loads(data)
            finally:
                response.close()
            current = self._identity()
            if (current.get("device_id"), current.get("epoch"), current.get("build_id")) != identity:
                return {"identity_changed": True}
            sent = {r["local_plan_id"]: r["revision"] for r in reports}
            for ack in result.get("accepted", [])[:MAX_REPORTS]:
                if sent.get(ack.get("local_plan_id")) == ack.get("revision"):
                    acknowledgement[ack["local_plan_id"]] = ack["revision"]
            saved_journal = {"identity": list(identity), "ack": dict(list(acknowledgement.items())[-MAX_PLANS:])}
            if saved_journal != journal:
                atomic_json(journal_path, saved_journal)
            rows = [_sanitize({key: row[key] for key in ROW_FIELDS if key in row}, token)
                    for row in result.get("remediation_status", [])[:1000]]
            cached = {"device_id": identity[0], "epoch": identity[1], "remediation_status": rows,
                      "remediation_truncated": bool(result.get("remediation_truncated", False))}
            cache_path = self.store.directory / "remediation-status.json"
            try:
                previous = json.loads(cache_path.read_text())
            except (OSError, ValueError):
                previous = {}
            if {k: v for k, v in previous.items() if k != "remediation_updated_at"} != cached:
                cached["remediation_updated_at"] = now()
                atomic_json(cache_path, cached, mode=0o644)
            self._last_metadata, self._last_send = metadata, time.monotonic()
            return result

    def run(self, stop):
        while not stop.is_set():
            try:
                self.report_once()
            except Exception as error:
                # Durable plan snapshots survive connection failure. Never let
                # reporting failures retry or fail a package operation.
                LOG.debug("Remediation reporting deferred: %s", type(error).__name__)
            stop.wait(5)
        if self._owns_session:
            self.session.close()
