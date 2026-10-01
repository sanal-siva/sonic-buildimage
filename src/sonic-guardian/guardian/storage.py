"""Crash-safe state with a separate lock spanning complete transactions."""
import contextlib
import fcntl
import json
import hashlib
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".guardian-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, separators=(",", ":"), sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _fingerprint(value):
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"))
    for chunk in encoder.iterencode(value):
        digest.update(chunk.encode())
    return digest.digest()


class StateStore:
    def __init__(self, directory=None):
        self.directory = Path(directory or os.getenv("GUARDIAN_STATE_DIR", "/var/lib/sonic-guardian"))
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "state.json"

    @contextlib.contextmanager
    def transaction(self):
        with (self.directory / "state.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                state = json.loads(self.path.read_text()) if self.path.exists() else {}
                previous = _fingerprint(state)
                yield state
                if _fingerprint(state) != previous:
                    atomic_json(self.path, state)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def load(self):
        # Reads share the dedicated lock but never serialize, replace or fsync
        # the inventory. A status read must not become a flash write.
        with (self.directory / "state.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            try:
                return json.loads(self.path.read_text()) if self.path.exists() else {}
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def public_snapshot(state, credentials=()):
    """Project only operational fields; never publish config, actions or raw facts."""
    scalar_fields = ("device_id", "epoch", "sequence", "build_id", "sync_status", "assessment_status",
                     "assessment_revision", "last_sync", "collected_at", "inventory_digest",
                     "assessed_inventory_digest", "findings_total", "findings_truncated", "cache_status", "cache_omitted_count", "retained_last_known_count")
    result = {key: state[key] for key in scalar_fields if key in state and isinstance(state[key], (str, int, float, bool, type(None)))}
    result["component_count"] = len(state.get("inventory", {}))
    result["clock_alignment"] = {key: value for key,value in state.get("clock_alignment", {}).items()
                                  if key in ("status", "offset_seconds", "uncertainty_seconds", "round_trip_seconds", "device_calibrated_at", "server_time")
                                  and isinstance(value, (str, int, float))}
    result["error"] = "Synchronization failed; consult the Guardian service journal" if state.get("error") else None
    result["resources"] = {key: value for key, value in state.get("resources", {}).items()
                           if key in ("rss_bytes", "cpu_seconds", "collection_seconds") and isinstance(value, (int, float))}
    result["coverage"] = {key: value for key, value in state.get("coverage", {}).items()
                          if key in ("complete", "scopes_total", "scopes_scanned", "components_scanned", "components_total") and isinstance(value, (bool, int, float))}
    result["scopes"] = [{key: item[key] for key in ("scope", "status", "packages", "image_digest")
                          if key in item and isinstance(item[key], (str, int, type(None)))} for item in state.get("scopes", [])[:128]]
    from guardian.decision import current_finding
    finding_fields = ("id", "cve_id", "component_id", "scope", "package_name", "affected_version", "severity",
                      "cvss_score", "applicability", "exposure", "rationale", "assessed_at", "inventory_digest", "action_type", "cache_state", "vex_justification", "justification", "decision_valid_until", "verdict_validity", "previous_applicability",
                      "decision_basis", "artifact_binding", "build_evidence_policy", "remediation_eligible", "remediation_reason")
    findings = []
    for item in state.get("findings", [])[:1000]:
        item = current_finding(item, state.get("clock_alignment", {}))
        finding = {key:item[key] for key in finding_fields if key in item and isinstance(item[key], (str, int, float, type(None)))}
        versions = item.get("fixed_versions") or []
        finding["fixed_versions"] = [value for value in versions[:32] if isinstance(value, str)] if isinstance(versions, list) else []
        evidence = item.get("evidence") or item.get("evidence_ids") or []
        if not isinstance(evidence, list):
            evidence = []
        references = [value if isinstance(value, str) else value.get("id", value.get("evidence_id", "unknown"))
                      for value in evidence[:64] if isinstance(value, (str, dict))]
        finding["evidence"] = [value for value in references if isinstance(value, str)]
        findings.append(finding)
    result["findings"] = findings
    pending = state.get("pending", {})
    result["pending_summary"] = {"kind": pending.get("kind"), "upserts":len(pending.get("components", [])),
                                 "removals":len(pending.get("removed", []))}
    # Defense in depth for server-supplied display text accidentally containing
    # the local credential. The allowlist above excludes all secret-bearing data.
    def scrub(value):
        if isinstance(value, str):
            for credential in credentials:
                if credential and len(credential) >= 8:
                    value = value.replace(credential, "[redacted]")
            return value
        if isinstance(value, dict):
            return {key:scrub(item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value
    return scrub(result)


def read_public_state(directory=None):
    """Atomic snapshots are readable without acquiring any writable state lock."""
    path = Path(directory or os.getenv("GUARDIAN_STATE_DIR", "/var/lib/sonic-guardian")) / "public.json"
    try:
        state = json.loads(path.read_text())
        from guardian.decision import current_finding
        state["findings"] = [current_finding(item, state.get("clock_alignment", {})) for item in state.get("findings", [])]
        state["expired_or_unverifiable_verdicts"] = sum(item.get("verdict_validity") in ("expired", "clock_unknown", "invalid_deadline") for item in state["findings"])
        return state
    except FileNotFoundError:
        return {}
