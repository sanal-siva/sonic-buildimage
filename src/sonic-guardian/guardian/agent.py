"""Durable checkpoint/delta synchronization with bounded offline state."""
import fcntl
import json
import os
import time
import uuid
from pathlib import Path
import requests
from guardian.collector import InventoryCollector, collect_evidence, identity, digest, run
from guardian.config import ConfigManager, PUBLIC_FIELDS
from guardian.storage import StateStore, now, atomic_json, public_snapshot
from guardian.timebase import calibrate, align_state


class Agent:
    def __init__(self, config=None, store=None, collector=None, session=None):
        self.config = config or ConfigManager()
        self.store = store or StateStore()
        self.collector = collector or InventoryCollector(max_components=int(self.config.values()["max_components"]))
        self.session = session or requests.Session()

    def _url(self):
        url = self.config.get_service_url()
        if not url:
            raise ValueError("Intelligence service URL is not configured")
        if url.startswith("http:") and self.config.values().get("allow_http") != "true":
            raise ValueError("HTTPS is required; explicitly set allow_http only for isolated labs")
        return url.rstrip("/") + ("" if url.rstrip("/").endswith("/api/v1") else "/api/v1") + "/agents/sync"

    def _collect(self, state):
        meminfo = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        if int(meminfo["MemAvailable"].split()[0]) < int(self.config.values()["min_available_mb"])*1024:
            raise RuntimeError("Inventory deferred: available memory below configured budget")
        result = self.collector.collect()
        fresh = {item["component_id"]: item for item in result["components"]}
        old = state.get("inventory", {})
        # An unreadable scope cannot prove removals. Keep its last known components
        # and send explicit unknown scope status; service must mark coverage stale.
        failures = {scope["scope"] for scope in result["scopes"] if scope["status"] != "complete"}
        for key, item in old.items():
            if key not in fresh and (item["scope"] in failures or ("containers" in failures and item["scope"].startswith("container:"))):
                fresh[key] = item
        state["inventory"] = fresh
        state["inventory_digest"] = digest(sorted(fresh.values(), key=lambda item: item["component_id"]))
        state["scopes"] = result["scopes"]
        state["resources"] = result["resources"]
        state["collected_at"] = result["collected_at"]
        state["device_collected_at"] = result["collected_at"]
        state["collection_time_basis"] = "device_unaligned"
        state["last_collection"] = time.time()
        state["facts"] = [{"fact_id": "inventory-coverage", "collector": "inventory", "scope": "device",
                           "value": result["scopes"], "status": "observed", "collected_at": result["collected_at"],
                           "inventory_digest": state["inventory_digest"]}]

    def _prepare(self, state, force=False):
        # Upgrade old journals without changing any committed wire digest. Keep
        # only fingerprints of acknowledged components, not a second inventory.
        if "acknowledged_inventory" in state:
            legacy = state.pop("acknowledged_inventory")
            state["acknowledged_fingerprints"] = {key:digest(item) for key,item in legacy.items()}
        device = identity(self.config.get_sbom_source(), self.config.directory)
        identity_changed = state.get("device_id") not in (None, device["device_id"])
        if identity_changed:
            # An operator may preserve an existing enrollment or rotate it during
            # clone recovery. Never replay another device's queued authorization.
            for field in ("pending", "findings", "assessed_inventory_digest", "assessment_revision",
                          "action_requests", "action_facts", "remote_plans", "plan_findings",
                          "evidence_requests", "autonomous_attempts"):
                state.pop(field, None)
            state["assessment_status"] = "unassessed"
        if state.get("pending"):
            return state["pending"]
        if state.get("build_id") != device["build_id"] or state.get("device_id") != device["device_id"]:
            state.update(epoch=str(uuid.uuid4()), sequence=0, acknowledged_fingerprints={}, acknowledged_digest="",
                         build_id=device["build_id"], device_id=device["device_id"])
        dirty = self.store.directory / "dirty"
        dirty_time = dirty.stat().st_mtime_ns if dirty.exists() else 0
        # Poll cheap container topology between full inventory passes. Metadata
        # inside unchanged containers is reconciled on the slower interval.
        topology_changed = False
        if hasattr(self.collector, "topology"):
            topology = self.collector.topology()
            topology_changed = topology != state.get("container_topology")
            state["container_topology"] = topology
        if force or not state.get("last_collection") or dirty_time > state.get("dirty_time", 0) or topology_changed or time.time()-state["last_collection"] >= int(self.config.values()["inventory_interval"]):
            self._collect(state)
            state["dirty_time"] = dirty_time
        requests = state.pop("evidence_requests", [])[:8]
        if requests:
            facts = {fact["fact_id"]: fact for fact in state.get("facts", [])}
            for request in requests:
                fact = collect_evidence(request, inventory_context=state)
                fact["inventory_digest"] = state["inventory_digest"]
                facts[fact["fact_id"]] = fact
            # Bound retained facts; inventory coverage remains the first record.
            state["facts"] = list(facts.values())[-32:]
        align_state(state)
        previous = state.get("acknowledged_fingerprints", {})
        current = state.get("inventory", {})
        components = [item for key, item in current.items() if previous.get(key) != digest(item)]
        removed = sorted(set(previous)-set(current))
        checkpoint = not state.get("sequence")
        kind = "checkpoint" if checkpoint else "delta" if components or removed else "heartbeat"
        sequence = state.get("sequence", 0) + (kind != "heartbeat")
        envelope = {"schema_version": 1, **device, "epoch": state["epoch"], "sequence": sequence,
            "kind": kind, "baseline_digest": state.get("acknowledged_digest", ""),
            "inventory_digest": state["inventory_digest"], "collected_at": state["collected_at"],
            "components": list(current.values()) if checkpoint else components, "removed": removed,
            "facts": state.get("facts", []) + state.get("action_facts", []), "resources": state.get("resources", {}),
            "clock_alignment": {**state.get("clock_alignment", {"status":"unknown", "reason":"no_authenticated_time"}),
                                "device_collected_at":state.get("device_collected_at"),
                                "collection_time_basis":state.get("collection_time_basis", "device_unaligned")}}
        state["pending"] = envelope
        return envelope

    def sync(self, force=False):
        # One process owns collect/send/ack; the state lock itself is not held over HTTP.
        with (self.store.directory / "sync.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                url = self._url()
                token = self.config.get_auth_token()
                if not token:
                    raise ValueError("Device token is not configured")
                self._process_actions()
                with self.store.transaction() as state:
                    envelope = self._prepare(state, force)
                ca = self.config.values().get("ca_bundle") or True
                sent_wall, sent_monotonic = time.time(), time.monotonic()
                response = self.session.post(url, json=envelope, headers={"Authorization": "Bearer " + token}, timeout=(5, 30), verify=ca, stream=True, allow_redirects=False)
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_content(65536):
                    body.extend(chunk)
                    if len(body) > 16*1024*1024:
                        raise ValueError("Service response exceeded 16 MiB budget")
                response.close()
                result = json.loads(body)
                received_wall, elapsed = time.time(), time.monotonic()-sent_monotonic
                clock = calibrate(result.get("service_time"), sent_wall, received_wall, elapsed,
                                  verified_transport=url.startswith("https://"))
                with self.store.transaction() as state:
                    if result.get("resync_required"):
                        state.update(epoch=str(uuid.uuid4()), sequence=0, acknowledged_fingerprints={})
                        state.pop("pending", None)
                        state["sync_status"] = "resync_required"
                        return result
                    if result.get("ack_sequence") != envelope["sequence"]:
                        raise ValueError("Server acknowledgement does not match pending sequence")
                    if result.get("inventory_digest") not in (None, envelope["inventory_digest"]):
                        raise ValueError("Server inventory digest mismatch")
                    state["clock_alignment"] = clock
                    # Only after a valid acknowledgement: mutate retained unsent
                    # evidence for the next heartbeat, never the retry envelope.
                    align_state(state)
                    state["sequence"] = envelope["sequence"]
                    state["acknowledged_fingerprints"] = {key:digest(item) for key,item in state["inventory"].items()}
                    state.pop("acknowledged_inventory", None)
                    state["acknowledged_digest"] = envelope["inventory_digest"]
                    state.pop("pending", None)
                    state.pop("action_facts", None)
                    state["last_sync"] = now()
                    state["sync_status"] = "connected"
                    state.pop("error", None)
                    state["assessment_status"] = result.get("assessment_status", "pending")
                    state["assessment_revision"] = result.get("assessment_revision")
                    state["findings_total"] = result.get("findings_total", len(result.get("findings", [])))
                    state["findings_truncated"] = result.get("findings_truncated", False)
                    state["coverage"] = result.get("coverage", {})
                    self._cache_findings(state, result, envelope["inventory_digest"])
                    state["evidence_requests"] = result.get("evidence_requests", [])[:8]
                    state["action_requests"] = result.get("action_requests", [])[:4]
                self.publish_status()
                return result
            except Exception as error:
                with self.store.transaction() as state:
                    state["sync_status"] = "stale"
                    state["error"] = str(error)[:250]
                    state["last_attempt"] = now()
                self.publish_status()
                raise
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @staticmethod
    def _cache_findings(state, result, inventory_digest):
        status = result.get("assessment_status")
        if "findings" not in result or status not in ("complete", "completed", "ready", "partial"):
            # Pending/failed work cannot erase observations or leave an older
            # inventory labelled current after drift.
            for finding in state.get("findings", []):
                if finding.get("inventory_digest") != inventory_digest:
                    finding["cache_state"] = "last_known"
            state["retained_last_known_count"] = sum(item.get("cache_state") == "last_known" for item in state.get("findings", []))
            if state.get("cache_omitted_count"):
                state["findings_truncated"] = True
            return
        incoming = [{**finding, "evidence": finding.get("evidence") or finding.get("evidence_ids", []),
                     "cache_state":"current" if finding.get("inventory_digest") == inventory_digest else "last_known"}
                    for finding in result["findings"] if isinstance(finding, dict) and finding.get("id")]
        if status == "partial":
            current_ids = {finding["id"] for finding in incoming}
            retained = [{**finding, "cache_state":"last_known"} for finding in state.get("findings", [])
                        if finding.get("id") not in current_ids]
            merged = incoming + retained
            state["findings"] = merged[:1000]
            state["cache_status"] = "partial_with_last_known_observations"
        else:
            merged = incoming
            state["findings"] = incoming[:1000]
            state["cache_status"] = "complete" if not result.get("findings_truncated") and len(incoming) <= 1000 else "truncated"
            state["assessed_inventory_digest"] = inventory_digest
        state["findings_truncated"] = bool(result.get("findings_truncated") or len(merged) > 1000)
        state["cache_omitted_count"] = max(0, len(merged)-1000)
        state["retained_last_known_count"] = sum(item.get("cache_state") == "last_known" for item in state["findings"])

    def _process_actions(self):
        from guardian.actions import ActionExecutor
        from guardian.remediation import maintenance_checks_enabled
        current = self.store.load()
        requests = current.get("action_requests", [])[:4]
        if not requests or current.get("pending"):
            return
        if current.get("device_id") != identity(self.config.get_sbom_source(), self.config.directory)["device_id"]:
            return
        # Full reconciliation is a local maintenance preflight when enabled.
        # Ordinary inventory scheduling continues independently in _prepare.
        if maintenance_checks_enabled(self.config):
            with self.store.transaction() as state:
                self._collect(state)
        executor = ActionExecutor(self.store, self.config)
        facts = [executor.execute(request) for request in requests]
        with self.store.transaction() as state:
            state["action_requests"] = []
            # Facts remain durable until the next acknowledgement.
            state["action_facts"] = facts

    def publish_status(self, configuration=None):
        state = self.store.load()
        configuration = configuration or self.config.values()
        if configuration["enabled"] != "true":
            state["sync_status"] = "disabled"
        token = self.config.get_auth_token()
        atomic_json(self.store.directory / "public.json", public_snapshot(state, credentials=(token,)), mode=0o644)
        atomic_json(self.config.directory / "public-config.json",
                    {key:configuration[key] for key in PUBLIC_FIELDS}, mode=0o644)
        values = {"sync_status": state.get("sync_status", "never_connected"), "last_sync": state.get("last_sync", "never"),
                  "assessment_status": state.get("assessment_status", "unassessed"),
                  "component_count": str(len(state.get("inventory", {}))), "finding_count": str(len(state.get("findings", []))),
                  "rss_bytes": str(state.get("resources", {}).get("rss_bytes", 0)),
                  "error": state.get("error", ""), "enabled":configuration["enabled"], "mode":configuration["mode"]}
        try:
            from swsscommon import swsscommon
            database = swsscommon.DBConnector("STATE_DB", 0, True)
            table = swsscommon.Table(database, "SONIC_GUARDIAN_STATUS")
            table.set("GLOBAL", swsscommon.FieldValuePairs(list(values.items())))
        except ImportError:
            pass
        except Exception:
            # Redis status is optional; the durable local state remains authoritative.
            pass
