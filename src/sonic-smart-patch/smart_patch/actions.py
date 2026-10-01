"""Idempotent execution of authenticated, explicitly approved maintenance requests."""
from datetime import datetime, timezone
import re
from smart_patch.remediation import RemediationEngine, remediation_eligible, maintenance_checks_enabled
from smart_patch.storage import now
from smart_patch.decision import current_finding


class ActionExecutor:
    def __init__(self, store, config, engine=None):
        self.store, self.config = store, config
        self.engine = engine or RemediationEngine(store, config)

    def execute(self, request):
        request_id = request.get("request_id")
        remote = request.get("plan", {})
        action = request.get("action")
        fact = {"fact_id": request_id, "collector": "remediation", "scope": remote.get("scope", "unknown"), "collected_at": now(),
                "value": {"plan_id": remote.get("id"), "action": action}}
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            fact.update(status="denied", error="Invalid action identifier")
            return fact
        try:
            state = self.store.load()
            checks = maintenance_checks_enabled(self.config)
            existing = state.get("action_journal", {}).get(request_id)
            if existing:
                if existing.get("fact"):
                    return existing["fact"]
                raise ValueError("Interrupted maintenance action requires operator recovery; it will not be replayed")
            if len(state.get("action_journal", {})) >= 1024:
                raise ValueError("Action journal capacity reached; administrative archival required")
            if action not in ("stage_plan", "execute_plan", "rollback_plan"):
                raise ValueError("Unknown maintenance action")
            if remote.get("device_id") != state.get("device_id"):
                raise ValueError("Plan belongs to a different device")
            if not remote.get("inventory_digest") or (checks and remote["inventory_digest"] != state.get("inventory_digest")):
                raise ValueError("Plan inventory is stale or missing")
            if checks and not any(item.get("scope") == remote.get("scope") and item.get("status") == "complete" for item in state.get("scopes", [])):
                raise ValueError("Current inventory coverage is incomplete for this scope")
            if remote.get("approved") is not True or not remote.get("approved_at"):
                raise ValueError("Explicit administrative approval is required")
            expiry = datetime.fromisoformat(remote.get("expires_at", "").replace("Z", "+00:00"))
            approved = datetime.fromisoformat(remote["approved_at"].replace("Z", "+00:00"))
            if expiry.tzinfo is None or approved.tzinfo is None or expiry <= datetime.now(timezone.utc) or approved > datetime.now(timezone.utc):
                raise ValueError("Plan approval expired or has an invalid timestamp")
            if self.config.get_operating_mode() == "advisory":
                raise ValueError("Advisory mode cannot execute maintenance requests")
            remote_id = str(remote.get("id", ""))
            if not remote_id or len(remote_id) > 128:
                raise ValueError("Invalid remote plan identifier")
            local_id = state.get("remote_plans", {}).get(remote_id)
            if local_id:
                plan = self.engine._load(local_id)
            else:
                if action == "rollback_plan":
                    raise ValueError("Rollback requires an existing local retained transaction")
                finding_id = remote.get("finding_id")
                if remote.get("finding"):
                    finding = remote["finding"]
                    component = state.get("inventory", {}).get(finding.get("component_id"))
                    if finding.get("id") != finding_id or (checks and (not component or finding.get("inventory_digest") != state["inventory_digest"])):
                        raise ValueError("Supplied finding does not match current component/inventory")
                    if (finding.get("scope"), finding.get("package_name"), finding.get("affected_version")) != (remote.get("scope"), remote.get("package_name"), remote.get("from_version")):
                        raise ValueError("Supplied finding does not match the approved package target")
                    if component and ((finding.get("scope"), finding.get("package_name")) != (component["scope"], component["name"])
                                      or (checks and finding.get("affected_version") != component["version"])):
                        raise ValueError("Supplied finding component identity mismatch")
                    if finding.get("applicability") != "affected" or remote.get("target_version") not in finding.get("fixed_versions", []):
                        raise ValueError("Supplied finding does not justify the selected fixed version")
                    if not remediation_eligible(finding):
                        raise ValueError("Inventory-only advisory matches require scoped operator review before remediation")
                    with self.store.transaction() as state:
                        cached = state.setdefault("plan_findings", {})
                        if finding_id not in cached and len(cached) >= 128:
                            raise ValueError("Maintenance finding cache capacity reached")
                        cached[finding_id] = finding
                        # An authenticated scoped review may be newer than the
                        # bounded finding cache delivered on an earlier poll.
                        state["findings"] = [finding if item.get("id") == finding_id else item for item in state.get("findings", [])]
                plan = self.engine.create_plan(remote.get("finding_id"), remote.get("target_version"))
                local_id = plan["id"]
            for local_key, remote_key in (("scope", "scope"), ("package", "package_name"), ("from_version", "from_version"), ("target_version", "target_version"), ("inventory_digest", "inventory_digest")):
                if local_key == "inventory_digest" and (action == "rollback_plan" or not checks):
                    continue
                if plan.get(local_key) != remote.get(remote_key):
                    raise ValueError("Plan identity or version mismatch: " + remote_key)
            expected_sha = remote.get("target_package_sha256")
            if expected_sha:
                if not isinstance(expected_sha, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", expected_sha):
                    raise ValueError("Invalid verified catalog target digest")
                expected_sha = expected_sha.removeprefix("sha256:").lower()
                if plan.get("target_package_sha256") not in (None, expected_sha):
                    raise ValueError("Verified target digest changed after local plan creation")
                if checks and plan.get("status") != "planned" and not plan.get("target_package_sha256"):
                    raise ValueError("A staged plan cannot acquire a different catalog verification basis")
                plan["target_package_sha256"] = expected_sha
                self.engine._save(plan)
            elif checks and plan.get("target_package_sha256"):
                raise ValueError("Verified target digest missing from previously verified plan")
            with self.store.transaction() as state:
                state.setdefault("remote_plans", {})[remote_id] = local_id
                state.setdefault("action_journal", {})[request_id] = {"status":"executing", "local_plan_id": local_id, "started_at":now(), "expires_at":remote["expires_at"]}
            if action == "stage_plan":
                result = self.engine.stage(local_id) if plan["status"] == "planned" else plan
                if result["status"] != "staged":
                    raise RuntimeError("Plan is not stageable: " + result["status"])
            elif action == "execute_plan":
                if plan["status"] == "planned":
                    self.engine.stage(local_id)
                result = self.engine.apply(local_id, approved=True)
            else:
                result = self.engine.rollback(local_id)
            successful = result["status"] in ("staged", "pending_reassessment", "rolled_back")
            fact["status"] = "complete" if successful else "failed"
            fact["value"].update(status=result["status"], local_plan_id=local_id,
                                 details={key:result[key] for key in ("error", "pre_validation", "post_validation", "rollback_validation", "rollback_error",
                                     "maintenance_checks_enabled", "checks_skipped", "rollback_available", "rollback_missing") if key in result})
        except ValueError as error:
            fact["status"] = "denied"
            fact["value"].update(status="denied", details=str(error))
        except Exception as error:
            fact["status"] = "failed"
            fact["value"].update(status="failed", details=str(error)[:500])
        with self.store.transaction() as state:
            journal = state.setdefault("action_journal", {})
            if request_id in journal or len(journal) < 1024:
                journal[request_id] = {"status": fact["status"], "fact":fact, "finished_at":now()}
        return fact


class AutonomousCoordinator:
    """One low-impact transaction per cycle, under an explicit exact allowlist."""
    def __init__(self, store, config, engine=None):
        self.store, self.config = store, config
        self.engine = engine or RemediationEngine(store, config)

    def run_once(self):
        if self.config.get_operating_mode() != "autonomous":
            return None
        allowlist = set(filter(None, self.config.values().get("autonomous_allowlist", "").split(",")))
        if not allowlist:
            return None
        state = self.store.load()
        if state.get("sync_status") != "connected" or state.get("assessment_status") not in ("complete", "completed", "ready"):
            return None
        if state.get("assessed_inventory_digest") != state.get("inventory_digest"):
            return None
        from smart_patch.collector import digest
        from smart_patch.remediation import HIGH_IMPACT
        attempts = state.get("autonomous_attempts", {})
        if len(attempts) >= 128:
            return None
        for stored_finding in state.get("findings", []):
            finding = current_finding(stored_finding, state.get("clock_alignment", {}))
            scope, package = finding.get("scope", ""), finding.get("package_name", "")
            if scope + "/" + package not in allowlist or HIGH_IMPACT.match(package) or finding.get("applicability") != "affected":
                continue
            if not remediation_eligible(finding):
                continue
            if not any(item.get("scope") == scope and item.get("status") == "complete" for item in state.get("scopes", [])):
                continue
            for target in finding.get("fixed_versions", []):
                key = digest([finding.get("id"), state["inventory_digest"], target])
                if key in attempts:
                    continue
                result = {"finding_id":finding.get("id"), "scope":scope, "package":package, "target_version":target, "started_at":now()}
                with self.store.transaction() as current:
                    current.setdefault("autonomous_attempts", {})[key] = {**result, "status":"started"}
                try:
                    plan = self.engine.create_plan(finding["id"], target)
                    result["plan_id"] = plan["id"]
                    self.engine.stage(plan["id"])
                    completed = self.engine.apply(plan["id"], approved=False)
                    result["status"] = completed["status"]
                except Exception as error:
                    result.update(status="failed", error=str(error)[:500])
                result["finished_at"] = now()
                with self.store.transaction() as current:
                    current.setdefault("autonomous_attempts", {})[key] = result
                return result
        return None
