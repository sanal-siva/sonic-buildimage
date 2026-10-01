"""Exercise optional maintenance preflights without running a package manager."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from smart_patch.actions import ActionExecutor
from smart_patch.agent import Agent
from smart_patch.config import ConfigManager
from smart_patch.remediation import RemediationEngine
from smart_patch.storage import StateStore


class PackageRunner:
    """A package-manager boundary fixture; the real engine owns all transitions."""
    def __init__(self):
        self.calls = []
        self.simulation = "Inst smart-patch-testprobe [1.0] (1.1 stable [amd64])\n"
        self.missing = set()
        self.versions = {"smart-patch-testprobe": "1.0"}
        self.install_failure = None

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:2] == ["apt-get", "-s"]:
            return self.simulation
        if argv[:2] == ["apt-get", "download"]:
            package, version = argv[2].split("=", 1)
            if (package, version) in self.missing:
                raise RuntimeError("Requested version is not available in configured repositories")
            path = Path(kwargs["cwd"]) / (package + "_" + version + ".deb")
            path.write_text(json.dumps({"package": package, "version": version}))
        elif argv[:2] == ["dpkg-deb", "-f"]:
            value = json.loads(Path(argv[2]).read_text())
            return "Package: " + value["package"] + "\nVersion: " + value["version"] + "\n"
        elif argv[0] == "dpkg-query":
            return self.versions.get(argv[-1], "unknown")
        elif argv[0] == "env":
            if self.install_failure:
                raise RuntimeError(self.install_failure)
            for path in argv[argv.index("install") + 1:]:
                value = json.loads(Path(path).read_text())
                self.versions[value["package"]] = value["version"]
        return ""


class MaintenanceChecksTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = ConfigManager(directory=root / "config")
        self.config.set_operating_mode("assisted")
        self.store = StateStore(root / "state")
        self.finding = {"id": "finding-one", "component_id": "component-one", "scope": "host",
                        "package_name": "smart-patch-testprobe", "affected_version": "1.0",
                        "fixed_versions": ["1.1"], "applicability": "affected", "inventory_digest": "inventory-one",
                        "decision_basis": "operator_review", "remediation_eligible": True}
        with self.store.transaction() as state:
            state.update(device_id="device-one", inventory_digest="inventory-one", findings=[self.finding],
                         scopes=[{"scope": "host", "status": "complete"}], inventory={"component-one": {
                             "component_id": "component-one", "scope": "host", "name": "smart-patch-testprobe", "version": "1.0"}})
        self.runner = PackageRunner()
        self.engine = RemediationEngine(self.store, self.config, self.runner)
        self.plan = self.engine.create_plan("finding-one", "1.1")

    def enabled(self):
        self.config.set("", "", "maintenance_checks_enabled", "true")

    def test_default_disabled_stages_stale_inventory_with_low_space_and_missing_rollback(self):
        self.assertEqual(self.config.values()["maintenance_checks_enabled"], "false")
        with self.store.transaction() as state:
            state["inventory_digest"] = "inventory-new"
        self.runner.versions["smart-patch-testprobe"] = "0.9"
        self.runner.missing.add(("smart-patch-testprobe", "1.0"))
        with patch("smart_patch.remediation.shutil.disk_usage", return_value=SimpleNamespace(free=0)) as disk:
            staged = self.engine.stage(self.plan["id"])
        disk.assert_not_called()
        self.assertEqual(staged["status"], "staged")
        self.assertFalse(staged["maintenance_checks_enabled"])
        self.assertFalse(staged["rollback_available"])
        self.assertEqual(staged["rollback_missing"][0]["version"], "1.0")
        self.assertIn("rollback_package_availability", staged["checks_skipped"])
        self.assertTrue(staged["artifacts"]["forward"])
        self.assertFalse(any(argv[0] == "dpkg-query" for argv in self.runner.calls))

    def test_default_disabled_installs_without_health_or_version_claims(self):
        self.runner.missing.add(("smart-patch-testprobe", "1.0"))
        self.engine.stage(self.plan["id"])
        with patch.object(self.engine.validation, "snapshot", side_effect=AssertionError("health must be skipped")) as health:
            result = self.engine.apply(self.plan["id"], approved=True)
        health.assert_not_called()
        self.assertEqual(result["status"], "pending_reassessment")
        self.assertEqual(result["pre_validation"]["status"], "SKIPPED")
        self.assertEqual(result["post_validation"]["status"], "SKIPPED")
        self.assertFalse(result["rollback_available"])
        self.assertEqual(self.runner.versions["smart-patch-testprobe"], "1.1")
        self.assertTrue((self.store.directory / "dirty").exists())
        self.assertFalse(any(argv[0] == "dpkg-query" for argv in self.runner.calls))

    def test_new_dependency_and_removal_are_recorded_without_claiming_rollback(self):
        self.runner.simulation += "Inst new-helper (2.0 stable [amd64])\nRemv old-helper [1.0]\n"
        staged = self.engine.stage(self.plan["id"])
        self.assertEqual(len(staged["artifacts"]["forward"]), 2)
        self.assertEqual({row["package"] for row in staged["rollback_missing"]}, {"new-helper", "old-helper"})
        self.assertFalse(staged["rollback_available"])
        self.assertEqual(staged["transaction_removed"], ["Remv old-helper [1.0]"])
        self.engine.apply(self.plan["id"], approved=True)
        self.assertFalse(any("--no-remove" in argv for argv in self.runner.calls))

    def test_strict_dependency_restrictions_remain(self):
        self.enabled()
        cases = [("Remv old-helper [1.0]\n", "remove packages"),
                 ("Inst new-helper (2.0 stable [amd64])\n", "New dependencies"),
                 ("Inst libc6 [2.1] (2.2 stable [amd64])\n", "Core/routing/kernel")]
        for extra, expected in cases:
            with self.subTest(extra=extra):
                self.runner.simulation = "Inst smart-patch-testprobe [1.0] (1.1 stable [amd64])\n" + extra
                with self.assertRaisesRegex(ValueError, expected):
                    self.engine.stage(self.plan["id"])
        simulations = [argv for argv in self.runner.calls if argv[:2] == ["apt-get", "-s"]]
        self.assertTrue(all("--no-remove" in argv for argv in simulations))
        self.assertFalse(any(argv[:2] == ["apt-get", "download"] for argv in self.runner.calls))

    def test_strict_mode_blocks_missing_rollback(self):
        self.enabled()
        self.runner.missing.add(("smart-patch-testprobe", "1.0"))
        with self.assertRaisesRegex(ValueError, "rollback version download unavailable"):
            self.engine.stage(self.plan["id"])
        self.assertEqual(self.engine._load(self.plan["id"])["status"], "planned")

    def test_missing_forward_package_cannot_be_reported_as_staged_when_checks_are_disabled(self):
        self.runner.missing.add(("smart-patch-testprobe", "1.1"))
        with self.assertRaisesRegex(ValueError, "forward version download unavailable"):
            self.engine.stage(self.plan["id"])
        self.assertEqual(self.engine._load(self.plan["id"])["status"], "planned")

    def test_strict_installed_inventory_and_assessment_checks_remain(self):
        self.enabled()
        self.runner.versions["smart-patch-testprobe"] = "0.9"
        with self.assertRaisesRegex(ValueError, "Installed package version"):
            self.engine.stage(self.plan["id"])
        self.runner.versions["smart-patch-testprobe"] = "1.0"
        with self.store.transaction() as state:
            state["inventory_digest"] = "inventory-new"
        with self.assertRaisesRegex(ValueError, "Inventory changed"):
            self.engine.stage(self.plan["id"])
        with self.store.transaction() as state:
            state["inventory_digest"] = "inventory-one"
        self.engine._save({**self.plan, "decision_valid_until": "not-a-date"})
        with self.assertRaisesRegex(ValueError, "assessment expired or its validity"):
            self.engine.stage(self.plan["id"])
        self.assertFalse(any(argv[:2] == ["apt-get", "download"] for argv in self.runner.calls))

    def test_enabling_checks_after_unchecked_stage_requires_restaging(self):
        self.engine.stage(self.plan["id"])
        self.enabled()
        with self.assertRaisesRegex(ValueError, "staged with maintenance checks disabled"):
            self.engine.apply(self.plan["id"], approved=True)
        self.assertFalse(any(argv[0] == "env" for argv in self.runner.calls))

    def test_failed_install_cannot_attempt_partial_rollback_and_marks_inventory_dirty(self):
        self.runner.simulation += "Inst helper [1.0] (1.1 stable [amd64])\n"
        self.runner.missing.add(("helper", "1.0"))
        staged = self.engine.stage(self.plan["id"])
        self.assertEqual(len(staged["artifacts"]["rollback"]), 1)
        self.runner.install_failure = "simulated installer failure"
        result = self.engine.apply(self.plan["id"], approved=True)
        installs = [argv for argv in self.runner.calls if argv[0] == "env"]
        self.assertEqual(len(installs), 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "simulated installer failure")
        self.assertIn("Automatic rollback unavailable", result["rollback_error"])
        self.assertFalse(result["rollback_available"])
        self.assertTrue((self.store.directory / "dirty").exists())

    def test_complete_rollback_still_works_with_explicitly_skipped_health(self):
        staged = self.engine.stage(self.plan["id"])
        self.assertTrue(staged["rollback_available"])
        self.engine.apply(self.plan["id"], approved=True)
        with patch.object(self.engine.validation, "snapshot", side_effect=AssertionError("health skipped")):
            result = self.engine.rollback(self.plan["id"])
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["rollback_validation"]["status"], "SKIPPED")
        self.assertEqual(self.runner.versions["smart-patch-testprobe"], "1.0")

    def test_missing_rollback_file_is_not_advertised_as_available(self):
        staged = self.engine.stage(self.plan["id"])
        Path(staged["artifacts"]["rollback"][0]["path"]).unlink()
        self.runner.install_failure = "installer failure"
        result = self.engine.apply(self.plan["id"], approved=True)
        self.assertFalse(result["rollback_available"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len([argv for argv in self.runner.calls if argv[0] == "env"]), 1)

    def test_disabled_catalog_and_staged_hash_checks_do_not_claim_verification(self):
        self.engine._save({**self.plan, "target_package_sha256": "0" * 64})
        staged = self.engine.stage(self.plan["id"])
        artifact = staged["artifacts"]["forward"][0]
        self.assertNotIn("catalog_hash_verified", artifact)
        path = Path(artifact["path"])
        path.write_text(path.read_text() + "\n")
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), artifact["sha256"])
        result = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(result["status"], "pending_reassessment")
        self.assertIn("artifact_hashes", result["checks_skipped"])

    def test_strict_apply_refuses_changed_staged_hash(self):
        self.enabled()
        staged = self.engine.stage(self.plan["id"])
        Path(staged["artifacts"]["forward"][0]["path"]).write_text("changed")
        with patch.object(self.engine.validation, "snapshot", return_value={"errors": []}):
            result = self.engine.apply(self.plan["id"], approved=True)
        self.assertIn("Staged artifact digest changed", result["error"])
        self.assertEqual(result["status"], "rolled_back")
        self.assertTrue(all("/rollback/" in argv[-1] for argv in self.runner.calls if argv[0] == "env"))

    def test_approval_advisory_scope_and_target_guards_survive_disabled_checks(self):
        with self.assertRaisesRegex(ValueError, "advisory-supported"):
            self.engine.create_plan("finding-one", "9.0")
        self.config.set_operating_mode("advisory")
        with self.assertRaisesRegex(ValueError, "Advisory"):
            self.engine.stage(self.plan["id"])
        self.config.set_operating_mode("assisted")
        self.engine.stage(self.plan["id"])
        with self.assertRaisesRegex(ValueError, "Explicit approval"):
            self.engine.apply(self.plan["id"])
        self.engine._save({**self.engine._load(self.plan["id"]), "scope": "container:pmon"})
        with self.assertRaisesRegex(ValueError, "host packages only"):
            self.engine.apply(self.plan["id"], approved=True)
        self.assertFalse(any(argv[0] == "env" for argv in self.runner.calls))

    def remote_request(self):
        return {"request_id": "request-one", "action": "stage_plan", "plan": {
            "id": "remote-one", "device_id": "device-one", "finding_id": "finding-one",
            "scope": "host", "package_name": "smart-patch-testprobe", "from_version": "1.0", "target_version": "1.1",
            "inventory_digest": "inventory-one", "approved": True, "approved_at": "2025-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00", "finding": self.finding}}

    def test_remote_stale_inventory_and_scope_coverage_are_optional_but_results_are_explicit(self):
        with self.store.transaction() as state:
            state.update(inventory_digest="inventory-new", scopes=[{"scope": "host", "status": "unknown"}])
        self.runner.missing.add(("smart-patch-testprobe", "1.0"))
        result = ActionExecutor(self.store, self.config, self.engine).execute(self.remote_request())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["value"]["status"], "staged")
        self.assertFalse(result["value"]["details"]["maintenance_checks_enabled"])
        self.assertFalse(result["value"]["details"]["rollback_available"])

    def test_authoritative_review_replaces_older_inventory_only_finding(self):
        with self.store.transaction() as state:
            state["findings"] = [{**self.finding, "decision_basis": "inventory_advisory_match", "remediation_eligible": False,
                                  "fixed_versions": []}]
        result = ActionExecutor(self.store, self.config, self.engine).execute(self.remote_request())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.store.load()["findings"][0]["decision_basis"], "operator_review")
        self.assertEqual(self.store.load()["findings"][0]["fixed_versions"], ["1.1"])

    def test_remote_authorization_identity_and_expiry_still_block(self):
        cases = [("device_id", "another-device", "different device"),
                 ("approved", False, "approval"),
                 ("expires_at", "2000-01-01T00:00:00+00:00", "expired"),
                 ("package_name", "different-package", "approved package target"),
                 ("target_version", "9.0", "selected fixed version")]
        for index, (field, value, message) in enumerate(cases):
            with self.subTest(field=field):
                request = self.remote_request()
                request["request_id"] = "request-" + str(index)
                request["plan"][field] = value
                result = ActionExecutor(self.store, self.config, self.engine).execute(request)
                self.assertEqual(result["status"], "denied")
                self.assertIn(message, result["value"]["details"])
        self.assertEqual(self.runner.calls, [])

    def test_action_poll_skips_only_optional_forced_inventory_collection(self):
        agent = Agent(self.config, self.store, collector=Mock())
        fact = {"status": "complete", "value": {"status": "staged"}}
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                self.config.set("", "", "maintenance_checks_enabled", str(enabled).lower())
                with self.store.transaction() as state:
                    state["action_requests"] = [self.remote_request()]
                with patch("smart_patch.agent.identity", return_value={"device_id": "device-one"}), \
                        patch.object(agent, "_collect") as collect, \
                        patch("smart_patch.actions.ActionExecutor.execute", return_value=fact) as execute:
                    agent._process_actions()
                self.assertEqual(collect.call_count, int(enabled))
                execute.assert_called_once()
                self.assertEqual(self.store.load()["action_facts"], [fact])


if __name__ == "__main__":
    unittest.main()
