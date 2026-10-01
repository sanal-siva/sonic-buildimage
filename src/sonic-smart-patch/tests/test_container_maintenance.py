"""Exercise selected-container transactions with synthetic package boundaries."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from smart_patch.config import ConfigManager
from smart_patch.remediation import RemediationEngine
from smart_patch.storage import StateStore


class ContainerRunner:
    """No Docker, package installation or container restart is performed."""
    def __init__(self, root):
        self.root = root
        self.identity = {"id": "a" * 64, "image": "sha256:" + "b" * 64,
                         "name": "/pmon", "running": True, "pid": 123}
        self.calls = []
        self.version = "1.0"
        self.restart_failure = False
        self.extra_dependency = ""
        self.missing = set()

    def __call__(self, argv, **options):
        self.calls.append(("host", argv, options))
        if argv[:2] == ["docker", "inspect"]:
            return json.dumps(self.identity)
        if argv[:2] == ["docker", "restart"]:
            if self.restart_failure:
                raise RuntimeError("Selected container did not restart")
            self.identity["pid"] += 1
            return self.identity["id"]
        if argv[:2] == ["dpkg-deb", "-f"]:
            data = json.loads(Path(argv[2]).read_text())
            return "Package: socat\nVersion: %s\n" % data["version"]
        raise AssertionError("Unexpected host command: " + repr(argv))

    def _runtime(self, identity):
        outer = self
        class Root:
            def __enter__(self):
                self.root = os.open(outer.root, os.O_RDONLY | os.O_DIRECTORY)
                return self
            def verify(self):
                assert identity["id"] == outer.identity["id"]
            def __exit__(self, *_):
                os.close(self.root)
        return Root()

    def copy_from_container(self, identity, source, destination, **options):
        from smart_patch.container_artifacts import copy_from_container
        self.calls.append(("host", ["artifact-export", identity["id"], source, str(destination)], options))
        return copy_from_container(identity, source, str(destination), runtime_factory=self._runtime)

    def copy_to_container(self, identity, source, destination, sha256, **options):
        from smart_patch.container_artifacts import copy_to_container
        self.calls.append(("host", ["artifact-import", identity["id"], source, destination], options))
        return copy_to_container(identity, source, destination, sha256, runtime_factory=self._runtime)

    def container(self, identity, argv, **options):
        assert identity["id"] == self.identity["id"]
        self.calls.append(("container", argv, options))
        if argv[0] == "dpkg-query":
            return self.version
        if argv[:2] == ["mkdir", "-p"]:
            (self.root / argv[-1].lstrip("/")).mkdir(parents=True, exist_ok=True)
            return ""
        if argv[:2] == ["apt-get", "-s"]:
            return "Inst socat [1.0] (1.1 stable [amd64])\n" + self.extra_dependency
        if argv[:2] == ["apt-get", "download"]:
            version = argv[-1].split("=", 1)[1]
            if version in self.missing:
                raise RuntimeError("Exact version absent")
            directory = self.root / options["cwd"].lstrip("/")
            (directory / ("socat_" + version + "_amd64.deb")).write_text(json.dumps({"version": version}))
            return ""
        if argv[:2] == ["env", "DEBIAN_FRONTEND=noninteractive"]:
            assert "--no-download" in argv and "--no-remove" in argv
            assert any(arg.startswith("Dir::Cache::Archives=/var/tmp/") for arg in argv)
            target = self.root / argv[-1].lstrip("/")
            self.version = json.loads(target.read_text())["version"]
            return ""
        raise AssertionError("Unexpected container command: " + repr(argv))


class ContainerMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = ConfigManager(directory=root / "config")
        self.config.set_operating_mode("assisted")
        self.config.set("", "", "rollback_snapshot_enabled", "false")
        self.store = StateStore(root / "state")
        self.finding = {"id": "finding-one", "cve_id": "CVE-2026-12345", "component_id": "component-one",
                        "scope": "container:pmon", "package_name": "socat", "affected_version": "1.0",
                        "fixed_versions": ["1.1"], "applicability": "affected", "decision_basis": "operator_review"}
        with self.store.transaction() as state:
            state.update(device_id="device-one", inventory_digest="inventory-one", epoch="epoch-one",
                         build_id="build-one", findings=[self.finding], inventory={"component-one": {"architecture": "amd64"}})
        self.runner = ContainerRunner(root / "container")
        self.engine = RemediationEngine(self.store, self.config, self.runner)
        self.plan = self.engine.create_plan("finding-one", "1.1")
        self.sleep = patch("smart_patch.remediation.time.sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def enable(self):
        self.config.set("", "", "maintenance_mode", "true")

    def test_default_mode_blocks_before_package_work(self):
        self.assertEqual(self.config.values()["maintenance_mode"], "false")
        with self.assertRaisesRegex(ValueError, "maintenance mode"):
            self.engine.stage(self.plan["id"])
        self.assertFalse(any(scope == "container" for scope, _, _ in self.runner.calls))

    def test_end_to_end_only_selected_container_restarts_and_reports_progress(self):
        self.enable()
        staged = self.engine.stage(self.plan["id"])
        self.assertEqual(staged["status"], "staged")
        self.assertTrue(staged["rollback_available"])
        result = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(result["status"], "pending_reassessment")
        self.assertEqual(self.runner.version, "1.1")
        self.assertEqual(result["container_restart"]["status"], "complete")
        self.assertEqual(result["container_restart"]["observed_version"], "1.1")
        self.assertIn("Recreating", result["writable_layer_warning"])
        self.assertEqual(result["cve_ids"], ["CVE-2026-12345"])
        self.assertEqual(result["component_id"], "component-one")
        self.assertEqual(result["inventory_epoch"], "epoch-one")
        self.assertEqual(result["architecture"], "amd64")
        self.assertEqual([event["status"] for event in result["history"]],
                         ["planned", "staging", "downloading", "downloaded", "staged", "installing", "installed", "restarting", "pending_reassessment"])
        restarts = [argv for _, argv, _ in self.runner.calls if argv[:2] == ["docker", "restart"]]
        self.assertEqual(restarts, [["docker", "restart", "--time", "10", "a" * 64]])
        self.assertFalse(any(argv[:2] == ["docker", "exec"] for _, argv, _ in self.runner.calls))
        self.assertTrue(all(scope == "container" for scope, argv, _ in self.runner.calls if "apt-get" in argv))

    def test_recreated_container_name_is_never_used(self):
        self.enable()
        self.runner.identity["id"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "recreated"):
            self.engine.stage(self.plan["id"])
        self.assertFalse(any(scope == "container" for scope, _, _ in self.runner.calls))

    def test_disabling_mode_after_staging_prevents_install(self):
        self.enable()
        self.engine.stage(self.plan["id"])
        self.config.set("", "", "maintenance_mode", "false")
        with self.assertRaisesRegex(ValueError, "maintenance mode"):
            self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(self.runner.version, "1.0")

    def test_identity_and_version_checks_cannot_be_disabled(self):
        self.enable()
        self.runner.version = "0.9"
        with self.assertRaisesRegex(ValueError, "Installed package version"):
            self.engine.stage(self.plan["id"])

    def test_core_dependency_requires_manual_image_even_with_optional_checks_off(self):
        self.enable()
        self.runner.extra_dependency = "Inst libc6 [2.1] (2.2 stable [amd64])\n"
        with self.assertRaisesRegex(ValueError, "Core/routing/kernel"):
            self.engine.stage(self.plan["id"])
        self.assertEqual(self.engine._load(self.plan["id"])["status"], "failed")
        self.assertFalse(any(argv[:2] == ["apt-get", "download"] for _, argv, _ in self.runner.calls))

    def test_missing_rollback_remains_explicit_and_failed_restart_is_not_success(self):
        self.enable()
        self.runner.missing.add("1.0")
        self.engine.stage(self.plan["id"])
        self.runner.restart_failure = True
        result = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["rollback_available"])
        self.assertEqual(result["container_restart"]["status"], "unknown")
        self.assertEqual(self.runner.version, "1.1")
        self.assertTrue((self.store.directory / "dirty").exists())

    def test_rollback_restarts_same_container_and_restores_version(self):
        self.enable()
        self.engine.stage(self.plan["id"])
        self.engine.apply(self.plan["id"], approved=True)
        result = self.engine.rollback(self.plan["id"])
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(self.runner.version, "1.0")
        self.assertEqual(result["container_restart"]["direction"], "rollback")
        self.assertEqual(result["container_restart"]["observed_version"], "1.0")

    def test_artifact_integrity_remains_mandatory_for_containers(self):
        self.enable()
        staged = self.engine.stage(self.plan["id"])
        artifact = staged["artifacts"]["forward"][0]
        Path(artifact["path"]).write_text('{"version":"9.0"}')
        result = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(result["status"], "rolled_back")
        self.assertIn("Staged artifact digest changed", result["error"])
        self.assertEqual(self.runner.version, "1.0")

    def test_history_revision_monotonic_and_bounded(self):
        revision = self.plan["revision"]
        for index in range(70):
            self.plan["status"] = "planned" if index % 2 else "staging"
            self.engine._save(self.plan)
        result = self.engine._load(self.plan["id"])
        self.assertEqual(result["revision"], revision + 70)
        self.assertLessEqual(len(result["history"]), 64)

    def test_staged_artifacts_repopulate_runtime_cache_before_install_and_rollback(self):
        self.enable()
        staged = self.engine.stage(self.plan["id"])
        self.assertTrue(staged["rollback_available"])
        cache = self.runner.root / "var/tmp" / ("sonic-smart-patch-" + self.plan["id"])
        shutil.rmtree(cache / "forward")
        installed = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(installed["status"], "pending_reassessment")
        self.assertEqual(self.runner.version, "1.1")
        shutil.rmtree(cache / "rollback")
        rolled = self.engine.rollback(self.plan["id"])
        self.assertEqual(rolled["status"], "rolled_back")
        self.assertEqual(self.runner.version, "1.0")
        self.assertFalse(any(argv[:2] == ["docker", "cp"] for _, argv, _ in self.runner.calls))

    def test_maintenance_revoked_after_install_records_failure_without_false_denial(self):
        self.enable()
        self.engine.stage(self.plan["id"])
        original = self.engine._install
        def install_then_revoke(plan, direction):
            original(plan, direction)
            self.config.set("", "", "maintenance_mode", "false")
        with patch.object(self.engine, "_install", side_effect=install_then_revoke):
            result = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(self.runner.version, "1.1")
        self.assertEqual(result["status"], "rollback_failed")
        self.assertIn("maintenance mode", result["rollback_error"])
        self.assertTrue(result.get("installed_at"))
        self.assertFalse(any(argv[:2] == ["docker", "restart"] for _, argv, _ in self.runner.calls))

    def test_recreated_container_after_install_records_failure_and_never_restarts_replacement(self):
        self.enable()
        self.engine.stage(self.plan["id"])
        original = self.engine._install
        def install_then_recreate(plan, direction):
            original(plan, direction)
            self.runner.identity["id"] = "c" * 64
        with patch.object(self.engine, "_install", side_effect=install_then_recreate):
            result = self.engine.apply(self.plan["id"], approved=True)
        self.assertEqual(result["status"], "rollback_failed")
        self.assertIn("recreated", result["rollback_error"])
        self.assertTrue(result.get("installed_at"))
        self.assertFalse(any(argv[:2] == ["docker", "restart"] for _, argv, _ in self.runner.calls))


if __name__ == "__main__":
    unittest.main()
