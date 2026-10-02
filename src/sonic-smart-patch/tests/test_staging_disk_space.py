"""Check the staging free-space boundary before package-manager work."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from smart_patch.config import ConfigManager
from smart_patch.remediation import RemediationEngine
from smart_patch.storage import StateStore


class StagingDiskSpaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        config = ConfigManager(directory=root / "config")
        config.set_operating_mode("assisted")
        config.set("", "", "maintenance_checks_enabled", "true")
        self.engine = RemediationEngine(StateStore(root / "state"), config)
        self.plan = {"id": "11111111-1111-1111-1111-111111111111", "status": "planned",
                     "impact": "package_update", "scope": "host", "package": "socat",
                     "from_version": "1.0", "target_version": "1.1", "inventory_digest": "fixture-inventory"}
        with self.engine.store.transaction() as state:
            state["inventory_digest"] = "fixture-inventory"
        self.engine._save(self.plan)

    def tearDown(self):
        self.temp.cleanup()

    def test_below_500_mib_is_denied_before_any_package_work(self):
        with patch("smart_patch.remediation.shutil.disk_usage", return_value=SimpleNamespace(free=500 * 1024**2 - 1)), \
                patch.object(self.engine, "_verify_current") as verify, \
                patch.object(self.engine, "_transaction") as transaction, \
                patch.object(self.engine, "_download") as download:
            with self.assertRaisesRegex(ValueError, "At least 500 MiB"):
                self.engine.stage(self.plan["id"])
            verify.assert_not_called()
            transaction.assert_not_called()
            download.assert_not_called()
            self.assertEqual(self.engine._load(self.plan["id"])["status"], "planned")

    def test_500_mib_and_previous_blocked_capacity_pass_space_guard(self):
        for free in (500 * 1024**2, 943 * 1024**2):
            with self.subTest(free=free), \
                    patch("smart_patch.remediation.shutil.disk_usage", return_value=SimpleNamespace(free=free)), \
                    patch.object(self.engine, "_verify_current", side_effect=ValueError("next identity check")) as verify, \
                    patch.object(self.engine, "_transaction") as transaction:
                with self.assertRaisesRegex(ValueError, "next identity check"):
                    self.engine.stage(self.plan["id"])
                verify.assert_called_once()
                transaction.assert_not_called()

    def test_configured_free_space_applies_to_staging_and_forward_installation(self):
        self.engine.config.set("", "", "maintenance_min_free_mib", "750")
        with patch("smart_patch.remediation.shutil.disk_usage", return_value=SimpleNamespace(free=600 * 1024**2)), \
                patch.object(self.engine, "_verify_current") as verify, \
                patch.object(self.engine, "_install") as install:
            with self.assertRaisesRegex(ValueError, "At least 750 MiB"):
                self.engine.stage(self.plan["id"])
            self.engine._save({**self.plan, "status": "staged"})
            with self.assertRaisesRegex(ValueError, "At least 750 MiB"):
                self.engine.apply(self.plan["id"], approved=True)
            verify.assert_not_called()
            install.assert_not_called()

    def test_invalid_direct_config_fails_before_package_work(self):
        for value in ("0", "-1", "65537", "bad"):
            with self.subTest(value=value), patch.object(self.engine, "_verify_current") as verify:
                self.engine.config.set("", "", "maintenance_min_free_mib", value)
                with self.assertRaisesRegex(ValueError, "maintenance_min_free_mib"):
                    self.engine.stage(self.plan["id"])
                verify.assert_not_called()

    def test_rollback_recovery_is_not_blocked_by_new_free_space_guard(self):
        rollback = self.engine.directory / "retained.deb"
        rollback.write_bytes(b"synthetic rollback fixture")
        self.engine._save({**self.plan, "status": "rollback_required", "pre_validation": {},
                          "transaction": [{"package": "socat", "from_version": "1.0", "to_version": "1.1"}],
                          "artifacts": {"rollback": [{"package": "socat", "version": "1.0", "path": str(rollback)}]}})
        with patch.object(self.engine, "_check_free_space", side_effect=AssertionError("must not block recovery")), \
                patch.object(self.engine, "_install") as install, \
                patch.object(self.engine.validation, "snapshot", return_value={}), \
                patch.object(self.engine.validation, "compare", return_value={"status": "PASS"}):
            result = self.engine.rollback(self.plan["id"])
            self.assertEqual(result["status"], "rolled_back")
            self.assertEqual(install.call_args.args[1], "rollback")

    def test_container_maintenance_cannot_claim_a_host_cpu_budget(self):
        self.engine._save({**self.plan, "scope": "container:pmon"})
        with patch.object(self.engine, "_transaction") as transaction:
            with self.assertRaisesRegex(ValueError, "maintenance mode"):
                self.engine.stage(self.plan["id"])
            self.engine._save({**self.plan, "scope": "container:pmon", "status": "staged"})
            with self.assertRaisesRegex(ValueError, "maintenance mode"):
                self.engine.apply(self.plan["id"], approved=True)
            transaction.assert_not_called()


if __name__ == "__main__":
    unittest.main()
