"""Native settings preserve maintenance defaults and reject unsafe boundaries."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import click
from click.testing import CliRunner

from smart_patch.config import ConfigManager, public_config


ROOT = Path(__file__).resolve().parents[1]


class Database:
    def __init__(self):
        self.entry = {}

    def get_entry(self, table, key):
        return dict(self.entry)

    def set_entry(self, table, key, entry):
        self.entry = dict(entry)


class MaintenanceConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = Database()
        self.config = ConfigManager(self.database, self.directory.name)
        self.root = click.Group(name="config")
        spec = importlib.util.spec_from_file_location("maintenance_config_plugin", ROOT / "plugins/config.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        plugin.register(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def invoke(self, name, value):
        with patch("smart_patch.cli.ConfigManager", return_value=self.config):
            return CliRunner().invoke(self.root, ["security", "setting", name, value])

    def test_absent_or_reloaded_settings_use_requested_defaults(self):
        for values in (self.config.values(), ConfigManager(directory=self.directory.name).values()):
            self.assertEqual(values["maintenance_min_free_mib"], "500")
            self.assertEqual(values["maintenance_cpu_quota_percent"], "0")
            self.assertEqual(values["maintenance_checks_enabled"], "false")
        self.invoke("maintenance_min_free_mib", "900")
        self.invoke("maintenance_checks_enabled", "true")
        self.database.entry = {}
        self.config.refresh()
        self.assertEqual(self.config.values()["maintenance_min_free_mib"], "500")
        self.assertEqual(ConfigManager(directory=self.directory.name).values()["maintenance_min_free_mib"], "500")
        self.assertEqual(self.config.values()["maintenance_checks_enabled"], "false")
        self.assertEqual(ConfigManager(directory=self.directory.name).values()["maintenance_checks_enabled"], "false")

    def test_native_settings_persist_in_configdb_and_outage_fallback(self):
        for name, value in (("maintenance_min_free_mib", "500"),
                            ("maintenance_cpu_quota_percent", "30"),
                            ("maintenance_cpu_quota_percent", "0"),
                            ("maintenance_checks_enabled", "true"),
                            ("maintenance_checks_enabled", "false")):
            with self.subTest(name=name, value=value):
                result = self.invoke(name, value)
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(self.database.entry[name], value)
                fallback = json.loads((Path(self.directory.name) / "config.json").read_text())
                self.assertEqual(fallback[name], value)

    def test_invalid_settings_do_not_replace_previous_valid_value(self):
        cases = {"maintenance_cpu_quota_percent": ("30", ("-1", "101", "disabled", "10.5")),
                 "maintenance_min_free_mib": ("500", ("0", "-1", "65537", "500MiB", "500.5")),
                 "maintenance_checks_enabled": ("true", ("0", "1", "yes", "False", "disabled"))}
        for name, (previous, rejected) in cases.items():
            self.assertEqual(self.invoke(name, previous).exit_code, 0)
            for value in rejected:
                with self.subTest(name=name, value=value):
                    result = self.invoke(name, value)
                    self.assertNotEqual(result.exit_code, 0, result.output)
                    self.assertEqual(self.database.entry[name], previous)
                    self.assertEqual(ConfigManager(directory=self.directory.name).values()[name], previous)

    def test_check_policy_is_readable_without_private_configuration(self):
        self.assertEqual(public_config(self.directory.name)["maintenance_checks_enabled"], "false")
        self.invoke("maintenance_checks_enabled", "true")
        self.config.set_auth_token("not-for-public-config")
        public_path = Path(self.directory.name) / "public-config.json"
        self.assertEqual(public_config(self.directory.name)["maintenance_checks_enabled"], "true")
        self.assertEqual(public_path.stat().st_mode & 0o777, 0o644)
        self.assertNotIn("not-for-public-config", public_path.read_text())

    def test_supported_upper_and_lower_bounds_are_accepted(self):
        for name, values in {"maintenance_cpu_quota_percent": ("0", "100"),
                             "maintenance_min_free_mib": ("1", "65536")}.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    result = self.invoke(name, value)
                    self.assertEqual(result.exit_code, 0, result.output)

    def test_maintenance_mode_cli_is_explicit_and_public(self):
        self.assertEqual(self.config.values()["maintenance_mode"], "false")
        with patch("smart_patch.cli.ConfigManager", return_value=self.config):
            result = CliRunner().invoke(self.root, ["security", "smart-patch", "maintenance-mode", "enable"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("does not drain", result.output)
        self.assertEqual(self.database.entry["maintenance_mode"], "true")
        self.assertEqual(public_config(self.directory.name)["maintenance_mode"], "true")
        with patch("smart_patch.cli.ConfigManager", return_value=self.config):
            result = CliRunner().invoke(self.root, ["security", "smart-patch", "maintenance-mode", "disable"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(public_config(self.directory.name)["maintenance_mode"], "false")

    def test_snapshot_settings_validate_date_and_boolean(self):
        self.assertEqual(self.config.values()["rollback_snapshot_enabled"], "true")
        for value in ("20241222T205329Z", ""):
            self.assertEqual(self.invoke("rollback_snapshot_timestamp", value).exit_code, 0)
        for value in ("20249999T000000Z", "2024011T000000Z", "latest", "20240101T000000Z;evil"):
            self.assertNotEqual(self.invoke("rollback_snapshot_timestamp", value).exit_code, 0)
        self.assertEqual(self.invoke("rollback_snapshot_enabled", "false").exit_code, 0)
        self.assertNotEqual(self.invoke("rollback_snapshot_enabled", "yes").exit_code, 0)

    def test_remediation_cli_filters_and_displays_central_resolution(self):
        from smart_patch.cli import security
        projected = {"maintenance_mode": True, "sync_status": "connected", "truncated": False,
                     "rows": [{"cve_id": "CVE-2026-12345", "scope": "container:pmon", "package_name": "socat",
                               "status": "pending_reassessment", "state": "resolved", "plan_id": None,
                               "local_plan_id": "11111111-1111-1111-1111-111111111111"}]}
        with patch("smart_patch.remediation_status.get_status", return_value=projected) as get:
            result = CliRunner().invoke(security, ["show", "remediation", "--cve", "CVE-2026-12345",
                                                  "--scope", "container:pmon", "--status", "resolved"])
        self.assertEqual(result.exit_code, 0, result.output)
        get.assert_called_once_with(cve="CVE-2026-12345", scope="container:pmon", status="resolved")
        self.assertIn("resolved", result.output)
        self.assertIn("11111111-1111-1111-1111-111111111111", result.output)
        self.assertNotIn("pending_reassessment", result.output)
        with patch("smart_patch.remediation_status.get_status", return_value=projected):
            result = CliRunner().invoke(security, ["show", "cves", "--json"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output), projected)


if __name__ == "__main__":
    unittest.main()
