"""Maintenance budgets must not inherit the inventory collector's limits."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from smart_patch.maintenance_resources import (
    MaintenanceCommandRunner, SYSTEMCTL, SYSTEMD_RUN, in_collector_cgroup,
    systemd_available,
)


class MaintenanceResourceTests(unittest.TestCase):
    def setUp(self):
        self.config = Mock()
        self.config.values.return_value = {}
        self.process = Mock(return_value="APT result")
        self.command = MaintenanceCommandRunner(self.config, runner=self.process, available=True)

    def test_default_is_separate_memory_budget_without_cpu_quota(self):
        self.assertEqual(self.command(["apt-get", "-s", "install", "socat=1.1"], timeout=60, limit=1234), "APT result")
        args, options = self.process.call_args
        command = args[0]
        self.assertEqual(command[0], SYSTEMD_RUN)
        self.assertIn("--slice=system.slice", command)
        self.assertIn("--property=MemoryMax=512M", command)
        self.assertIn("--property=TasksMax=128", command)
        self.assertIn("--property=RuntimeMaxSec=60s", command)
        self.assertIn("--property=TimeoutStopSec=5s", command)
        self.assertIn("--property=KillMode=control-group", command)
        self.assertIn("--setenv=LC_ALL=C", command)
        self.assertFalse(any("CPUQuota=" in arg for arg in command))
        self.assertEqual(command[-5:], ["--", "apt-get", "-s", "install", "socat=1.1"])
        self.assertEqual(options, {"timeout": 70, "limit": 1234})
        self.process.assert_called_once()

    def test_configured_quota_and_working_directory_are_enforced(self):
        self.config.values.return_value = {"maintenance_cpu_quota_percent": "25"}
        with tempfile.TemporaryDirectory(prefix="smart_patch%test-") as directory:
            self.command.run(["apt-get", "download", "socat=1.1"], cwd=directory)
        command = self.process.call_args.args[0]
        self.assertIn("--property=CPUQuota=25%", command)
        self.assertIn("--property=WorkingDirectory=" + directory.replace("%", "%%"), command)

    def test_daemon_workers_stop_with_the_collector_without_restarting_transactions(self):
        command = MaintenanceCommandRunner(self.config, runner=self.process, available=True, in_collector=True)
        command(["apt-get", "-s", "install", "socat=1.1"])
        args = self.process.call_args.args[0]
        self.assertIn("--property=BindsTo=sonic-smart-patch.service", args)
        self.assertIn("--property=After=sonic-smart-patch.service", args)
        self.assertFalse(any("PartOf=" in value or "Restart=" in value for value in args))

    def test_each_command_has_a_distinct_transient_unit(self):
        self.command(["apt-get", "-s", "install", "socat=1.1"])
        self.command(["apt-get", "download", "socat=1.1"])
        units = [next(arg for arg in call.args[0] if arg.startswith("--unit=")) for call in self.process.call_args_list]
        self.assertNotEqual(*units)
        self.assertTrue(all(unit.startswith("--unit=sonic-smart-patch-maint-") for unit in units))

    def test_dpkg_format_dollars_are_escaped_only_for_systemd_transport(self):
        argv = ["dpkg-query", "-W", "-f=${Version}", "socat"]
        self.command(argv)
        command = self.process.call_args.args[0]
        self.assertFalse(any(arg.startswith("--expand-environment") for arg in command))
        self.assertEqual(command[-4:], ["dpkg-query", "-W", "-f=$${Version}", "socat"])
        self.assertEqual(argv[2], "-f=${Version}")

    def test_each_literal_dollar_is_transport_escaped(self):
        self.command(["printf", "%s", "${Version} $PATH $$ $ literal"])
        self.assertEqual(self.process.call_args.args[0][-1], "$${Version} $$PATH $$$$ $$ literal")

    def test_standalone_arguments_do_not_receive_systemd_escapes(self):
        command = MaintenanceCommandRunner(self.config, runner=self.process, available=False, in_collector=False)
        command(["dpkg-query", "-W", "-f=${Version}", "socat"])
        self.assertEqual(self.process.call_args.args[0][-4:], ["dpkg-query", "-W", "-f=${Version}", "socat"])

    def test_all_failure_types_stop_the_separate_unit(self):
        for error in (TimeoutError("Collector command exceeded deadline"), ValueError("Output budget exceeded"),
                      RuntimeError("APT download unavailable"), OSError("No manager")):
            with self.subTest(error=type(error).__name__):
                process = Mock(side_effect=[error, ""])
                command = MaintenanceCommandRunner(self.config, runner=process, available=True)
                with self.assertRaisesRegex(RuntimeError, "Maintenance apt-get failed.*deadline 60s"):
                    command(["apt-get", "-s", "install", "socat=1.1"], timeout=60)
                unit = next(arg.split("=", 1)[1] for arg in process.call_args_list[0].args[0] if arg.startswith("--unit="))
                self.assertEqual(process.call_args_list[1].args[0], [SYSTEMCTL, "stop", unit])
                self.assertEqual(process.call_args_list[1].kwargs, {"timeout": 10, "limit": 8192})

    def test_interrupt_stops_unit_then_propagates(self):
        self.process.side_effect = [KeyboardInterrupt(), ""]
        with self.assertRaises(KeyboardInterrupt):
            self.command(["apt-get", "download", "socat=1.1"])
        self.assertEqual(self.process.call_count, 2)

    def test_cleanup_failure_is_visible_and_original_error_retained(self):
        self.process.side_effect = [TimeoutError("deadline"), RuntimeError("Manager unavailable")]
        with self.assertRaisesRegex(RuntimeError, "deadline.*cleanup failed.*Manager unavailable"):
            self.command(["apt-get", "download", "socat=1.1"])

    def test_already_collected_unit_does_not_mask_original_failure(self):
        self.process.side_effect = [RuntimeError("Exact version unavailable"), RuntimeError("Unit not loaded.")]
        with self.assertRaises(RuntimeError) as result:
            self.command(["apt-get", "download", "socat=1.1"])
        self.assertIn("Exact version unavailable", str(result.exception))
        self.assertNotIn("cleanup failed", str(result.exception))

    def test_error_does_not_echo_command_arguments(self):
        self.process.side_effect = [TimeoutError("deadline"), ""]
        with self.assertRaises(RuntimeError) as result:
            self.command(["apt-get", "--private-argument=do-not-print"])
        self.assertNotIn("do-not-print", str(result.exception))

    def test_invalid_quotas_are_rejected_before_command(self):
        for value in ("-1", "101", "0; rm anything", "1.5", "infinity", "", True, "２０"):
            with self.subTest(value=value):
                self.config.values.return_value = {"maintenance_cpu_quota_percent": value}
                with self.assertRaisesRegex(ValueError, "CPU quota"):
                    self.command(["apt-get", "-s", "install", "socat=1.1"])
        self.process.assert_not_called()

    def test_working_directory_must_exist_and_be_absolute(self):
        for directory in (".", "/smart-patch-test-directory-does-not-exist", __file__):
            with self.subTest(directory=directory):
                with self.assertRaisesRegex(ValueError, "absolute directory"):
                    self.command(["apt-get", "download", "socat=1.1"], cwd=directory)
        self.process.assert_not_called()

    def test_no_systemd_never_silently_ignores_configured_quota(self):
        self.config.values.return_value = {"maintenance_cpu_quota_percent": "10"}
        command = MaintenanceCommandRunner(self.config, runner=self.process, available=False, in_collector=False)
        with self.assertRaisesRegex(RuntimeError, "CPU quota requires"):
            command(["apt-get", "-s", "install", "socat=1.1"])
        self.process.assert_not_called()

    def test_no_systemd_never_falls_back_inside_collector(self):
        command = MaintenanceCommandRunner(self.config, runner=self.process, available=False, in_collector=True)
        with self.assertRaisesRegex(RuntimeError, "cannot escape collector"):
            command(["apt-get", "-s", "install", "socat=1.1"])
        self.process.assert_not_called()

    def test_standalone_unlimited_fallback_preserves_bounds_and_directory(self):
        command = MaintenanceCommandRunner(self.config, runner=self.process, available=False, in_collector=False)
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(command(["apt-get", "download", "socat=1.1"], timeout=20, limit=300, cwd=directory), "APT result")
        self.assertEqual(self.process.call_args.kwargs, {"timeout": 20, "limit": 300, "cwd": directory})
        self.assertEqual(self.process.call_args.args[0][-3:], ["apt-get", "download", "socat=1.1"])
        self.process.reset_mock()
        command(["true"])
        self.assertNotIn("cwd", self.process.call_args.kwargs)

    def test_standalone_cgroup_detection(self):
        with patch.object(Path, "read_text", return_value="0::/system.slice/sonic-smart-patch.service\n"):
            self.assertTrue(in_collector_cgroup())
        with patch.object(Path, "read_text", return_value="0::/user.slice/session.scope\n"):
            self.assertFalse(in_collector_cgroup())
        with patch.object(Path, "read_text", side_effect=OSError("unavailable")):
            self.assertTrue(in_collector_cgroup())

    def test_default_systemd_requires_root_and_trusted_binaries(self):
        with patch("smart_patch.maintenance_resources.os.geteuid", return_value=1000), \
                patch.object(Path, "is_dir", return_value=True), \
                patch("smart_patch.maintenance_resources._trusted_executable", return_value=True):
            self.assertFalse(systemd_available())
        with patch("smart_patch.maintenance_resources.os.geteuid", return_value=0), \
                patch.object(Path, "is_dir", return_value=True), \
                patch("smart_patch.maintenance_resources._trusted_executable", return_value=False):
            self.assertFalse(systemd_available())
        with patch("smart_patch.maintenance_resources.os.geteuid", return_value=0), \
                patch.object(Path, "is_dir", return_value=True), \
                patch("smart_patch.maintenance_resources._trusted_executable", return_value=True):
            self.assertTrue(systemd_available())


if __name__ == "__main__":
    unittest.main()
