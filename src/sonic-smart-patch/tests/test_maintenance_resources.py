"""Maintenance budgets must not inherit the inventory collector's limits."""
from pathlib import Path
import json
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from smart_patch.maintenance_resources import (
    MaintenanceCommandRunner, SYSTEMCTL, SYSTEMD_RUN, in_collector_cgroup,
    systemd_available, _container_entry, _compatible_security, _container_exec, _run_in_namespaces,
)


class MaintenanceResourceTests(unittest.TestCase):
    def setUp(self):
        self.config = Mock()
        self.config.values.return_value = {}
        self.process = Mock(return_value="APT result")
        self.command = MaintenanceCommandRunner(self.config, runner=self.process, available=True)
        self.cgroup_fixture = patch("smart_patch.maintenance_resources._cgroup_v2", return_value=False)
        self.cgroup_fixture.start()
        self.addCleanup(self.cgroup_fixture.stop)

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

    def test_container_process_runs_inside_host_bounded_unit_not_docker_exec(self):
        identity = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/pmon", "running": True, "pid": 12}
        self.config.values.return_value = {"maintenance_cpu_quota_percent": "25"}
        with patch("smart_patch.maintenance_resources._trusted_executable", return_value=True):
            self.command.container(identity, ["apt-get", "download", "socat=1.1"], timeout=180, cwd="/var/tmp/stage")
        argv = self.process.call_args.args[0]
        self.assertEqual(argv[0], SYSTEMD_RUN)
        self.assertIn("--property=MemoryMax=512M", argv)
        self.assertIn("--property=CPUQuota=25%", argv)
        self.assertIn("--property=RuntimeMaxSec=180s", argv)
        self.assertIn("--property=DevicePolicy=strict", argv)
        self.assertEqual([arg for arg in argv if arg.startswith("--property=DeviceAllow=")],
                         ["--property=DeviceAllow=/dev/%s rw" % name for name in ("null", "zero", "full", "random", "urandom")])
        self.assertIn("smart_patch.maintenance_resources", argv)
        self.assertIn("--container", argv)
        self.assertEqual(argv[-4:], ["/var/tmp/stage", "apt-get", "download", "socat=1.1"])
        self.assertNotIn("exec", argv)

    def test_container_never_falls_back_to_an_unbounded_process(self):
        identity = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/pmon", "running": True, "pid": 12}
        command = MaintenanceCommandRunner(self.config, runner=self.process, available=False, in_collector=False)
        with self.assertRaisesRegex(RuntimeError, "enforce package-process limits"):
            command.container(identity, ["apt-get", "download", "socat=1.1"])
        self.process.assert_not_called()

    def test_namespace_helper_pins_all_handles_without_joining_container_cgroup(self):
        identity = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/pmon", "running": True, "pid": 12}
        seen = SimpleNamespace(stdout=json.dumps(identity))
        with patch("smart_patch.maintenance_resources.os.geteuid", return_value=0), \
                patch("smart_patch.maintenance_resources._trusted_executable", return_value=True), \
                patch("smart_patch.maintenance_resources._process_start", return_value="stable-start"), \
                patch("smart_patch.maintenance_resources._process_security", return_value={"Seccomp": 0, "NoNewPrivs": 0, "profile": "unconfined"}), \
                patch.object(Path, "read_text", return_value="0 0 4294967295"), \
                patch("smart_patch.maintenance_resources.os.open", side_effect=range(10, 30)) as opened, \
                patch("smart_patch.maintenance_resources.os.close") as closed, \
                patch("smart_patch.maintenance_resources._run_in_namespaces", return_value=0) as entered, \
                patch("smart_patch.maintenance_resources.subprocess.run", side_effect=[seen, seen]) as run:
            self.assertEqual(_container_entry(identity, "/var/tmp", ["dpkg-query", "-W", "-f=${Version}", "socat"]), 0)
        self.assertEqual(entered.call_args.args[1:4], (list(range(10, 15)), 15, 17))
        namespaces = [call.args[0] for call in opened.call_args_list[:5]]
        self.assertEqual(namespaces, ["/proc/12/ns/" + name for name in ("mnt", "uts", "ipc", "net", "pid")])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(closed.call_count, opened.call_count)

    def test_namespace_helper_rejects_pid_restart_before_running_command(self):
        identity = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/pmon", "running": True, "pid": 12}
        before = SimpleNamespace(stdout=json.dumps(identity))
        after = SimpleNamespace(stdout=json.dumps({**identity, "pid": 14}))
        with patch("smart_patch.maintenance_resources.os.geteuid", return_value=0), \
                patch("smart_patch.maintenance_resources._trusted_executable", return_value=True), \
                patch("smart_patch.maintenance_resources._process_start", return_value="stable-start"), \
                patch("smart_patch.maintenance_resources._process_security", return_value={"Seccomp": 0, "NoNewPrivs": 0, "profile": "unconfined"}), \
                patch.object(Path, "read_text", return_value="0 0 4294967295"), \
                patch("smart_patch.maintenance_resources.os.open", side_effect=range(10, 30)), \
                patch("smart_patch.maintenance_resources.os.close"), \
                patch("smart_patch.maintenance_resources.subprocess.run", side_effect=[before, after]) as run:
            with self.assertRaisesRegex(ValueError, "process changed"):
                _container_entry(identity, "/", ["apt-get", "install", "socat=1.1"])
        self.assertEqual(run.call_count, 2)

    def test_namespace_helper_rejects_remapped_root(self):
        identity = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/pmon", "running": True, "pid": 12}
        with patch("smart_patch.maintenance_resources.os.geteuid", return_value=0), \
                patch("smart_patch.maintenance_resources._trusted_executable", return_value=True), \
                patch("smart_patch.maintenance_resources._process_start", return_value="stable-start"), \
                patch.object(Path, "read_text", return_value="0 100000 65536"), \
                patch("smart_patch.maintenance_resources.os.open") as opened, \
                patch("smart_patch.maintenance_resources.subprocess.run", return_value=SimpleNamespace(stdout=json.dumps(identity))):
            with self.assertRaisesRegex(ValueError, "remapped"):
                _container_entry(identity, "/", ["apt-get", "install", "socat=1.1"])
        opened.assert_not_called()

    def test_seccomp_and_lsm_constraints_are_never_silently_removed(self):
        unconfined = {"Seccomp": 0, "NoNewPrivs": 0, "profile": "unconfined"}
        for changed in ({"Seccomp": 2}, {"profile": "docker-default (enforce)"}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "cannot preserve"):
                _compatible_security({**unconfined, **changed}, unconfined)

    def test_namespace_entry_forks_for_pid_namespace_and_retains_outer_cgroup(self):
        libc = Mock()
        libc.setns.return_value = 0
        with patch("smart_patch.maintenance_resources.os.fork", return_value=42) as fork, \
                patch("smart_patch.maintenance_resources.os.waitpid", return_value=(42, 0)) as wait:
            self.assertEqual(_run_in_namespaces(libc, [10, 11, 12, 13, 14], 15, 15, {}, {}, ["true"], 1024), 0)
        self.assertEqual([call.args for call in libc.setns.call_args_list], [(10, 0), (11, 0), (12, 0), (13, 0), (14, 0)])
        fork.assert_called_once()
        wait.assert_called_once_with(42, 0)

    def test_host_privileges_and_handles_are_dropped_before_any_container_exec(self):
        libc = Mock()
        libc.prctl.return_value = 0
        masks = []
        def capture_capset(header, data):
            masks.append((data._obj[0].effective, data._obj[0].permitted, data._obj[0].inheritable))
            return 0
        libc.capset.side_effect = capture_capset
        target = {"CapBnd": 3, "CapPrm": 3, "CapEff": 1}
        helper = {"CapBnd": 255, "CapPrm": 255, "CapEff": 255}
        events = []
        with patch("smart_patch.maintenance_resources.os.fchdir", side_effect=lambda fd: events.append(("cwd", fd))), \
                patch("smart_patch.maintenance_resources.os.chroot", side_effect=lambda path: events.append(("root", path))), \
                patch("smart_patch.maintenance_resources.os.setgroups", side_effect=lambda groups: events.append(("groups", groups))), \
                patch("smart_patch.maintenance_resources.os.setgid"), \
                patch("smart_patch.maintenance_resources.os.setuid"), \
                patch("smart_patch.maintenance_resources.os.closerange", side_effect=lambda a, b: events.append(("close", a, b))), \
                patch("smart_patch.maintenance_resources.os.execvpe", side_effect=lambda *args: events.append(("exec", args))) as execute:
            _container_exec(libc, 15, 17, target, helper, ["dpkg-query", "-W", "socat"], 1024)
        self.assertEqual(masks, [(1, 1, 0)])
        dropped = [call.args[1] for call in libc.prctl.call_args_list if call.args[0] == 24]
        self.assertEqual(dropped, list(range(1, 8)))
        self.assertIn((47, 4, 0, 0, 0), [call.args for call in libc.prctl.call_args_list])
        self.assertIn((38, 1, 0, 0, 0), [call.args for call in libc.prctl.call_args_list])
        self.assertEqual(events[:4], [("cwd", 15), ("root", "."), ("cwd", 17), ("groups", [])])
        self.assertEqual(events[-2][0], "close")
        self.assertEqual(events[-1][0], "exec")
        self.assertEqual(execute.call_args.args[2], {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"})


if __name__ == "__main__":
    unittest.main()
