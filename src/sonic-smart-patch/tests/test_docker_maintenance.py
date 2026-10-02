"""Docker exec gating is tested without a Docker daemon or package changes."""
import array
import ctypes
import errno
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from smart_patch.docker_maintenance import (
    BASIC_DEVICES, CGROUP_BPF_ATTACH_TYPES, DockerFrames, GATE_CODE, owned_cgroup, run_container_exec,
    _verify_device_policy, _reject_extra_cgroup_bpf, _verify_default_cgroup,
)


class FramingTests(unittest.TestCase):
    def test_fragmented_stdout_and_stderr_are_decoded_in_order(self):
        output = []
        frames = DockerFrames(12, output.append)
        encoded = b"\1\0\0\0" + struct.pack(">I", 3) + b"out" + b"\2\0\0\0" + struct.pack(">I", 3) + b"err"
        for byte in encoded:
            frames.feed(bytes([byte]))
        frames.finish()
        self.assertEqual(b"".join(output), b"outerr")

    def test_output_limit_checked_before_accepting_large_frame(self):
        frames = DockerFrames(4, lambda _: None)
        with self.assertRaisesRegex(ValueError, "output budget"):
            frames.feed(b"\1\0\0\0" + struct.pack(">I", 10000000))

    def test_invalid_and_partial_frames_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "framing"):
            DockerFrames(100, lambda _: None).feed(b"\1\0\1\0\0\0\0\0")
        frames = DockerFrames(100, lambda _: None)
        frames.feed(b"\1\0\0\0\0\0\0\4xx")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            frames.finish()


class CgroupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.group = "/system.slice/sonic-smart-patch-maint-" + "a" * 32 + ".service"
        self.directory = self.root / self.group.lstrip("/")
        self.directory.mkdir(parents=True)
        (self.root / "cgroup.controllers").write_text("memory cpu pids")
        for name, value in (("memory.max", str(512 * 1024 * 1024)), ("pids.max", "128"), ("cpu.max", "25000 100000"), ("cgroup.procs", "")):
            (self.directory / name).write_text(value)
        for patcher in (patch("smart_patch.docker_maintenance.CGROUP_ROOT", self.root),
                        patch("smart_patch.docker_maintenance._verify_device_policy"),
                        patch("smart_patch.docker_maintenance._cgroup_path", return_value=self.group)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_descriptor_is_for_own_bounded_unit_and_does_not_write_numeric_pid(self):
        group, descriptor = owned_cgroup(25)
        try:
            self.assertEqual(group, self.group)
            self.assertEqual(os.readlink("/proc/self/fd/%d" % descriptor), str(self.directory / "cgroup.procs"))
            self.assertEqual((self.directory / "cgroup.procs").read_text(), "")
        finally:
            os.close(descriptor)

    def test_unbounded_memory_tasks_or_weaker_cpu_rejected(self):
        for name, value, message in (("memory.max", "max", "memory/task"), ("pids.max", "max", "memory/task"),
                                      ("cpu.max", "max 100000", "CPU quota"), ("cpu.max", "50000 100000", "CPU quota")):
            path = self.directory / name
            before = path.read_text()
            try:
                path.write_text(value)
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, message):
                    owned_cgroup(25)
            finally:
                path.write_text(before)

    def test_cannot_attach_to_collector_or_other_unit(self):
        with patch("smart_patch.docker_maintenance._cgroup_path", return_value="/system.slice/sonic-smart-patch.service"):
            with self.assertRaisesRegex(ValueError, "own Smart Patch"):
                owned_cgroup(0)


class DevicePolicyTests(unittest.TestCase):
    def test_sonic_platform_device_grants_do_not_expand_the_worker_allowlist(self):
        expected = {"id": "a" * 64}
        group = "/system.slice/docker-" + expected["id"] + ".scope"
        inspected = {"State": {"Pid": 123}, "HostConfig": {"CgroupParent": "", "DeviceCgroupRules": ["c 153:* rwm", "c 254:* rwm"]}}
        with patch("smart_patch.docker_maintenance._cgroup_path", return_value=group), \
                patch("smart_patch.docker_maintenance._reject_extra_cgroup_bpf") as verify:
            self.assertEqual(_verify_default_cgroup(inspected, expected), group)
            verify.assert_called_once()
        self.assertEqual(BASIC_DEVICES, {"null": 3, "zero": 5, "full": 7, "random": 8, "urandom": 9})

    def test_exact_strict_allowlist_is_required(self):
        group = "/system.slice/sonic-smart-patch-maint-" + "a" * 32 + ".service"
        output = "DevicePolicy=strict\nControlGroup=" + group + "\n" + "\n".join(
            "DeviceAllow=/dev/%s rw" % name for name in BASIC_DEVICES)
        with patch("smart_patch.docker_maintenance.subprocess.run", return_value=SimpleNamespace(stdout=output)):
            _verify_device_policy(group)
        for replacement in (output.replace("DevicePolicy=strict", "DevicePolicy=auto"),
                            output + "\nDeviceAllow=/dev/sda rwm", output.replace("/dev/null rw", "/dev/null rwm")):
            with patch("smart_patch.docker_maintenance.subprocess.run", return_value=SimpleNamespace(stdout=replacement)):
                with self.assertRaisesRegex(ValueError, "deny all devices"):
                    _verify_device_policy(group)

    def test_unknown_bpf_policy_or_query_failure_blocks_migration(self):
        for policy, error in ((True, 0), (False, errno.EPERM)):
            libc = Mock()
            def query(_number, command, pointer, size):
                self.assertEqual(command, 16)
                pointer._obj.prog_cnt = int(policy)
                ctypes.set_errno(error)
                return -1 if error else 0
            libc.syscall.side_effect = query
            with patch("smart_patch.docker_maintenance.ctypes.CDLL", return_value=libc), \
                    patch("smart_patch.docker_maintenance.platform.machine", return_value="x86_64"), \
                    patch("smart_patch.docker_maintenance.os.open", return_value=10), \
                    patch("smart_patch.docker_maintenance.os.close"):
                with self.subTest(policy=policy, error=error), self.assertRaises((ValueError, OSError)):
                    _reject_extra_cgroup_bpf(Path("/fixture"))

    def test_queries_all_non_device_attachment_slots_without_mutation(self):
        libc = Mock()
        seen = []
        def query(_number, command, pointer, size):
            seen.append(pointer._obj.attach_type)
            self.assertEqual(pointer._obj.query_flags, 1)
            self.assertEqual(pointer._obj.prog_ids, 0)
            ctypes.set_errno(errno.EINVAL if pointer._obj.attach_type else 0)
            return -1 if pointer._obj.attach_type else 0
        libc.syscall.side_effect = query
        with patch("smart_patch.docker_maintenance.ctypes.CDLL", return_value=libc), \
                patch("smart_patch.docker_maintenance.platform.machine", return_value="x86_64"), \
                patch("smart_patch.docker_maintenance.os.open", return_value=10), \
                patch("smart_patch.docker_maintenance.os.close"):
            _reject_extra_cgroup_bpf(Path("/fixture"))
        self.assertEqual(seen, list(CGROUP_BPF_ATTACH_TYPES))
        self.assertEqual(set(seen), {0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 22,
                                    29, 30, 31, 32, 34, 43, 49, 50, 51, 52, 53})
        self.assertNotIn(54, seen)  # NETKIT: valid API type, but not a cgroup query.
        self.assertNotIn(55, seen)

    def test_all_invalid_queries_cannot_be_mistaken_for_an_empty_policy(self):
        libc = Mock()
        def invalid(*_):
            ctypes.set_errno(errno.EINVAL)
            return -1
        libc.syscall.side_effect = invalid
        with patch("smart_patch.docker_maintenance.ctypes.CDLL", return_value=libc), \
                patch("smart_patch.docker_maintenance.platform.machine", return_value="x86_64"), \
                patch("smart_patch.docker_maintenance.os.open", return_value=10), \
                patch("smart_patch.docker_maintenance.os.close"):
            with self.assertRaisesRegex(ValueError, "query ABI"):
                _reject_extra_cgroup_bpf(Path("/fixture"))


class GateProtocolTests(unittest.TestCase):
    """Real local Python/SCM_RIGHTS handshake; the descriptor is a fixture file."""
    def run_gate(self, approve):
        with tempfile.TemporaryDirectory(prefix="spg-") as directory:
            address = directory + "/gate"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(address)
            listener.listen(1)
            listener.settimeout(3)
            resource_file = Path(directory) / "resource-fixture"
            descriptor = os.open(resource_file, os.O_WRONLY | os.O_CREAT, 0o600)
            marker = Path(directory) / "command-ran"
            command = [sys.executable, "-I", "-S", "-c", GATE_CODE, address, "fixture-nonce",
                       sys.executable, "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[2])", str(marker), "literal $(not a shell)"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(3)
                    credentials = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                    self.assertEqual(credentials[0], process.pid)
                    self.assertEqual(peer.recv(64), b"fixture-nonce")
                    self.assertFalse(marker.exists())
                    peer.sendmsg([b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))])
                    self.assertEqual(peer.recv(8), b"ATTACHED")
                    self.assertEqual(resource_file.read_text(), "0")
                    self.assertFalse(marker.exists())
                    if approve:
                        peer.sendall(b"GO")
                output, error = process.communicate(timeout=3)
                if approve:
                    self.assertEqual(process.returncode, 0, error)
                    self.assertEqual(marker.read_text(), "literal $(not a shell)")
                else:
                    self.assertEqual(process.returncode, 125)
                    self.assertFalse(marker.exists())
                    self.assertIn(b"disconnected", error)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                os.close(descriptor)
                listener.close()

    def test_command_starts_only_after_self_attachment_and_explicit_go(self):
        self.run_gate(True)

    def test_disconnect_before_go_never_executes_requested_command(self):
        self.run_gate(False)


class FakeAPI:
    def __init__(self):
        self.expected = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/pmon", "pid": 123, "running": True}
        self.ident = "c" * 64
        self.config = None
        self.go = threading.Event()
        self.ready = threading.Event()
        self.order = []
        self.wrong_container = False

    def json(self, method, path, body=None):
        if path.startswith("/containers/") and path.endswith("/json"):
            return {"Id": self.expected["id"], "Image": self.expected["image"], "Name": "/pmon", "State": {"Running": True, "Pid": 123}}
        if method == "POST":
            self.config = body
            return {"Id": self.ident}
        return {"ID": self.ident, "ContainerID": "d" * 64 if self.wrong_container else self.expected["id"],
                "Running": not self.go.is_set(), "Pid": 321, "ExitCode": 0,
                "ProcessConfig": {"entrypoint": self.config["Cmd"][0], "arguments": self.config["Cmd"][1:],
                                  "privileged": self.config["Privileged"], "tty": self.config["Tty"], "user": self.config["User"]}}

    def stream(self, ident, ready, cancel, output, limit):
        ready.set()
        self.ready.set()
        while not self.go.wait(0.01):
            if cancel.is_set():
                return


class FakePeer:
    def __init__(self, api):
        self.api = api
        self.step = 0
    def settimeout(self, _):
        pass
    def getsockopt(self, *_):
        return struct.pack("3i", 321, 0, 0)
    def recv(self, _):
        self.step += 1
        return self.api.config["Cmd"][6].encode() if self.step == 1 else b"ATTACHED"
    def sendmsg(self, payload, ancillary):
        self.api.order.append("FD")
        self.descriptors = ancillary[0][2]
    def sendall(self, value):
        assert value == b"GO"
        self.api.order.append("GO")
        self.api.go.set()
    def close(self):
        pass


class CoordinationTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.peer = FakePeer(self.api)
        self.group = "/system.slice/sonic-smart-patch-maint-" + "a" * 32 + ".service"
        self.group_observed = self.group
        api, peer = self.api, self.peer
        @contextmanager
        def gate(*_):
            listener = Mock()
            def accept():
                assert api.ready.wait(1)
                return peer, None
            listener.accept.side_effect = accept
            yield listener, "/var/tmp/gate-fixture/control.sock"
        def membership(_):
            if "FD" in self.api.order:
                self.api.order.append("verified")
                return self.group_observed
            self.api.order.append("original")
            return "/system.slice/docker-" + "a" * 64 + ".scope"
        patchers = [patch("smart_patch.docker_maintenance.owned_cgroup", return_value=(self.group, 91)),
                    patch("smart_patch.docker_maintenance.gate_socket", gate),
                    patch("smart_patch.docker_maintenance._verify_gate", return_value="start-one"),
                    patch("smart_patch.docker_maintenance._verify_default_cgroup", return_value="/system.slice/docker-" + "a" * 64 + ".scope"),
                    patch("smart_patch.docker_maintenance._cgroup_path", side_effect=membership),
                    patch.object(Path, "read_text", return_value="0 0 4294967295"),
                    patch("smart_patch.maintenance_resources._process_start", return_value="start-one"),
                    patch("smart_patch.docker_maintenance.os.pidfd_open", return_value=92),
                    patch("smart_patch.docker_maintenance.os.close"),
                    patch("smart_patch.docker_maintenance.signal.pidfd_send_signal")]
        self.patches = []
        for patcher in patchers:
            self.patches.append(patcher.start())
            self.addCleanup(patcher.stop)

    def run_command(self):
        return run_container_exec(self.api.expected, "/", ["dpkg-query", "-W", "socat"], timeout=2,
                                  api_factory=lambda _: self.api)

    def test_docker_retains_security_and_fd_membership_precedes_go(self):
        self.assertEqual(self.run_command(), 0)
        self.assertFalse(self.api.config["Privileged"])
        self.assertFalse(self.api.config["Tty"])
        self.assertEqual(self.api.config["User"], "0:0")
        self.assertEqual(self.api.config["Cmd"][-3:], ["dpkg-query", "-W", "socat"])
        self.assertEqual(list(self.peer.descriptors), [91])
        self.assertEqual(self.api.order, ["original", "FD", "verified", "GO"])

    def test_failed_attachment_never_releases_package_command(self):
        self.group_observed = "/some-other-cgroup"
        with self.assertRaisesRegex(ValueError, "did not join"):
            self.run_command()
        self.assertFalse(self.api.go.is_set())
        self.assertNotIn("GO", self.api.order)
        self.patches[-1].assert_any_call(92, signal.SIGKILL)

    def test_other_container_exec_is_rejected_before_fd_transfer(self):
        self.api.wrong_container = True
        with self.assertRaisesRegex(ValueError, "identity or security"):
            self.run_command()
        self.assertEqual(self.api.order, [])
        self.assertFalse(self.api.go.is_set())

    def test_command_timeout_kills_exact_pidfd_and_cancels_stream(self):
        cancelled = threading.Event()
        def stuck_stream(ident, ready, cancel, output, limit):
            ready.set()
            self.api.ready.set()
            if cancel.wait(2):
                cancelled.set()
        self.api.stream = stuck_stream
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            run_container_exec(self.api.expected, "/", ["dpkg-query", "-W", "socat"], timeout=0.05,
                               api_factory=lambda _: self.api)
        self.assertTrue(cancelled.is_set())
        self.patches[-1].assert_any_call(92, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
