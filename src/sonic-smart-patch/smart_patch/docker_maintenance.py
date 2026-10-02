"""Docker-secured exec with resource attachment before package execution.

The Docker daemon creates the process with the container's original namespaces,
seccomp, LSM and capabilities. A small Python gate receives this worker unit's
cgroup descriptor, moves *itself* by writing PID 0, and waits for confirmation.
Passing a descriptor avoids a numeric PID-reuse race in host cgroup writes.
The package command runs only after host verification and an explicit GO.
"""
from contextlib import contextmanager
import array
import ctypes
import errno
import http.client
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid


DOCKER_SOCKET = "/var/run/docker.sock"
CGROUP_ROOT = Path("/sys/fs/cgroup")
MAX_MEMORY = 512 * 1024 * 1024
MAX_TASKS = 128
BASIC_DEVICES = {"null": 3, "zero": 5, "full": 7, "random": 8, "urandom": 9}
# Linux UAPI cgroup attachment types through 6.12. Other bpf_attach_type
# values address network devices, socket maps, tracing, etc.; a cgroup FD is
# not a valid query target for those APIs (NETKIT returns ENXIO, for example).
# BPF_CGROUP_DEVICE (6) is replaced by the verified basic-device subset.
CGROUP_BPF_ATTACH_TYPES = (0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15,
                           18, 19, 20, 21, 22, 29, 30, 31, 32, 34, 43, 49, 50, 51, 52, 53)
GATE_TIMEOUT = 15
GATE_CODE = r'''
import array, os, socket, stat, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(15)
fds = []
try:
    # Verify that our conservative destination device allowlist grants no
    # device opens that were forbidden by the original container cgroup.
    for name, minor in (("null",3),("zero",5),("full",7),("random",8),("urandom",9)):
        info = os.stat("/dev/" + name)
        if not stat.S_ISCHR(info.st_mode) or os.major(info.st_rdev) != 1 or os.minor(info.st_rdev) != minor:
            raise RuntimeError("Container basic device identity cannot be verified")
        probe = os.open("/dev/" + name, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
        os.close(probe)
    s.connect(sys.argv[1])
    s.sendall(sys.argv[2].encode("ascii"))
    data, anc, flags, address = s.recvmsg(1, socket.CMSG_SPACE(4))
    for level, kind, payload in anc:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            received = array.array("i")
            received.frombytes(payload[:len(payload) - len(payload) % received.itemsize])
            fds.extend(received)
    if data != b"F" or flags & socket.MSG_CTRUNC or len(fds) != 1:
        raise RuntimeError("Invalid resource attachment descriptor")
    if os.write(fds[0], b"0") != 1:
        raise RuntimeError("Incomplete resource attachment")
    os.close(fds.pop())
    s.sendall(b"ATTACHED")
    go = b""
    while len(go) < 2:
        part = s.recv(2 - len(go))
        if not part:
            raise RuntimeError("Maintenance controller disconnected before approval")
        go += part
    if go != b"GO":
        raise RuntimeError("Maintenance controller did not approve execution")
    s.close()
    os.execvpe(sys.argv[3], sys.argv[3:], {"LANG":"C", "LC_ALL":"C", "PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "HOME":"/root"})
except BaseException as error:
    sys.stderr.write("Container maintenance gate: " + str(error)[:300] + "\n")
    sys.exit(125)
finally:
    for descriptor in fds:
        os.close(descriptor)
    s.close()
'''.strip()


def _remaining(deadline, maximum=5):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Container maintenance command exceeded its deadline")
    return min(maximum, remaining)


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class DockerAPI:
    def __init__(self, deadline, path=DOCKER_SOCKET):
        info = Path(path).stat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002:
            raise ValueError("Docker Engine socket must be root-owned and not world writable")
        self.path, self.deadline = path, deadline
        self.prefix = ""
        version = self.json("GET", "/version")
        def parsed(value):
            if not re.fullmatch(r"[0-9]+\.[0-9]+", str(value)):
                raise ValueError("Cannot establish the Docker Engine API version")
            return tuple(int(part) for part in value.split("."))
        newest = parsed(version.get("ApiVersion"))
        oldest = parsed(version.get("MinAPIVersion", "1.24"))
        selected = max((1, 41), oldest)
        if newest < selected:
            raise ValueError("Container maintenance needs Docker Engine API 1.41 or newer")
        self.prefix = "/v%d.%d" % selected

    def json(self, method, path, body=None):
        connection = _UnixHTTP(self.path, _remaining(self.deadline))
        try:
            encoded = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
            connection.request(method, self.prefix + path, body=encoded, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise ValueError("Docker Engine metadata exceeds its output budget")
            if not 200 <= response.status < 300:
                raise RuntimeError("Docker Engine request failed with HTTP %d" % response.status)
            result = json.loads(raw) if raw else {}
            if not isinstance(result, dict):
                raise ValueError("Docker Engine returned invalid metadata")
            return result
        finally:
            connection.close()

    def stream(self, exec_id, ready, cancel, output, limit):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(_remaining(self.deadline))
            connection.connect(self.path)
            body = b'{"Detach":false,"Tty":false}'
            request = ("POST %s/exec/%s/start HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
                       "Upgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % (
                           self.prefix, exec_id, len(body))).encode() + body
            connection.sendall(request)
            connection.settimeout(0.2)
            buffer = bytearray()
            while b"\r\n\r\n" not in buffer:
                _remaining(self.deadline)
                if cancel.is_set():
                    raise RuntimeError("Container output session cancelled")
                try:
                    chunk = connection.recv(16384)
                except socket.timeout:
                    continue
                if not chunk:
                    raise RuntimeError("Docker Engine closed the exec start response")
                buffer.extend(chunk)
                if len(buffer) > 32768:
                    raise ValueError("Docker Engine exec headers exceed their budget")
            header, initial = bytes(buffer).split(b"\r\n\r\n", 1)
            status_line = header.split(b"\r\n", 1)[0].split()
            if len(status_line) < 2 or status_line[1] not in (b"101", b"200") or b"transfer-encoding: chunked" in header.lower():
                raise RuntimeError("Docker Engine did not establish the raw exec stream")
            ready.set()
            decoder = DockerFrames(limit, output)
            decoder.feed(initial)
            while not cancel.is_set():
                _remaining(self.deadline)
                try:
                    chunk = connection.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    decoder.finish()
                    return
                decoder.feed(chunk)
            raise RuntimeError("Container output session cancelled")
        finally:
            connection.close()


class DockerFrames:
    """Decode Docker's non-TTY stdout/stderr frames with a cumulative bound."""
    def __init__(self, limit, output):
        self.limit, self.output, self.total = limit, output, 0
        self.buffer = bytearray()

    def feed(self, chunk):
        self.buffer.extend(chunk)
        while len(self.buffer) >= 8:
            stream, reserved, length = self.buffer[0], self.buffer[1:4], struct.unpack(">I", self.buffer[4:8])[0]
            if stream not in (1, 2, 3) or reserved != b"\0\0\0":
                raise ValueError("Invalid Docker stdout/stderr framing")
            if length > self.limit - self.total:
                raise ValueError("Container command exceeded its output budget")
            if len(self.buffer) < 8 + length:
                return
            payload = bytes(self.buffer[8:8 + length])
            del self.buffer[:8 + length]
            self.total += length
            if stream == 3:
                raise RuntimeError("Docker exec failed: " + payload.decode("utf-8", errors="replace")[:500])
            self.output(payload)

    def finish(self):
        if self.buffer:
            raise ValueError("Docker exec output stream ended with an incomplete frame")


def _cgroup_path(pid):
    lines = Path("/proc/%s/cgroup" % pid).read_text().splitlines()
    unified = [line[3:] for line in lines if line.startswith("0::")]
    if len(lines) != 1 or len(unified) != 1:
        raise ValueError("Docker-secured package maintenance requires unified cgroup v2")
    return unified[0]


def owned_cgroup(quota):
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ValueError("Docker-secured maintenance requires kernel/Python pidfd support")
    relative = _cgroup_path("self")
    if not re.fullmatch(r"/system\.slice/sonic-smart-patch-maint-[0-9a-f]{32}\.service", relative):
        raise ValueError("Docker-secured maintenance must run in its own Smart Patch transient unit")
    directory = CGROUP_ROOT / relative.lstrip("/")
    if not (CGROUP_ROOT / "cgroup.controllers").is_file():
        raise ValueError("Docker-secured package maintenance requires unified cgroup v2")
    memory, tasks = (directory / "memory.max").read_text().strip(), (directory / "pids.max").read_text().strip()
    if not memory.isdigit() or not 0 < int(memory) <= MAX_MEMORY or not tasks.isdigit() or not 0 < int(tasks) <= MAX_TASKS:
        raise ValueError("Container worker memory/task limits were not established")
    cpu = (directory / "cpu.max").read_text().split()
    if quota and (len(cpu) != 2 or not all(value.isdigit() for value in cpu)
                  or int(cpu[1]) <= 0 or int(cpu[0]) * 100 > quota * int(cpu[1])):
        raise ValueError("Container worker CPU quota was not established")
    _verify_device_policy(relative)
    return relative, os.open(directory / "cgroup.procs", os.O_WRONLY | os.O_CLOEXEC)


def _verify_device_policy(relative):
    unit = relative.rsplit("/", 1)[1]
    result = subprocess.run(["/usr/bin/systemctl", "show", unit, "--property=DevicePolicy",
                             "--property=DeviceAllow", "--property=ControlGroup"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5, text=True)
    if len(result.stdout) > 16384:
        raise ValueError("Container device policy exceeds its metadata budget")
    fields = {}
    allowed = []
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError("Container device policy cannot be verified")
        if key == "DeviceAllow":
            tokens = value.split()
            if len(tokens) % 2:
                raise ValueError("Container device allowlist cannot be verified")
            allowed.extend(zip(tokens[::2], tokens[1::2]))
        else:
            fields[key] = value
    expected = {(str(Path("/dev") / name), "rw") for name in BASIC_DEVICES}
    if fields.get("DevicePolicy") != "strict" or fields.get("ControlGroup") != relative or set(allowed) != expected:
        raise ValueError("Container worker must deny all devices except verified basic character devices; mknod is not permitted")


class _BpfQuery(ctypes.Structure):
    _fields_ = [("target_fd", ctypes.c_uint32), ("attach_type", ctypes.c_uint32),
                ("query_flags", ctypes.c_uint32), ("attach_flags", ctypes.c_uint32),
                ("prog_ids", ctypes.c_uint64), ("prog_cnt", ctypes.c_uint32)]


def _verify_default_cgroup(current, expected):
    config = current.get("HostConfig", {})
    if config.get("CgroupParent"):
        raise ValueError("Custom container cgroup parents require reviewed image maintenance")
    # SONiC normally grants extra SPI/platform character devices through these
    # additive rules. We do not copy those grants to the worker: its strict
    # five-device allowlist remains a subset, checked by the gate while it is
    # still subject to the original Docker policy.
    rules = config.get("DeviceCgroupRules") or []
    if (not isinstance(rules, list) or len(rules) > 512
            or any(not isinstance(rule, str) or not re.fullmatch(r"[abc]\s+(?:[0-9]+|\*):(?:[0-9]+|\*)\s+[rwm]{1,3}", rule.strip())
                   for rule in rules)):
        raise ValueError("Container device rules metadata could not be verified")
    group = _cgroup_path(current["State"]["Pid"])
    if group != "/system.slice/docker-%s.scope" % expected["id"]:
        raise ValueError("Container must share the standard system.slice parent with its maintenance worker")
    _reject_extra_cgroup_bpf(CGROUP_ROOT / group.lstrip("/"))
    return group


def _reject_extra_cgroup_bpf(directory):
    """Reject effective non-device BPF policies before changing cgroups.

    Ancestor programs can branch on the current cgroup ID, so sharing an
    ancestor does not prove equivalent policy. Query effective attachments.
    Device BPF is replaced by a verified strict subset. Unsupported attach
    types return EINVAL; privilege/query errors and an unverifiable ABI block.
    """
    syscall = {"x86_64": 321, "aarch64": 280, "riscv64": 280}.get(platform.machine())
    if syscall is None:
        raise ValueError("Container cgroup BPF policy inspection is unsupported on this architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        known_query_succeeded = False
        for attach_type in CGROUP_BPF_ATTACH_TYPES:
            query = _BpfQuery(target_fd=descriptor, attach_type=attach_type, query_flags=1)  # BPF_F_QUERY_EFFECTIVE
            result = libc.syscall(syscall, 16, ctypes.byref(query), ctypes.sizeof(query))  # BPF_PROG_QUERY
            error = ctypes.get_errno() if result < 0 else 0
            if error == errno.EINVAL:
                continue
            if query.prog_cnt:
                raise ValueError("Container has additional cgroup BPF security policies; reviewed image maintenance is required")
            if result != 0:
                raise OSError(error, "Container cgroup BPF security policy could not be verified")
            if attach_type in (0, 1, 2, 3):
                known_query_succeeded = True
        if not known_query_succeeded:
            raise ValueError("Container cgroup BPF query ABI could not be verified")
    finally:
        os.close(descriptor)


@contextmanager
def gate_socket(container_pid, nonce):
    """Bind through pinned directory FDs, independent of later PID/name reuse."""
    handles, listener, made = [], None, False
    name = "smart-patch-gate-" + nonce
    try:
        root = os.open("/proc/%d/root" % container_pid, os.O_PATH | os.O_DIRECTORY)
        handles.append(root)
        parent = root
        for part in ("var", "tmp"):
            parent = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            handles.append(parent)
        os.mkdir(name, 0o700, dir_fd=parent)
        made = True
        directory = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        handles.append(directory)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind("/proc/self/fd/%d/control.sock" % directory)
        os.chmod("control.sock", 0o600, dir_fd=directory)
        listener.listen(1)
        listener.settimeout(0.2)
        yield listener, "/var/tmp/%s/control.sock" % name
    finally:
        if listener is not None:
            listener.close()
        if made:
            try:
                if len(handles) == 4:
                    os.unlink("control.sock", dir_fd=handles[-1])
            except FileNotFoundError:
                pass
            try:
                os.rmdir(name, dir_fd=handles[2])
            except FileNotFoundError:
                pass
        for descriptor in reversed(handles):
            os.close(descriptor)


def _receive(peer, length):
    value = bytearray()
    while len(value) < length:
        chunk = peer.recv(length - len(value))
        if not chunk:
            raise RuntimeError("Container maintenance gate disconnected")
        value.extend(chunk)
    return bytes(value)


def _inspect_exec(api, ident, expected, command):
    info = api.json("GET", "/exec/%s/json" % ident)
    config = info.get("ProcessConfig", {})
    if (info.get("ID") != ident or info.get("ContainerID") != expected["id"]
            or config.get("entrypoint") != command[0] or config.get("arguments") != command[1:]
            or config.get("privileged") is not False or config.get("tty") is not False
            or config.get("user") not in ("0", "0:0")):
        raise ValueError("Docker exec identity or security configuration changed")
    return info


def _verify_gate(pid, expected_pid, command):
    from smart_patch.maintenance_resources import _process_start
    start = _process_start(pid)
    observed = Path("/proc/%d/cmdline" % pid).read_bytes().split(b"\0")
    if observed != [part.encode() for part in command] + [b""]:
        raise ValueError("Docker exec gate command identity changed")
    for namespace in ("mnt", "pid", "net", "uts", "ipc", "user"):
        if os.stat("/proc/%d/ns/%s" % (pid, namespace)).st_ino != os.stat("/proc/%d/ns/%s" % (expected_pid, namespace)).st_ino:
            raise ValueError("Docker exec gate is not in the approved container namespaces")
    return start


def run_container_exec(expected, directory, argv, timeout=15, limit=4 * 1024 * 1024, quota=0, api_factory=DockerAPI):
    from smart_patch.maintenance_resources import _process_start, _same_container, container_identity
    deadline = time.monotonic() + timeout
    group, group_fd = owned_cgroup(quota)
    peer = None
    pidfd = None
    thread = None
    ready, cancel, done = threading.Event(), threading.Event(), threading.Event()
    errors = []
    nonce = uuid.uuid4().hex
    try:
        api = api_factory(deadline)
        inspected = api.json("GET", "/containers/%s/json" % expected["id"])
        current = container_identity({"id": inspected.get("Id"), "image": inspected.get("Image"), "name": inspected.get("Name"),
                                      "running": inspected.get("State", {}).get("Running"), "pid": inspected.get("State", {}).get("Pid")})
        if not _same_container(current, expected):
            raise ValueError("Container identity changed before Docker exec")
        if Path("/proc/%d/uid_map" % current["pid"]).read_text().split() != ["0", "0", "4294967295"]:
            raise ValueError("User-namespace remapped containers require image maintenance")
        original_group = _verify_default_cgroup(inspected, expected)
        initial_start = _process_start(current["pid"])
        with gate_socket(current["pid"], nonce) as (listener, address):
            command = ["/usr/bin/python3", "-I", "-S", "-c", GATE_CODE, address, nonce, *argv]
            created = api.json("POST", "/containers/%s/exec" % expected["id"], {
                "User": "0:0", "Privileged": False, "Tty": False, "AttachStdin": False,
                "AttachStdout": True, "AttachStderr": True, "WorkingDir": directory,
                "Env": ["LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root",
                        "LD_PRELOAD=", "LD_LIBRARY_PATH=", "LD_AUDIT=", "PYTHONPATH=", "PYTHONHOME="], "Cmd": command})
            ident = created.get("Id")
            if not re.fullmatch(r"[0-9a-f]{64}", str(ident)):
                raise ValueError("Docker Engine returned an invalid exec identifier")
            def stream():
                try:
                    api.stream(ident, ready, cancel, lambda data: (sys.stdout.buffer.write(data), sys.stdout.buffer.flush()), limit)
                except BaseException as error:
                    errors.append(error)
                finally:
                    done.set()
            thread = threading.Thread(target=stream, daemon=True, name="smart-patch-docker-output")
            thread.start()
            gate_deadline = min(deadline, time.monotonic() + GATE_TIMEOUT)
            while peer is None:
                _remaining(gate_deadline)
                if errors:
                    raise errors[0]
                if done.is_set():
                    raise RuntimeError("Container gate exited before attaching; inspect Python 3 availability and gate access in the selected container")
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    continue
            peer.settimeout(_remaining(gate_deadline))
            pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != 0 or gid != 0 or _receive(peer, len(nonce)) != nonce.encode():
                raise ValueError("Container gate peer identity was not established")
            info = _inspect_exec(api, ident, expected, command)
            while info.get("Pid") in (None, 0) and not errors:
                time.sleep(min(0.05, _remaining(gate_deadline)))
                info = _inspect_exec(api, ident, expected, command)
            if info.get("Pid") != pid or info.get("Running") is not True:
                raise ValueError("Container gate peer is not the approved running Docker exec")
            start = _verify_gate(pid, current["pid"], command)
            pidfd = os.pidfd_open(pid, 0)
            signal.pidfd_send_signal(pidfd, 0)
            if (_process_start(pid) != start or _process_start(current["pid"]) != initial_start
                    or _cgroup_path(pid) != original_group):
                raise ValueError("Container process changed while binding the exec gate")
            # The child writes PID 0 to attach itself. We never write a remote
            # numeric PID, and SO_PEERCRED binds the descriptor recipient.
            peer.sendmsg([b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [group_fd]))])
            if _receive(peer, 8) != b"ATTACHED" or _cgroup_path(pid) != group or _process_start(pid) != start:
                raise ValueError("Container package process did not join the bounded worker cgroup")
            info = _inspect_exec(api, ident, expected, command)
            if info.get("Pid") != pid or info.get("Running") is not True or errors or not ready.is_set():
                raise ValueError("Container exec changed before package execution")
            peer.sendall(b"GO")
            peer.close()
            peer = None
            while not done.wait(min(0.2, _remaining(deadline))):
                pass
            if errors:
                raise errors[0]
            info = _inspect_exec(api, ident, expected, command)
            finish_deadline = min(deadline, time.monotonic() + 2)
            while info.get("Running") is True:
                time.sleep(min(0.05, _remaining(finish_deadline)))
                info = _inspect_exec(api, ident, expected, command)
            if info.get("Running") is not False or type(info.get("ExitCode")) is not int:
                raise RuntimeError("Docker exec outcome is unknown")
            return info["ExitCode"]
    finally:
        cancel.set()
        if peer is not None:
            peer.close()
        if pidfd is not None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(pidfd)
        os.close(group_fd)
        if thread is not None:
            thread.join(timeout=0.5)
