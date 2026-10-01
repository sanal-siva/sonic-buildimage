"""Run host maintenance separately from the small inventory collector cgroup.

CPU quota zero means no Smart Patch maintenance CPU quota. Platform or ancestor
slice limits still apply. The independent memory budget and wall-time/output
budgets remain enforced. On cgroup v2 a Docker exec gate preserves container
security settings and attaches itself to the bounded worker before package
execution. Legacy unconfined containers use pinned namespaces. Bounding a
Docker client alone would not bound a package manager started by the daemon.
"""
import ctypes
import json
import math
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import uuid

from smart_patch.collector import run


SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
MEMORY_MAX_MIB = 512
STANDARD_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DOCKER = "/usr/bin/docker"
CONTAINER_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
                    '"running":{{json .State.Running}},"pid":{{json .State.Pid}}}')


def container_identity(value, require_running=True):
    """Keep only immutable identity and the observed running process."""
    if (not isinstance(value, dict)
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("id", "")))
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("image", "")))
            or not re.fullmatch(r"/?[A-Za-z0-9][A-Za-z0-9_.-]*", str(value.get("name", "")))
            or type(value.get("running")) is not bool or type(value.get("pid")) is not int
            or value["pid"] < 0 or (require_running and (value["running"] is not True or value["pid"] <= 1))):
        raise ValueError("Container must have a verified full ID, image identity and running process")
    return {key: value[key] for key in ("id", "image", "name", "running", "pid")}


def _same_container(observed, expected):
    return all(observed.get(key) == expected.get(key) for key in ("id", "image", "name"))


def _process_start(pid):
    # The comm field may contain spaces and parentheses. Field 22 is starttime.
    return Path("/proc/%d/stat" % pid).read_text().rsplit(") ", 1)[1].split()[19]


def _process_security(pid):
    fields = dict(line.split(":", 1) for line in Path("/proc/%s/status" % pid).read_text().splitlines() if ":" in line)
    result = {key: int(fields[key].strip(), 16) for key in ("CapBnd", "CapPrm", "CapEff", "CapAmb")}
    result["Seccomp"] = int(fields["Seccomp"].strip())
    result["NoNewPrivs"] = int(fields["NoNewPrivs"].strip())
    result["profile"] = Path("/proc/%s/attr/current" % pid).read_text().strip()
    return result


def _compatible_security(target, helper):
    # Namespace entry cannot copy a target's seccomp or LSM filter. Matching
    # mode numbers do not prove matching filters: support only unconfined
    # containers (normal for privileged SONiC service containers).
    if target["Seccomp"] != 0 or helper["Seccomp"] != 0 or target["profile"] != "unconfined" or helper["profile"] != "unconfined":
        raise ValueError("Seccomp/LSM-confined containers require image maintenance; namespace execution cannot preserve their filters")
    if target["NoNewPrivs"] not in (0, 1):
        raise ValueError("Container security policy cannot be verified")


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def _checked(result, operation):
    if result != 0:
        raise OSError(ctypes.get_errno(), "Container namespace helper failed to " + operation)


def _container_exec(libc, root, cwd, target, helper, argv, max_descriptor):
    """Trusted child path: chroot then remove host privileges before any exec."""
    os.fchdir(root)
    os.chroot(".")
    os.fchdir(cwd)
    os.setgroups([])
    os.setgid(0)
    os.setuid(0)
    # Close pinned root/namespace descriptors before running container code.
    os.closerange(3, max_descriptor)
    allowed = target["CapBnd"] & target["CapPrm"] & target["CapEff"] & helper["CapPrm"] & helper["CapEff"]
    # Drop bounding-set bits while CAP_SETPCAP is still held. Dropping a bit
    # from the bounding set does not itself clear the current effective bit.
    for capability in range(64):
        if helper["CapBnd"] & (1 << capability) and not allowed & (1 << capability):
            _checked(libc.prctl(24, capability, 0, 0, 0), "drop a capability bounding bit")
    _checked(libc.prctl(47, 4, 0, 0, 0), "clear ambient capabilities")
    data = (_CapData * 2)()
    for index in range(2):
        data[index].effective = data[index].permitted = (allowed >> (index * 32)) & 0xffffffff
        data[index].inheritable = 0
    header = _CapHeader(0x20080522, 0)
    _checked(libc.capset(ctypes.byref(header), ctypes.byref(data)), "restrict effective/permitted capabilities")
    _checked(libc.prctl(38, 1, 0, 0, 0), "set no-new-privileges")
    os.execvpe(argv[0], argv, {"LANG": "C", "LC_ALL": "C", "PATH": STANDARD_PATH, "HOME": "/root"})


def _run_in_namespaces(libc, namespaces, root, cwd, target, helper, argv, max_descriptor):
    for descriptor in namespaces:
        _checked(libc.setns(descriptor, 0), "enter a pinned namespace")
    # setns(CLONE_NEWPID) affects children, so fork after entering namespaces.
    child = os.fork()
    if child == 0:
        try:
            _container_exec(libc, root, cwd, target, helper, argv, max_descriptor)
        except BaseException as error:
            os.write(2, (_brief(error) + "\n").encode())
        os._exit(126)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status)


def _cgroup_v2():
    return Path("/sys/fs/cgroup/cgroup.controllers").is_file()


def _container_entry(expected, directory, argv, timeout=15, limit=4 * 1024 * 1024, quota=0):
    """Internal root helper. Package work runs in the outer systemd cgroup.

    Namespace and root handles are opened while the container PID is stable.
    Recreated container names and recycled PIDs never select a replacement.
    No command text is evaluated by a shell and no container cgroup is joined.
    """
    if os.geteuid() != 0 or not _trusted_executable(DOCKER):
        raise RuntimeError("Container maintenance requires a trusted root helper and Docker executable")
    expected = container_identity(expected)
    if not argv or not directory.startswith("/") or "\0" in directory:
        raise ValueError("Invalid container command or working directory")
    if _cgroup_v2():
        # Docker itself establishes seccomp/LSM/capability settings. The gate
        # attaches to our bounded unit before it executes any package command.
        from smart_patch.docker_maintenance import run_container_exec
        return run_container_exec(expected, directory, argv, timeout=timeout, limit=limit, quota=quota)
    # Load libc and all supporting modules before changing namespaces/root.
    libc = ctypes.CDLL(None, use_errno=True)
    for name in ("setns", "prctl", "capset"):
        getattr(libc, name)
    descriptor_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if descriptor_limit < 0 or descriptor_limit > 1048576:
        raise ValueError("Container helper file-descriptor bound is unsupported")

    def inspect():
        result = subprocess.run([DOCKER, "inspect", "--format", CONTAINER_FORMAT, expected["id"]],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                                text=True)
        if len(result.stdout) > 16384:
            raise ValueError("Container identity exceeds output budget")
        value = container_identity(json.loads(result.stdout))
        if not _same_container(value, expected):
            raise ValueError("Container identity changed before command execution")
        return value

    before = inspect()
    pid = before["pid"]
    start = _process_start(pid)
    # Host root must map to container root. User-namespace remapping requires a
    # distinct implementation; never enter it with ambiguous credentials.
    if Path("/proc/%d/uid_map" % pid).read_text().split() != ["0", "0", "4294967295"]:
        raise ValueError("User-namespace remapped containers require image maintenance")
    target_security, helper_security = _process_security(pid), _process_security("self")
    _compatible_security(target_security, helper_security)
    handles = []
    try:
        for namespace in ("mnt", "uts", "ipc", "net", "pid"):
            descriptor = os.open("/proc/%d/ns/%s" % (pid, namespace), os.O_RDONLY)
            handles.append(descriptor)
        root = os.open("/proc/%d/root" % pid, os.O_PATH | os.O_DIRECTORY)
        handles.append(root)
        # Open cwd relative to the pinned root and reject symlink traversal.
        # All maintenance directories are fixed absolute paths created by us.
        current = root
        for segment in directory.split("/"):
            if not segment:
                continue
            if segment in (".", ".."):
                raise ValueError("Invalid container working directory")
            current = os.open(segment, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            handles.append(current)
        after = inspect()
        if after["pid"] != pid or _process_start(pid) != start or _process_security(pid) != target_security:
            raise ValueError("Container process changed while pinning namespaces")
        return _run_in_namespaces(libc, handles[:5], root, current, target_security,
                                  helper_security, argv, descriptor_limit)
    finally:
        for descriptor in reversed(handles):
            os.close(descriptor)


def _trusted_executable(filename):
    try:
        path = Path(filename).resolve(strict=True)
        info = path.stat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and os.access(path, os.X_OK))
    except OSError:
        return False


def systemd_available():
    return (os.geteuid() == 0 and Path("/run/systemd/system").is_dir()
            and _trusted_executable(SYSTEMD_RUN) and _trusted_executable(SYSTEMCTL))


def container_maintenance_available():
    return systemd_available() and _trusted_executable("/usr/bin/python3") and _trusted_executable(DOCKER)


def in_collector_cgroup():
    try:
        return any("sonic-smart-patch.service" in line.split(":", 2)[-1].split("/")
                   for line in Path("/proc/self/cgroup").read_text().splitlines())
    except OSError:
        # No observable cgroup means that escaping a daemon limit is unverified.
        return True


def _brief(error):
    return " ".join(str(error).split())[:500]


class MaintenanceCommandRunner:
    def __init__(self, config, runner=run, available=None, in_collector=None):
        self.config = config
        self.runner = runner
        self.available = available
        self.in_collector = in_collector

    @staticmethod
    def _check(value, fallback):
        return fallback() if value is None else value() if callable(value) else bool(value)

    def __call__(self, argv, timeout=15, limit=4 * 1024 * 1024, cwd=None):
        return self.run(argv, timeout=timeout, limit=limit, cwd=cwd)

    def container(self, identity, argv, timeout=15, limit=4 * 1024 * 1024, cwd="/"):
        identity = container_identity(identity)
        if not self._check(self.available, systemd_available) or not _trusted_executable("/usr/bin/python3"):
            raise RuntimeError("Container maintenance requires a trusted root systemd manager and Python namespace helper to enforce package-process limits")
        # Launch the host-installed helper before entering the container. It
        # opens namespace/root descriptors itself so systemd need not inherit FDs.
        command = ["/usr/bin/python3", "-m", "smart_patch.maintenance_resources", "--container",
                   json.dumps(identity, separators=(",", ":")), str(timeout), str(limit),
                   str(self.config.values().get("maintenance_cpu_quota_percent", "0")), cwd, *argv]
        return self.run(command, timeout=timeout, limit=limit, container_worker=True)

    def run(self, argv, timeout=15, limit=4 * 1024 * 1024, cwd=None, container_worker=False):
        if (not isinstance(argv, (list, tuple)) or not argv or not argv[0]
                or any(not isinstance(arg, str) or "\0" in arg for arg in argv)):
            raise ValueError("Maintenance command must be an argument list")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Maintenance command deadline must be positive")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("Maintenance command output budget must be positive")
        value = self.config.values().get("maintenance_cpu_quota_percent", "0")
        if isinstance(value, bool) or not str(value).isascii() or not str(value).isdigit() or not 0 <= int(value) <= 100:
            raise ValueError("Maintenance CPU quota must be 0 (disabled) or 1-100 percent")
        quota = int(value)
        directory = None
        if cwd is not None:
            path = Path(cwd)
            if not path.is_absolute() or not path.is_dir():
                raise ValueError("Maintenance working directory must be an existing absolute directory")
            directory = str(path.resolve(strict=True))

        if not self._check(self.available, systemd_available):
            if quota:
                raise RuntimeError("Maintenance CPU quota requires a trusted root systemd manager")
            if self._check(self.in_collector, in_collector_cgroup):
                raise RuntimeError("Maintenance cannot escape collector resource limits without a trusted root systemd manager")
            # Standalone tools/tests have no collector cgroup to escape. They
            # retain command/output bounds but have no systemd memory ceiling.
            options = {"timeout": timeout, "limit": limit}
            if directory is not None:
                options["cwd"] = directory
            return self.runner(["/usr/bin/env", "LANG=C", "LC_ALL=C", "PATH=" + STANDARD_PATH, *argv], **options)

        unit = "sonic-smart-patch-maint-" + uuid.uuid4().hex + ".service"
        command = [SYSTEMD_RUN, "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
                   "--slice=system.slice", "--unit=" + unit,
                   "--property=MemoryMax=%dM" % MEMORY_MAX_MIB, "--property=TasksMax=128",
                   "--property=RuntimeMaxSec=%ss" % timeout, "--property=TimeoutStopSec=5s",
                   "--property=KillMode=control-group", "--setenv=LANG=C", "--setenv=LC_ALL=C",
                   "--setenv=PATH=" + STANDARD_PATH]
        if container_worker:
            # Moving an exec to this cgroup must not grant host block/hardware
            # device access. No mknod permission is included in this allowlist.
            command.append("--property=DevicePolicy=strict")
            command.extend("--property=DeviceAllow=/dev/%s rw" % name
                           for name in ("null", "zero", "full", "random", "urandom"))
        if self._check(self.in_collector, in_collector_cgroup):
            # A collector restart must stop, not restart, a child transaction.
            # Keep the worker in its sibling cgroup but tie its lifetime to the
            # owning service so a killed client cannot leave package work behind.
            command.extend(["--property=BindsTo=sonic-smart-patch.service",
                            "--property=After=sonic-smart-patch.service"])
        if quota:
            command.append("--property=CPUQuota=%d%%" % quota)
        if directory is not None:
            # systemd expands specifiers in WorkingDirectory, even without a
            # shell. Escape percent signs to preserve the exact validated path.
            command.append("--property=WorkingDirectory=" + directory.replace("%", "%%"))
        # A transient service's ExecStart arguments undergo PID 1 environment
        # expansion. Its documented $$ escape preserves each literal dollar
        # (notably dpkg-query's ${Version}) without requiring systemd >= 254.
        # Only the transport representation changes; the command sees argv.
        command.extend(["--", *(arg.replace("$", "$$") for arg in argv)])
        try:
            return self.runner(command, timeout=timeout + 10, limit=limit)
        except BaseException as error:
            cleanup = None
            try:
                # Killing systemd-run only kills the client. Stop its separate
                # service synchronously; RuntimeMaxSec is a second backstop.
                self.runner([SYSTEMCTL, "stop", unit], timeout=10, limit=8192)
            except Exception as stop_error:
                message = _brief(stop_error)
                if not any(marker in message.lower() for marker in ("not loaded", "not found", "does not exist")):
                    cleanup = message
            if not isinstance(error, Exception):
                raise
            detail = "Maintenance %s failed (command deadline %ss): %s" % (Path(argv[0]).name, timeout, _brief(error))
            if cleanup:
                detail += "; transient-unit cleanup failed (unit retains its runtime deadline): " + cleanup
            raise RuntimeError(detail) from error


if __name__ == "__main__":
    if len(sys.argv) < 8 or sys.argv[1] != "--container":
        raise SystemExit("Internal container maintenance helper requires an identity and command")
    try:
        raise SystemExit(_container_entry(json.loads(sys.argv[2]), sys.argv[6], sys.argv[7:],
                                         timeout=float(sys.argv[3]), limit=int(sys.argv[4]), quota=int(sys.argv[5])))
    except Exception as error:
        raise SystemExit(_brief(error))
