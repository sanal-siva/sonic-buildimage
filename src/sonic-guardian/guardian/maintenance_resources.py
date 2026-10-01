"""Run host maintenance separately from the small inventory collector cgroup.

CPU quota zero means no Guardian maintenance CPU quota. Platform or ancestor
slice limits still apply. The independent memory budget and wall-time/output
budgets remain enforced; Docker-exec workloads are not covered by this runner.
"""
import math
import os
from pathlib import Path
import stat
import uuid

from guardian.collector import run


SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
MEMORY_MAX_MIB = 512
STANDARD_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


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


def in_collector_cgroup():
    try:
        return any("sonic-guardian.service" in line.split(":", 2)[-1].split("/")
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

    def run(self, argv, timeout=15, limit=4 * 1024 * 1024, cwd=None):
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

        unit = "sonic-guardian-maint-" + uuid.uuid4().hex + ".service"
        command = [SYSTEMD_RUN, "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
                   "--slice=system.slice", "--unit=" + unit,
                   "--property=MemoryMax=%dM" % MEMORY_MAX_MIB, "--property=TasksMax=128",
                   "--property=RuntimeMaxSec=%ss" % timeout, "--property=TimeoutStopSec=5s",
                   "--property=KillMode=control-group", "--setenv=LANG=C", "--setenv=LC_ALL=C",
                   "--setenv=PATH=" + STANDARD_PATH]
        if self._check(self.in_collector, in_collector_cgroup):
            # A collector restart must stop, not restart, a child transaction.
            # Keep the worker in its sibling cgroup but tie its lifetime to the
            # owning service so a killed client cannot leave package work behind.
            command.extend(["--property=BindsTo=sonic-guardian.service",
                            "--property=After=sonic-guardian.service"])
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
