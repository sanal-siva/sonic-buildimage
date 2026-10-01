"""Native Guardian service lifecycle with an explicit standalone/test boundary."""
import os
from pathlib import Path
import subprocess
from guardian.config import ConfigManager


class GuardianServiceManager:
    UNIT = "sonic-guardian.service"

    def __init__(self, config, runner=None, available=None):
        self.runner = runner or subprocess.run
        self.available = available if available is not None else bool(
            getattr(config, "_auto_connect", False)
            and Path("/etc/sonic/sonic_version.yml").is_file()
            and Path("/run/systemd/system").is_dir())

    def _run(self, operation):
        if not self.available:
            return False
        result = self.runner(["systemctl", operation, "--now", self.UNIT],
                             capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError("Guardian service %s failed: %s" % (operation, result.stderr[-512:]))
        return True

    def enable(self):
        return self._run("enable")

    def disable(self):
        return self._run("disable")


def _publish(config, service, publisher=None):
    if publisher is not None:
        publisher(config.values())
    elif service.available or os.getenv("GUARDIAN_STATE_DIR"):
        from guardian.agent import Agent
        Agent(config=config).publish_status(config.values())


def set_enabled(enabled, config=None, service=None, publisher=None):
    config = config or ConfigManager()
    service = service or GuardianServiceManager(config)
    config.set_service_enabled(enabled)
    # In particular, make disabled state visible before stopping the process
    # that would otherwise publish it. Credentials/history are not removed.
    _publish(config, service, publisher)
    return service.enable() if enabled else service.disable()


def set_mode(mode, config=None, service=None, publisher=None):
    config = config or ConfigManager()
    service = service or GuardianServiceManager(config)
    config.set_operating_mode(mode)
    _publish(config, service, publisher)
