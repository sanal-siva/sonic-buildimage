"""APT/dpkg hook: only mark inventory dirty; never scan or use the network."""
import os
from pathlib import Path


def main_hook_handler():
    try:
        directory = Path(os.getenv("SMART_PATCH_STATE_DIR", "/var/lib/sonic-smart-patch"))
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "dirty").touch()
    except OSError:
        # Package management must not fail because optional telemetry is unavailable.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main_hook_handler())
