#!/usr/bin/python3
"""Register the standalone model without replacing image-owned SONiC schemas."""
import importlib
from pathlib import Path
import sys

SOURCE = Path("/usr/share/sonic-guardian/yang/sonic-guardian.yang")


def native_yang_directory():
    for name in ("generic_config_updater.config_mgmt", "config.config_mgmt", "config_mgmt"):
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        directory = getattr(module, "YANG_DIR", None)
        if directory:
            return Path(directory)
    # SONiC's native default, also used when optional config updater imports are
    # unavailable during package installation. Do not create it on other OSes.
    default = Path("/usr/local/yang-models")
    return default if default.is_dir() else None


def register_model(directory, source=SOURCE, remove=False):
    directory, source = Path(directory), Path(source)
    target = directory / "sonic-guardian.yang"
    owned_link = target.is_symlink() and target.resolve() == source.resolve()
    if remove:
        if owned_link:
            target.unlink()
            return "removed-owned-symlink"
        return "preserved-existing-model"
    if target.exists() or target.is_symlink():
        return "already-registered" if owned_link else "preserved-existing-model"
    if not source.is_file():
        raise FileNotFoundError("Packaged Guardian model missing: " + str(source))
    directory.mkdir(parents=True, exist_ok=True)
    target.symlink_to(source)
    return "registered"


def main():
    directory = native_yang_directory()
    if directory is not None:
        register_model(directory, remove="--remove" in sys.argv)


if __name__ == "__main__":
    main()
