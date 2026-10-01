#!/usr/bin/python3
"""Link plugins into the active sonic-utilities package, independent of Python minor version."""
import importlib.util
import pathlib
import sys

remove = "--remove" in sys.argv
for package in ("config", "show"):
    spec = importlib.util.find_spec(package)
    if not spec or not spec.submodule_search_locations:
        continue
    for directory in spec.submodule_search_locations:
        target = pathlib.Path(directory) / "plugins" / "guardian.py"
        source = pathlib.Path("/usr/share/sonic-guardian/plugins") / (package + ".py")
        if target.is_symlink() and target.resolve() == source:
            target.unlink()
        if not remove:
            if target.exists():
                raise RuntimeError("Refusing to overwrite another Guardian plugin: " + str(target))
            target.parent.mkdir(exist_ok=True)
            target.symlink_to(source)
