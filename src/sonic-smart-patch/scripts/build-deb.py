#!/usr/bin/python3
"""Build an architecture-independent .deb without installing build tools.

The normal SONiC pipeline uses debian/rules via dpkg-buildpackage. This helper
stages identical runtime assets for rapid deployment and package verification.
"""
import compileall
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
destination = root.parent / "sonic-smart-patch_3.0.0-1_all.deb"
with tempfile.TemporaryDirectory(prefix="smart-patch-deb-") as temporary:
    stage = Path(temporary)
    stage.chmod(0o755)
    def copy(source, target):
        source, target = root / source, stage / target
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o644)
    shutil.copytree(root / "smart_patch", stage / "usr/lib/python3/dist-packages/smart_patch", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    control = (root / "debian/control").read_text().split("Package: ", 1)[1]
    control = "Package: " + control.replace("${python3:Depends}, ${misc:Depends}, ", "")
    control = control.replace("Architecture: all", "Version: 3.0.0-1\nArchitecture: all\nMaintainer: SONiC Contributors <dev@sonicdev.org>")
    (stage / "DEBIAN").mkdir()
    (stage / "DEBIAN/control").write_text(control)
    for name in ("postinst", "prerm"):
        copy("debian/" + name, "DEBIAN/" + name)
        (stage / "DEBIAN" / name).chmod(0o755)
    (stage / "DEBIAN/conffiles").write_text("/etc/apt/apt.conf.d/50sonic-smart-patch-hooks\n")
    copy("debian/sonic-smart-patch.service", "lib/systemd/system/sonic-smart-patch.service")
    for package in ("config", "show"):
        copy("plugins/"+package+".py", "usr/share/sonic-smart-patch/plugins/"+package+".py")
    for name in ("install-plugins.py", "install-yang.py", "smart-patch-manifest.py"):
        copy("scripts/"+name, "usr/share/sonic-smart-patch/"+name)
    copy("../sonic-yang-models/yang-models/sonic-smart-patch.yang", "usr/share/sonic-smart-patch/yang/sonic-smart-patch.yang")
    copy("config/50sonic-smart-patch-hooks", "etc/apt/apt.conf.d/50sonic-smart-patch-hooks")
    for name, module, function in (("security", "smart_patch.cli", "security"), ("sonic-smart-patch-daemon", "smart_patch.main", "main")):
        path = stage / "usr/bin" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/usr/bin/python3\nfrom %s import %s\nraise SystemExit(%s())\n" % (module, function, function))
        path.chmod(0o755)
    for path in stage.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode & ~0o022)
        elif path.is_dir():
            path.chmod(0o755)
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(destination)], check=True)
print(destination)
