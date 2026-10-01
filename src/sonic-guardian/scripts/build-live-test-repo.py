#!/usr/bin/env python3
"""Build a signed, file-only synthetic APT repository for live acceptance.

No package scripts, dependencies, services or SONiC files are installed. The
private signing key is temporary and destroyed after signing the repository.
"""
import argparse
from datetime import datetime, timezone, timedelta
import email.utils
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


PACKAGES = ("sonic-guardian-testprobe", "guardian-testprobe")
VERSIONS = ("1.0", "1.1")


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs)


def build(destination):
    destination = Path(destination).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Output directory must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "pool").mkdir()
    for package in PACKAGES:
        for version in VERSIONS:
            with tempfile.TemporaryDirectory(prefix="guardian-fixture-package-") as temporary:
                stage = Path(temporary)
                stage.chmod(0o755)
                (stage / "DEBIAN").mkdir()
                (stage / "DEBIAN/control").write_text(
                    f"Package: {package}\nVersion: {version}\nArchitecture: all\n"
                    "Maintainer: SONiC Guardian Acceptance Tests <test@example.invalid>\n"
                    "Section: misc\nPriority: optional\n"
                    "Description: SYNTHETIC Guardian acceptance fixture, not a real vulnerability\n"
                    " Contains only a version marker under /usr/share; no scripts or dependencies.\n")
                marker = stage / "usr/share" / package / "version"
                marker.parent.mkdir(parents=True)
                marker.write_text(f"SYNTHETIC ACCEPTANCE FIXTURE\n{version}\n")
                run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(destination / "pool" / f"{package}_{version}_all.deb")])
    packages = run(["dpkg-scanpackages", "--multiversion", "pool", "/dev/null"], cwd=destination).stdout.encode()
    (destination / "Packages").write_bytes(packages)
    (destination / "Packages.gz").write_bytes(gzip.compress(packages, mtime=0))
    timestamp = datetime.now(timezone.utc)
    release = ("Origin: SONiC Guardian Synthetic Acceptance\nLabel: SYNTHETIC file-only fixtures\n"
               "Suite: guardian-acceptance\nCodename: guardian-acceptance\nArchitectures: amd64 arm64 all\n"
               f"Date: {email.utils.format_datetime(timestamp)}\n"
               f"Valid-Until: {email.utils.format_datetime(timestamp + timedelta(days=7))}\nSHA256:\n")
    for filename in ("Packages", "Packages.gz"):
        content = (destination / filename).read_bytes()
        release += f" {hashlib.sha256(content).hexdigest()} {len(content)} {filename}\n"
    (destination / "Release").write_text(release)
    with tempfile.TemporaryDirectory(prefix="guardian-fixture-signing-") as temporary:
        keyring = Path(temporary)
        keyring.chmod(0o700)
        common = ["gpg", "--homedir", str(keyring), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        run(common + ["--quick-generate-key", "Guardian SYNTHETIC acceptance <test@example.invalid>", "ed25519", "sign", "7d"])
        run(common + ["--yes", "--output", str(destination / "fixture-key.gpg"), "--export"])
        run(common + ["--yes", "--output", str(destination / "InRelease"), "--clearsign", str(destination / "Release")])
        run(common + ["--yes", "--output", str(destination / "Release.gpg"), "--detach-sign", str(destination / "Release")])
        subprocess.run(["gpgconf", "--homedir", str(keyring), "--kill", "gpg-agent"], capture_output=True, check=False)
    run(["gpgv", "--keyring", str(destination / "fixture-key.gpg"), str(destination / "InRelease")])
    files = {str(path.relative_to(destination)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in destination.rglob("*") if path.is_file()}
    manifest = {"fixture": True, "contains_real_vulnerabilities": False, "packages":list(PACKAGES),
                "versions":list(VERSIONS), "created_at":timestamp.isoformat(), "sha256":files}
    (destination / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = build(args.output)
    print(json.dumps({"repository":str(Path(args.output).resolve()), **result}, indent=2))
