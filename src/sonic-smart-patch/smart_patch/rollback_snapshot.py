"""Recover exact Debian rollback archives through isolated, authenticated APT.

Snapshot's small machine-readable index locates candidate dates. APT then
authenticates the dated Release/Packages chain with the Debian archive keyring.
Only the private historical source ignores Release Valid-Until; signatures and
package hashes remain required. System repository configuration is untouched.
"""
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import requests

BASE = "https://snapshot.debian.org"
KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")
MAX_METADATA = 1024 * 1024
MAX_CANDIDATES = 6
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?$")
VERSION = re.compile(r"^[0-9A-Za-z.+:~_-]+$")
STAMP = re.compile(r"^\d{8}T\d{6}Z$")
HASH = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _metadata(package, version, session):
    url = BASE + "/mr/binary/" + quote(package, safe="") + "/" + quote(version, safe="") + "/binfiles?fileinfo=1"
    response = session.get(url, timeout=(5, 20), stream=True, allow_redirects=False)
    try:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("Snapshot metadata did not return an exact package result")
        body = bytearray()
        for block in response.iter_content(65536):
            body.extend(block)
            if len(body) > MAX_METADATA:
                raise ValueError("Snapshot metadata exceeds the lookup budget")
        result = json.loads(body)
    finally:
        response.close()
    if (result.get("binary") != package or
            result.get("binary_version", result.get("binary-version")) != version):
        raise ValueError("Snapshot metadata package identity does not match")
    return result


def _candidates(metadata, architecture, codename, version, override=""):
    if override:
        if not STAMP.fullmatch(override):
            raise ValueError("Snapshot timestamp must be YYYYMMDDThhmmssZ")
        datetime.strptime(override, "%Y%m%dT%H%M%SZ")
    candidates, identities = [], set()
    for binary in metadata.get("result", [])[:256]:
        file_hash = binary.get("hash", "")
        if binary.get("architecture") not in (architecture, "all") or not HASH.fullmatch(file_hash):
            continue
        identities.add(file_hash)
        for info in metadata.get("fileinfo", {}).get(file_hash, [])[:16]:
            archive = info.get("archive_name")
            if archive not in ("debian", "debian-security", "debian-archive"):
                continue
            stamp = info.get("first_seen", info.get("run", ""))
            if not STAMP.fullmatch(stamp):
                continue
            parts = info.get("path", "").strip("/").split("/")
            if not parts or parts[0] != "pool" or ".." in parts:
                continue
            component_index = 2 if len(parts) > 1 and parts[1] == "updates" else 1
            if len(parts) <= component_index:
                continue
            component = parts[component_index]
            if component not in ("main", "contrib", "non-free", "non-free-firmware"):
                continue
            if archive == "debian-security":
                suites = [codename + ("/updates" if codename in ("stretch", "buster") else "-security")]
            else:
                suites = [codename + "-backports"] if "~bpo" in version else [codename, codename + "-updates"]
            first = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            # A binary first enters unstable before migration to the requested
            # release. Check a small bounded window; never substitute a suite.
            dates = [override] if override else [
                (first + timedelta(days=days)).strftime("%Y%m%dT%H%M%SZ") for days in (0, 14, 30)]
            for date in dates:
                for suite in suites:
                    item = (archive, date, suite, component)
                    if item not in candidates:
                        candidates.append(item)
    return candidates[:MAX_CANDIDATES], identities


def _apt_options(root, architecture):
    values = {
        "Dir::Etc::sourcelist": str(root / "sources.list"),
        "Dir::Etc::sourceparts": "-",
        "Dir::State::lists": str(root / "lists"),
        "Dir::State::status": str(root / "status"),
        "Dir::Cache": str(root / "cache"),
        "APT::Architecture": architecture,
        "APT::Architectures": architecture,
        "APT::Sandbox::User": "root",
        "Acquire::Languages": "none",
        "Acquire::Retries": "0",
        "Acquire::https::Timeout": "20",
        "Acquire::http::Timeout": "20",
        "Acquire::Check-Valid-Until": "false",
        "Acquire::AllowInsecureRepositories": "false",
        "Acquire::AllowDowngradeToInsecureRepositories": "false",
        "APT::Get::AllowUnauthenticated": "false",
        "APT::Get::List-Cleanup": "0",
    }
    return [value for key, setting in values.items() for value in ("-o", key + "=" + setting)]


def download_rollback(package, version, directory, *, runner, distro, architecture, config=None, session=None):
    """Return an authenticated retained artifact, or explain why none was found.

    The caller obtains distro and architecture from the actual target scope.
    ``runner`` runs on the host under the existing maintenance resource limits;
    this operation only downloads archives and never installs any package.
    """
    if not PACKAGE.fullmatch(package) or not VERSION.fullmatch(version):
        raise ValueError("Invalid exact rollback package/version")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", architecture or ""):
        raise ValueError("Rollback requires the exact package architecture")
    distro_id = str(distro.get("id", distro.get("ID", ""))).lower()
    codename = distro.get("codename") or distro.get("version_codename", distro.get("VERSION_CODENAME", ""))
    if not codename:
        release = str(distro.get("version_id", distro.get("VERSION_ID", ""))).split(".")[0]
        codename = {"9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie"}.get(release)
    if distro_id != "debian" or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", codename or ""):
        raise ValueError("Official Debian snapshot fallback requires a known Debian release in the target scope")
    values = config.values() if config else {}
    if values.get("rollback_snapshot_enabled", "true") != "true":
        raise ValueError("Debian snapshot rollback fallback is disabled")
    if not KEYRING.is_file():
        raise ValueError("Debian archive keyring is unavailable; snapshot authentication cannot proceed")
    binary = package.split(":", 1)[0]
    requested_arch = package.split(":", 1)[1] if ":" in package else architecture
    if requested_arch != architecture:
        raise ValueError("Rollback package architecture differs from the captured occurrence")
    owned_session = session is None
    session = session or requests.Session()
    try:
        metadata = _metadata(binary, version, session)
    finally:
        if owned_session:
            session.close()
    candidates, identities = _candidates(metadata, architecture, codename, version,
                                         values.get("rollback_snapshot_timestamp", ""))
    if not candidates:
        raise ValueError("The exact rollback package/version/architecture is absent from the official Debian snapshot index")
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    failures = []
    for archive, stamp, suite, component in candidates:
        url = BASE + "/archive/" + archive + "/" + stamp + "/"
        with tempfile.TemporaryDirectory(prefix=".snapshot-", dir=directory) as temporary:
            root = Path(temporary)
            (root / "lists/partial").mkdir(parents=True)
            (root / "cache/archives/partial").mkdir(parents=True)
            (root / "download").mkdir()
            (root / "status").touch()
            # APT_CONFIG is read before apt.conf.d. Merely redirecting lists on
            # the command line would still execute the host's update hooks.
            (root / "apt.conf").write_text(
                'Dir::Etc::main "-";\nDir::Etc::parts "-";\n'
                'Dir::Etc::preferences "-";\nDir::Etc::preferencesparts "-";\n'
                'Dir::Etc::netrc "/dev/null";\nDir::Etc::netrcparts "-";\n'
                'Dir::Etc::trusted "-";\nDir::Etc::trustedparts "-";\n'
                'Dir::State "%s";\nDir::Log "%s";\n'
                '#clear APT::Architectures;\nAPT::Architectures { "%s"; };\n'
                '#clear APT::Update::Pre-Invoke;\n#clear APT::Update::Post-Invoke;\n'
                '#clear APT::Update::Post-Invoke-Success;\n' %
                (root, root / "log", architecture))
            (root / "sources.list").write_text(
                "deb [arch=%s check-valid-until=no signed-by=%s] %s %s %s\n" %
                (architecture, KEYRING, url, suite, component))
            command = ["env", "APT_CONFIG=" + str(root / "apt.conf"), "apt-get"] + _apt_options(root, architecture)
            try:
                runner(command + ["update", "--error-on=any"], timeout=180, limit=1048576)
                runner(command + ["download", binary + ":" + architecture + "=" + version],
                       cwd=root / "download", timeout=180, limit=1048576)
                matches = []
                for path in (root / "download").glob("*.deb"):
                    if not path.is_file() or path.is_symlink():
                        continue
                    text = runner(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"], timeout=30)
                    fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
                    if (fields.get("Package") != binary or fields.get("Version") != version or
                            fields.get("Architecture") not in (architecture, "all")):
                        continue
                    sha1, sha256 = hashlib.sha1(), hashlib.sha256()
                    with path.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            sha1.update(block)
                            sha256.update(block)
                    file_hash = sha1.hexdigest() if sha1.hexdigest() in identities else sha256.hexdigest()
                    if file_hash not in identities:
                        raise ValueError("Authenticated rollback archive differs from the exact snapshot file identity")
                    matches.append((path, sha256.hexdigest(), file_hash, fields["Architecture"]))
                if len(matches) != 1:
                    raise ValueError("Exactly one authenticated rollback archive is required")
                path, sha256, file_hash, actual_arch = matches[0]
                retained = directory / path.name
                shutil.move(str(path), retained)
                return {"path": str(retained), "sha256": sha256, "package": package,
                        "version": version, "architecture": actual_arch,
                        "source": {"type": "debian_snapshot", "snapshot": stamp,
                                   "archive": archive, "suite": suite, "url": url,
                                   "verification": "apt_signed_repository", "snapshot_file_hash": file_hash}}
            except (ValueError, OSError, RuntimeError) as error:
                failures.append("%s/%s/%s: %s" % (archive, stamp, suite, str(error)[:180]))
    raise ValueError("Exact signed Debian snapshot rollback download unavailable; " + "; ".join(failures))
