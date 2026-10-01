"""Bounded package metadata and read-only evidence collection; no vulnerability DB."""
import hashlib
import fcntl
import uuid
import json
import os
import platform
import re
import resource
import selectors
import signal
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import quote
from guardian.storage import now

DPKG_FORMAT = '${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(argv, timeout=15, limit=4 * 1024 * 1024, cwd=None):
    """Cap subprocess wall time and output, killing the entire process group."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, cwd=cwd)
    result = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Collector command exceeded deadline")
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    result.extend(chunk)
                    if len(result) > limit:
                        raise ValueError("Collector command exceeded output budget")
        code = process.wait(timeout=max(0.01, deadline-time.monotonic()))
        if code:
            raise RuntimeError("Command failed (%s): %s" % (code, result[:200].decode(errors="replace")))
        return result.decode(errors="replace")
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()


def os_release(text):
    return dict(line.split("=", 1) for line in text.replace('"', '').splitlines() if "=" in line)


def package_rows(text, scope, distro, image_digest=None):
    records = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 6 or fields[5] != "installed":
            continue
        name, version, architecture, source_name, source_version, _ = fields
        name = name.split(":")[0]
        component_id = digest([scope, name, architecture])[:32]
        records.append({"component_id": component_id, "scope": scope, "name": name,
            "version": version, "architecture": architecture, "source_name": source_name or name,
            "source_version": source_version or version, "distro": distro,
            "image_digest": image_digest or "",
            "purl": "pkg:deb/%s/%s@%s?arch=%s&distro=%s" % (
                quote(distro.get("id", "debian"), safe=""), quote(name, safe=""), quote(version, safe=""),
                quote(architecture, safe=""), quote(distro.get("version_id", "unknown"), safe=""))})
    return records


class InventoryCollector:
    def __init__(self, runner=run, max_components=20000, max_containers=64, deadline=120):
        self.runner = runner
        self.max_components = max_components
        self.max_containers = max_containers
        self.deadline = deadline

    def topology(self):
        try:
            text = self.runner(["docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Image}} {{.Names}} {{.State}}"], timeout=5, limit=65536)
            return digest(sorted(text.splitlines()))
        except Exception:
            return "unknown"

    def collect(self):
        started = time.monotonic()
        components, scopes = [], []
        def collect_scope(scope, prefix, image_digest=None):
            try:
                if time.monotonic() - started > self.deadline:
                    raise TimeoutError("Inventory collection deadline exceeded")
                release = os_release(self.runner(prefix + ["cat", "/etc/os-release"]))
                distro = {"id": release.get("ID", "unknown"), "version_id": release.get("VERSION_ID", "unknown"),
                          "codename": release.get("VERSION_CODENAME", "unknown")}
                rows = package_rows(self.runner(prefix + ["dpkg-query", "-W", "-f=" + DPKG_FORMAT]), scope, distro, image_digest)
                if len(components) + len(rows) > self.max_components:
                    raise ValueError("Component budget exceeded")
                if not rows:
                    raise ValueError("No installed Debian package metadata; scope unsupported")
                components.extend(rows)
                scopes.append({"scope": scope, "status": "complete", "packages": len(rows), "image_digest": image_digest})
            except Exception as error:
                scopes.append({"scope": scope, "status": "unknown", "error": str(error)[:250], "image_digest": image_digest})
        collect_scope("host", [])
        try:
            containers = [json.loads(line) for line in self.runner(["docker", "ps", "-a", "--format", "{{json .}}"], limit=262144).splitlines() if line.strip()]
            if len(containers) > self.max_containers:
                scopes.append({"scope": "containers", "status": "partial", "error": "Container budget exceeded"})
            for container in containers[:self.max_containers]:
                if time.monotonic() - started > self.deadline:
                    scopes.append({"scope": "containers", "status": "partial", "error": "Collection deadline reached"})
                    break
                name = container["Names"]
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
                    continue
                identity = json.loads(self.runner(["docker", "inspect", "--format", "{{json .}}", name], limit=262144))
                scope = "container:" + name
                if not identity.get("State", {}).get("Running"):
                    scopes.append({"scope": scope, "status": "unknown", "error": "Container stopped", "image_digest": identity.get("Image")})
                    continue
                collect_scope(scope, ["docker", "exec", name], identity.get("Image"))
        except Exception as error:
            scopes.append({"scope": "containers", "status": "unknown", "error": str(error)[:250]})
        components.sort(key=lambda item: item["component_id"])
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return {"components": components, "scopes": scopes, "collected_at": now(),
                "resources": {"collection_seconds": round(time.monotonic()-started, 3),
                              "rss_bytes": usage.ru_maxrss*1024, "cpu_seconds": usage.ru_utime+usage.ru_stime}}


def enrollment_id(config_directory=None):
    """Persist a per-installation identity; cloned machine-id values are not unique.

    The lock serializes creation and reading, including processes that race at
    first startup. O_EXCL prevents replacing a pre-provisioned enrollment ID.
    This file is runtime state and must never be embedded by an image build.
    """
    directory = Path(config_directory or os.getenv("GUARDIAN_CONFIG_DIR", "/etc/sonic/guardian"))
    directory.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(str(directory / ".enrollment.lock"), flags, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        path = directory / "device-id"
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "r") as stream:
                value = stream.read(130).strip()
        else:
            value = str(uuid.uuid4())
            with os.fdopen(fd, "w") as stream:
                stream.write(value + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            parent_fd = os.open(str(directory), os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
            raise ValueError("Invalid persisted Guardian device-id; administrative recovery required")
        return value
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def identity(manifest_path="/etc/sonic/guardian/manifest.json", config_directory=None):
    manifest_file = Path(manifest_path)
    if manifest_file.exists() and manifest_file.stat().st_size > 256*1024:
        raise ValueError("Runtime manifest exceeds 256 KiB budget; full SBOMs belong in the service")
    raw_manifest = manifest_file.read_bytes() if manifest_file.exists() else b""
    manifest = json.loads(raw_manifest) if raw_manifest else {}
    manifest_digest = "sha256:" + hashlib.sha256(raw_manifest).hexdigest() if raw_manifest else ""
    device_id = enrollment_id(config_directory)
    version_path = Path("/etc/sonic/sonic_version.yml")
    version = {}
    if version_path.exists():
        import yaml
        version = yaml.safe_load(version_path.read_text()) or {}
    return {"device_id": device_id, "hostname": socket.gethostname(), "platform": manifest.get("platform", version.get("platform", platform.machine())),
            "sonic_version": version.get("build_version", "unknown"),
            "build_id": manifest.get("build_id") or "unverified:" + digest(version),
            "artifact_verified": False, "manifest": manifest, "manifest_digest": manifest_digest}


def collect_evidence(request, runner=run, inventory_context=None):
    collector, scope = request.get("collector"), request.get("scope", "host")
    command_collector = "bgp" if collector == "routing" else collector
    fact = {"fact_id": request.get("request_id", collector), "collector": collector, "scope": scope, "collected_at": now()}
    prefix = []
    if scope != "host" and not (scope == "device" and collector == "inventory"):
        name = scope.removeprefix("container:")
        if not scope.startswith("container:") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            return {**fact, "status":"unknown", "error":"Invalid container scope"}
        prefix = ["docker", "exec", name]
    try:
        commands = {"listeners": ["ss", "-H", "-lntup"], "kernel": ["uname", "-r"],
                    "processes": ["ps", "-eo", "comm="], "interfaces": ["ip", "-j", "link", "show"],
                    "bgp": ["vtysh", "-c", "show bgp summary json"]}
        if collector == "features" and scope == "host":
            from swsscommon.swsscommon import ConfigDBConnector
            database = ConfigDBConnector(); database.connect(wait_for_init=False)
            fact["value"] = {str(k): {f: v for f, v in values.items() if f in ("state", "auto_restart", "has_global_scope", "has_per_asic_scope")}
                             for k, values in database.get_table("FEATURE").items()}
        elif collector == "package_versions":
            packages = request.get("args", {}).get("packages", [])
            if not isinstance(packages, list) or not 1 <= len(packages) <= 10 or any(not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?", name) for name in packages):
                raise ValueError("package_versions requires 1-10 validated Debian package names")
            policies = {}
            for name in packages:
                text = runner(prefix + ["apt-cache", "policy", name], timeout=5, limit=16384)
                item = {"available_versions": [], "policy_evidence": text}
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("Installed:"):
                        item["installed"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("Candidate:"):
                        item["candidate"] = stripped.split(":", 1)[1].strip()
                    else:
                        match = re.match(r"^\s*(?:\*\*\*\s+)?([0-9][A-Za-z0-9.+:~_-]*)\s+[0-9]+\s*$", line)
                        if match:
                            item["available_versions"].append(match.group(1))
                policies[name] = item
            fact["value"] = policies
        elif collector == "resources":
            mem = runner(prefix + ["cat", "/proc/meminfo"], timeout=3, limit=16384)
            selected = {}
            for line in mem.splitlines():
                key, separator, value = line.partition(":")
                if separator and key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                    selected[key + "_bytes"] = int(value.split()[0])*1024
            selected["load_average"] = runner(prefix + ["cat", "/proc/loadavg"], timeout=3, limit=1024).split()[:3]
            selected["measurement_scope"] = "procfs namespace view; container memory limits may differ"
            fact["value"] = selected
        elif collector == "services":
            if scope == "host":
                text = runner(["systemctl", "show", "*.service", "--property=Id", "--property=ActiveState"], timeout=8, limit=65536)
                fact["value"] = [dict(line.split("=", 1) for line in block.splitlines() if line.startswith(("Id=", "ActiveState="))) for block in text.strip().split("\n\n") if block]
            else:
                try:
                    fact["value"] = {"method":"supervisor_status", "status":runner(prefix + ["supervisorctl", "status"], timeout=8, limit=65536)}
                except Exception:
                    fact["value"] = {"method":"process_names", "processes":runner(prefix + ["ps", "-eo", "comm="], timeout=8, limit=65536).splitlines()}
        elif collector == "inventory":
            if inventory_context is None:
                from guardian.storage import read_public_state
                inventory_context = read_public_state()
            scopes = [item for item in inventory_context.get("scopes", []) if scope in ("device", item.get("scope"))]
            fact["value"] = {"scopes":[{key:item.get(key) for key in ("scope", "status", "packages")} for item in scopes],
                             "inventory_digest":inventory_context.get("inventory_digest"), "collected_at":inventory_context.get("collected_at")}
        elif command_collector in commands:
            fact["value"] = runner(prefix + commands[command_collector], timeout=8, limit=65536)
        else:
            raise ValueError("Collector is not allowlisted")
        fact["status"] = "observed"
    except Exception as error:
        fact.update(status="unknown", error=str(error)[:250])
    return fact
