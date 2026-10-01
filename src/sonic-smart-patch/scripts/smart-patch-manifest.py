#!/usr/bin/python3
"""Bind an embedded pre-seal manifest to completed release artifacts.

No completed-image hash is embedded in that same image. The external index
links immutable image/SBOM/provenance digests to the pre-seal manifest digest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import re
import tarfile


def file_digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def container_identities(records, machine=""):
    """Read Docker's content-addressed config identities, never overlay paths."""
    identities = []
    for record in records.split():
        fields = record.split("|")
        if len(fields) != 4:
            raise ValueError("Malformed installer_images record")
        package, _recipe_path, target_machine, archive_reference = fields
        if target_machine and target_machine != machine:
            continue
        archive_path = archive_reference.rsplit(":", 1)[0]
        with tarfile.open(archive_path, "r:*") as archive:
            member = archive.getmember("manifest.json")
            if member.size > 1024*1024:
                raise ValueError("Docker manifest exceeds metadata budget")
            manifest = json.load(archive.extractfile(member))
            for image in manifest:
                config = archive.getmember(image["Config"])
                if config.size > 8*1024*1024:
                    raise ValueError("Docker configuration exceeds metadata budget")
                image_digest = hashlib.sha256(archive.extractfile(config).read()).hexdigest()
                identities.append({"name":package or Path(archive_path).name,
                                   "image_digest":"sha256:"+image_digest,
                                   "references":sorted(image.get("RepoTags") or [])})
    return identities


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs")
    parser.add_argument("--source-revision")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--artifact")
    parser.add_argument("--container-identities", help="Explicit JSON array of container name/image_digest identities")
    parser.add_argument("--installer-images", default="", help="SONiC installer_images records; extract Docker config identities")
    parser.add_argument("--machine", default="")
    parser.add_argument("--build-parameters-json", help="Explicit JSON object of non-secret reproducible build parameters")
    parser.add_argument("--build-parameter", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--platform", default=os.getenv("CONFIGURED_PLATFORM", "unknown"))
    parser.add_argument("--architecture", default=os.getenv("CONFIGURED_ARCH", "unknown"))
    parser.add_argument("--version", default=os.getenv("SONIC_IMAGE_VERSION", "unknown"))
    args = parser.parse_args()
    manifest_path = Path(args.manifest)
    if args.rootfs:
        source = args.source_revision or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        rootfs = Path(args.rootfs)
        status = rootfs / "var/lib/dpkg/status"
        parameters = json.loads(Path(args.build_parameters_json).read_text()) if args.build_parameters_json else {}
        if not isinstance(parameters, dict):
            raise ValueError("Build parameters must be an object")
        for item in args.build_parameter:
            key, separator, value = item.partition("=")
            if not separator or not key:
                raise ValueError("Build parameter must be NAME=VALUE")
            parameters[key] = value
        containers = json.loads(Path(args.container_identities).read_text()) if args.container_identities else []
        if not isinstance(containers, list):
            raise ValueError("Container identities must be an array")
        containers += container_identities(args.installer_images, args.machine)
        for item in containers:
            if not isinstance(item, dict) or not item.get("name") or not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("image_digest", "")):
                raise ValueError("Each container needs a name and SHA256 image identity")
        containers.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        manifest = {"schema_version": 1, "platform": args.platform, "architecture": args.architecture,
                    "sonic_version": args.version, "source_revision": source,
                    "host_package_database_sha256": file_digest(status),
                    "build_parameters":parameters, "container_identities":containers,
                    "provenance": "build_pipeline", "artifact_binding": "external_release_index"}
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest["build_id"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
        destination = rootfs / "etc/sonic/smart-patch/manifest.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(manifest_path.read_bytes())
        return
    if not args.artifact:
        parser.error("--rootfs or --artifact is required")
    manifest = json.loads(manifest_path.read_text())
    artifact = Path(args.artifact)
    entries = []
    for kind, path in (("image", artifact), ("sbom", Path(str(artifact)+".cdx.json")), ("provenance", Path(str(artifact)+".intoto.json"))):
        if path.exists():
            entries.append({"kind": kind, "filename": path.name, "sha256": file_digest(path), "bytes": path.stat().st_size})
        elif kind == "image":
            raise FileNotFoundError(path)
    index = {"schema_version": 1, "build_id": manifest["build_id"], "manifest_sha256": file_digest(manifest_path),
             "artifacts": entries, "sbom_available": any(item["kind"] == "sbom" for item in entries)}
    Path(str(artifact)+".smart-patch.json").write_text(json.dumps(index, indent=2)+"\n")


if __name__ == "__main__":
    main()
