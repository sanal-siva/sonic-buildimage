"""Transfer staged .deb files through a pinned running-container root.

Docker's archive API cannot read container tmpfs mounts. This helper uses the
actual runtime mount view, including tmpfs, without executing container code.
Only plan-scoped regular package files are copied; no symlinks are followed.
The caller runs it in the normal bounded maintenance worker.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import uuid

from smart_patch.collector import run
from smart_patch.maintenance_resources import CONTAINER_FORMAT, container_identity, _same_container, _process_start


MAX_FILES = 64
MAX_ENTRIES = 256
MAX_BYTES = 512 * 1024 * 1024
CHUNK_BYTES = 128 * 1024
ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+%:_~-]{0,239}\.deb$")
DIRECTORY = re.compile(r"^/var/tmp/sonic-smart-patch-([0-9a-f-]{36})/(forward|rollback)$")


def _runtime_directory(value):
    match = DIRECTORY.fullmatch(value)
    if not match:
        raise ValueError("Container artifact directory must belong to an exact maintenance plan")
    return match.groups()


def _host_directory(value, plan_id, direction):
    path = PurePosixPath(value)
    if (not path.is_absolute() or any(part in (".", "..") for part in value.split("/"))
            or path.parts[-3:] != ("plans", plan_id, direction)):
        raise ValueError("Host artifact directory must match the exact plan and direction")
    return str(path)


@contextmanager
def _directory(root, path):
    """Open every component without following a symlink, including the leaf."""
    if not path.startswith("/") or any(part in (".", "..") for part in path.split("/")):
        raise ValueError("Artifact directories must be absolute and contain no traversal")
    descriptors = []
    try:
        current = root
        for part in path.split("/"):
            if not part:
                continue
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            descriptors.append(current)
        yield current
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


class RuntimeRoot:
    """Pin one full container identity and process lifetime across a transfer."""
    def __init__(self, expected, runner=run):
        self.expected = container_identity(expected)
        self.runner = runner
        self.root = None

    def inspect(self):
        observed = container_identity(json.loads(self.runner(
            ["docker", "inspect", "--format", CONTAINER_FORMAT, self.expected["id"]], timeout=15, limit=16384)))
        if not _same_container(observed, self.expected):
            raise ValueError("Container identity changed during artifact transfer")
        return observed

    def __enter__(self):
        observed = self.inspect()
        self.pid, self.start = observed["pid"], _process_start(observed["pid"])
        self.root = os.open("/proc/%d/root" % self.pid, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self.verify()
        except BaseException:
            os.close(self.root)
            self.root = None
            raise
        return self

    def verify(self):
        observed = self.inspect()
        if observed["pid"] != self.pid or _process_start(self.pid) != self.start:
            raise ValueError("Container process changed during artifact transfer; recreate or restage the plan")

    def __exit__(self, *_):
        if self.root is not None:
            os.close(self.root)


def _regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Staged package artifacts must be regular files without links")
    if not 0 < info.st_size <= MAX_BYTES:
        raise ValueError("Staged package artifact exceeds the 512 MiB transfer budget or is empty")


def _unchanged(before, after):
    return all(getattr(before, field) == getattr(after, field)
               for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def _prepare_copy(source_directory, destination_directory, name, mode, expected_sha256=None, byte_budget=None):
    if not ARTIFACT_NAME.fullmatch(name):
        raise ValueError("Invalid staged package artifact filename")
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=source_directory)
    temporary = ".smart-patch-artifact-" + uuid.uuid4().hex
    output = None
    try:
        before = os.fstat(source)
        _regular(before)
        byte_budget = MAX_BYTES if byte_budget is None else byte_budget
        if not 0 < byte_budget <= MAX_BYTES or before.st_size > byte_budget:
            raise ValueError("Package artifacts exceed the remaining transfer budget")
        output = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=destination_directory)
        hasher, count = hashlib.sha256(), 0
        while True:
            block = os.read(source, CHUNK_BYTES)
            if not block:
                break
            count += len(block)
            if count > byte_budget:
                raise ValueError("Staged package artifact exceeded its transfer budget")
            hasher.update(block)
            view = memoryview(block)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise OSError("Package artifact write did not make progress")
                view = view[written:]
        after = os.fstat(source)
        named = os.stat(name, dir_fd=source_directory, follow_symlinks=False)
        if count != before.st_size or not _unchanged(before, after) or not _unchanged(before, named):
            raise ValueError("Package artifact changed while it was being transferred")
        sha256 = hasher.hexdigest()
        if expected_sha256 is not None and sha256 != expected_sha256:
            raise ValueError("Copied package artifact differs from its staged SHA256")
        os.fchmod(output, mode)
        os.fsync(output)
        # Rehash the actual destination through its retained FD, not merely the
        # source stream. A writer must not alter already-copied bytes unnoticed.
        written = os.fstat(output)
        destination_hash, checked = hashlib.sha256(), 0
        os.lseek(output, 0, os.SEEK_SET)
        while True:
            block = os.read(output, CHUNK_BYTES)
            if not block:
                break
            checked += len(block)
            if checked > byte_budget:
                raise ValueError("Copied package artifact exceeded its transfer budget")
            destination_hash.update(block)
        if (checked != count or destination_hash.hexdigest() != sha256
                or not _unchanged(written, os.fstat(output))):
            raise ValueError("Destination package artifact changed while it was being verified")
        prepared = {"name": name, "temporary": temporary, "size": count, "sha256": sha256,
                    "descriptor": output, "metadata": written}
        output = None  # Retained through publication; _cleanup owns this FD.
        return prepared
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=destination_directory)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source)
        if output is not None:
            os.close(output)


def _commit(directory, pending):
    for artifact in pending:
        current = os.fstat(artifact["descriptor"])
        temporary = os.stat(artifact["temporary"], dir_fd=directory, follow_symlinks=False)
        _regular(current)
        _regular(temporary)
        if not _unchanged(artifact["metadata"], current) or not _unchanged(current, temporary):
            raise ValueError("Prepared package artifact changed before publication")
        try:
            existing = os.stat(artifact["name"], dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        _regular(existing)
    for artifact in pending:
        os.replace(artifact["temporary"], artifact["name"], src_dir_fd=directory, dst_dir_fd=directory)
        try:
            final = os.stat(artifact["name"], dir_fd=directory, follow_symlinks=False)
            current = os.fstat(artifact["descriptor"])
            _regular(final)
            _regular(current)
            # Rename can update ctime; stable inode, contents metadata and mode
            # must still match the retained destination descriptor/checkpoint.
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode", "st_nlink")
            if any(getattr(final, key) != getattr(current, key) or
                   getattr(current, key) != getattr(artifact["metadata"], key) for key in fields):
                raise ValueError("Published package artifact differs from its verified destination")
        except BaseException:
            # This is a plan-owned artifact name. Unlink the entry itself,
            # never its target, if a concurrent substitution was detected.
            os.unlink(artifact["name"], dir_fd=directory)
            raise
    os.fsync(directory)


def _cleanup(directory, pending):
    for artifact in pending:
        try:
            os.unlink(artifact["temporary"], dir_fd=directory)
        except FileNotFoundError:
            pass
        finally:
            descriptor = artifact.pop("descriptor", None)
            if descriptor is not None:
                os.close(descriptor)


def copy_from_container(identity, source, destination, runtime_factory=RuntimeRoot):
    plan_id, direction = _runtime_directory(source)
    destination = _host_directory(destination, plan_id, direction)
    host = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with runtime_factory(identity) as runtime, _directory(runtime.root, source) as incoming, _directory(host, destination) as outgoing:
            pending, total, entries = [], 0, 0
            try:
                with os.scandir(incoming) as files:
                    for entry in files:
                        entries += 1
                        if entries > MAX_ENTRIES:
                            raise ValueError("Container staging directory exceeds its entry budget")
                        if not entry.name.endswith(".deb"):
                            continue
                        if len(pending) >= MAX_FILES:
                            raise ValueError("Container staging directory exceeds its package count budget")
                        copied = _prepare_copy(incoming, outgoing, entry.name, 0o600, byte_budget=MAX_BYTES - total)
                        pending.append(copied)
                        total += copied["size"]
                        if total > MAX_BYTES:
                            raise ValueError("Container package export exceeds its 512 MiB transfer budget")
                if not pending:
                    raise ValueError("No downloaded package artifacts exist in the running container")
                runtime.verify()
                _commit(outgoing, pending)
                return {"files": [{key: item[key] for key in ("name", "size", "sha256")} for item in pending]}
            finally:
                _cleanup(outgoing, pending)
    finally:
        os.close(host)


def copy_to_container(identity, source, destination, expected_sha256, runtime_factory=RuntimeRoot):
    target = PurePosixPath(destination)
    plan_id, direction = _runtime_directory(str(target.parent))
    source_path = PurePosixPath(source)
    source_directory = _host_directory(str(source_path.parent), plan_id, direction)
    if source_path.name != target.name or not ARTIFACT_NAME.fullmatch(target.name):
        raise ValueError("Container artifact import must preserve the exact staged package filename")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Container artifact import requires the staged SHA256")
    host = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with runtime_factory(identity) as runtime, _directory(host, source_directory) as incoming, _directory(runtime.root, str(target.parent)) as outgoing:
            pending = []
            try:
                pending.append(_prepare_copy(incoming, outgoing, target.name, 0o644, expected_sha256))
                runtime.verify()
                _commit(outgoing, pending)
                return {key: pending[0][key] for key in ("name", "size", "sha256")}
            finally:
                _cleanup(outgoing, pending)
    finally:
        os.close(host)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "export":
            result = copy_from_container(json.loads(sys.argv[2]), sys.argv[3], sys.argv[4])
        elif len(sys.argv) == 6 and sys.argv[1] == "import":
            result = copy_to_container(json.loads(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
        else:
            raise ValueError("Internal artifact helper requires an exact container and plan-scoped paths")
        print(json.dumps(result, separators=(",", ":")))
    except Exception as error:
        raise SystemExit("Container artifact transfer failed: " + " ".join(str(error).split())[:1000])
