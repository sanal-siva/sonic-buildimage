"""Runtime-mount package transfers reject escapes, mutations and stale IDs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from smart_patch.container_artifacts import copy_from_container, copy_to_container, RuntimeRoot


PLAN = "11111111-1111-4111-8111-111111111111"
NAME = "socat_1.8.0.3-1+deb13u1_amd64.deb"
IDENTITY = {"id": "a" * 64, "image": "sha256:" + "b" * 64, "name": "/radv", "running": True, "pid": 123}


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "runtime"
        self.archive = self.root / "docker-archive-view"
        self.archive.mkdir()
        self.container_path = "/var/tmp/sonic-smart-patch-" + PLAN + "/forward"
        self.runtime_directory = self.runtime / self.container_path.lstrip("/")
        self.runtime_directory.mkdir(parents=True)
        self.host_directory = self.root / "state/plans" / PLAN / "forward"
        self.host_directory.mkdir(parents=True)
        self.payload = b"synthetic package bytes for runtime mount transfer"
        self.source = self.runtime_directory / NAME
        self.source.write_bytes(self.payload)
        self.verify = Mock()
        self.output = self.host_directory / NAME

    def factory(self, identity):
        outer = self
        class Root:
            def __enter__(self):
                self.root = os.open(outer.runtime, os.O_RDONLY | os.O_DIRECTORY)
                return self
            def verify(self):
                outer.verify()
            def __exit__(self, *_):
                os.close(self.root)
        return Root()

    def export(self):
        return copy_from_container(IDENTITY, self.container_path, str(self.host_directory), runtime_factory=self.factory)

    def import_package(self, expected=None):
        return copy_to_container(IDENTITY, str(self.output), self.container_path + "/" + NAME,
                                 expected or hashlib.sha256(self.payload).hexdigest(), runtime_factory=self.factory)

    def test_export_reads_runtime_view_even_when_docker_archive_view_is_empty(self):
        self.assertFalse((self.archive / self.container_path.lstrip("/")).exists())
        result = self.export()
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.verify.call_count, 1)

    def test_import_restores_cleared_runtime_tmpfs_from_retained_host_artifact(self):
        self.export()
        self.source.unlink()
        result = self.import_package()
        self.assertEqual(self.source.read_bytes(), self.payload)
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o644)

    def test_source_symlink_hardlink_and_fifo_are_rejected_without_blocking(self):
        external = self.root / "outside"
        external.write_bytes(self.payload)
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                self.source.unlink()
                if kind == "symlink":
                    self.source.symlink_to(external)
                elif kind == "hardlink":
                    os.link(external, self.source)
                else:
                    os.mkfifo(self.source)
                with self.assertRaises((OSError, ValueError)):
                    self.export()
                self.assertFalse(self.output.exists())
                self.assertEqual(external.read_bytes(), self.payload)

    def test_runtime_directory_symlink_is_not_followed(self):
        real = self.runtime_directory.with_name("elsewhere")
        self.runtime_directory.rename(real)
        self.runtime_directory.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_host_plan_directory_symlink_is_not_followed(self):
        external = self.root / "elsewhere"
        external.mkdir()
        self.host_directory.rmdir()
        self.host_directory.symlink_to(external, target_is_directory=True)
        with self.assertRaises(OSError):
            self.export()
        self.assertEqual(list(external.iterdir()), [])

    def test_wrong_plan_or_direction_is_rejected_before_accessing_runtime(self):
        for destination in (self.root / "wrong", self.host_directory.with_name("rollback"),
                            self.root / "state/plans" / ("2" * 36) / "forward"):
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "exact plan"):
                copy_from_container(IDENTITY, self.container_path, str(destination), runtime_factory=self.factory)
        self.verify.assert_not_called()

    def test_import_cannot_follow_symlink_or_change_staged_filename(self):
        external = self.root / "outside"
        external.write_bytes(self.payload)
        self.output.symlink_to(external)
        with self.assertRaises(OSError):
            self.import_package()
        with self.assertRaisesRegex(ValueError, "exact staged"):
            copy_to_container(IDENTITY, str(self.output), self.container_path + "/other.deb", "0" * 64,
                              runtime_factory=self.factory)

    def test_wrong_import_hash_leaves_previous_runtime_file_unchanged(self):
        self.output.write_bytes(self.payload)
        self.source.write_bytes(b"previous runtime data")
        with self.assertRaisesRegex(ValueError, "staged SHA256"):
            self.import_package("0" * 64)
        self.assertEqual(self.source.read_bytes(), b"previous runtime data")
        self.assertEqual(list(self.runtime_directory.glob(".smart-patch-artifact-*")), [])

    def test_container_restart_before_publication_leaves_no_new_artifact(self):
        self.verify.side_effect = ValueError("Container process changed")
        with self.assertRaisesRegex(ValueError, "process changed"):
            self.export()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.host_directory.iterdir()), [])

    def test_count_and_entry_budgets_do_not_publish_partial_results(self):
        for index in range(3):
            (self.runtime_directory / ("extra_%d_all.deb" % index)).write_bytes(b"fixture")
        with patch("smart_patch.container_artifacts.MAX_FILES", 2):
            with self.assertRaisesRegex(ValueError, "package count"):
                self.export()
        self.assertEqual(list(self.host_directory.iterdir()), [])
        with patch("smart_patch.container_artifacts.MAX_ENTRIES", 2):
            with self.assertRaisesRegex(ValueError, "entry budget"):
                self.export()
        self.assertEqual(list(self.host_directory.iterdir()), [])

    def test_remaining_total_budget_checked_before_creating_next_tempfile(self):
        self.source.write_bytes(b"123456")
        (self.runtime_directory / "second_1_all.deb").write_bytes(b"123456")
        real_open = os.open
        created = []
        def tracked(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                created.append(path)
            return real_open(path, flags, *args, **kwargs)
        with patch("smart_patch.container_artifacts.MAX_BYTES", 8), patch("smart_patch.container_artifacts.os.open", side_effect=tracked):
            with self.assertRaisesRegex(ValueError, "remaining transfer budget"):
                self.export()
        self.assertEqual(len(created), 1)
        self.assertEqual(list(self.host_directory.iterdir()), [])

    def test_destination_rehash_detects_changed_already_copied_bytes(self):
        real_write = os.write
        changed = []
        def alter(fd, data):
            written = real_write(fd, data)
            if not changed:
                path = Path(os.readlink("/proc/self/fd/%d" % fd))
                with path.open("r+b") as stream:
                    stream.write(b"X")
                changed.append(True)
            return written
        with patch("smart_patch.container_artifacts.os.write", side_effect=alter):
            with self.assertRaisesRegex(ValueError, "Destination package artifact changed"):
                self.export()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.host_directory.iterdir()), [])

    def test_temp_replacement_during_container_recheck_never_publishes_a_symlink(self):
        outside = self.root / "outside"
        outside.write_bytes(b"outside data")
        def replace():
            temporary = next(self.host_directory.glob(".smart-patch-artifact-*"))
            temporary.unlink()
            temporary.symlink_to(outside)
        self.verify.side_effect = replace
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())
        self.assertEqual(outside.read_bytes(), b"outside data")
        self.assertEqual(list(self.host_directory.iterdir()), [])

    def test_temp_byte_mutation_during_container_recheck_is_rejected(self):
        def mutate():
            temporary = next(self.host_directory.glob(".smart-patch-artifact-*"))
            temporary.write_bytes(b"X" * len(self.payload))
        self.verify.side_effect = mutate
        with self.assertRaisesRegex(ValueError, "changed before publication"):
            self.export()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.host_directory.iterdir()), [])

    def test_substitution_at_rename_is_detected_and_removed(self):
        real_replace = os.replace
        def substitute(source, destination, **kwargs):
            fd = kwargs["src_dir_fd"]
            os.unlink(source, dir_fd=fd)
            os.symlink("/nonexistent-artifact-review-canary", source, dir_fd=fd)
            return real_replace(source, destination, **kwargs)
        with patch("smart_patch.container_artifacts.os.replace", side_effect=substitute):
            with self.assertRaises(ValueError):
                self.export()
        self.assertFalse(self.output.is_symlink())
        self.assertFalse(self.output.exists())


class RuntimeIdentityTests(unittest.TestCase):
    def test_process_replacement_after_pinning_closes_root_and_fails(self):
        runner = Mock(side_effect=[json.dumps(IDENTITY), json.dumps({**IDENTITY, "pid": 124})])
        with patch("smart_patch.container_artifacts._process_start", return_value="original-start"), \
                patch("smart_patch.container_artifacts.os.open", return_value=91) as opened, \
                patch("smart_patch.container_artifacts.os.close") as closed:
            with self.assertRaisesRegex(ValueError, "Container process changed"):
                with RuntimeRoot(IDENTITY, runner=runner):
                    self.fail("Replaced process must not enter the copy context")
        self.assertEqual(opened.call_args.args[0], "/proc/123/root")
        closed.assert_called_once_with(91)

    def test_recreated_name_does_not_select_a_new_container(self):
        runner = Mock(return_value=json.dumps({**IDENTITY, "id": "c" * 64}))
        with patch("smart_patch.container_artifacts.os.open") as opened:
            with self.assertRaisesRegex(ValueError, "identity changed"):
                with RuntimeRoot(IDENTITY, runner=runner):
                    self.fail("Replacement must be rejected")
        opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
