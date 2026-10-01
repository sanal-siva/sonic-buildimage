"""Clone-safe enrollment and permission-safe operational snapshots."""
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from click.testing import CliRunner
from smart_patch.collector import enrollment_id, identity
from smart_patch.storage import StateStore, atomic_json, public_snapshot
from smart_patch.config import ConfigManager
from smart_patch.cli import show


def enroll(directory, queue):
    queue.put(enrollment_id(directory))


class IdentityPublicTests(unittest.TestCase):
    def test_cloned_machine_identity_gets_distinct_persisted_enrollment(self):
        with tempfile.TemporaryDirectory() as directory, patch("smart_patch.collector.socket.gethostname", return_value="cloned-sonic"):
            directory = Path(directory)
            first = identity(str(directory / "missing-manifest"), directory / "first")
            second = identity(str(directory / "missing-manifest"), directory / "second")
            self.assertNotEqual(first["device_id"], second["device_id"])
            self.assertEqual(first["hostname"], second["hostname"])
            self.assertEqual(first["device_id"], identity(str(directory / "missing-manifest"), directory / "first")["device_id"])
            self.assertEqual((directory / "first/device-id").stat().st_mode & 0o777, 0o600)

    def test_manifest_digest_preserves_exact_raw_bytes(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            manifest = directory / "manifest.json"
            raw = b'{"build_id":"test-build"}\n\n'
            manifest.write_bytes(raw)
            result = identity(str(manifest), directory / "config")
            self.assertEqual(result["manifest_digest"], "sha256:"+hashlib.sha256(raw).hexdigest())
            self.assertEqual(result["manifest"], {"build_id":"test-build"})
            self.assertFalse(result["artifact_verified"])

    def test_concurrent_first_startup_creates_one_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = multiprocessing.Queue()
            processes = [multiprocessing.Process(target=enroll, args=(directory, queue)) for _ in range(5)]
            for process in processes:
                process.start()
            identities = [queue.get(timeout=5) for _ in processes]
            for process in processes:
                process.join(5)
            self.assertEqual(len(set(identities)), 1)
            self.assertTrue(all(process.exitcode == 0 for process in processes))

    def test_preprovisioned_legacy_id_preserved_and_invalid_id_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "device-id"
            path.write_text("ea6d5e29703fd1abcb1cdd9f8985a553\n")
            path.chmod(0o600)
            self.assertEqual(enrollment_id(directory), "ea6d5e29703fd1abcb1cdd9f8985a553")
            path.write_text("invalid identity containing spaces")
            with self.assertRaises(ValueError):
                enrollment_id(directory)
            self.assertEqual(path.read_text(), "invalid identity containing spaces")

    def test_identity_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            target = path / "other"
            target.write_text("another-identity")
            (path / "device-id").symlink_to(target)
            with self.assertRaises(OSError):
                enrollment_id(directory)

    def test_public_snapshot_excludes_private_state_and_redacts_credential(self):
        secret = "test-secret-device-credential"
        state = {"device_id":"one", "inventory":{"component":{}}, "sync_status":"connected",
                 "error":secret, "config":{"auth_token":secret}, "facts":[{"value":secret}],
                 "action_requests":[{"plan":{"secret":secret}}], "resources":{"rss_bytes":1024,"secret":secret},
                 "findings":[{"id":"finding", "rationale":"text " + secret, "auth_token":secret,
                              "evidence":[{"id":"evidence-one","secret":secret}], "fixed_versions":["2"]}]}
        public = public_snapshot(state, (secret,))
        encoded = json.dumps(public)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("auth_token", encoded)
        self.assertNotIn("action_requests", public)
        self.assertNotIn("facts", public)
        self.assertNotIn("inventory", public)
        self.assertEqual(public["component_count"], 1)
        self.assertEqual(public["findings"][0]["evidence"], ["evidence-one"])

    def test_show_commands_only_read_sanitized_public_files(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"SMART_PATCH_STATE_DIR":directory+"/state", "SMART_PATCH_CONFIG_DIR":directory+"/config"}):
            store = StateStore()
            config = ConfigManager()
            config.set_service_enabled(True)
            config.set_auth_token("secret-not-public")
            state = {"sync_status":"connected", "assessment_status":"completed", "inventory":{"one":{}},
                     "resources":{"rss_bytes":1024}, "findings":[{"id":"finding", "cve_id":"CVE-2026-1", "fixed_versions":[]}]}
            with store.transaction() as private:
                private.update(state)
            atomic_json(store.directory / "public.json", public_snapshot(state), mode=0o644)
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((store.directory / "public.json").stat().st_mode & 0o777, 0o644)
            self.assertEqual((config.directory / "credentials.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((config.directory / "public-config.json").stat().st_mode & 0o777, 0o644)
            with patch("smart_patch.cli.StateStore.load", side_effect=PermissionError("private file")), patch("smart_patch.cli.ConfigManager.values", side_effect=PermissionError("private config")):
                runner = CliRunner()
                for args in (["status", "--json"], ["findings", "--json"], ["finding", "finding"], ["inventory-drift"], ["resource-usage"]):
                    result = runner.invoke(show, args)
                    self.assertEqual(result.exit_code, 0, result.output)
                    self.assertNotIn("secret-not-public", result.output)


if __name__ == "__main__":
    unittest.main()
