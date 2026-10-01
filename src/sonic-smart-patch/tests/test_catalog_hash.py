"""A catalog identity mismatch must stop staging before installation."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from smart_patch.config import ConfigManager
from smart_patch.remediation import RemediationEngine
from smart_patch.storage import StateStore


class CatalogHashTests(unittest.TestCase):
    def test_primary_artifact_must_match_verified_catalog_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            engine = RemediationEngine(StateStore(directory / "state"), ConfigManager(directory=directory / "config"),
                                       runner=lambda *args, **kwargs:"Package: smart-patch-testprobe\nVersion: 1.1\n")
            engine.config.set("", "", "maintenance_checks_enabled", "true")
            plan = {"id":"11111111-1111-1111-1111-111111111111", "scope":"host", "package":"smart-patch-testprobe", "target_package_sha256":"0"*64}
            folder = engine._path(plan["id"]).parent / "forward"
            folder.mkdir(parents=True)
            artifact = folder / "smart-patch-testprobe_1.1_all.deb"
            artifact.write_bytes(b"synthetic test artifact")
            change = {"package":"smart-patch-testprobe", "from_version":"1.0", "to_version":"1.1"}
            with patch("smart_patch.remediation.subprocess.run", return_value=SimpleNamespace(returncode=0)):
                with self.assertRaisesRegex(ValueError, "catalog SHA256"):
                    engine._download(plan, change, "forward")
                plan["target_package_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
                result = engine._download(plan, change, "forward")
                self.assertTrue(result["catalog_hash_verified"])
                plan.pop("target_package_sha256")
                result = engine._download(plan, change, "forward")
                self.assertEqual(result["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
                self.assertNotIn("catalog_hash_verified", result)


if __name__ == "__main__":
    unittest.main()
