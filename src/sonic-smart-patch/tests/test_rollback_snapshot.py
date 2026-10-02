"""Exact historical rollback packages retain signed APT authentication."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from smart_patch.rollback_snapshot import download_rollback


class Response:
    status_code = 200
    def __init__(self, value):
        self.value = value
    def raise_for_status(self):
        pass
    def iter_content(self, _):
        yield json.dumps(self.value).encode()
    def close(self):
        pass


class Session:
    def __init__(self, architecture="amd64", version="1.0-1"):
        self.body = b"synthetic retained Debian archive bytes"
        self.file_hash = hashlib.sha1(self.body).hexdigest()
        self.value = {"binary": "socat", "binary_version": version,
                      "result": [{"architecture": architecture, "hash": self.file_hash}],
                      "fileinfo": {self.file_hash: [{"archive_name": "debian", "first_seen": "20250101T120000Z",
                                                   "path": "/pool/main/s/socat"}]}}
        self.calls = []
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(self.value)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "archive-keyring.gpg"
        self.key.write_bytes(b"fixture keyring; no real signature verification in this unit test")
        self.session = Session()
        self.commands = []
        self.source = ""
    def tearDown(self):
        self.temp.cleanup()
    def runner(self, argv, **kwargs):
        self.commands.append(argv)
        if "apt-get" in argv:
            if "update" in argv:
                source = next(x.split("=", 1)[1] for x in argv if x.startswith("Dir::Etc::sourcelist="))
                self.source = Path(source).read_text()
            if "download" in argv:
                (Path(kwargs["cwd"]) / "socat_1.0-1_amd64.deb").write_bytes(self.session.body)
            return ""
        return "Package: socat\nVersion: 1.0-1\nArchitecture: amd64\n"
    def download(self, **kwargs):
        args = dict(runner=self.runner, distro={"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"},
                    architecture="amd64", session=self.session)
        args.update(kwargs)
        with patch("smart_patch.rollback_snapshot.KEYRING", self.key):
            return download_rollback("socat", "1.0-1", self.root / "retained", **args)
    def test_exact_snapshot_download_is_isolated_and_authenticated(self):
        result = self.download()
        self.assertEqual(Path(result["path"]).read_bytes(), self.session.body)
        self.assertEqual(result["sha256"], hashlib.sha256(self.session.body).hexdigest())
        self.assertEqual(result["source"]["verification"], "apt_signed_repository")
        self.assertIn("trixie main", self.source)
        self.assertIn("signed-by=" + str(self.key), self.source)
        self.assertIn("check-valid-until=no", self.source)
        self.assertNotIn("trusted=yes", self.source)
        self.assertTrue(all(command[:1] == ["env"] for command in self.commands if "apt-get" in command))
        command = " ".join(" ".join(c) for c in self.commands)
        self.assertIn("APT::Get::AllowUnauthenticated=false", command)
        self.assertIn("socat:amd64=1.0-1", command)
        self.assertNotIn(" install ", command)
        self.assertFalse(list((self.root / "retained").glob(".snapshot-*")))
    def test_signature_failure_never_downloads_or_bypasses_authentication(self):
        def failed(argv, **kwargs):
            self.commands.append(argv)
            raise RuntimeError("NO_PUBKEY: signature cannot be verified")
        with self.assertRaisesRegex(ValueError, "signed Debian snapshot"):
            self.download(runner=failed)
        self.assertEqual(len(self.commands), 6)
        self.assertTrue(all("download" not in command for command in self.commands))
    def test_mismatched_architecture_version_and_distribution_rejected(self):
        self.session = Session(architecture="arm64")
        with self.assertRaisesRegex(ValueError, "absent"):
            self.download()
        self.assertFalse(self.commands)
        self.session = Session(version="2.0-1")
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            self.download()
        with self.assertRaisesRegex(ValueError, "known Debian release"):
            self.download(distro={"ID": "ubuntu", "VERSION_CODENAME": "jammy"})
    def test_bad_snapshot_hash_never_retained(self):
        self.session.file_hash = "a" * 40
        self.session.value["result"][0]["hash"] = self.session.file_hash
        self.session.value["fileinfo"] = {self.session.file_hash: [{"archive_name": "debian", "first_seen": "20250101T120000Z", "path": "/pool/main/s/socat"}]}
        with self.assertRaisesRegex(ValueError, "differs from the exact snapshot file identity"):
            self.download()
        self.assertFalse(list((self.root / "retained").glob("*.deb")))
    def test_fixed_timestamp_and_security_suite_use_scope_release(self):
        info = self.session.value["fileinfo"][self.session.file_hash][0]
        info.update(archive_name="debian-security", path="/pool/updates/main/s/socat")
        class Config:
            def values(self):
                return {"rollback_snapshot_timestamp": "20250201T000000Z"}
        result = self.download(distro={"ID": "debian", "VERSION_ID": "12"}, config=Config())
        self.assertEqual(result["source"]["suite"], "bookworm-security")
        self.assertEqual(result["source"]["snapshot"], "20250201T000000Z")
    def test_epoch_version_is_encoded_and_exact(self):
        self.session.value["binary_version"] = "1:1.0-1"
        with patch("smart_patch.rollback_snapshot.KEYRING", self.key):
            # Metadata is accepted but the synthetic archive's version must not
            # silently satisfy a requested Debian epoch.
            with self.assertRaisesRegex(ValueError, "Exactly one"):
                download_rollback("socat", "1:1.0-1", self.root / "retained", runner=self.runner,
                                  distro={"ID": "debian", "VERSION_ID": "13"}, architecture="amd64", session=self.session)
        self.assertIn("1%3A1.0-1", self.session.calls[0][0])


if __name__ == "__main__":
    unittest.main()
