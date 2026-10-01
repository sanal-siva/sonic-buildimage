"""Real offline APT acquisition checks against isolated synthetic package state.

No system packages are installed: every real APT invocation requires BOTH
--download-only and --no-download and uses temporary status, lists and caches.
Synthetic HTTP repository metadata is pre-seeded; no server or network is used.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from guardian.config import ConfigManager
from guardian.remediation import RemediationEngine
from guardian.storage import StateStore


@unittest.skipUnless(shutil.which("apt-get") and shutil.which("dpkg-deb") and shutil.which("dpkg"),
                     "Real isolated archive tests require Debian APT and dpkg-deb")
class AptArchiveCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="guardian-apt-cache-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native_arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        self.config = ConfigManager(directory=self.root / "config")
        self.runner = Mock(return_value="")
        self.engine = RemediationEngine(StateStore(self.root / "state"), self.config, self.runner)
        self.plan_id = "11111111-1111-1111-1111-111111111111"
        self.package = "guardian-cacheprobe"
        self.archive_root = self.engine._path(self.plan_id).parent
        self.empty_cache = self.root / "empty-cache"
        self.lists = self.root / "lists"
        self.apt_config = self.root / "apt.conf"
        for path in (self.empty_cache / "partial", self.lists / "partial", self.root / "empty-config"):
            path.mkdir(parents=True)
        (self.root / "empty.conf").write_text("")
        (self.root / "sources.list").write_text("deb [trusted=yes] http://guardian.invalid/ stable main\n")
        settings = {
            "Dir::Etc::parts": self.root / "empty-config", "Dir::Etc::main": self.root / "empty.conf",
            "Dir::Etc::sourcelist": self.root / "sources.list", "Dir::Etc::sourceparts": self.root / "empty-config",
            "Dir::State::status": self.root / "status", "Dir::State::lists": self.lists,
            "Dir::State::extended_states": self.root / "extended_states", "Dir::Cache": self.root / "cache",
            "Dir::Cache::archives": self.empty_cache, "Dir::Cache::pkgcache": "", "Dir::Cache::srcpkgcache": "",
            "Dir::Log": self.root / "log", "Debug::NoLocking": "true",
        }
        self.apt_config.write_text("\n".join(key + " " + json.dumps(str(value)) + ";" for key, value in settings.items()) + "\n")

    def artifact(self, version, architecture, direction):
        package_root = self.root / ("package-" + direction)
        (package_root / "DEBIAN").mkdir(parents=True)
        control = ("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <test@example.invalid>\n"
                   "Description: isolated Guardian archive lookup fixture\n" % (self.package, version, architecture))
        (package_root / "DEBIAN/control").write_text(control)
        directory = self.archive_root / direction
        directory.mkdir(parents=True, mode=0o700)
        # Match apt-get download's cache basename. The install implementation
        # must use the downloaded name, not reconstruct it from a :arch target.
        basename = self.package + "_" + version.replace(":", "%3a") + "_" + architecture + ".deb"
        artifact = directory / basename
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(package_root), str(artifact)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return {"package": self.package if architecture == "all" else self.package + ":" + architecture,
                "version": version, "path": str(artifact), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}

    def apt_state(self, artifact, installed_version, architecture):
        status = ("Package: %s\nStatus: install ok installed\nArchitecture: %s\nVersion: %s\n"
                  "Maintainer: Test <test@example.invalid>\nDescription: installed fixture\n\n"
                  % (self.package, architecture, installed_version))
        (self.root / "status").write_text(status)
        path = Path(artifact["path"])
        index = ("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <test@example.invalid>\n"
                 "Filename: pool/%s\nSize: %s\nSHA256: %s\nDescription: repository fixture\n\n"
                 % (self.package, artifact["version"], architecture, path.name, path.stat().st_size, artifact["sha256"]))
        (self.lists / ("guardian.invalid_dists_stable_main_binary-" + self.native_arch + "_Packages")).write_text(index)
        return status

    def capture_install(self, artifact, direction):
        plan = {"id": self.plan_id, "scope": "host", "artifacts": {direction: [artifact]}}
        self.engine._install(plan, direction)
        command = self.runner.call_args.args[0]
        self.assertEqual(command[:3], ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"])
        self.assertIn("--no-download", command)
        self.assertIn("Dir::Cache::Archives=" + str(self.archive_root / direction), command)
        return command

    def acquire_only(self, command, use_plan_cache):
        # Never execute the engine's installation command. Insert an unconditional
        # download-only guard; no-download also prohibits HTTP acquisition.
        args = command[3:]
        if not use_plan_cache:
            index = args.index("-o")
            self.assertTrue(args[index + 1].startswith("Dir::Cache::Archives="))
            args = args[:index] + args[index + 2:]
        command = ["apt-get", "--download-only"] + args
        self.assertIn("--download-only", command)
        self.assertIn("--no-download", command)
        return subprocess.run(command, env={**os.environ, "APT_CONFIG": str(self.apt_config), "LC_ALL": "C", "LANG": "C"},
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)

    def check_archive_resolution(self, direction, target, installed, architecture):
        artifact = self.artifact(target, architecture, direction)
        status = self.apt_state(artifact, installed, architecture)
        command = self.capture_install(artifact, direction)
        before = self.acquire_only(command, use_plan_cache=False)
        self.assertEqual(before.returncode, 100, before.stdout)
        self.assertIn("Unable to fetch some archives", before.stdout)
        after = self.acquire_only(command, use_plan_cache=True)
        self.assertEqual(after.returncode, 0, after.stdout)
        self.assertIn("download only mode", after.stdout)
        self.assertEqual((self.root / "status").read_text(), status)
        self.assertEqual(hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest(), artifact["sha256"])
        self.assertEqual((self.archive_root / direction).stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(self.empty_cache.glob("*.deb")), [])

    def test_forward_uses_staged_archive_when_repository_copy_would_require_network(self):
        self.check_archive_resolution("forward", "1.1", "1.0", "all")

    def test_rollback_uses_its_own_cache_with_epoch_and_arch_qualified_package(self):
        self.check_archive_resolution("rollback", "2:1.1+fixture1", "2:1.2+fixture1", self.native_arch)

    def test_artifact_cannot_redirect_cache_outside_its_plan_directory(self):
        artifact = self.artifact("1.1", "all", "forward")
        with self.assertRaisesRegex(ValueError, "this plan's rollback directory"):
            self.capture_install(artifact, "rollback")
        self.runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
