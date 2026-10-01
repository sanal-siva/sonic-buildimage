"""Build identity, scoped VEX and real native plugin registration checks."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import click
from click.testing import CliRunner
from guardian.vex import VEXManager

ROOT = Path(__file__).resolve().parents[1]


class IntegrationTests(unittest.TestCase):
    def test_manifest_binds_completed_artifacts_without_self_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            rootfs = directory / "rootfs"
            (rootfs / "var/lib/dpkg").mkdir(parents=True)
            (rootfs / "var/lib/dpkg/status").write_text("Package: fixture\nVersion: 1\n")
            manifest = directory / "manifest.json"
            command = ["python3", str(ROOT / "scripts/guardian-manifest.py")]
            subprocess.run(command + ["--rootfs", str(rootfs), "--manifest", str(manifest), "--source-revision", "test-source"], check=True)
            embedded = (rootfs / "etc/sonic/guardian/manifest.json").read_bytes()
            self.assertEqual(embedded, manifest.read_bytes())
            self.assertNotIn("image_sha256", json.loads(embedded))
            self.assertNotIn("device_id", json.loads(embedded))
            image = directory / "sonic-fixture.bin"
            image.write_bytes(b"synthetic completed image")
            Path(str(image)+".cdx.json").write_text('{"bomFormat":"CycloneDX"}')
            subprocess.run(command + ["--manifest", str(manifest), "--artifact", str(image)], check=True)
            index = json.loads(Path(str(image)+".guardian.json").read_text())
            self.assertEqual(index["build_id"], json.loads(embedded)["build_id"])
            self.assertTrue(index["sbom_available"])
            self.assertEqual({item["kind"] for item in index["artifacts"]}, {"image", "sbom"})
            self.assertEqual(embedded, (rootfs / "etc/sonic/guardian/manifest.json").read_bytes())

    def test_build_identity_is_reproducible_and_sensitive_to_semantic_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            rootfs = directory / "rootfs"
            (rootfs / "var/lib/dpkg").mkdir(parents=True)
            (rootfs / "var/lib/dpkg/status").write_text("Package: fixture\nVersion: 1\n")
            containers = directory / "containers.json"
            containers.write_text(json.dumps([{"name":"bgp","image_digest":"sha256:"+"a"*64}]))
            manifest = directory / "manifest.json"
            command = ["python3", str(ROOT / "scripts/guardian-manifest.py"), "--rootfs", str(rootfs),
                       "--manifest", str(manifest), "--source-revision", "same-source",
                       "--container-identities", str(containers), "--build-parameter", "feature=enabled"]
            subprocess.run(command, check=True)
            original = manifest.read_bytes()
            subprocess.run(command, check=True)
            self.assertEqual(original, manifest.read_bytes())
            self.assertNotIn("build_nonce", json.loads(original))
            containers.write_text(json.dumps([{"name":"bgp","image_digest":"sha256:"+"b"*64}]))
            subprocess.run(command, check=True)
            self.assertNotEqual(json.loads(original)["build_id"], json.loads(manifest.read_text())["build_id"])
            changed_container = manifest.read_bytes()
            subprocess.run(command + ["--build-parameter", "feature=disabled"], check=True)
            self.assertNotEqual(json.loads(changed_container)["build_id"], json.loads(manifest.read_text())["build_id"])

    def test_native_plugins_register_working_commands(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"GUARDIAN_CONFIG_DIR": directory+"/config", "GUARDIAN_STATE_DIR": directory+"/state"}):
            roots = {}
            for name in ("config", "show"):
                root = click.Group(name=name)
                spec = importlib.util.spec_from_file_location("guardian_test_plugin_"+name, ROOT / "plugins" / (name+".py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module.register(root)
                self.assertIn("security", root.commands)
                roots[name] = root
            runner = CliRunner()
            enabled = runner.invoke(roots["config"], ["security", "guardian", "enable"])
            self.assertEqual(enabled.exit_code, 0, enabled.output)
            mode = runner.invoke(roots["config"], ["security", "guardian", "mode", "assisted"])
            self.assertEqual(mode.exit_code, 0, mode.output)
            displayed = runner.invoke(roots["show"], ["security", "status", "--json"])
            self.assertEqual(displayed.exit_code, 0, displayed.output)
            status = json.loads(displayed.output)
            self.assertEqual(status["enabled"], "true")
            self.assertEqual(status["mode"], "assisted")
            self.assertFalse(status["fresh"])

    def test_vex_keeps_scope_and_never_manufactures_safe_verdicts(self):
        manager = VEXManager("/unused")
        base = {"cve_id":"CVE-2026-0001", "package_name":"curl", "affected_version":"1", "applicability":"not_affected"}
        findings = [{**base,"scope":"host","component_id":"host-curl","evidence":[]},
                    {**base,"scope":"container:bgp","component_id":"bgp-curl","applicability":"affected"}]
        result = manager.create_vex_document("test",findings)
        self.assertEqual(result["vulnerabilities"][0]["analysis"]["state"],"in_triage")
        self.assertEqual(result["vulnerabilities"][1]["analysis"]["state"],"exploitable")
        self.assertNotEqual(result["vulnerabilities"][0]["affects"],result["vulnerabilities"][1]["affects"])
        with self.assertRaises(ValueError):
            manager.create_vex_document("test",[base])
        with self.assertRaises(ValueError):
            manager.generate_vex_file(result,"../escape.json")


if __name__ == "__main__":
    unittest.main()
