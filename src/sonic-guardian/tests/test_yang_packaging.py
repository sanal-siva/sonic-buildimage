"""Standalone schema registration must coexist with native image-owned models."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
specification = importlib.util.spec_from_file_location("guardian_install_yang", ROOT / "scripts/install-yang.py")
registration = importlib.util.module_from_spec(specification)
specification.loader.exec_module(registration)


class YangPackagingTests(unittest.TestCase):
    def test_register_and_remove_only_private_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "private/sonic-guardian.yang"
            source.parent.mkdir()
            source.write_text("private schema")
            native = directory / "native"
            native.mkdir()
            self.assertEqual(registration.register_model(native, source), "registered")
            target = native / source.name
            self.assertTrue(target.is_symlink())
            self.assertEqual(target.resolve(), source)
            self.assertEqual(registration.register_model(native, source), "already-registered")
            self.assertEqual(registration.register_model(native, source, remove=True), "removed-owned-symlink")
            self.assertFalse(target.exists())
            self.assertTrue(source.exists())

    def test_real_image_model_and_foreign_symlink_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "private.yang"
            source.write_text("private schema")
            native = directory / "native"
            native.mkdir()
            target = native / "sonic-guardian.yang"
            target.write_text("image-owned schema")
            registration.register_model(native, source)
            registration.register_model(native, source, remove=True)
            self.assertEqual(target.read_text(), "image-owned schema")
            target.unlink()
            target.symlink_to(directory / "missing-foreign-package-model")
            registration.register_model(native, source)
            registration.register_model(native, source, remove=True)
            self.assertTrue(target.is_symlink())
            self.assertNotEqual(target.resolve(), source.resolve())


if __name__ == "__main__":
    unittest.main()
