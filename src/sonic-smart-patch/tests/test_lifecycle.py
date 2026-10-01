from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from smart_patch.config import ConfigManager
from smart_patch.lifecycle import SmartPatchServiceManager, set_enabled, set_mode


class LifecycleTests(unittest.TestCase):
    def test_enable_persists_and_starts_only_smart_patch_disable_publishes_first(self):
        with tempfile.TemporaryDirectory() as directory:
            config=ConfigManager(directory=directory)
            events=[]
            def runner(argv, **kwargs):
                events.append(("systemctl",argv,config.get_service_enabled()))
                return SimpleNamespace(returncode=0,stderr="")
            def publisher(values):events.append(("publish",values["enabled"],values["mode"]))
            service=SmartPatchServiceManager(config,runner,available=True)
            self.assertTrue(set_enabled(True,config,service,publisher))
            self.assertEqual(events[-1],("systemctl",["systemctl","enable","--now","sonic-smart-patch.service"],True))
            events.clear()
            self.assertTrue(set_enabled(False,config,service,publisher))
            self.assertEqual(events[0][0:2],("publish","false"))
            self.assertEqual(events[1],("systemctl",["systemctl","disable","--now","sonic-smart-patch.service"],False))
            events.clear()
            set_mode("assisted",config,service,publisher)
            self.assertEqual(events,[("publish","false","assisted")])

    def test_standalone_configuration_never_runs_host_systemctl(self):
        with tempfile.TemporaryDirectory() as directory:
            config=ConfigManager(directory=directory)
            with patch("smart_patch.lifecycle.subprocess.run",side_effect=AssertionError("host systemctl forbidden")):
                self.assertFalse(set_enabled(True,config,publisher=lambda values:None))
                self.assertTrue(config.get_service_enabled())
                self.assertFalse(set_enabled(False,config,publisher=lambda values:None))

    def test_failed_systemctl_is_reported_instead_of_claiming_start_success(self):
        with tempfile.TemporaryDirectory() as directory:
            config=ConfigManager(directory=directory)
            service=SmartPatchServiceManager(config,runner=lambda *args,**kwargs:SimpleNamespace(returncode=1,stderr="unit failed"),available=True)
            with self.assertRaisesRegex(RuntimeError,"unit failed"):
                set_enabled(True,config,service,publisher=lambda values:None)
