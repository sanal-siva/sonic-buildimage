"""ConfigDB reload/removal is authoritative and disabled status needs no network."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from guardian.agent import Agent
from guardian.config import ConfigManager
from guardian.main import GuardianDaemon
from guardian.storage import StateStore, atomic_json, read_public_state


class Database:
    def __init__(self, entry):
        self.entry = entry
        self.unavailable = False
    def get_entry(self, table, key):
        if self.unavailable:raise RuntimeError("DB unavailable")
        return dict(self.entry)
    def set_entry(self, table, key, entry):
        self.entry = dict(entry)


class ConfigReloadTests(unittest.TestCase):
    def test_removed_configdb_entry_does_not_reappear_from_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Database({"enabled":"true","mode":"assisted","service_url":"https://old-service"})
            config=ConfigManager(database,directory)
            atomic_json(Path(directory)/"config.json",database.entry)
            database.entry={}
            self.assertFalse(config.get_service_enabled())
            self.assertIsNone(config.get_service_url())
            config.refresh()
            self.assertEqual(json.loads((Path(directory)/"config.json").read_text()),{})
            database.unavailable=True
            self.assertFalse(config.get_service_enabled())

    def test_live_db_overrides_disk_but_unavailable_db_uses_last_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Database({"enabled":"false","mode":"advisory"})
            config=ConfigManager(database,directory)
            atomic_json(Path(directory)/"config.json",{"enabled":"true","mode":"assisted"})
            self.assertFalse(config.get_service_enabled())
            database.unavailable=True
            self.assertTrue(config.get_service_enabled())
            self.assertEqual(config.get_operating_mode(),"assisted")
            database.unavailable=False
            config.refresh()
            database.unavailable=True
            self.assertFalse(config.get_service_enabled())

    def test_live_database_repairs_invalid_fallback_without_reading_it_as_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Database({"enabled":"false"})
            config=ConfigManager(database,directory)
            path=Path(directory)/"config.json"
            path.write_text("broken-json")
            self.assertFalse(config.get_service_enabled())
            self.assertEqual(config.refresh()["enabled"],"false")
            self.assertEqual(json.loads(path.read_text()),{"enabled":"false"})

    def test_setting_after_reload_does_not_restore_deleted_enable_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            database=Database({})
            config=ConfigManager(database,directory)
            atomic_json(Path(directory)/"config.json",{"enabled":"true","mode":"autonomous"})
            config.set_service_url("https://new-service")
            self.assertNotIn("enabled",database.entry)
            self.assertNotIn("enabled",json.loads((Path(directory)/"config.json").read_text()))
            self.assertFalse(config.get_service_enabled())

    def test_disabled_mode_changes_publish_without_collection_or_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory)
            database=Database({"enabled":"false","mode":"assisted"})
            config=ConfigManager(database,directory/"config")
            store=StateStore(directory/"state")
            with store.transaction() as state:
                state.update(sync_status="connected",last_sync="2026-09-29T12:00:00+00:00")
            agent=Agent(config,store)
            with patch.object(agent,"sync",side_effect=AssertionError("disabled network call")), patch.object(agent.collector,"collect",side_effect=AssertionError("disabled scan")):
                GuardianDaemon(agent).step()
            public=read_public_state(store.directory)
            self.assertEqual(public["sync_status"],"disabled")
            self.assertEqual(json.loads((config.directory/"public-config.json").read_text())["mode"],"assisted")
            self.assertEqual(store.load()["last_sync"],"2026-09-29T12:00:00+00:00")
            database.entry={}
            with patch.object(agent,"sync",side_effect=AssertionError("removed config network call")):
                GuardianDaemon(agent).step()
            self.assertEqual(json.loads((config.directory/"public-config.json").read_text())["mode"],"advisory")


if __name__ == "__main__":unittest.main()
