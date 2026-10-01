import fcntl
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from smart_patch.storage import StateStore, atomic_json


class StorageReadTests(unittest.TestCase):
    def test_load_is_shared_read_only_and_noop_transaction_does_not_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            store=StateStore(directory)
            atomic_json(store.path,{"value":1})
            before=store.path.stat()
            original=fcntl.flock
            calls=[]
            def flock(fd, operation):
                calls.append(operation);return original(fd,operation)
            with patch("smart_patch.storage.os.replace",side_effect=AssertionError("read replaced file")), patch("smart_patch.storage.os.fsync",side_effect=AssertionError("read fsynced file")), patch("smart_patch.storage.fcntl.flock",side_effect=flock):
                self.assertEqual(store.load(),{"value":1})
                with store.transaction() as state:state["value"]=1
            after=store.path.stat()
            self.assertEqual((before.st_ino,before.st_mtime_ns),(after.st_ino,after.st_mtime_ns))
            self.assertEqual(calls[0],fcntl.LOCK_SH)

    def test_empty_read_and_noop_do_not_create_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            store=StateStore(directory)
            with patch("smart_patch.storage.os.fsync",side_effect=AssertionError("unexpected fsync")):
                self.assertEqual(store.load(),{})
                with store.transaction():pass
            self.assertFalse(store.path.exists())

    def test_json_type_change_is_a_write_even_if_python_equality_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            store=StateStore(directory)
            with store.transaction() as state:state["value"]=1
            with store.transaction() as state:state["value"]=True
            self.assertIs(store.load()["value"],True)
