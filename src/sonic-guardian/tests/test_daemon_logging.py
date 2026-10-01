"""The daemon entry point emits machine-parseable JSON log records."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


class DaemonLoggingTests(unittest.TestCase):
    def test_entry_point_configures_structured_stderr(self):
        script = '''
import logging
import guardian.main as module
class FakeDaemon:
    def run(self):
        logging.getLogger('sonic-guardian').warning('Inventory deferred: resource budget')
        return 0
module.GuardianDaemon = FakeDaemon
raise SystemExit(module.main())
'''
        project = str(Path(__file__).resolve().parents[1])
        result = subprocess.run([sys.executable, '-c', script], cwd=project,
                                env={**os.environ, 'PYTHONPATH': project},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stderr.splitlines() if line]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['level'], 'WARNING')
        self.assertEqual(records[0]['component'], 'sonic-guardian')
        self.assertEqual(records[0]['message'], 'Inventory deferred: resource budget')
        self.assertTrue(records[0]['timestamp'].endswith('Z'))
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
