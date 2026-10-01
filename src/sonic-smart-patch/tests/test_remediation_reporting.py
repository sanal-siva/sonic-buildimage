"""Progress is durable, bounded, enrollment scoped and never authorizes work."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests

from smart_patch.config import ConfigManager
from smart_patch.storage import StateStore, atomic_json
from smart_patch.remediation_status import RemediationReporter, get_status, local_reports, publish_plan


class Response:
    def __init__(self, result):
        self.result = result
    def raise_for_status(self):
        pass
    def iter_content(self, _):
        yield json.dumps(self.result).encode()
    def close(self):
        pass


class Server:
    def __init__(self):
        self.sent, self.rows, self.during = [], [], None
        self.fail = False
    def post(self, url, json, **kwargs):
        self.sent.append((url, json, kwargs))
        if self.fail:
            raise requests.ConnectionError("Synthetic offline service")
        if self.during:
            self.during()
        return Response({"accepted": [{"local_plan_id": r["local_plan_id"], "revision": r["revision"]} for r in json["reports"]],
                         "remediation_status": self.rows})


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "state")
        self.config = ConfigManager(directory=self.root / "config")
        self.config.set_service_enabled(True)
        self.config.set_service_url("https://service.invalid/api/v1")
        self.config.set_auth_token("fixture-secret-never-public")
        with self.store.transaction() as state:
            state.update(device_id="fixture-one", epoch="epoch-one", build_id="build-one",
                         inventory_digest="new-not-acked", acknowledged_digest="accepted-digest", findings=[],
                         inventory={str(i): {"component_id": str(i), "name": "fixture"} for i in range(100)})
        atomic_json(self.store.directory/'remediation-identity.json',
                    {key:state[key] for key in ('device_id','epoch','build_id','acknowledged_digest')})
        self.plan = {"id": "11111111-1111-4111-8111-111111111111", "revision": 1, "origin": "cli",
                     "scope": "container:pmon", "package": "socat", "from_version": "1.0-1", "target_version": "1.1-1",
                     "component_id": "component-one", "finding_ids": ["finding-one"], "cve_ids": ["SYNTHETIC-NOT-A-CVE"],
                     "inventory_digest": "accepted-digest", "inventory_epoch": "epoch-one", "build_id": "build-one",
                     "status": "staged", "architecture": "amd64", "created_at": "2026-10-01T00:00:00Z",
                     "updated_at": "2026-10-01T00:01:00Z", "history": [{"status": "staged", "at": "2026-10-01T00:01:00Z"}]}
        self.path = self.store.directory / "plans" / self.plan["id"] / "plan.json"
        self.save()
        self.server = Server()
        self.reporter = RemediationReporter(self.config, self.store, self.server)
        self.cap = patch("smart_patch.maintenance_resources.container_maintenance_available", return_value=False)
        self.cap.start()
    def tearDown(self):
        self.cap.stop()
        self.temp.cleanup()
    def save(self):
        atomic_json(self.path, self.plan)
        publish_plan(self.plan, self.store.directory, self.config)
    def test_exact_report_retries_and_does_not_rewrite_inventory(self):
        before = (self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns)
        self.reporter.report_once()
        url, body, options = self.server.sent[0]
        self.assertEqual(url, "https://service.invalid/api/v1/agents/remediation")
        self.assertEqual(body["inventory_digest"], "accepted-digest")
        self.assertEqual(body["reports"][0]["component_id"], "component-one")
        self.assertFalse(options["allow_redirects"])
        self.assertEqual(before, (self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns))
        self.reporter.report_once()
        self.assertEqual(len(self.server.sent), 1)
        self.plan.update(revision=2, status="installing")
        self.save()
        self.reporter.report_once()
        self.assertEqual(self.server.sent[-1][1]["reports"][0]["revision"], 2)
        self.assertEqual(before, (self.store.path.read_bytes(), self.store.path.stat().st_mtime_ns))
    def test_offline_preserves_durable_plan_and_retries_exact_revision(self):
        self.server.fail = True
        with self.assertRaises(requests.ConnectionError):
            self.reporter.report_once()
        self.assertFalse((self.store.directory / "remediation-reporter.json").exists())
        self.server.fail = False
        self.reporter.report_once()
        self.assertEqual(self.server.sent[0][1], self.server.sent[1][1])
    def test_enrollment_rotation_during_upload_does_not_commit_old_ack(self):
        def rotate():
            with self.store.transaction() as state:
                state.update(device_id="fixture-two", epoch="epoch-two")
            atomic_json(self.store.directory/'remediation-identity.json',
                        {key:state[key] for key in ('device_id','epoch','build_id','acknowledged_digest')})
        self.server.during = rotate
        self.assertTrue(self.reporter.report_once()["identity_changed"])
        self.assertFalse((self.store.directory / "remediation-reporter.json").exists())
        self.assertEqual(get_status(self.store, self.config)["rows"], [])
    def test_old_unbound_plan_is_not_uploaded_and_does_not_gain_identity(self):
        self.plan.pop("inventory_epoch")
        self.save()
        self.assertEqual(local_reports(self.store, self.config), [])
    def test_new_local_progress_overrides_old_cache_but_same_revision_resolution_is_visible(self):
        row = {"local_plan_id": self.plan["id"], "cve_id": "SYNTHETIC-NOT-A-CVE", "component_id": "component-one",
               "origin": "cli", "report_revision": 1, "state": "resolved", "status": "resolved"}
        self.server.rows = [row]
        self.reporter.report_once()
        self.assertEqual(get_status(self.store, self.config)["rows"][0]["state"], "resolved")
        self.plan.update(revision=2, status="rolling_back")
        self.save()
        self.assertEqual(get_status(self.store, self.config)["rows"][0]["state"], "rolling_back")
    def test_public_snapshots_hide_token_url_credentials_and_paths(self):
        self.plan["error"] = "https://user:password@repo.invalid/pkg fixture-secret-never-public"
        self.plan["artifacts"] = {"rollback": [{"path": "/private/secret.deb", "package": "socat", "version": "1.0-1", "sha256": "a" * 64}]}
        self.save()
        raw = (self.store.directory / "remediation-public" / (self.plan["id"] + ".json")).read_text()
        for secret in ("fixture-secret-never-public", "user:password", "/private/secret.deb"):
            self.assertNotIn(secret, raw)
    def test_status_response_keeps_more_than_100_rows_without_list_truncation(self):
        self.server.rows = [{"id": str(i), "origin": "inventory", "cve_id": "SYNTHETIC-%d" % i,
                             "component_id": str(i), "state": "no_plan"} for i in range(150)]
        self.reporter.report_once()
        cached = json.loads((self.store.directory / "remediation-status.json").read_text())
        self.assertEqual(len(cached["remediation_status"]), 150)
    def test_public_cache_failure_never_fails_private_plan_publication(self):
        with patch('smart_patch.remediation_status.atomic_json', side_effect=PermissionError('fixture')):
            self.assertFalse(publish_plan(self.plan,self.store.directory,self.config))
        self.assertTrue(self.path.exists())
    def test_public_directory_is_traversable_under_daemon_umask(self):
        old=os.umask(0o077)
        try:
            directory=self.root/'restrictive'
            directory.mkdir()
            publish_plan(self.plan,directory,self.config)
            self.assertEqual((directory/'remediation-public').stat().st_mode & 0o777,0o755)
        finally:
            os.umask(old)
    def test_existing_unplanned_cache_row_is_replaced_by_local_progress(self):
        self.server.rows=[{'origin':'inventory','cve_id':'SYNTHETIC-NOT-A-CVE',
                          'component_id':'component-one','state':'no_plan'}]
        self.reporter.report_once()
        rows=get_status(self.store,self.config)['rows']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['state'],'staged')
    def test_reporting_never_opens_or_hashes_full_inventory(self):
        with patch.object(self.store,'load',side_effect=AssertionError('Full inventory read forbidden')):
            with patch.object(self.store,'transaction',side_effect=AssertionError('Inventory write lock forbidden')):
                self.assertTrue(self.reporter.report_once()['accepted'])
    def test_missing_ack_identity_waits_without_reading_inventory(self):
        (self.store.directory/'remediation-identity.json').unlink()
        with patch.object(self.store,'load',side_effect=AssertionError('Full inventory read forbidden')):
            self.assertTrue(self.reporter.report_once()['waiting_for_inventory'])
        self.assertFalse(self.server.sent)
    def test_reporter_config_has_its_own_connector_and_config_state(self):
        from smart_patch.main import SmartPatchDaemon
        from types import SimpleNamespace
        daemon=SmartPatchDaemon(SimpleNamespace(config=self.config,store=self.store))
        cloned=daemon.reporter_config()
        self.assertIsNot(cloned,self.config)
        self.assertEqual(cloned.values(),self.config.values())
        self.assertFalse(cloned._auto_connect)
    def test_forward_download_alone_is_not_reported_as_successful_staging(self):
        self.plan.update(status='downloaded',transaction=[{'package':'socat'}],
                         artifacts={'forward':[{'package':'socat','version':'1.1-1','sha256':'a'*64}]})
        self.save()
        self.assertEqual(local_reports(self.store,self.config)[0]['staging_result']['status'],'downloaded')
        self.plan.update(status='staged',staged_at='2026-10-01T00:02:00Z')
        self.save()
        self.assertEqual(local_reports(self.store,self.config)[0]['staging_result']['status'],'staged')


if __name__ == '__main__':
    unittest.main()
