"""Protocol and failure-path tests; no switch or external network required."""
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import requests
from guardian.agent import Agent
from guardian.collector import digest, package_rows, collect_evidence, run, InventoryCollector
from guardian.config import ConfigManager
from guardian.storage import StateStore
from guardian.validation import ValidationEngine
from guardian.remediation import RemediationEngine


def increment(directory):
    for _ in range(10):
        with StateStore(directory).transaction() as state:
            state["counter"] = state.get("counter", 0)+1


class Response:
    def __init__(self, data):
        self.data = data
    def raise_for_status(self):
        pass
    def iter_content(self, size):
        yield json.dumps(self.data).encode()
    def close(self):
        pass


class Server:
    def __init__(self):
        self.envelopes = []
        self.fail = False
        self.resync = False
        self.inventory = {}
        self.findings = []
        self.status = "complete"
    def post(self, url, json, **kwargs):
        self.url = url
        self.envelopes.append(json)
        if self.fail:
            raise requests.ConnectionError("offline")
        if self.resync:
            return Response({"resync_required": True})
        if json["kind"] == "checkpoint":
            self.inventory = {}
        self.inventory.update({item["component_id"]: item for item in json["components"]})
        for key in json["removed"]:
            self.inventory.pop(key, None)
        return Response({"ack_sequence": json["sequence"], "inventory_digest": digest(sorted(self.inventory.values(), key=lambda item: item["component_id"])),
                         "findings": self.findings, "assessment_status": self.status, "assessment_revision": "test"})


class Collector:
    def __init__(self):
        self.items = package_rows("curl\t1.0-1\tamd64\tcurl\t1.0-1\tinstalled\n", "host", {"id":"debian","version_id":"13"})
        self.scopes = [{"scope":"host", "status":"complete"}]
    def collect(self):
        return {"components": self.items, "scopes": self.scopes, "collected_at": "2026-09-29T12:00:00+00:00", "resources": {"rss_bytes": 1234}}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = ConfigManager(directory=Path(self.temp.name)/"config")
        self.config.set_service_url("https://server/api/v1")
        self.config.set_auth_token("test-device-token")
        self.store = StateStore(Path(self.temp.name)/"state")
        self.collector = Collector()
        self.server = Server()
        self.agent = Agent(self.config, self.store, self.collector, self.server)
        self.identity = patch("guardian.agent.identity", return_value={"device_id":"one", "hostname":"one", "build_id":"build-one"})
        self.identity.start()
    def tearDown(self):
        self.identity.stop()
        self.temp.cleanup()
    def test_identity_rotation_does_not_replay_old_pending_message(self):
        self.server.fail = True
        with self.assertRaises(requests.ConnectionError):
            self.agent.sync()
        old_epoch = self.store.load()["pending"]["epoch"]
        with patch("guardian.agent.identity", return_value={"device_id":"new-device", "hostname":"one", "build_id":"build-one"}):
            self.server.fail = False
            self.agent.sync()
        self.assertEqual(self.server.envelopes[-1]["device_id"], "new-device")
        self.assertEqual(self.server.envelopes[-1]["kind"], "checkpoint")
        self.assertNotEqual(self.server.envelopes[-1]["epoch"], old_epoch)

    def test_legacy_acknowledged_inventory_migrates_without_false_delta(self):
        self.agent.sync()
        with self.store.transaction() as state:
            state["acknowledged_inventory"] = state["inventory"]
            state.pop("acknowledged_fingerprints")
        self.agent.sync()
        state = self.store.load()
        self.assertNotIn("acknowledged_inventory", state)
        self.assertEqual(self.server.envelopes[-1]["kind"], "heartbeat")
        self.assertEqual(self.server.envelopes[-1]["components"], [])
        self.assertTrue(all(isinstance(value, str) and len(value) == 64 for value in state["acknowledged_fingerprints"].values()))

    def test_first_ack_calibrates_next_heartbeat_without_rewriting_sent_evidence(self):
        from guardian.storage import now
        original = self.server.post
        def timed(*args, **kwargs):
            response = original(*args, **kwargs)
            response.data["service_time"] = now()
            return response
        self.server.post = timed
        self.agent.sync()
        self.assertEqual(self.server.envelopes[0]["facts"][0]["time_basis"], "device_unaligned")
        retained = self.store.load()["facts"][0]
        self.assertEqual(retained["time_basis"], "server_aligned")
        self.agent.sync()
        self.assertEqual(self.server.envelopes[1]["facts"][0], retained)
        self.assertEqual(self.store.load()["facts"][0], retained)

    def test_checkpoint_and_heartbeat_sequence(self):
        self.agent.sync()
        self.agent.sync()
        self.assertEqual([x["kind"] for x in self.server.envelopes], ["checkpoint","heartbeat"])
        self.assertEqual([x["sequence"] for x in self.server.envelopes], [1,1])
        self.assertEqual(self.server.url, "https://server/api/v1/agents/sync")
    def test_changed_version_and_removal(self):
        self.agent.sync()
        self.collector.items = [dict(self.collector.items[0], version="2.0-1")]
        self.agent.sync(force=True)
        self.assertEqual(self.server.envelopes[-1]["components"][0]["version"],"2.0-1")
        self.collector.items = []
        self.agent.sync(force=True)
        self.assertEqual(len(self.server.envelopes[-1]["removed"]),1)
        self.assertEqual(self.store.load()["sequence"],3)
    def test_unknown_scope_does_not_claim_removal(self):
        self.agent.sync()
        self.collector.items = []
        self.collector.scopes = [{"scope":"host", "status":"unknown", "error":"timeout"}]
        self.agent.sync(force=True)
        self.assertEqual(self.server.envelopes[-1]["removed"],[])
        self.assertEqual(len(self.store.load()["inventory"]),1)
    def test_retry_replays_exact_pending_envelope(self):
        self.server.fail=True
        with self.assertRaises(requests.ConnectionError):
            self.agent.sync()
        pending=self.store.load()["pending"]
        self.collector.items=[]
        self.server.fail=False
        self.agent.sync(force=True)
        self.assertEqual(self.server.envelopes[-1],pending)
        self.assertEqual(self.store.load()["sync_status"],"connected")
    def test_resync_new_epoch_and_checkpoint(self):
        self.agent.sync()
        old=self.store.load()["epoch"]
        self.server.resync=True
        self.agent.sync()
        self.server.resync=False
        self.agent.sync()
        self.assertNotEqual(self.store.load()["epoch"],old)
        self.assertEqual(self.server.envelopes[-1]["kind"],"checkpoint")
    def test_pending_assessment_preserves_findings(self):
        self.server.findings=[{"id":"finding-one"}]
        self.agent.sync()
        previous = self.store.load()["findings"]
        self.server.status="pending"
        self.server.findings=[]
        self.agent.sync()
        self.assertEqual(self.store.load()["findings"],previous)
    def test_partial_assessment_shows_new_findings_and_retains_unknown_scope(self):
        state = {"findings":[{"id":"old-container", "inventory_digest":"old", "scope":"container:bgp"}],
                 "assessed_inventory_digest":"old"}
        incoming = {"id":"new-host", "inventory_digest":"new", "scope":"host", "applicability":"affected"}
        Agent._cache_findings(state, {"assessment_status":"partial", "findings":[incoming]}, "new")
        cached = {item["id"]:item for item in state["findings"]}
        self.assertEqual(set(cached), {"old-container", "new-host"})
        self.assertEqual(cached["new-host"]["cache_state"], "current")
        self.assertEqual(cached["old-container"]["cache_state"], "last_known")
        self.assertEqual(state["assessed_inventory_digest"], "old")
        self.assertEqual(state["retained_last_known_count"], 1)
        Agent._cache_findings(state, {"assessment_status":"partial", "findings":[]}, "new")
        self.assertEqual(len(state["findings"]), 2)
        self.assertEqual(state["retained_last_known_count"], 2)
        Agent._cache_findings(state, {"assessment_status":"completed", "findings":[]}, "new")
        self.assertEqual(state["findings"], [])
        self.assertEqual(state["assessed_inventory_digest"], "new")

    def test_partial_cache_is_bounded_and_truncation_explicit(self):
        state = {"findings":[{"id":"old-"+str(i)} for i in range(1000)]}
        incoming = [{"id":"new-"+str(i), "inventory_digest":"new"} for i in range(200)]
        Agent._cache_findings(state, {"assessment_status":"partial", "findings":incoming}, "new")
        self.assertEqual(len(state["findings"]), 1000)
        self.assertEqual(state["findings"][0]["id"], "new-0")
        self.assertTrue(state["findings_truncated"])
        self.assertEqual(state["cache_omitted_count"], 200)
        self.assertEqual(state["retained_last_known_count"], 800)
        Agent._cache_findings(state, {"assessment_status":"pending", "findings":[]}, "newer")
        self.assertEqual(state["retained_last_known_count"], 1000)
        self.assertTrue(state["findings_truncated"])

    def test_no_findings_is_not_unassessed(self):
        self.agent.sync()
        self.assertEqual(self.store.load()["assessment_status"],"complete")
        self.assertEqual(self.store.load()["findings"],[])
    def test_http_requires_explicit_lab_exception(self):
        self.config.set_service_url("http://server")
        with self.assertRaises(ValueError):
            self.agent.sync()
        self.config.set("","","allow_http","true")
        self.agent.sync()
    def test_secret_permissions_and_persistence(self):
        path=self.config.directory/"credentials.json"
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.config.set_service_enabled(True)
        self.assertTrue(ConfigManager(directory=self.config.directory).get_service_enabled())
        self.assertNotIn("token",(self.config.directory/"config.json").read_text())
    def test_digest_mismatch_not_acknowledged(self):
        self.server.post=lambda *a,**k: Response({"ack_sequence":1,"inventory_digest":"wrong"})
        with self.assertRaises(ValueError):
            self.agent.sync()
        self.assertIn("pending",self.store.load())
    def test_memory_pressure_defers_inventory(self):
        self.config.set("","","min_available_mb","999999999")
        with self.assertRaisesRegex(RuntimeError,"memory"):
            self.agent.sync()
        self.assertEqual(len(self.server.envelopes),0)
    def test_concurrent_transactions_do_not_lose_updates(self):
        processes=[multiprocessing.Process(target=increment,args=(str(self.store.directory),)) for _ in range(3)]
        for process in processes: process.start()
        for process in processes: process.join(5)
        self.assertTrue(all(process.exitcode==0 for process in processes))
        self.assertEqual(self.store.load()["counter"],30)
    def test_scope_identity_separates_same_package(self):
        text="curl\t1.0-1\tamd64\tcurl\t1.0-1\tinstalled\n"
        host=package_rows(text,"host",{})[0]
        container=package_rows(text,"container:bgp",{})[0]
        self.assertNotEqual(host["component_id"],container["component_id"])
    def test_bounded_output_and_timeout(self):
        with self.assertRaises(ValueError):
            run(["python3","-c","print('a'*10000)"],limit=100)
        with self.assertRaises(TimeoutError):
            run(["python3","-c","import time; time.sleep(3)"],timeout=.05)
    def test_arbitrary_collector_denied(self):
        result=collect_evidence({"request_id":"bad","collector":"shell","args":{"command":"rm -rf /"}})
        self.assertEqual(result["status"],"unknown")
    def test_package_policy_collector_is_scoped_and_rejects_shell_names(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return "curl:\n  Installed: 1.0\n  Candidate: 1.1\n  Version table:\n     1.1 500\n *** 1.0 100\n"
        result = collect_evidence({"collector":"package_versions", "scope":"container:bgp", "args":{"packages":["curl"]}}, runner)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["value"]["curl"]["available_versions"], ["1.1", "1.0"])
        self.assertEqual(calls[0], ["docker", "exec", "bgp", "apt-cache", "policy", "curl"])
        denied = collect_evidence({"collector":"package_versions", "args":{"packages":["curl;id"]}}, runner)
        self.assertEqual(denied["status"], "unknown")
        self.assertEqual(len(calls), 1)

    def test_service_and_routing_aliases_are_read_only(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return "Id=ssh.service\nActiveState=active\n"
        result = collect_evidence({"collector":"services", "scope":"host"}, runner)
        self.assertEqual(result["value"], [{"Id":"ssh.service", "ActiveState":"active"}])
        collect_evidence({"collector":"routing", "scope":"container:bgp"}, runner)
        self.assertEqual(calls[-1], ["docker", "exec", "bgp", "vtysh", "-c", "show bgp summary json"])

    def test_inventory_evidence_does_not_reenter_private_state_lock(self):
        with patch("guardian.storage.StateStore.load", side_effect=AssertionError("nested lock")):
            fact = collect_evidence({"collector":"inventory", "scope":"device"}, inventory_context={"inventory_digest":"one", "scopes":[{"scope":"host","status":"complete","packages":42}]})
        self.assertEqual(fact["status"], "observed")
        self.assertEqual(fact["value"]["scopes"][0]["packages"], 42)

    def test_missing_health_evidence_fails(self):
        validation=ValidationEngine(lambda *a,**kw: (_ for _ in ()).throw(RuntimeError("missing")))
        baseline=validation.snapshot()
        self.assertEqual(validation.compare(baseline,baseline)["status"],"FAIL")
    def test_bgp_and_interfaces_baseline(self):
        before={"containers":["bgp"],"interfaces":[{"ifname":"Ethernet0","operstate":"UP"}],"bgp":{"bgp":{"ipv4Unicast":{"peers":{"10.0.0.2":{"state":"Established"}}}}},"errors":[]}
        after={"containers":["bgp"],"interfaces":[],"bgp":{},"errors":[]}
        self.assertEqual(ValidationEngine.compare(before,after)["status"],"FAIL")
    def test_no_unscoped_or_unfixed_remediation(self):
        with self.store.transaction() as state:
            state["findings"]=[{"id":"one","applicability":"affected","package_name":"curl","affected_version":"1","scope":"host","fixed_versions":["2"]}]
        engine=RemediationEngine(self.store,self.config)
        with self.assertRaises(ValueError):engine.create_plan("one","3")
        plan=engine.create_plan("one","2")
        with self.assertRaisesRegex(ValueError,"Advisory"):
            engine.stage(plan["id"])
    def test_vulnerable_results_need_explicit_approval(self):
        with self.store.transaction() as state:
            state["findings"]=[{"id":"one","applicability":"affected","package_name":"curl","affected_version":"1","scope":"host","fixed_versions":["2"]}]
        engine=RemediationEngine(self.store,self.config)
        plan=engine.create_plan("one","2")
        self.config.set_operating_mode("autonomous")
        with self.assertRaisesRegex(ValueError,"approval"):
            engine.apply(plan["id"])


if __name__=="__main__":
    unittest.main()
