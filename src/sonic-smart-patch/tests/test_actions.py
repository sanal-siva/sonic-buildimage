import copy
import tempfile
import unittest
from pathlib import Path
from smart_patch.actions import ActionExecutor
from smart_patch.config import ConfigManager
from smart_patch.storage import StateStore


class Engine:
    def __init__(self):
        self.calls = []
        self.plan = {"id":"local", "status":"planned", "scope":"host", "package":"curl", "from_version":"1", "target_version":"2", "inventory_digest":"inventory-one"}
    def create_plan(self, finding, target):
        self.calls.append("create")
        return self.plan
    def _load(self, plan_id):
        return self.plan
    def stage(self, plan_id):
        self.calls.append("stage")
        self.plan["status"]="staged"
        return self.plan
    def apply(self, plan_id, approved):
        if not approved: raise ValueError("approval missing")
        self.calls.append("apply")
        self.plan["status"]="pending_reassessment"
        return self.plan
    def rollback(self, plan_id):
        self.calls.append("rollback")
        self.plan["status"]="rolled_back"
        return self.plan


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=StateStore(Path(self.temp.name)/"state")
        self.config=ConfigManager(directory=Path(self.temp.name)/"config")
        self.config.set_operating_mode("assisted")
        self.config.set("", "", "maintenance_checks_enabled", "true")
        with self.store.transaction() as state:
            state.update(device_id="device-one",inventory_digest="inventory-one",scopes=[{"scope":"host","status":"complete"}])
        self.engine=Engine()
        self.executor=ActionExecutor(self.store,self.config,self.engine)
        self.request={"request_id":"action-one","action":"execute_plan","plan":{"id":"remote-one","finding_id":"finding-one","device_id":"device-one","scope":"host","package_name":"curl","from_version":"1","target_version":"2","inventory_digest":"inventory-one","approved":True,"approved_at":"2025-01-01T00:00:00+00:00","expires_at":"2099-01-01T00:00:00+00:00"}}
    def tearDown(self):
        self.temp.cleanup()
    def test_execute_is_idempotent(self):
        first=self.executor.execute(self.request)
        second=self.executor.execute(self.request)
        self.assertEqual(first,second)
        self.assertEqual(self.engine.calls,["create","stage","apply"])
        self.assertEqual(first["status"],"complete")
    def test_advisory_denied(self):
        self.config.set_operating_mode("advisory")
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertEqual(self.engine.calls,[])
    def test_missing_approval_denied(self):
        self.request["plan"]["approved"]=False
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertEqual(self.engine.calls,[])
    def test_other_device_denied(self):
        self.request["plan"]["device_id"]="someone-else"
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertEqual(self.engine.calls,[])
    def test_different_inventory_denied(self):
        self.request["plan"]["inventory_digest"]="different"
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertEqual(self.engine.calls,[])
    def test_expiry_denied(self):
        self.request["plan"]["expires_at"]="2000-01-01T00:00:00+00:00"
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertEqual(self.engine.calls,[])
    def test_changed_scope_denied(self):
        self.request["plan"]["scope"]="container:bgp"
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertNotIn("apply",self.engine.calls)
    def test_interrupted_action_not_reexecuted(self):
        with self.store.transaction() as state:
            state["action_journal"]={"action-one":{"status":"executing","local_plan_id":"local"}}
        result=self.executor.execute(self.request)
        self.assertEqual(result["status"],"denied")
        self.assertIn("Interrupted",result["value"]["details"])
        self.assertEqual(self.engine.calls,[])
    def test_failed_operation_reported(self):
        def fail(*args,**kwargs): raise RuntimeError("failed download")
        self.engine.stage=fail
        self.assertEqual(self.executor.execute(self.request)["status"],"failed")
        self.assertNotIn("apply",self.engine.calls)

    def test_untrusted_full_finding_rejected(self):
        self.request["plan"]["finding"]={"id":"finding-one","component_id":"missing","inventory_digest":"inventory-one","scope":"host","package_name":"curl","affected_version":"1","applicability":"affected","fixed_versions":["2"]}
        self.assertEqual(self.executor.execute(self.request)["status"],"denied")
        self.assertEqual(self.engine.calls,[])

    def test_current_full_finding_imported_for_truncated_cache(self):
        component={"component_id":"component-one","scope":"host","name":"curl","version":"1"}
        with self.store.transaction() as state:
            state["inventory"]={"component-one":component}
        finding={"id":"finding-one","component_id":"component-one","inventory_digest":"inventory-one","scope":"host","package_name":"curl","affected_version":"1","applicability":"affected","fixed_versions":["2"]}
        self.request["plan"]["finding"]=finding
        self.assertEqual(self.executor.execute(self.request)["status"],"complete")
        self.assertEqual(self.store.load()["plan_findings"]["finding-one"],finding)

    def test_autonomous_requires_explicit_allowlist_and_current_verdict(self):
        from smart_patch.actions import AutonomousCoordinator
        self.config.set_operating_mode("autonomous")
        with self.store.transaction() as state:
            state.update(sync_status="connected",assessment_status="complete",assessed_inventory_digest="inventory-one",findings=[{"id":"finding-one","scope":"host","package_name":"curl","applicability":"affected","fixed_versions":["2"]}])
        coordinator=AutonomousCoordinator(self.store,self.config,self.engine)
        self.assertIsNone(coordinator.run_once())
        self.config.set("","","autonomous_allowlist","host/curl")
        def apply(plan_id, approved):
            self.assertFalse(approved)
            self.engine.calls.append("policy_apply")
            return {"status":"pending_reassessment"}
        self.engine.apply=apply
        self.assertEqual(coordinator.run_once()["status"],"pending_reassessment")
        self.assertIsNone(coordinator.run_once())
        self.assertEqual(self.engine.calls,["create","stage","policy_apply"])

    def test_autonomous_does_not_use_stale_or_incomplete_assessment(self):
        from smart_patch.actions import AutonomousCoordinator
        self.config.set_operating_mode("autonomous")
        self.config.set("","","autonomous_allowlist","host/curl")
        with self.store.transaction() as state:
            state.update(sync_status="connected",assessment_status="complete",assessed_inventory_digest="old-inventory",findings=[{"id":"finding-one","scope":"host","package_name":"curl","applicability":"affected","fixed_versions":["2"]}])
        self.assertIsNone(AutonomousCoordinator(self.store,self.config,self.engine).run_once())
        self.assertEqual(self.engine.calls,[])


if __name__=="__main__": unittest.main()
