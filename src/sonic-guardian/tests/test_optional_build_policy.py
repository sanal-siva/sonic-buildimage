"""Inventory-only advisory decisions are visible but cannot initiate maintenance."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner
from guardian.actions import ActionExecutor, AutonomousCoordinator
from guardian.cli import security
from guardian.config import ConfigManager
from guardian.remediation import RemediationEngine
from guardian.storage import StateStore, public_snapshot


class OptionalBuildPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = StateStore(Path(self.temp.name) / "state")
        self.config = ConfigManager(directory=Path(self.temp.name) / "config")
        self.config.set_operating_mode("autonomous")
        self.config.set("", "", "maintenance_checks_enabled", "true")
        self.config.set("", "", "autonomous_allowlist", "host/curl")
        self.finding = {
            "id": "finding-one", "component_id": "component-one", "scope": "host",
            "package_name": "curl", "affected_version": "1", "fixed_versions": ["2"],
            "applicability": "affected", "inventory_digest": "inventory-one",
            "decision_basis": "inventory_advisory_match", "artifact_binding": "unverified",
            "build_evidence_policy": "optional", "remediation_eligible": False,
            "remediation_reason": "Scoped operator review required", "action_type": "defer",
        }
        with self.store.transaction() as state:
            state.update(
                device_id="device-one", inventory_digest="inventory-one",
                assessed_inventory_digest="inventory-one", assessment_status="completed",
                sync_status="connected", scopes=[{"scope": "host", "status": "complete"}],
                findings=[self.finding], inventory={"component-one": {
                    "component_id": "component-one", "scope": "host", "name": "curl", "version": "1",
                }},
            )
        self.runner = Mock(return_value="1")
        self.engine = RemediationEngine(self.store, self.config, self.runner)

    def reviewed(self):
        finding = dict(self.finding, decision_basis="operator_review", remediation_eligible=True)
        with self.store.transaction() as state:
            state["findings"] = [finding]
        return finding

    def test_unreviewed_match_cannot_create_plan_or_run_command(self):
        with self.assertRaisesRegex(ValueError, "scoped operator review"):
            self.engine.create_plan("finding-one", "2")
        self.runner.assert_not_called()
        self.assertEqual(list(self.engine.directory.glob("*/plan.json")), [])

    def test_missing_eligibility_field_does_not_override_inventory_only_basis(self):
        with self.store.transaction() as state:
            state["findings"][0].pop("remediation_eligible")
        with self.assertRaisesRegex(ValueError, "scoped operator review"):
            self.engine.create_plan("finding-one", "2")
        self.runner.assert_not_called()

    def test_explicit_ineligibility_blocks_even_with_review_basis(self):
        with self.store.transaction() as state:
            state["findings"][0]["decision_basis"] = "operator_review"
        with self.assertRaisesRegex(ValueError, "scoped operator review"):
            self.engine.create_plan("finding-one", "2")
        self.runner.assert_not_called()

    def test_scoped_review_allows_planning_and_persists_basis(self):
        self.reviewed()
        plan = self.engine.create_plan("finding-one", "2")
        self.assertEqual(plan["decision_basis"], "operator_review")
        self.assertIs(plan["remediation_eligible"], True)
        self.runner.assert_called_once_with(["dpkg", "--compare-versions", "2", "gt", "1"], timeout=5)
        self.runner.reset_mock()
        self.engine._verify_current(plan)
        self.runner.assert_called_once()

    def test_legacy_findings_preserve_previous_eligibility(self):
        with self.store.transaction() as state:
            for key in ("decision_basis", "remediation_eligible", "build_evidence_policy", "artifact_binding"):
                state["findings"][0].pop(key)
        plan = self.engine.create_plan("finding-one", "2")
        self.assertEqual(plan["status"], "planned")
        self.assertNotIn("decision_basis", plan)

    def test_reverted_assessment_blocks_existing_plan_before_commands(self):
        self.reviewed()
        plan = self.engine.create_plan("finding-one", "2")
        with self.store.transaction() as state:
            state["findings"] = [self.finding]
        self.runner.reset_mock()
        with self.assertRaisesRegex(ValueError, "scoped operator review"):
            self.engine._verify_current(plan)
        self.runner.assert_not_called()

    def test_truncated_cached_finding_still_blocks_existing_plan(self):
        self.reviewed()
        plan = self.engine.create_plan("finding-one", "2")
        with self.store.transaction() as state:
            state["findings"] = []
            state["plan_findings"] = {"finding-one": self.finding}
        self.runner.reset_mock()
        with self.assertRaisesRegex(ValueError, "scoped operator review"):
            self.engine._verify_current(plan)
        self.runner.assert_not_called()

    def test_plan_metadata_itself_cannot_bypass_review(self):
        self.reviewed()
        plan = self.engine.create_plan("finding-one", "2")
        plan["decision_basis"] = "inventory_advisory_match"
        self.runner.reset_mock()
        with self.assertRaisesRegex(ValueError, "scoped operator review"):
            self.engine._verify_current(plan)
        self.runner.assert_not_called()

    def test_autonomous_does_not_create_attempt_or_call_engine_for_match(self):
        engine = Mock()
        self.assertIsNone(AutonomousCoordinator(self.store, self.config, engine).run_once())
        self.assertEqual(engine.mock_calls, [])
        self.assertFalse(self.store.load().get("autonomous_attempts"))

    def test_autonomous_reviewed_finding_preserves_allowlist_behavior(self):
        self.reviewed()
        engine = Mock()
        engine.create_plan.return_value = {"id": "local-plan"}
        engine.apply.return_value = {"status": "pending_reassessment"}
        result = AutonomousCoordinator(self.store, self.config, engine).run_once()
        self.assertEqual(result["status"], "pending_reassessment")
        engine.create_plan.assert_called_once_with("finding-one", "2")
        engine.apply.assert_called_once_with("local-plan", approved=False)

    def test_remote_plan_approval_does_not_replace_scoped_finding_review(self):
        with self.store.transaction() as state:
            state["findings"] = []
        request = {"request_id": "request-one", "action": "execute_plan", "plan": {
            "id": "remote-one", "device_id": "device-one", "finding_id": "finding-one",
            "scope": "host", "package_name": "curl", "from_version": "1", "target_version": "2",
            "inventory_digest": "inventory-one", "approved": True,
            "approved_at": "2025-01-01T00:00:00+00:00", "expires_at": "2099-01-01T00:00:00+00:00",
            "finding": self.finding,
        }}
        engine = Mock()
        result = ActionExecutor(self.store, self.config, engine).execute(request)
        self.assertEqual(result["status"], "denied")
        self.assertIn("scoped operator review", result["value"]["details"])
        self.assertEqual(engine.mock_calls, [])
        self.assertFalse(self.store.load().get("plan_findings"))

    def test_public_cli_preserves_and_labels_optional_assessment(self):
        public = public_snapshot(self.store.load())
        finding = public["findings"][0]
        for key in ("decision_basis", "artifact_binding", "build_evidence_policy", "remediation_eligible", "remediation_reason"):
            self.assertEqual(finding[key], self.finding[key])
        with patch("guardian.cli.read_public_state", return_value=public):
            cli = CliRunner()
            readable = cli.invoke(security, ["show", "findings"])
            self.assertEqual(readable.exit_code, 0, readable.output)
            self.assertIn("build unverified", readable.output)
            self.assertIn("operator review required", readable.output)
            as_json = cli.invoke(security, ["show", "findings", "--json"])
            self.assertEqual(as_json.exit_code, 0, as_json.output)
            self.assertIs(json.loads(as_json.output)[0]["remediation_eligible"], False)


if __name__ == "__main__":
    unittest.main()
