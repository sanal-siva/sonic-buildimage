"""Local harness contract tests; no SSH, HTTP, scanning or hardware execution.

Run with the intelligence service on PYTHONPATH. These tests validate that an
explicit synthetic fixture binds the real assessment identity without treating
operational action receipts as software applicability evidence.
"""
import copy
from types import SimpleNamespace

import pytest

store_module = pytest.importorskip("app.db.store", reason="Requires sibling intelligence-service Python environment")
from app.main import finding_is_current
from app.services.applicability_context import applicability_facts
from live_acceptance import LiveAcceptance


@pytest.fixture
def fixture_seed():
    device={"id":"local-contract-only", "components":[{"name":"guardian-testprobe","scope":"host", "version":"1.0",
             "component_id":"host:guardian-testprobe:amd64"}], "inventory_digest":"inventory", "epoch":"epoch", "build_id":"build",
            "assessment_revision":"actual-assessment", "assessment_ruleset_version":"actual-ruleset", "artifact_id":"verified-build",
            "artifact_verified":True, "binding_revision":"actual-binding", "facts":[
                {"collector":"listeners","status":"ok","collected_at":store_module.now(),"value":{"ports":[22]}},
                {"collector":"remediation","value":{"status":"staged"}},
                {"collector":"maintenance_action","value":{"status":"complete"}},
                {"collector":"inventory","value":{"components":1}},
                {"collector":"resources","value":{"rss_bytes":1}}]}
    writes=[]
    harness=object.__new__(LiveAcceptance)
    harness.service_store=SimpleNamespace(put=lambda *args:writes.append(args))
    harness.devices={"local-only":"local-contract-only"}
    harness.run_id="explicit-local-synthetic-fixture"
    harness.fixture_records=[]
    harness.api=lambda *args:copy.deepcopy(device)
    harness.wait_for_scan=lambda *args:None
    dut=SimpleNamespace(host="local-only",invoke=lambda *args:None)
    return harness,dut,device,writes


def test_fixture_uses_current_assessment_identity_and_shared_context(fixture_seed):
    harness,dut,device,writes=fixture_seed
    finding=harness.seed_fixture(dut)
    assert finding["assessment_revision"]==device["assessment_revision"]
    assert finding["ruleset_version"]==device["assessment_ruleset_version"]
    assert finding["context_hash"]==store_module.stable_hash(applicability_facts(device["facts"]))
    assert finding_is_current(finding,device)
    assert finding["fixture"] is True
    assert finding["cve_id"]=="SYNTHETIC-GUARDIAN-ACCEPTANCE-NOT-A-CVE"
    assert finding["decision_basis"]=="synthetic_acceptance_fixture"
    assert {record[0] for record in writes}=={"finding","evidence"}
    # Receipt changes preserve context; a real evidence change invalidates it.
    device["facts"][1]["value"]["status"]="complete"
    assert finding_is_current(finding,device)
    device["facts"][0]["value"]["ports"]=[443]
    assert not finding_is_current(finding,device)


@pytest.mark.parametrize("missing",["assessment_revision","assessment_ruleset_version"])
def test_fixture_never_invents_missing_real_assessment_binding(fixture_seed,missing):
    harness,dut,device,writes=fixture_seed
    del device[missing]
    with pytest.raises(AssertionError,match="real baseline assessment"):
        harness.seed_fixture(dut)
    assert writes==[]
