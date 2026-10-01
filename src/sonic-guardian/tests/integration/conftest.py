"""Opt-in pytest runner for actual SSH/API acceptance; never runs implicitly."""
import json
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from live_acceptance import LiveAcceptance, parser


def pytest_addoption(parser):
    parser.addoption("--guardian-live-config", help="JSON containing explicit live harness argv (secret file paths only)")


def pytest_configure(config):
    config.addinivalue_line("markers", "guardian_live: authorized real two-DUT SSH/API integration")


@pytest.fixture(scope="module")
def live_lab(request):
    configuration = request.config.getoption("--guardian-live-config")
    if not configuration:
        pytest.skip("Real two-DUT acceptance requires explicit --guardian-live-config")
    args = parser().parse_args(json.loads(Path(configuration).read_text())["argv"])
    lab = LiveAcceptance(args)
    try:
        lab.record("prepare", lab.prepare)
        yield lab
    finally:
        cleanup = lab.cleanup()
        expected = {"prepare", "native_cli_configdb_yang", "actual_package_deltas_and_two_device_isolation",
                    "runtime_evidence_round_trip", "offline_replay_daemon_restart_and_freshness",
                    "measured_resources_and_low_memory_guard", "signed_fixture_stage_apply_rollback", "host_services_resources_and_scheduled_collection",
                    "actual_autonomous_modes_and_protected_plan", "injected_health_failure_actual_rollback", "scoped_native_and_service_vex"}
        covered = {item["case"] for item in lab.results}
        okay = all(item["status"] == "passed" for item in lab.results) and all(item.get("restored") for item in cleanup.values())
        report = {"run_id":lab.run_id, "executed_on_real_duts":True, "hosts":args.hosts,
                  "status":"passed" if okay and expected == covered else "partial" if okay else "failed",
                  "results":lab.results, "cleanup":cleanup, "unexecuted_cases":sorted(expected-covered),
                  "represents_real_cve_confirmation":False, "contains_synthetic_remediation_fixture":True}
        Path(args.output).write_text(json.dumps(report, indent=2)+"\n")
        if not all(item.get("restored") for item in cleanup.values()):
            pytest.fail("Live acceptance cleanup failed; inspect report recovery directories")
