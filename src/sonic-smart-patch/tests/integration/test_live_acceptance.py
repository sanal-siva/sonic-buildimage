"""These tests execute actual switch commands only with explicit live configuration."""
import pytest

pytestmark = pytest.mark.smart_patch_live


def test_native_cli_configdb_yang(live_lab):
    live_lab.record("native_cli_configdb_yang", live_lab.native_cli_and_yang)


def test_actual_package_deltas_and_two_device_isolation(live_lab):
    live_lab.record("actual_package_deltas_and_two_device_isolation", live_lab.package_delta_and_isolation)


def test_runtime_evidence_round_trip(live_lab):
    live_lab.record("runtime_evidence_round_trip", live_lab.evidence_round_trip)


def test_offline_replay_daemon_restart_and_freshness(live_lab):
    live_lab.record("offline_replay_daemon_restart_and_freshness", live_lab.offline_replay_and_restart)


def test_measured_resources_and_low_memory_guard(live_lab):
    live_lab.record("measured_resources_and_low_memory_guard", live_lab.resource_guards)


def test_signed_fixture_stage_apply_rollback(live_lab):
    live_lab.record("signed_fixture_stage_apply_rollback", live_lab.real_fixture_stage_apply_rollback)


def test_host_services_resources_and_scheduled_collection(live_lab):
    live_lab.record("host_services_resources_and_scheduled_collection", live_lab.health_and_scheduling)


def test_actual_autonomous_modes_and_protected_plan(live_lab):
    live_lab.record("actual_autonomous_modes_and_protected_plan", live_lab.autonomous_modes_and_protected_plan)


def test_injected_health_failure_actual_rollback(live_lab):
    live_lab.record("injected_health_failure_actual_rollback", live_lab.injected_health_failure_restores_real_package)


def test_scoped_native_and_service_vex(live_lab):
    live_lab.record("scoped_native_and_service_vex", live_lab.scoped_vex_from_service_fixture)
