"""Calibrate evidence timestamps against authenticated service time, never set OS time."""
from datetime import datetime, timezone
import math
import time


def parse_timestamp(value):
    if not isinstance(value, str) or not value or len(value) > 96:
        raise ValueError("Timestamp is missing or malformed")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed


def timestamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def calibrate(server_time, sent_wall, received_wall, elapsed, verified_transport=True):
    if not verified_transport:
        return {"status":"unknown", "reason":"verified_service_transport_required"}
    try:
        server = parse_timestamp(server_time).timestamp()
        if not all(math.isfinite(value) for value in (sent_wall, received_wall, elapsed)) or elapsed < 0:
            raise ValueError("Invalid request timing")
        if received_wall < sent_wall or abs((received_wall-sent_wall)-elapsed) > 5:
            raise ValueError("Device clock changed during synchronization")
        midpoint = (sent_wall+received_wall)/2
        return {"status":"aligned", "time_basis":"authenticated_service_time",
                "offset_seconds":round(server-midpoint, 6), "uncertainty_seconds":round(elapsed/2, 6),
                "round_trip_seconds":round(elapsed, 6), "server_time":server_time,
                "device_calibrated_at":timestamp(received_wall)}
    except (TypeError, ValueError, OverflowError, OSError) as error:
        return {"status":"unknown", "reason":str(error)}


def usable(calibration, current_wall=None):
    if calibration.get("status") != "aligned":
        return False
    try:
        age = (time.time() if current_wall is None else current_wall)-parse_timestamp(calibration["device_calibrated_at"]).timestamp()
        return 0 <= age <= 900 and math.isfinite(float(calibration["offset_seconds"]))
    except (TypeError, ValueError, KeyError):
        return False


def align_fact(fact, calibration):
    """Align an observation once. Recalibration must never refresh old evidence."""
    if fact.get("time_basis") == "server_aligned":
        return fact
    aligned = dict(fact)
    raw = aligned.setdefault("device_collected_at", aligned.get("collected_at"))
    if not usable(calibration):
        aligned["time_basis"] = "device_unaligned"
        return aligned
    try:
        aligned["collected_at"] = timestamp(parse_timestamp(raw).timestamp()+calibration["offset_seconds"])
    except (TypeError, ValueError, OverflowError, OSError):
        aligned["time_basis"] = "unknown"
        return aligned
    aligned.update(time_basis="server_aligned", clock_offset_seconds=calibration["offset_seconds"],
                   clock_uncertainty_seconds=calibration["uncertainty_seconds"])
    return aligned


def align_state(state):
    calibration = state.get("clock_alignment", {})
    for name in ("facts", "action_facts"):
        if name in state:
            state[name] = [align_fact(fact, calibration) for fact in state[name]]
    if state.get("collected_at") and state.get("collection_time_basis") != "server_aligned":
        observation = align_fact({"collected_at":state["collected_at"],
                                  "device_collected_at":state.get("device_collected_at", state["collected_at"])}, calibration)
        state["collected_at"] = observation["collected_at"]
        state["device_collected_at"] = observation["device_collected_at"]
        state["collection_time_basis"] = observation["time_basis"]
