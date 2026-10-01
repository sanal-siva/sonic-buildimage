"""Apply optional service-issued decision expiry at read and execution time."""
import math
import time
from guardian.timebase import parse_timestamp, usable


def decision_validity(record, calibration, current_server_time=None):
    if "decision_valid_until" not in record or record["decision_valid_until"] is None:
        return "not_time_limited"
    try:
        deadline = parse_timestamp(record["decision_valid_until"]).timestamp()
    except (ValueError, TypeError, OverflowError):
        return "invalid_deadline"
    if current_server_time is None:
        if not usable(calibration or {}):
            return "clock_unknown"
        uncertainty = (calibration or {}).get("uncertainty_seconds")
        if not isinstance(uncertainty, (int, float)) or not math.isfinite(uncertainty) or uncertainty < 0:
            return "clock_unknown"
        # An exemption must not outlive its deadline within measured uncertainty.
        current_server_time = time.time()+calibration["offset_seconds"]+uncertainty
    return "current" if current_server_time < deadline else "expired"


def current_finding(finding, calibration=None, current_server_time=None):
    result = dict(finding)
    validity = decision_validity(finding, calibration, current_server_time)
    if validity in ("not_time_limited", "current"):
        return result
    result.update(previous_applicability=finding.get("previous_applicability", finding.get("applicability")),
                  applicability="under_investigation", cache_state="last_known", verdict_validity=validity,
                  rationale="Decision validity is %s; refresh authoritative evidence before relying on the previous verdict." % validity)
    return result
