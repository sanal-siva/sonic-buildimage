"""Rollback requires a durable, scoped maintenance transaction."""
from smart_patch.remediation import RemediationEngine


class RollbackEngine:
    def trigger_rollback(self, plan_id, previous_version=None):
        if previous_version is not None:
            raise ValueError("Rollback requires an exact retained plan, not a version placeholder")
        return RemediationEngine().rollback(plan_id)
