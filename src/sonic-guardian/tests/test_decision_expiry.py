"""A live connection cannot keep an expired exemption authoritative."""
from datetime import datetime, timezone
import unittest
from unittest.mock import patch
from guardian.decision import current_finding
from guardian.timebase import calibrate, timestamp
from guardian.vex import VEXManager


class DecisionExpiryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026,9,29,12,tzinfo=timezone.utc).timestamp()
        self.finding = {"id":"one", "cve_id":"SYNTHETIC-NOT-A-CVE", "component_id":"host-one", "scope":"host", "package_name":"fixture", "affected_version":"1", "applicability":"not_affected", "vex_justification":"vulnerable_code_not_present", "evidence":["fixture-evidence"], "decision_valid_until":timestamp(self.now+30)}
        self.clock = calibrate(timestamp(self.now),self.now+180,self.now+180,0)
    def test_exemption_downgrades_at_deadline_despite_fresh_connection(self):
        before=current_finding(self.finding,current_server_time=self.now)
        after=current_finding(self.finding,current_server_time=self.now+31)
        self.assertEqual(before["applicability"],"not_affected")
        self.assertEqual(after["applicability"],"under_investigation")
        self.assertEqual(after["verdict_validity"],"expired")
        self.assertEqual(after["previous_applicability"],"not_affected")
    def test_invalid_deadline_or_untrusted_clock_does_not_preserve_exemption(self):
        self.assertEqual(current_finding(self.finding)["verdict_validity"],"clock_unknown")
        self.assertEqual(current_finding({**self.finding,"decision_valid_until":"invalid"})["verdict_validity"],"invalid_deadline")
    def test_absent_optional_deadline_leaves_static_decision_unchanged(self):
        finding={key:value for key,value in self.finding.items() if key!="decision_valid_until"}
        self.assertEqual(current_finding(finding),finding)
        self.assertEqual(current_finding({**finding,"decision_valid_until":None})["applicability"],"not_affected")
    def test_local_vex_respects_service_time_and_direct_justification_mapping(self):
        with patch("guardian.timebase.time.time",return_value=self.now+180):
            document=VEXManager("/unused").create_vex_document("fixture",[self.finding],self.clock)
        self.assertEqual(document["vulnerabilities"][0]["analysis"]["state"],"not_affected")
        self.assertEqual(document["vulnerabilities"][0]["analysis"]["justification"],"code_not_present")
        with patch("guardian.timebase.time.time",return_value=self.now+211):
            document=VEXManager("/unused").create_vex_document("fixture",[self.finding],self.clock)
        self.assertEqual(document["vulnerabilities"][0]["analysis"]["state"],"in_triage")


if __name__ == "__main__":unittest.main()
