"""Clock skew must not invent freshness or mutate acknowledged retry payloads."""
from datetime import datetime, timezone
import unittest
from unittest.mock import patch
from smart_patch.timebase import align_fact, align_state, calibrate, timestamp


class TimebaseTests(unittest.TestCase):
    def setUp(self):
        self.server = datetime(2026, 9, 29, 12, tzinfo=timezone.utc).timestamp()
        self.device = self.server+180

    def test_three_minute_ahead_device_aligns_fact_with_rtt_uncertainty(self):
        calibration = calibrate(timestamp(self.server+1), self.device, self.device+2, 2)
        self.assertEqual(calibration["offset_seconds"], -180)
        self.assertEqual(calibration["uncertainty_seconds"], 1)
        with patch("smart_patch.timebase.time.time", return_value=self.device+2):
            fact = align_fact({"collected_at":timestamp(self.device), "status":"observed"}, calibration)
        self.assertEqual(fact["collected_at"], timestamp(self.server))
        self.assertEqual(fact["device_collected_at"], timestamp(self.device))
        self.assertEqual(fact["time_basis"], "server_aligned")

    def test_old_aligned_facts_do_not_become_new_on_next_calibration(self):
        first = calibrate(timestamp(self.server), self.device, self.device, 0)
        second = calibrate(timestamp(self.server+60), self.device+90, self.device+90, 0)
        with patch("smart_patch.timebase.time.time", return_value=self.device):
            original = align_fact({"collected_at":timestamp(self.device-500)}, first)
        with patch("smart_patch.timebase.time.time", return_value=self.device+90):
            self.assertEqual(align_fact(original, second), original)
        self.assertEqual(original["collected_at"], timestamp(self.server-500))

    def test_first_ack_aligns_unaligned_inventory_and_retains_original_time(self):
        state = {"collected_at":timestamp(self.device), "facts":[{"collected_at":timestamp(self.device), "collector":"inventory"}]}
        align_state(state)
        self.assertEqual(state["facts"][0]["time_basis"], "device_unaligned")
        state["clock_alignment"] = calibrate(timestamp(self.server), self.device, self.device, 0)
        with patch("smart_patch.timebase.time.time", return_value=self.device):
            align_state(state)
        self.assertEqual(state["collected_at"], timestamp(self.server))
        self.assertEqual(state["device_collected_at"], timestamp(self.device))
        self.assertEqual(state["facts"][0]["time_basis"], "server_aligned")

    def test_missing_malformed_or_untrusted_service_time_stays_unknown(self):
        for value in (None, "", "not-a-date", "2026-09-29T12:00:00"):
            self.assertEqual(calibrate(value, self.device, self.device+2, 2)["status"], "unknown")
        self.assertEqual(calibrate(timestamp(self.server), self.device, self.device, 0, False)["status"], "unknown")
        fact = {"collected_at":timestamp(self.device)}
        self.assertEqual(align_fact(fact, {"status":"unknown"})["collected_at"], fact["collected_at"])

    def test_clock_jump_during_request_is_not_calibrated(self):
        self.assertEqual(calibrate(timestamp(self.server), self.device, self.device+182, 2)["status"], "unknown")

    def test_expired_calibration_does_not_guess_new_fact_time(self):
        calibration = calibrate(timestamp(self.server), self.device, self.device, 0)
        with patch("smart_patch.timebase.time.time", return_value=self.device+901):
            fact = align_fact({"collected_at":timestamp(self.device+901)}, calibration)
        self.assertEqual(fact["time_basis"], "device_unaligned")
        self.assertEqual(fact["collected_at"], timestamp(self.device+901))


if __name__ == "__main__":
    unittest.main()
