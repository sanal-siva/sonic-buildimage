"""Critical service/resource evidence must fail closed without rejecting unused down ports."""
from pathlib import Path
import tempfile
import unittest
from guardian.config import ConfigManager
from guardian.validation import ValidationEngine


class HealthPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.config = ConfigManager(directory=Path(self.directory.name))
        self.resources = {"cpu_percent":10.0,"memory_percent":30.0,"disk_percent":20.0}
        self.service_output = "LoadState=loaded\nActiveState=active\n"
    def tearDown(self):
        self.directory.cleanup()
    def runner(self, argv, **kwargs):
        if argv[0] == "systemctl":return self.service_output
        if argv[:3] == ["ip","-j","link"]:return '[{"ifname":"Ethernet0","operstate":"UP"},{"ifname":"Ethernet4","operstate":"DOWN"}]'
        if argv[:2] == ["docker","ps"]:return "bgp\nswss\nsyncd\ndatabase\n"
        if "vtysh" in argv:return '{"ipv4Unicast":{"peers":{"192.0.2.1":{"state":"Established","pfxRcd":100}}}}'
        raise AssertionError(argv)
    def engine(self):
        return ValidationEngine(self.runner,self.config,lambda:self.resources)
    def test_healthy_services_and_resources_preserve_unused_down_ports(self):
        before=self.engine().snapshot()
        self.assertEqual(before["errors"],[])
        self.assertEqual(set(before["services"]),{"ssh","database","swss","syncd","bgp"})
        self.assertEqual(self.engine().compare(before,self.engine().snapshot())["status"],"PASS")
    def test_inactive_or_missing_critical_service_refuses_validation(self):
        self.service_output="LoadState=loaded\nActiveState=inactive\n"
        self.assertTrue(self.engine().snapshot()["errors"])
        self.service_output="LoadState=not-found\nActiveState=inactive\n"
        self.assertTrue(self.engine().snapshot()["errors"])
    def test_resource_threshold_and_unknown_measurement_fail_closed(self):
        self.resources["memory_percent"]=95
        snapshot=self.engine().snapshot()
        self.assertTrue(any("memory" in error for error in snapshot["errors"]))
        self.config.set("","","validation_memory_max_pct","98")
        self.assertEqual(self.engine().snapshot()["errors"],[])
        self.resources.pop("cpu_percent")
        self.assertTrue(any("cpu" in error for error in self.engine().snapshot()["errors"]))
    def test_critical_service_policy_is_configurable_but_not_shell_text(self):
        self.config.set("","","validation_services","ssh,bgp@0,bgp@1")
        self.assertEqual(set(self.engine().snapshot()["services"]),{"ssh","bgp@0","bgp@1"})
        self.config.set("","","validation_services","ssh;reboot")
        self.assertIn("Invalid or empty critical service policy",self.engine().snapshot()["errors"])

    def test_established_peer_with_withdrawn_prefixes_fails(self):
        import copy
        before=self.engine().snapshot()
        after=copy.deepcopy(before)
        after["bgp"]["bgp"]["ipv4Unicast"]["peers"]["192.0.2.1"]["pfxRcd"]=50
        result=self.engine().compare(before,after)
        self.assertEqual(result["status"],"FAIL")
        self.assertTrue(any("count decreased" in error for error in result["errors"]))
        before["routing_prefix_loss_pct"]=50
        self.assertEqual(self.engine().compare(before,after)["status"],"PASS")

    def test_required_missing_prefix_count_is_unknown_not_zero(self):
        import copy
        before=self.engine().snapshot()
        after=copy.deepcopy(before)
        after["bgp"]["bgp"]["ipv4Unicast"]["peers"]["192.0.2.1"].pop("pfxRcd")
        result=self.engine().compare(before,after)
        self.assertEqual(result["status"],"FAIL")
        self.assertTrue(any("unavailable" in error for error in result["errors"]))

    def test_available_route_total_cannot_collapse_with_peers_unchanged(self):
        import copy
        before=self.engine().snapshot()
        before["bgp"]["bgp"]["ipv4Unicast"]["ribCount"]=100
        after=copy.deepcopy(before)
        after["bgp"]["bgp"]["ipv4Unicast"]["ribCount"]=0
        self.assertEqual(self.engine().compare(before,after)["status"],"FAIL")


if __name__ == "__main__":unittest.main()
