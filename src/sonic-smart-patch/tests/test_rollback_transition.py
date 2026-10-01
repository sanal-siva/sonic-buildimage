"""Exercise real plan state transitions with an explicitly simulated installer."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from smart_patch.collector import digest
from smart_patch.config import ConfigManager
from smart_patch.remediation import RemediationEngine
from smart_patch.storage import StateStore
from smart_patch.validation import ValidationEngine


class RollbackTransitionTests(unittest.TestCase):
    def test_failed_prefix_health_triggers_rollback_and_persists_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            store=StateStore(Path(directory)/"state")
            config=ConfigManager(directory=Path(directory)/"config")
            config.set_operating_mode("assisted")
            config.set("", "", "maintenance_checks_enabled", "true")
            with store.transaction() as state:
                state["inventory_digest"]="fixture-inventory"
            engine=RemediationEngine(store,config)
            transaction=[{"package":"smart-patch-testprobe","from_version":"1.0","to_version":"1.1"}]
            plan={"id":"11111111-1111-1111-1111-111111111111","status":"staged","scope":"host","package":"smart-patch-testprobe","from_version":"1.0","target_version":"1.1","inventory_digest":"fixture-inventory","transaction":transaction,"transaction_digest":digest(transaction)}
            rollback = engine.directory / "retained.deb"
            rollback.write_bytes(b"synthetic rollback fixture")
            plan["artifacts"] = {"rollback": [{"package": "smart-patch-testprobe", "version": "1.0", "path": str(rollback)}]}
            engine._save(plan)
            baseline={"errors":[],"containers":["bgp"],"interfaces":[{"ifname":"Ethernet0","operstate":"UP"}],"bgp":{"bgp":{"ipv4Unicast":{"peers":{"192.0.2.1":{"state":"Established","pfxRcd":100}}}}},"require_prefix_counts":True,"routing_prefix_loss_pct":0}
            failed=copy.deepcopy(baseline)
            failed["bgp"]["bgp"]["ipv4Unicast"]["peers"]["192.0.2.1"]["pfxRcd"]=0
            installs=[]
            with patch.object(engine,"_verify_current"), patch.object(engine,"_transaction",return_value=transaction), patch.object(engine,"_install",side_effect=lambda plan,direction:installs.append(direction)), patch.object(engine.validation,"snapshot",side_effect=[baseline,failed,baseline]):
                result=engine.apply(plan["id"],approved=True)
            self.assertEqual(installs,["forward","rollback"])
            self.assertEqual(result["status"],"rolled_back")
            self.assertEqual(result["post_validation"]["status"],"FAIL")
            self.assertEqual(result["rollback_validation"]["status"],"PASS")
            self.assertEqual(engine._load(plan["id"])["status"],"rolled_back")
            self.assertTrue((store.directory/"dirty").exists())


if __name__=="__main__":unittest.main()
