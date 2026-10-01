"""Baseline-relative SONiC health checks. Missing evidence never passes."""
import json
import re
import shutil
import time
from pathlib import Path
from guardian.config import ConfigManager
from guardian.collector import run
from guardian.storage import now


def routing_counts(value, require_prefix_counts=False, path=""):
    counts, errors = {}, []
    def number(item):
        if isinstance(item, bool):
            return None
        if isinstance(item, int) and item >= 0:
            return item
        if isinstance(item, str) and item.isdigit():
            return int(item)
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            location = path+"/"+key
            if key == "peers" and isinstance(item, dict):
                for address, peer in item.items():
                    if not isinstance(peer, dict) or peer.get("state") != "Established":
                        continue
                    count = number(peer.get("pfxRcd"))
                    if count is None:
                        if require_prefix_counts:
                            errors.append("Prefix count unavailable for established peer: "+location+"/"+address)
                    else:
                        counts[location+"/"+address+"/pfxRcd"] = count
            elif key in ("ribCount", "routeCount", "prefixCount", "totalPrefixes"):
                count = number(item)
                if count is not None:
                    counts[location] = count
                elif require_prefix_counts:
                    errors.append("Declared route total is invalid: "+location)
            else:
                nested, failures = routing_counts(item, require_prefix_counts, location)
                counts.update(nested)
                errors.extend(failures)
    return counts, errors


class ValidationEngine:
    def __init__(self, runner=run, config=None, resource_reader=None):
        self.runner = runner
        self.config = config or ConfigManager()
        self.resource_reader = resource_reader or self._resources

    def _resources(self):
        def cpu():
            line = Path("/proc/stat").read_text().splitlines()[0].split()
            values = [int(value) for value in line[1:9]]
            return sum(values), values[3]+values[4]
        total_before, idle_before = cpu()
        time.sleep(0.1)
        total_after, idle_after = cpu()
        if total_after <= total_before:
            raise ValueError("CPU utilization sample is unavailable")
        memory = {line.split(":",1)[0]:int(line.split(":",1)[1].split()[0])*1024
                  for line in Path("/proc/meminfo").read_text().splitlines() if ":" in line}
        if not memory.get("MemTotal") or "MemAvailable" not in memory:
            raise ValueError("Memory availability is unknown")
        path = self.config.values().get("validation_disk_path", "/var/lib/sonic-guardian")
        disk = shutil.disk_usage(path)
        return {"cpu_percent":round(100*(1-(idle_after-idle_before)/(total_after-total_before)),2),
                "memory_percent":round(100*(1-memory["MemAvailable"]/memory["MemTotal"]),2),
                "disk_percent":round(100*disk.used/disk.total,2), "disk_free_bytes":disk.free,
                "disk_path":path, "cpu_sample_seconds":0.1}

    def _services_and_resources(self, result):
        config = self.config.values()
        names = [name.strip() for name in config.get("validation_services", "ssh,database,swss,syncd,bgp").split(",") if name.strip()]
        result["services"] = {}
        if not names or len(names)>16 or any(not re.fullmatch(r"[A-Za-z0-9_.@:-]+", name) for name in names):
            result["errors"].append("Invalid or empty critical service policy")
        else:
            for name in names:
                try:
                    text = self.runner(["systemctl", "show", name, "--property=LoadState", "--property=ActiveState"], timeout=3, limit=4096)
                    values = dict(line.split("=",1) for line in text.splitlines() if "=" in line)
                    result["services"][name] = {"load_state":values.get("LoadState", "unknown"), "active_state":values.get("ActiveState", "unknown")}
                    if values.get("LoadState") != "loaded" or values.get("ActiveState") != "active":
                        result["errors"].append("Critical service is unavailable or inactive: "+name)
                except Exception as error:
                    result["services"][name] = {"load_state":"unknown", "active_state":"unknown"}
                    result["errors"].append("Critical service could not be verified: "+name+": "+str(error))
        try:
            result["resources"] = self.resource_reader()
            result["resource_thresholds"] = {metric:int(config.get("validation_"+metric+"_max_pct", default))
                                              for metric,default in (("cpu",80),("memory",90),("disk",85))}
            for metric, maximum in result["resource_thresholds"].items():
                value = result["resources"].get(metric+"_percent")
                if not 1 <= maximum <= 100 or not isinstance(value,(int,float)) or not 0 <= value <= 100:
                    result["errors"].append("Resource measurement or threshold is invalid: "+metric)
                elif value > maximum:
                    result["errors"].append("Resource threshold exceeded: %s %.2f%% > %s%%" % (metric,value,maximum))
        except Exception as error:
            result["resources"] = {"status":"unknown"}
            result["errors"].append("Resources could not be verified: "+str(error))

    def snapshot(self):
        result = {"observed_at": now(), "errors": []}
        self._services_and_resources(result)
        for name, argv in {"interfaces": ["ip", "-j", "link", "show"],
                           "containers": ["docker", "ps", "--format", "{{.Names}}"]}.items():
            try:
                value = self.runner(argv, timeout=10, limit=262144)
                result[name] = json.loads(value) if name == "interfaces" else sorted(value.splitlines())
            except Exception as error:
                result["errors"].append(name + ": " + str(error))
        result["bgp"] = {}
        for name in result.get("containers", []):
            if name == "bgp" or name.startswith("bgp") and name[3:].isdigit():
                try:
                    result["bgp"][name] = json.loads(self.runner(["docker", "exec", name, "vtysh", "-c", "show bgp summary json"], timeout=15, limit=1048576))
                except Exception as error:
                    result["errors"].append("bgp:" + name + ": " + str(error))
        config = self.config.values()
        result["require_prefix_counts"] = config.get("validation_require_prefix_counts", "true") == "true"
        try:
            result["routing_prefix_loss_pct"] = int(config.get("validation_prefix_loss_pct", "0"))
            if not 0 <= result["routing_prefix_loss_pct"] <= 100:
                raise ValueError("Prefix loss tolerance must be between 0 and 100")
        except ValueError as error:
            result["errors"].append(str(error))
            result["routing_prefix_loss_pct"] = 0
        result["routing_counts"], count_errors = routing_counts(result["bgp"], result["require_prefix_counts"])
        result["errors"].extend(count_errors)
        return result

    @staticmethod
    def compare(before, after):
        errors = list(before.get("errors", [])) + list(after.get("errors", []))
        missing = set(before.get("containers", [])) - set(after.get("containers", []))
        if missing:
            errors.append("Previously running containers unavailable: " + ",".join(sorted(missing)))
        old = {link["ifname"] for link in before.get("interfaces", []) if link.get("operstate") == "UP"}
        new = {link["ifname"] for link in after.get("interfaces", []) if link.get("operstate") == "UP"}
        if old - new:
            errors.append("Previously operational interfaces down: " + ",".join(sorted(old-new)))
        def peers(value, prefix=""):
            found = {}
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "peers" and isinstance(item, dict):
                        for address, peer in item.items():
                            found[prefix + "/" + address] = peer.get("state")
                    else:
                        found.update(peers(item, prefix + "/" + key))
            return found
        previous_counts, previous_errors = routing_counts(before.get("bgp", {}), before.get("require_prefix_counts", False))
        current_counts, current_errors = routing_counts(after.get("bgp", {}), before.get("require_prefix_counts", False))
        errors.extend(previous_errors+current_errors)
        tolerance = before.get("routing_prefix_loss_pct", 0)
        for route, count in previous_counts.items():
            current = current_counts.get(route)
            if current is None:
                errors.append("Baseline route/prefix measurement disappeared: "+route)
            elif current < count*(1-tolerance/100):
                errors.append("Route/prefix count decreased beyond tolerance: %s %d -> %d" % (route,count,current))
        previous_peers = peers(before.get("bgp", {}))
        current_peers = peers(after.get("bgp", {}))
        for peer, state in previous_peers.items():
            if state == "Established" and current_peers.get(peer) != state:
                errors.append("Previously established BGP peer lost: " + peer)
        return {"status": "PASS" if not errors else "FAIL", "errors": errors, "checked_at": now()}

    def run_health_checks(self):
        snapshot = self.snapshot()
        return not snapshot["errors"], snapshot
