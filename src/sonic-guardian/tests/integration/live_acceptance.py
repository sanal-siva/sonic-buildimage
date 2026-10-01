#!/usr/bin/env python3
"""Actual SSH/API two-DUT acceptance, executed only by an explicit operator run.

This is neither a simulation nor SpyTest. The sibling SpyTest adapter uses the
real framework. A file-only fixture may change; routing/core packages never do.
"""
import argparse
import base64
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile
import tempfile
import time
import uuid
import subprocess
import requests

ROOT = Path(__file__).resolve().parents[2]


class DUT:
    def __init__(self, host, username, password, known_hosts=None, accept_new=False):
        self.host = host
        self.target = username + "@" + host
        self.control = tempfile.TemporaryDirectory(prefix="guardian-acceptance-ssh-")
        self.options = ["-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                        "-o", "ControlMaster=auto", "-o", "ControlPersist=60", "-o", "ControlPath="+self.control.name+"/socket",
                        "-o", "StrictHostKeyChecking="+("accept-new" if accept_new else "yes")]
        if known_hosts:
            self.options += ["-o", "UserKnownHostsFile="+known_hosts]
        self.environment = os.environ.copy()
        self.prefix = []
        if password is not None:
            self.environment["SSHPASS"] = password
            self.prefix = ["sshpass", "-e"]
        try:
            self.command(["true"])
        except Exception:
            self.control.cleanup()
            raise

    def command(self, argv, check=True, timeout=900):
        result = subprocess.run(self.prefix + ["ssh"] + self.options + [self.target, shlex.join(argv)],
                                env=self.environment, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"{self.host}: {argv[0]} failed ({result.returncode}): {result.stderr[-1500:]} {result.stdout[-1500:]}")
        return result.returncode, result.stdout, result.stderr

    def upload(self, path, destination):
        result = subprocess.run(self.prefix + ["scp"] + self.options + [str(path), self.target+":"+destination],
                                env=self.environment, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError("Fixture upload failed: " + result.stderr[-1000:])

    def invoke(self, action, **arguments):
        request = {"run_id":self.run_id, "action":action, **arguments}
        encoded = base64.b64encode(json.dumps(request).encode()).decode()
        code, output, error = self.command(["sudo", "-n", "python3", self.remote_dir+"/remote_probe.py", encoded], check=False)
        lines = [line[len("GUARDIAN_RESULT="):] for line in output.splitlines() if line.startswith("GUARDIAN_RESULT=")]
        if not lines:
            raise RuntimeError(f"{self.host}: no acceptance result: {error[-1500:]} {output[-1500:]}")
        result = json.loads(lines[-1])
        if code or not result["ok"]:
            raise RuntimeError(f"{self.host}: {action}: {result.get('error', error[-1500:])}")
        return result["result"]

    def close(self):
        subprocess.run(self.prefix + ["ssh"] + self.options + ["-O", "exit", self.target],
                       env=self.environment, capture_output=True, timeout=10, check=False)
        self.control.cleanup()


class LiveAcceptance:
    def __init__(self, args, dut_factory=DUT):
        self.dut_factory = dut_factory
        if len(args.hosts) != 2 or len(set(args.hosts)) != 2:
            raise ValueError("Exactly two distinct authorized DUT addresses are required")
        if not args.allow_mutations:
            raise ValueError("Live tests require --allow-mutations: only Guardian and named file-only fixtures change")
        self.args = args
        self.run_id = "guardian-acceptance-" + uuid.uuid4().hex[:12]
        self.results, self.devices, self.duts = [], {}, []
        self.fixture_records = []
        self.session = requests.Session()
        self.session.headers["Authorization"] = "Bearer " + Path(args.token_file).read_text().strip()
        self.session.verify = args.ca_file or True
        self.base = args.server.rstrip("/")
        if not self.base.endswith("/api/v1"):
            self.base += "/api/v1"
        password = Path(args.password_file).read_text().rstrip("\n") if args.password_file else os.getenv("GUARDIAN_SSH_PASSWORD")
        self.password = password
        self.service_store = None
        if args.service_database:
            if not args.allow_synthetic_service_fixture or not args.service_root:
                raise ValueError("Database fixture injection requires --allow-synthetic-service-fixture and --service-root")
            sys.path.insert(0, str(Path(args.service_root).resolve()))
            from app.db.store import Store
            self.service_store = Store(args.service_database)

    def api(self, method, route, **kwargs):
        response = self.session.request(method, self.base+route, timeout=(5, 60), **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"Service {method} {route}: {response.status_code}: {response.text[:1000]}")
        return response.json()

    def record(self, case, function):
        started = time.monotonic()
        print(json.dumps({"event":"start", "case":case}), flush=True)
        try:
            details = function()
            result = {"case":case, "status":"passed", "seconds":round(time.monotonic()-started, 3), "details":details}
        except Exception as error:
            result = {"case":case, "status":"failed", "seconds":round(time.monotonic()-started, 3), "error":str(error)}
            self.results.append(result)
            print(json.dumps(result), flush=True)
            raise
        self.results.append(result)
        print(json.dumps(result), flush=True)
        return details

    def prepare(self):
        repository = Path(self.args.fixture_repo).resolve()
        if not (repository / "fixture-manifest.json").exists():
            raise ValueError("Build the signed fixture repository first")
        with tempfile.TemporaryDirectory(prefix="guardian-live-upload-") as directory:
            archive = Path(directory) / "repo.tar.gz"
            with tarfile.open(archive, "w:gz") as target:
                for path in sorted(repository.rglob("*")):
                    target.add(path, arcname=str(path.relative_to(repository)), recursive=False)
            for host in self.args.hosts:
                dut = self.dut_factory(host, self.args.user, self.password, self.args.known_hosts, self.args.accept_new_host_keys)
                self.duts.append(dut)
                dut.run_id = self.run_id
                dut.remote_dir = "/tmp/"+self.run_id
                dut.command(["mkdir", "-m", "700", dut.remote_dir])
                dut.upload(ROOT / "tests/integration/remote_probe.py", dut.remote_dir+"/remote_probe.py")
                dut.upload(archive, dut.remote_dir+"/repo.tar.gz")
                dut.upload(ROOT.parents[0] / "sonic-yang-models/yang-models/sonic-guardian.yang", dut.remote_dir+"/sonic-guardian.yang")
                result = dut.invoke("prepare", archive=dut.remote_dir+"/repo.tar.gz")
                self.devices[host] = result["state"]["device_id"]
                dut.resources_before = result["before"]
                dut.invoke("sync", force=True)
        if len(set(self.devices.values())) != 2:
            raise AssertionError("Two DUTs share enrollment identity")
        return {"device_ids":self.devices, "signed_repository":str(repository), "fixture_packages":["sonic-guardian-testprobe", "guardian-testprobe"]}

    def native_cli_and_yang(self):
        results = {}
        for dut in self.duts:
            code, output, _ = dut.command(["show", "security", "status", "--json"])
            status = json.loads(output)
            if status["sync_status"] != "connected":
                raise AssertionError("Native non-sudo status is not connected")
            dut.command(["config", "security", "--help"])
            results[dut.host] = {"non_sudo_show":True, "status":status,
                                 "yang":dut.invoke("yang", model=dut.remote_dir+"/sonic-guardian.yang")}
        return results

    def package_delta_and_isolation(self):
        results = {}
        for index, dut in enumerate(self.duts):
            peer = self.duts[1-index]
            peer_before = self.api("GET", "/devices/"+self.devices[peer.host])["inventory_digest"]
            before = dut.invoke("state")
            steps = []
            for operation, target in (("install", "1.0"), ("install", "1.1"), ("remove", None)):
                change = dut.invoke("package", package="sonic-guardian-testprobe", operation=operation, version=target)
                if not change["apt_hook_observed"]:
                    raise AssertionError("Actual APT/dpkg transaction did not trigger Guardian dirty hook")
                if change["installed_version"] != target:
                    raise AssertionError("Fixture package version mismatch")
                if change["state"]["sequence"] <= before["sequence"]:
                    raise AssertionError("Inventory delta did not advance sequence")
                device = self.api("GET", "/devices/"+self.devices[dut.host])
                components = [item for item in device["components"] if item["name"] == "sonic-guardian-testprobe"]
                if target and (len(components) != 1 or components[0]["version"] != target or components[0]["scope"] != "host"):
                    raise AssertionError("Central scoped inventory failed to track installation/update")
                if target is None and components:
                    raise AssertionError("Removed fixture still appears in central inventory")
                if self.api("GET", "/devices/"+self.devices[peer.host])["inventory_digest"] != peer_before:
                    raise AssertionError("One device's package drift changed its peer's inventory")
                steps.append({"operation":operation, "version":target, "sequence":change["state"]["sequence"], "hook":True})
                before = change["state"]
            results[dut.host] = steps
        return results

    def evidence_round_trip(self):
        results = {}
        for dut in self.duts:
            ident = self.devices[dut.host]
            request = self.api("POST", "/devices/"+ident+"/evidence", json={"collector":"listeners", "scope":"host"})
            dut.invoke("sync")
            dut.invoke("sync")
            device = self.api("GET", "/devices/"+ident)
            facts = [fact for fact in device.get("facts", []) if fact.get("fact_id") == request["request_id"]]
            if len(facts) != 1 or facts[0].get("status") != "observed" or facts[0].get("scope") != "host":
                raise AssertionError("Requested real listener fact was not observed centrally")
            results[dut.host] = {"request_id":request["request_id"], "collector":"listeners", "status":"observed", "observed_at":facts[0]["collected_at"]}
        return results

    def offline_replay_and_restart(self):
        results = {}
        for dut in self.duts:
            before = dut.invoke("state")
            offline = dut.invoke("offline")
            status = json.loads(dut.command(["show", "security", "status", "--json"])[1])
            if status["fresh"] or status["sync_status"] != "stale":
                raise AssertionError("Offline status appears fresh")
            recovery = dut.invoke("recover")
            old_sync = recovery["state"]["last_sync"]
            resource = dut.invoke("daemon", operation="start")
            if int(resource.get("MainPID", "0")) <= 0:
                raise AssertionError("Guardian service did not start")
            deadline = time.monotonic()+self.args.timeout
            while time.monotonic() < deadline:
                state = dut.invoke("state")
                if state["last_sync"] != old_sync and state["sync_status"] == "connected":
                    break
                time.sleep(2)
            else:
                raise AssertionError("Restarted daemon did not synchronize before timeout")
            resource = dut.invoke("resources")
            peak = int(resource.get("MemoryPeak", "0"))
            ceiling = int(resource["MemoryMax"])
            if peak <= 0 or peak > ceiling:
                raise AssertionError("Actual daemon peak memory is unavailable or exceeded its ceiling")
            before_oom = int(dut.resources_before.get("memory_events", {}).get("oom_kill", 0))
            after_oom = int(resource.get("memory_events", {}).get("oom_kill", 0))
            if after_oom > before_oom:
                raise AssertionError("Guardian cgroup recorded an OOM kill during acceptance")
            dut.invoke("daemon", operation="stop")
            if state["device_id"] != before["device_id"]:
                raise AssertionError("Enrollment identity changed across restart")
            results[dut.host] = {"offline_pending_hash":offline["pending_hash"], "replayed_hash":recovery["actual_sent_hash"],
                                 "device_id_stable":True, "daemon_resources":resource}
        return results

    def resource_guards(self):
        results = {}
        for dut in self.duts:
            low_memory = dut.invoke("low-memory")
            dut.invoke("sync", force=True)
            measured = dut.invoke("state")["resources"]
            configured = dut.invoke("resources")
            maximum = int(configured["MemoryMax"])
            if maximum > 128*1024*1024:
                raise AssertionError("Guardian cgroup exceeds the configured 128 MiB ceiling")
            if measured["rss_bytes"] >= maximum:
                raise AssertionError("Measured collector RSS is at or above its cgroup ceiling")
            results[dut.host] = {"low_memory_guard":low_memory, "measured":measured, "configured":configured}
        return results

    def seed_fixture(self, dut, package="guardian-testprobe", applicability="affected"):
        if self.service_store is None:
            raise RuntimeError("Full remediation acceptance requires explicit synthetic service fixture permission and database access")
        from app.db.store import stable_hash, now
        from app.services.applicability_context import applicability_facts
        # Clear transient action acknowledgements before binding a fixture to the
        # current context; do not fabricate a complete scanner result.
        dut.invoke("sync")
        self.wait_for_scan(dut)
        device = self.api("GET", "/devices/"+self.devices[dut.host])
        if not device.get("assessment_revision") or not device.get("assessment_ruleset_version"):
            raise AssertionError("A real baseline assessment revision and ruleset are required before synthetic fixture injection")
        components = [item for item in device["components"] if item["name"] == package and item["scope"] == "host"]
        if len(components) != 1 or components[0]["version"] != "1.0":
            raise AssertionError("Synthetic package baseline is not present")
        component = components[0]
        ident = self.run_id+":"+package+":"+device["id"]
        evidence_id = ident+":evidence"
        finding = {"id":ident, "device_id":device["id"], "component_id":component["component_id"], "scope":"host",
                   "cve_id":"SYNTHETIC-GUARDIAN-ACCEPTANCE-NOT-A-CVE", "package_name":package, "affected_version":"1.0",
                   "fixed_versions":["1.1"], "candidate_fixed_versions":["1.1"], "applicability":applicability, "severity":"UNKNOWN",
                   "vex_justification":"vulnerable_code_not_present" if applicability=="not_affected" else None,
                   "status":"current", "fixture":True, "fixture_run_id":self.run_id,
                   "inventory_digest":device["inventory_digest"], "inventory_epoch":device["epoch"], "build_id":device["build_id"],
                   "assessment_revision":device["assessment_revision"], "ruleset_version":device["assessment_ruleset_version"],
                   "artifact_id":device.get("artifact_id"), "artifact_verified":bool(device.get("artifact_verified")),
                   "binding_revision":device.get("binding_revision","unverified"),
                   "context_hash":stable_hash(applicability_facts(device.get("facts", []))),
                   "evidence_ids":[evidence_id], "evidence":[{"id":evidence_id, "type":"synthetic_fixture", "fixture":True}],
                   "rationale":"SYNTHETIC acceptance fixture for a harmless file-only package; this does not represent a real vulnerability.",
                   "assessed_at":now(), "decision_basis":"synthetic_acceptance_fixture"}
        self.service_store.put("finding", ident, finding, device["id"])
        self.fixture_records.append(("finding", ident))
        self.service_store.put("evidence", evidence_id, finding["evidence"][0], device["id"])
        self.fixture_records.append(("evidence", evidence_id))
        return finding

    def real_fixture_stage_apply_rollback(self):
        dut, peer = self.duts
        peer_before = self.api("GET", "/devices/"+self.devices[peer.host])["inventory_digest"]
        dut.invoke("package", package="guardian-testprobe", operation="install", version="1.0")
        dut.invoke("mode", mode="assisted")
        # Let queued real scanning finish before injecting the labelled test record.
        deadline = time.monotonic()+self.args.timeout
        while time.monotonic() < deadline:
            device = self.api("GET", "/devices/"+self.devices[dut.host])
            if device.get("scan_status") not in ("queued", "running", "pending"):
                break
            time.sleep(3)
        else:
            raise AssertionError("Real baseline scan did not finish before synthetic fixture injection")
        fixture = self.seed_fixture(dut)
        plan = self.api("POST", "/plans", json={"device_id":self.devices[dut.host], "finding_ids":[fixture["id"]], "target_version":"1.1"})
        self.fixture_records.append(("plan", plan["id"]))
        self.api("POST", "/plans/"+plan["id"]+"/approve")
        remediation_started = time.monotonic()
        staging = self.api("POST", "/plans/"+plan["id"]+"/stage", json={"confirmed_device_id":self.devices[dut.host]})
        stage_request_id = staging.get("stage_request_id") or staging.get("action_request_id")
        if stage_request_id:
            self.fixture_records.append(("action_request", stage_request_id))
        dut.invoke("sync")
        dut.invoke("sync")
        staged = dut.invoke("plan", plan_id=plan["id"])
        service_plan = self.api("GET", "/plans/"+plan["id"])
        if staged.get("status") != "staged" or staged.get("package_version") != "1.0":
            raise AssertionError("Real staging changed installed version or failed: "+json.dumps(staged))
        if service_plan.get("status") != "staged" or not service_plan.get("execution_eligible"):
            raise AssertionError("Service did not acknowledge staged artifact readiness")
        if {item["package"].split(":",1)[0] for item in staged.get("artifacts",{}).get("forward",[])} != {"guardian-testprobe"}:
            raise AssertionError("Fixture stage unexpectedly includes unrelated dependency packages")
        queued = self.api("POST", "/plans/"+plan["id"]+"/execute", json={"confirmed_device_id":self.devices[dut.host]})
        self.fixture_records.append(("action_request", queued["action_request_id"]))
        dut.invoke("sync")
        dut.invoke("sync")
        applied = dut.invoke("plan", plan_id=plan["id"])
        if applied.get("status") != "pending_reassessment" or applied.get("package_version") != "1.1":
            raise AssertionError("Actual approved fixture transaction did not apply: "+json.dumps(applied))
        remediation_seconds = time.monotonic()-remediation_started
        if remediation_seconds >= 300:
            raise AssertionError("Measured fixture remediation exceeded the specification's five-minute limit")
        if applied.get("post_validation", {}).get("status") != "PASS":
            raise AssertionError("Actual post-change SONiC baseline check did not pass")
        if {item["version"] for item in applied["artifacts"]["rollback"]} != {"1.0"}:
            raise AssertionError("Previous version artifact was not retained")
        rolled_back = dut.invoke("plan", plan_id=plan["id"], rollback=True)
        if rolled_back.get("status") != "rolled_back" or rolled_back.get("package_version") != "1.0":
            raise AssertionError("Actual retained-artifact rollback failed: "+json.dumps(rolled_back))
        if self.api("GET", "/devices/"+self.devices[peer.host])["inventory_digest"] != peer_before:
            raise AssertionError("Maintenance crossed device boundaries")
        dut.invoke("package", package="guardian-testprobe", operation="remove")
        return {"fixture":True, "not_a_real_cve":True, "plan_id":plan["id"], "remediation_seconds":remediation_seconds, "staged":staged, "applied":applied, "rollback":rolled_back, "peer_unchanged":True}

    def wait_for_scan(self, dut, require_complete=False):
        deadline = time.monotonic()+self.args.timeout
        while time.monotonic()<deadline:
            device = self.api("GET", "/devices/"+self.devices[dut.host])
            if device.get("scan_status") not in ("pending","queued","running"):
                if require_complete and device.get("scan_status") != "completed":
                    raise AssertionError("A genuine complete assessment is required; current coverage is "+str(device.get("scan_status")))
                return device
            time.sleep(2)
        raise AssertionError("Central scan did not finish before test deadline")

    def health_and_scheduling(self):
        result = {}
        for dut in self.duts:
            result[dut.host] = {"health":dut.invoke("health"), "schedule":dut.invoke("schedule")}
        return result

    def autonomous_modes_and_protected_plan(self):
        dut, peer = self.duts
        peer_before = self.api("GET", "/devices/"+self.devices[peer.host])["inventory_digest"]
        for package in ("guardian-testprobe","sonic-guardian-testprobe"):
            dut.invoke("package", package=package, operation="install", version="1.0")
        self.wait_for_scan(dut, require_complete=True)
        fixtures = [self.seed_fixture(dut, package) for package in ("guardian-testprobe","sonic-guardian-testprobe")]
        dut.invoke("sync")
        result = dut.invoke("autonomous-fixture", finding_ids=[item["id"] for item in fixtures])
        if self.api("GET", "/devices/"+self.devices[peer.host])["inventory_digest"] != peer_before:
            raise AssertionError("Autonomous fixture changed peer inventory")
        for package in ("guardian-testprobe","sonic-guardian-testprobe"):
            dut.invoke("package", package=package, operation="remove")
        return {"fixture":True, "not_a_real_cve":True, "results":result, "peer_unchanged":True}

    def injected_health_failure_restores_real_package(self):
        dut = self.duts[0]
        dut.invoke("package", package="guardian-testprobe", operation="install", version="1.0")
        dut.invoke("mode", mode="assisted")
        self.wait_for_scan(dut)
        finding = self.seed_fixture(dut)
        plan = self.api("POST", "/plans", json={"device_id":self.devices[dut.host],"finding_ids":[finding["id"]],"target_version":"1.1"})
        self.fixture_records.append(("plan",plan["id"]))
        self.api("POST", "/plans/"+plan["id"]+"/approve")
        staging = self.api("POST", "/plans/"+plan["id"]+"/stage", json={"confirmed_device_id":self.devices[dut.host]})
        request_id = staging.get("stage_request_id") or staging.get("action_request_id")
        if request_id:self.fixture_records.append(("action_request",request_id))
        dut.invoke("sync")
        dut.invoke("sync")
        result = dut.invoke("forced-health-rollback",plan_id=plan["id"])
        dut.invoke("package",package="guardian-testprobe",operation="remove")
        return result

    def scoped_vex_from_service_fixture(self):
        dut = self.duts[0]
        dut.invoke("package",package="guardian-testprobe",operation="install",version="1.0")
        self.wait_for_scan(dut, require_complete=True)
        finding = self.seed_fixture(dut,applicability="not_affected")
        dut.invoke("sync")
        local = dut.invoke("vex-fixture",finding_id=finding["id"])
        service = self.api("GET","/devices/"+self.devices[dut.host]+"/vex")
        statements = [item for item in service.get("statements",[]) if item.get("vulnerability",{}).get("name")==finding["cve_id"]
                      and any(product.get("@id")=="urn:guardian:component:"+finding["component_id"] for product in item.get("products",[]))]
        if len(statements)!=1 or statements[0].get("status")!="not_affected":
            raise AssertionError("Service VEX did not preserve the exact scoped fixture exclusion")
        dut.invoke("package",package="guardian-testprobe",operation="remove")
        return {"local":local,"service_statement":statements[0],"fixture":True,"not_a_real_cve":True}

    def cleanup(self):
        results = {}
        for dut in self.duts:
            try:
                results[dut.host] = dut.invoke("cleanup")
            except Exception as error:
                results[dut.host] = {"restored":False, "error":str(error), "recovery_directory":"/var/lib/sonic-guardian-test/"+self.run_id}
            finally:
                dut.close()
        if self.service_store:
            for kind, ident in reversed(self.fixture_records):
                self.service_store.remove(kind, ident)
            self.service_store.close()
        self.session.close()
        return results

    def run(self):
        success = False
        try:
            for case, function in (("prepare", self.prepare), ("native_cli_configdb_yang", self.native_cli_and_yang),
                                   ("actual_package_deltas_and_two_device_isolation", self.package_delta_and_isolation),
                                   ("runtime_evidence_round_trip", self.evidence_round_trip),
                                   ("offline_replay_daemon_restart_and_freshness", self.offline_replay_and_restart),
                                   ("measured_resources_and_low_memory_guard", self.resource_guards),
                                   ("signed_fixture_stage_apply_rollback", self.real_fixture_stage_apply_rollback),
                                   ("host_services_resources_and_scheduled_collection",self.health_and_scheduling),
                                   ("actual_autonomous_modes_and_protected_plan",self.autonomous_modes_and_protected_plan),
                                   ("injected_health_failure_actual_rollback",self.injected_health_failure_restores_real_package),
                                   ("scoped_native_and_service_vex",self.scoped_vex_from_service_fixture)):
                self.record(case, function)
            success = True
        finally:
            cleanup = self.cleanup()
            success = success and all(result.get("restored") for result in cleanup.values())
            report = {"run_id":self.run_id, "executed_on_real_duts":True, "hosts":self.args.hosts,
                      "contains_synthetic_remediation_fixture":True, "represents_real_cve_confirmation":False,
                      "specification_coverage_manifest":str(ROOT/"tests/integration/spec-coverage.json"),
                      "unproven_specification_gates":["reviewed CVE corpus/recall", "assessment ground truth", "full VEX schema validation", "complete quickstart and full image build"],
                      "status":"passed" if success else "failed", "results":self.results, "cleanup":cleanup,
                      "finished_at":datetime.now(timezone.utc).isoformat()}
            Path(self.args.output).write_text(json.dumps(report, indent=2)+"\n")
            print(json.dumps({"event":"finished", "status":report["status"], "report":self.args.output}), flush=True)
        return success


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--hosts", nargs=2, required=True)
    result.add_argument("--user", default="admin")
    result.add_argument("--password-file")
    result.add_argument("--known-hosts")
    result.add_argument("--accept-new-host-keys", action="store_true")
    result.add_argument("--server", required=True)
    result.add_argument("--token-file", required=True)
    result.add_argument("--ca-file")
    result.add_argument("--fixture-repo", required=True)
    result.add_argument("--allow-mutations", action="store_true")
    result.add_argument("--service-root")
    result.add_argument("--service-database")
    result.add_argument("--allow-synthetic-service-fixture", action="store_true")
    result.add_argument("--timeout", type=int, default=600)
    result.add_argument("--output", required=True)
    return result


if __name__ == "__main__":
    arguments = parser().parse_args()
    if not os.getenv("GUARDIAN_SSH_PASSWORD") and not arguments.password_file:
        os.environ["GUARDIAN_SSH_PASSWORD"] = getpass.getpass("Switch SSH password (not logged): ")
    raise SystemExit(0 if LiveAcceptance(arguments).run() else 1)
