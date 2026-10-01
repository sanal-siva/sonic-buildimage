"""Export scoped CycloneDX 1.5 VEX from explicit evidence-backed verdicts."""
from pathlib import Path
from uuid import uuid4
from smart_patch.storage import atomic_json, now
from smart_patch.decision import current_finding


class VEXManager:
    def __init__(self, vex_dir="/var/lib/sonic-smart-patch/vex"):
        self.vex_dir = Path(vex_dir)

    def create_vex_document(self, sonic_version, vulnerabilities, clock_alignment=None):
        document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:"+str(uuid4()), "version": 1,
                    "metadata": {"timestamp": now(), "component": {"type":"operating-system", "name":"SONiC", "version":sonic_version}},
                    "components": [], "vulnerabilities": []}
        seen = set()
        status_map = {"affected": "exploitable", "fixed": "resolved", "not_affected":"not_affected", "under_investigation":"in_triage"}
        valid_justifications = {"code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"}
        for finding in vulnerabilities:
            finding = current_finding(finding, clock_alignment)
            component = finding.get("component_id")
            if not component or not finding.get("scope"):
                raise ValueError("VEX requires an exact scoped component identity")
            verdict = finding.get("applicability", "under_investigation")
            evidence = finding.get("evidence", [])
            analysis = {"state": status_map.get(verdict, "in_triage"), "detail": finding.get("rationale", "Evidence unavailable")}
            if verdict in ("fixed", "not_affected") and not evidence:
                analysis = {"state":"in_triage", "detail":"Verdict lacks supporting evidence"}
            if verdict == "not_affected" and analysis["state"] == "not_affected":
                justification = finding.get("justification")
                if not justification:
                    # Only direct semantic equivalences; other OpenVEX terms
                    # remain in triage unless a CycloneDX justification exists.
                    justification = {"vulnerable_code_not_present":"code_not_present",
                                     "vulnerable_code_not_in_execute_path":"code_not_reachable"}.get(finding.get("vex_justification"))
                if justification not in valid_justifications:
                    analysis = {"state":"in_triage", "detail":"Missing supported CycloneDX justification"}
                else:
                    analysis["justification"] = justification
            if component not in seen:
                document["components"].append({"type":"library", "bom-ref":component,
                    "name": finding["package_name"], "version": finding["affected_version"],
                    "properties":[{"name":"sonic:scope", "value":finding["scope"]}]})
                seen.add(component)
            document["vulnerabilities"].append({"id":finding["cve_id"], "affects":[{"ref":component}], "analysis":analysis,
                "properties":[{"name":"sonic:evidence-ids", "value":",".join(str(item.get("id",item.get("evidence_id","unknown"))) if isinstance(item,dict) else str(item) for item in evidence)}]})
        return document

    def generate_vex_file(self, vex_doc, filename="smart-patch-vex.json"):
        if Path(filename).name != filename:
            raise ValueError("VEX filename must not contain a path")
        target=self.vex_dir/filename
        atomic_json(target,vex_doc,mode=0o644)
        return target
