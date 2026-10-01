"""Compatibility interface for remote scanning. No scanner runs on the switch."""
from smart_patch.agent import Agent


class VulnerabilityScanner:
    def __init__(self, *args, **kwargs):
        self.agent = Agent()

    def load_sbom(self):
        raise RuntimeError("Full SBOMs are processed centrally; use security sync --force")

    def scan_packages(self):
        result = self.agent.sync(force=True)
        return result.get("findings", [])
