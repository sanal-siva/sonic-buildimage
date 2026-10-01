"""Resource-bounded Smart Patch daemon; all vulnerability matching is central."""
import logging
import random
import signal
import threading
from smart_patch.agent import Agent
from smart_patch.logging import StructuredJsonFormatter

logger = logging.getLogger("sonic-smart-patch")


class SmartPatchDaemon:
    def __init__(self, agent=None):
        self.agent = agent or Agent()
        self.stop = threading.Event()

    def step(self):
        values = self.agent.config.refresh()
        if values["enabled"] == "true":
            self.agent.sync()
            from smart_patch.actions import AutonomousCoordinator
            AutonomousCoordinator(self.agent.store, self.agent.config).run_once()
        else:
            # A reload/disable must be visible locally even though monitoring and
            # outbound requests are intentionally stopped.
            self.agent.publish_status(values)
        return values

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        failures = 0
        while not self.stop.is_set():
            try:
                values = self.step()
                failures = 0
            except Exception as error:
                failures = min(failures + 1, 5)
                logger.warning("Sync deferred: %s", error)
            try:
                interval = max(10, int(self.agent.config.values()["sync_interval"]))
            except Exception:
                interval = 60
            self.stop.wait(min(900, interval*(2**failures)) + random.uniform(0, min(10, interval/10)))
        return 0


def main():
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    return SmartPatchDaemon().run()


if __name__ == "__main__":
    raise SystemExit(main())
