#!/usr/bin/python3
"""Validate real collected inventory against the central service's schema/hash."""
import sys
import tempfile
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: check-service-contract.py SERVICE_REPOSITORY")
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), sys.argv[1]]
from guardian.agent import Agent
from guardian.config import ConfigManager
from guardian.storage import StateStore
from app.api.models import SyncEnvelope
from app.db.store import inventory_hash

with tempfile.TemporaryDirectory() as directory:
    config = ConfigManager(directory=Path(directory)/"config")
    store = StateStore(Path(directory)/"state")
    agent = Agent(config, store)
    with store.transaction() as state:
        payload = agent._prepare(state)
    envelope = SyncEnvelope.model_validate(payload).model_dump()
    assert envelope["inventory_digest"] == inventory_hash(envelope["components"])
    print("Contract and canonical digest verified for %d actual components" % len(envelope["components"]))
