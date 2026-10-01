#!/bin/sh
set -eu
python3 -m compileall -q /usr/lib/python3/dist-packages/guardian
python3 -c 'from guardian.agent import Agent; from guardian.config import ConfigManager; from guardian.collector import InventoryCollector'
security --help
config security --help
show security --help
systemctl show sonic-guardian -p MemoryMax -p CPUQuotaPerSecUSec
security show status --json
