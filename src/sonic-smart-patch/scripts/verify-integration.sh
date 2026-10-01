#!/bin/sh
set -eu
python3 -m compileall -q /usr/lib/python3/dist-packages/smart_patch
python3 -c 'from smart_patch.agent import Agent; from smart_patch.config import ConfigManager; from smart_patch.collector import InventoryCollector'
security --help
config security --help
show security --help
systemctl show sonic-smart-patch -p MemoryMax -p CPUQuotaPerSecUSec
security show status --json
