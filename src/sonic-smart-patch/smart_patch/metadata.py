"""Metadata file management for SONiC Smart Patch"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
import fcntl
from smart_patch.exceptions import MetadataError
from smart_patch.logging import setup_logging

logger = setup_logging(__name__)

DEFAULT_METADATA_PATH = "/etc/sonic/smart-patch/metadata.json"


class MetadataManager:
    """Manages persistent metadata file"""

    def __init__(self, path: str = DEFAULT_METADATA_PATH):
        """Initialize metadata manager

        Args:
            path: Path to metadata file
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Dict[str, Any]:
        """Load metadata from file

        Returns:
            Metadata dict
        """
        if not self.path.exists():
            return self._init_metadata()

        try:
            with open(self.path, "r") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    return json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
            raise MetadataError(f"Cannot load metadata: {e}")

    def save(self, metadata: Dict[str, Any]) -> None:
        """Save metadata to file with atomic write

        Args:
            metadata: Metadata dict to save
        """
        try:
            temp_path = self.path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(metadata, f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            temp_path.replace(self.path)
            logger.info(f"Metadata saved: {self.path}")
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
            raise MetadataError(f"Cannot save metadata: {e}")

    def update_inventory(
        self, package_name: str, version: str, package_type: str
    ) -> None:
        """Add or update package in inventory

        Args:
            package_name: Package name
            version: Package version
            package_type: Type of package
        """
        metadata = self.load()
        inventory = metadata.get("inventory", [])

        existing = next((p for p in inventory if p["name"] == package_name), None)
        if existing:
            existing["version"] = version
            existing["updated_at"] = datetime.utcnow().isoformat() + "Z"
        else:
            inventory.append(
                {
                    "name": package_name,
                    "version": version,
                    "type": package_type,
                    "installed_at": datetime.utcnow().isoformat() + "Z",
                }
            )

        metadata["inventory"] = inventory
        metadata["last_updated"] = datetime.utcnow().isoformat() + "Z"
        self.save(metadata)

    def add_scan_result(self, scan_data: Dict[str, Any]) -> None:
        """Record scan result in history

        Args:
            scan_data: Scan result data
        """
        metadata = self.load()
        scan_history = metadata.get("scan_history", [])
        scan_data["timestamp"] = datetime.utcnow().isoformat() + "Z"
        scan_history.append(scan_data)

        metadata["scan_history"] = scan_history[-100:]
        metadata["last_updated"] = datetime.utcnow().isoformat() + "Z"
        self.save(metadata)

    def add_vex_record(self, vex_record: Dict[str, Any]) -> None:
        """Record VEX document

        Args:
            vex_record: VEX record data
        """
        metadata = self.load()
        vex_records = metadata.get("vex_records", [])
        vex_record["recorded_at"] = datetime.utcnow().isoformat() + "Z"
        vex_records.append(vex_record)

        metadata["vex_records"] = vex_records
        metadata["last_updated"] = datetime.utcnow().isoformat() + "Z"
        self.save(metadata)

    def add_remediation_action(self, action: Dict[str, Any]) -> None:
        """Record remediation action

        Args:
            action: Remediation action data
        """
        metadata = self.load()
        remediation_log = metadata.get("remediation_log", [])
        action["recorded_at"] = datetime.utcnow().isoformat() + "Z"
        remediation_log.append(action)

        metadata["remediation_log"] = remediation_log
        metadata["last_updated"] = datetime.utcnow().isoformat() + "Z"
        self.save(metadata)

    def get_last_scan(self) -> Optional[Dict[str, Any]]:
        """Get most recent scan result

        Returns:
            Last scan data or None
        """
        metadata = self.load()
        scan_history = metadata.get("scan_history", [])
        return scan_history[-1] if scan_history else None

    def _init_metadata(self) -> Dict[str, Any]:
        """Initialize empty metadata structure

        Returns:
            Empty metadata dict
        """
        return {
            "schema_version": "1.0.0",
            "sonic_version": "unknown",
            "sbom_loaded": False,
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "inventory": [],
            "scan_history": [],
            "vex_records": [],
            "remediation_log": [],
        }
