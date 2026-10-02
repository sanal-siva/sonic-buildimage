"""Persistent ConfigDB configuration and a portable file fallback.

Tokens live in a root-only file, never in ConfigDB or show output.
"""
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from smart_patch.storage import atomic_json
from smart_patch.exceptions import ConfigError

DEFAULTS = {"enabled": "false", "mode": "advisory", "sync_interval": "60",
            "inventory_interval": "900", "min_available_mb": "256",
            "allow_http": "false", "max_components": "20000",
            "maintenance_cpu_quota_percent": "0", "maintenance_min_free_mib": "500",
            "maintenance_checks_enabled": "false", "maintenance_mode": "false",
            "rollback_snapshot_enabled": "true", "rollback_snapshot_timestamp": "",
            "validation_services":"ssh,database,swss,syncd,bgp", "validation_cpu_max_pct":"80",
            "validation_memory_max_pct":"90", "validation_disk_max_pct":"85",
            "validation_disk_path":"/var/lib/sonic-smart-patch", "validation_prefix_loss_pct":"0",
            "validation_require_prefix_counts":"true"}

PUBLIC_FIELDS = ("enabled", "mode", "sync_interval", "maintenance_checks_enabled", "maintenance_mode")


class ConfigManager:
    def __init__(self, config_db=None, directory=None):
        self.directory = Path(directory or os.getenv("SMART_PATCH_CONFIG_DIR", "/etc/sonic/smart-patch"))
        self.config_db = config_db
        self._auto_connect = config_db is None and directory is None and not os.getenv("SMART_PATCH_CONFIG_DIR")
        self.db_available = False
        self._last_db_entry = None
        self.namespace = "SONIC_SMART_PATCH"
        if self._auto_connect:
            self._connect_db()

    def _connect_db(self):
        try:
            from swsscommon.swsscommon import ConfigDBConnector
            database = ConfigDBConnector()
            database.connect(wait_for_init=False)
            self.config_db = database
        except Exception:
            # Local file configuration supports standalone operation and outages.
            self.config_db = None

    def values(self):
        self.db_available = False
        if self.config_db is None and self._auto_connect:
            self._connect_db()
        if self.config_db is not None:
            try:
                entry = self.config_db.get_entry(self.namespace, "GLOBAL") or {}
                self._last_db_entry = dict(entry)
                self.db_available = True
                # An available ConfigDB is authoritative, including an absent
                # entry after config reload. Disk settings cannot resurrect it.
                return {**DEFAULTS, **entry}
            except Exception:
                if self._auto_connect:
                    self.config_db = None
        path = self.directory / "config.json"
        fallback = json.loads(path.read_text()) if path.exists() else {}
        return {**DEFAULTS, **fallback}

    def refresh(self):
        """Refresh the outage fallback from authoritative DB state, including removal."""
        values = self.values()
        if self.db_available:
            path = self.directory / "config.json"
            try:
                previous = json.loads(path.read_text()) if path.exists() else None
            except json.JSONDecodeError:
                previous = None
            if previous != self._last_db_entry:
                atomic_json(path, self._last_db_entry)
        return values

    def get(self, table, key, field):
        return self.values().get(field)

    def set(self, table, key, field, value):
        if field == "auth_token":
            return self.set_auth_token(value)
        # Select the available authority before saving. If Redis cannot be read,
        # use the explicit outage/standalone file path; a live DB takes priority.
        values = self.values()
        path = self.directory / "config.json"
        if self.db_available:
            current = dict(self._last_db_entry or {})
            current[field] = str(value)
            self.config_db.set_entry(self.namespace, "GLOBAL", current)
            values = current
        else:
            values = json.loads(path.read_text()) if path.exists() else {}
            values[field] = str(value)
        atomic_json(path, values)
        public = {key: str(values.get(key, DEFAULTS[key])) for key in PUBLIC_FIELDS}
        atomic_json(self.directory / "public-config.json", public, mode=0o644)
        return True

    def get_service_enabled(self):
        return self.values()["enabled"] == "true"

    def set_service_enabled(self, enabled):
        return self.set("", "", "enabled", "true" if enabled else "false")

    def get_operating_mode(self):
        return self.values()["mode"]

    def set_operating_mode(self, mode):
        if mode not in ("advisory", "assisted", "autonomous"):
            raise ConfigError("Invalid operating mode")
        return self.set("", "", "mode", mode)

    def get_service_url(self):
        return self.values().get("service_url")

    def set_service_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ConfigError("Service URL must be an HTTP(S) origin, optionally ending in /api/v1")
        return self.set("", "", "service_url", url.rstrip("/"))

    def get_auth_token(self):
        path = self.directory / "credentials.json"
        return json.loads(path.read_text()).get("token") if path.exists() else None

    def set_auth_token(self, token):
        if not token or len(token) > 4096:
            raise ConfigError("Invalid token")
        atomic_json(self.directory / "credentials.json", {"token": token})
        return True

    def get_sbom_source(self):
        return self.values().get("sbom_source", "/etc/sonic/smart-patch/manifest.json")

    def set_sbom_source(self, source):
        return self.set("", "", "sbom_source", source)


def public_config(directory=None):
    path = Path(directory or os.getenv("SMART_PATCH_CONFIG_DIR", "/etc/sonic/smart-patch")) / "public-config.json"
    values = {key: DEFAULTS[key] for key in PUBLIC_FIELDS}
    try:
        public = json.loads(path.read_text())
        values.update({key:str(public[key]) for key in values if key in public})
    except FileNotFoundError:
        pass
    return values
