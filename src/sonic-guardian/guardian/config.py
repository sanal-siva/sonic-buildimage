"""SONiC Config DB integration for SONiC Guardian"""

from typing import Any, Dict, Optional
from guardian.exceptions import ConfigError
from guardian.logging import setup_logging

logger = setup_logging(__name__)


class ConfigManager:
    """Manages SONiC Guardian configuration in Config DB"""

    def __init__(self, config_db=None):
        """Initialize config manager

        Args:
            config_db: Optional mock Config DB (for testing)
        """
        self.config_db = config_db
        self.namespace = "SONIC_GUARDIAN"

    def get(self, table: str, key: str, field: str) -> Optional[Any]:
        """Get configuration value

        Args:
            table: Config table (SERVICE, SCAN, etc.)
            key: Table key
            field: Field name

        Returns:
            Configuration value or None
        """
        if not self.config_db:
            return None

        full_key = f"{self.namespace}|{table}"
        try:
            config = self.config_db.get(full_key)
            if config and key in config:
                return config[key].get(field)
        except Exception as e:
            logger.warning(f"Failed to read config {full_key}: {e}")
        return None

    def set(self, table: str, key: str, field: str, value: Any) -> bool:
        """Set configuration value

        Args:
            table: Config table
            key: Table key
            field: Field name
            value: Value to set

        Returns:
            True if successful
        """
        if not self.config_db:
            return True

        full_key = f"{self.namespace}|{table}"
        try:
            config = self.config_db.get(full_key) or {}
            if key not in config:
                config[key] = {}
            config[key][field] = str(value)
            self.config_db.set(full_key, config)
            return True
        except Exception as e:
            logger.error(f"Failed to write config {full_key}: {e}")
            return False

    def get_service_enabled(self) -> bool:
        """Check if SONiC Guardian service is enabled"""
        value = self.get("SERVICE", "sonic-guardian", "enabled")
        return value == "true" if value else False

    def set_service_enabled(self, enabled: bool) -> bool:
        """Enable or disable SONiC Guardian service"""
        return self.set("SERVICE", "sonic-guardian", "enabled", "true" if enabled else "false")

    def get_operating_mode(self) -> str:
        """Get current operating mode (advisory, assisted, autonomous)"""
        return self.get("SERVICE", "sonic-guardian", "mode") or "advisory"

    def set_operating_mode(self, mode: str) -> bool:
        """Set operating mode"""
        if mode not in ["advisory", "assisted", "autonomous"]:
            raise ConfigError(f"Invalid operating mode: {mode}")
        return self.set("SERVICE", "sonic-guardian", "mode", mode)

    def get_service_url(self) -> Optional[str]:
        """Get Security Intelligence Service URL"""
        return self.get("SERVICE", "sonic-guardian", "service_url")

    def set_service_url(self, url: str) -> bool:
        """Set Security Intelligence Service URL"""
        return self.set("SERVICE", "sonic-guardian", "service_url", url)

    def get_auth_token(self) -> Optional[str]:
        """Get Security Intelligence Service auth token"""
        return self.get("SERVICE", "sonic-guardian", "auth_token")

    def set_auth_token(self, token: str) -> bool:
        """Set Security Intelligence Service auth token"""
        return self.set("SERVICE", "sonic-guardian", "auth_token", token)

    def get_sbom_source(self) -> str:
        """Get SBOM source (local path or remote URL)"""
        return self.get("SERVICE", "sonic-guardian", "sbom_source") or "/etc/sonic/SBOM.json"

    def set_sbom_source(self, source: str) -> bool:
        """Set SBOM source"""
        return self.set("SERVICE", "sonic-guardian", "sbom_source", source)
