"""Pytest configuration and fixtures for SONiC Guardian tests"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch


@pytest.fixture
def mock_config_db():
    """Mock SONiC Config DB interface"""
    mock = MagicMock()
    mock.get = Mock(return_value=None)
    mock.set = Mock(return_value=True)
    return mock


@pytest.fixture
def mock_state_db():
    """Mock SONiC State DB interface"""
    mock = MagicMock()
    mock.get = Mock(return_value=None)
    return mock


@pytest.fixture
def sample_sbom():
    """Sample SBOM for testing"""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "openssl",
                "version": "3.0.16",
                "purl": "pkg:deb/debian/openssl@3.0.16",
            },
            {
                "type": "library",
                "name": "curl",
                "version": "7.85.0",
                "purl": "pkg:deb/debian/curl@7.85.0",
            },
        ],
    }


@pytest.fixture
def sample_grype_output():
    """Sample grype scan output"""
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-12345",
                    "dataSource": "NVD",
                    "severity": "CRITICAL",
                    "cvssScore": 9.8,
                },
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.16",
                    "type": "deb",
                },
            },
            {
                "vulnerability": {
                    "id": "CVE-2026-54321",
                    "dataSource": "NVD",
                    "severity": "HIGH",
                    "cvssScore": 8.2,
                },
                "artifact": {
                    "name": "curl",
                    "version": "7.85.0",
                    "type": "deb",
                },
            },
        ]
    }


@pytest.fixture
def sample_metadata():
    """Sample metadata file structure"""
    return {
        "schema_version": "1.0.0",
        "sonic_version": "202609-release",
        "sbom_loaded": True,
        "last_updated": "2026-09-29T12:00:00Z",
        "inventory": [],
        "scan_history": [],
        "vex_records": [],
        "remediation_log": [],
    }


@pytest.fixture
def temp_metadata_dir(tmp_path):
    """Temporary directory for metadata files"""
    return tmp_path / "sonic-guardian"


@pytest.fixture(autouse=True)
def reset_imports():
    """Reset guardian module state between tests"""
    yield
    import sys

    modules_to_remove = [m for m in sys.modules if m.startswith("guardian")]
    for module in modules_to_remove:
        del sys.modules[module]
