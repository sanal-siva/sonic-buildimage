# SONiC Guardian - Self-Healing Security Framework

Autonomous vulnerability discovery, risk assessment, and remediation for SONiC network operating systems.

## Overview

SONiC Guardian continuously inventories installed software, identifies vulnerabilities using grype scanning, consults a remote Security Intelligence Service for risk assessment, and automatically applies low-risk security fixes while generating maintenance plans for impactful updates.

### Key Features

- **Vulnerability Discovery**: SBOM-based scanning with grype, delta metadata tracking
- **Risk Assessment**: Integration with Security Intelligence Service for contextual recommendations
- **Autonomous Remediation**: Package-type-aware procedures (kernel, FRR, OpenSSL, standard)
- **Health Validation**: Automated checks confirm services, routing, and interfaces remain stable
- **Rollback Capability**: Automatic recovery from failed remediations
- **Operating Modes**: Advisory (recommendations only), Assisted (download + plan), Autonomous (auto-apply)
- **VEX Integration**: Vulnerability Exploitability Exchange documents for non-impacted CVEs
- **Audit Trail**: Structured JSON logging for forensics and compliance

## Architecture

```
┌─────────────────────────────────────────┐
│      SONiC Guardian Daemon              │
├─────────────────────────────────────────┤
│ Discovery  │ Intelligence │ Remediation │
│  Engine    │   Service    │   Engine    │
├─────────────────────────────────────────┤
│  Config DB │ Metadata File │ VEX Docs   │
│  State DB  │ SONiC CLI     │ Logging    │
└─────────────────────────────────────────┘
       │              │              │
       ▼              ▼              ▼
   ┌────────────┬──────────────┬─────────────┐
   │ grype      │ Security     │ apt/dpkg    │
   │ SBOM       │ Intelligence │ systemd     │
   │ scanning   │ Service API  │ services    │
   └────────────┴──────────────┴─────────────┘
```

## Installation

### Build from source

```bash
cd sonic-buildimage/src/sonic-guardian
python3 -m pip install -r requirements.txt
python3 setup.py install
```

### Install as Debian package

```bash
cd sonic-buildimage/src/sonic-guardian
dpkg-buildpackage -us -uc
sudo dpkg -i ../sonic-guardian_*.deb
```

## Configuration

### Enable SONiC Guardian

```bash
config security guardian enable
```

### Configure Security Intelligence Service

```bash
config security service-url https://intelligence.example.com/api/v1
config security auth-token your-auth-token-here
```

### Set Operating Mode

```bash
# Advisory mode (recommendations only)
config security guardian mode advisory

# Assisted mode (download and plan)
config security guardian mode assisted

# Autonomous mode (auto-apply safe fixes)
config security guardian mode autonomous
```

## Usage

### Run Vulnerability Scan

```bash
# Trigger immediate scan
security scan now

# View results
show security vulnerabilities

# View specific CVE
show security vulnerability CVE-2026-12345
```

### Get Recommendations

```bash
# Display all recommendations
show security recommendations

# Assess specific CVE
security assess CVE-2026-12345
```

### Remediate Vulnerabilities

```bash
# Assisted mode: download and plan
security remediate openssl

# Generate maintenance plan for high-impact fix
security maintenance-plan linux-kernel

# Validate system health
security validate

# Rollback failed remediation
security rollback openssl
```

## Testing

### Run Unit Tests

```bash
pytest tests/unit/
```

### Run Integration Tests (Spytest)

```bash
pytest tests/spytest/ -v
```

### Run All Tests with Coverage

```bash
pytest --cov=guardian --cov-report=html tests/
```

## Development

### Project Structure

```
guardian/
├── __init__.py          # Module exports
├── main.py              # Daemon entry point
├── cli.py               # CLI command handlers
├── scanner.py           # Grype integration
├── intelligence.py      # Intelligence Service client
├── remediation.py       # Package remediation engine
├── validation.py        # Health checks
├── config.py            # SONiC Config DB integration
├── metadata.py          # Metadata file management
├── logging.py           # Structured JSON logging
├── models.py            # Data model classes
└── exceptions.py        # Custom exceptions

tests/
├── unit/                # Unit tests
├── spytest/             # Integration tests (Spytest)
└── conftest.py          # Pytest fixtures
```

### Code Style

```bash
# Format code
black guardian/ tests/

# Lint code
pylint guardian/ tests/

# Check with flake8
flake8 guardian/ tests/
```

## Performance Targets

- Vulnerability scanning: <2 minutes (50-100 packages)
- Remediation cycle: <5 minutes (download + install + validate)
- Health checks: <1 minute
- Rollback execution: <2 minutes

## Logging

SONiC Guardian logs all operations as structured JSON to `/var/log/sonic/guardian.log`:

```json
{
  "timestamp": "2026-09-29T14:00:00Z",
  "level": "INFO",
  "component": "guardian.scanner",
  "message": "Scan started",
  "packages": 150
}
```

## Security Considerations

- Auth tokens stored encrypted in Config DB
- All Intelligence Service communication via HTTPS
- Atomic metadata file writes prevent corruption
- Role-based access control (admin only for configuration)
- VEX documents follow NTIA standards

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE)

## References

- [SONiC Project](https://github.com/sonic-net/SONiC)
- [grype Scanner](https://github.com/anchore/grype)
- [VEX Specification](https://www.ntia.gov/files/ntia/publications/ntia_vex_communication_standards_report_12_19_21_0.pdf)
- [CycloneDX SBOM](https://cyclonedx.org/)
