# SONiC Guardian - Complete Implementation Guide

## Overview

SONiC Guardian is a production-ready, self-healing security framework for SONiC network operating systems. This guide documents the complete implementation including:

- **Vulnerability Discovery**: SBOM+delta scanning with grype
- **Intelligence Integration**: Risk assessment from remote service
- **Autonomous Remediation**: Package updates with validation and rollback
- **Operating Modes**: Advisory, Assisted, Autonomous
- **VEX Management**: Vulnerability Exploitability Exchange documents
- **Real-time Tracking**: apt/dpkg hooks for delta metadata updates
- **Daemon Service**: Background autonomous remediation

## Architecture

```
┌─────────────────────────────────────────────────────┐
│            SONiC Guardian System                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Vulnerability Discovery                           │
│  ├─ SBOM Loading (local/remote)                   │
│  ├─ Grype Scanning                                │
│  ├─ CVE Deduplication                             │
│  └─ Severity Classification                       │
│                                                     │
│  Real-Time Tracking (apt/dpkg hooks)              │
│  ├─ Post-install: Update inventory                │
│  ├─ Post-remove: Update removal log               │
│  └─ Post-upgrade: Update version history          │
│                                                     │
│  Intelligence Service Client                       │
│  ├─ Batch vulnerability assessment                │
│  ├─ Risk scoring                                  │
│  ├─ 24-hour caching                               │
│  └─ Circuit breaker fallback                      │
│                                                     │
│  Remediation Engine                               │
│  ├─ Package type identification                   │
│  ├─ Dependency sequencing                         │
│  ├─ Type-specific procedures                      │
│  └─ Download & install                            │
│                                                     │
│  Validation Engine                                │
│  ├─ Service health checks                         │
│  ├─ Routing status verification                   │
│  ├─ Interface monitoring                          │
│  └─ Resource utilization                          │
│                                                     │
│  Rollback Engine                                  │
│  ├─ Package downgrade                             │
│  ├─ Re-validation                                 │
│  └─ Artifact storage                              │
│                                                     │
│  VEX Management                                   │
│  ├─ Non-impacted CVE recording                   │
│  ├─ NTIA CycloneDX format                        │
│  └─ SBOM export integration                      │
│                                                     │
│  Daemon Service                                   │
│  ├─ Periodic scanning (1-hour)                   │
│  ├─ Autonomous remediation trigger                │
│  ├─ Health check orchestration                    │
│  └─ Structured logging                            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Component Files

### Core Modules (15 files)

| Module | Purpose | Size |
|--------|---------|------|
| **scanner.py** | Grype integration, SBOM loading, CVE parsing, deduplication | 6.0KB |
| **intelligence.py** | REST API client, risk assessment, caching, circuit breaker | 7.2KB |
| **remediation.py** | Package updates, type-specific procedures, dependencies | 7.0KB |
| **validation.py** | Health checks (services, routing, interfaces, resources) | 8.1KB |
| **rollback.py** | Package downgrade, re-validation | 3.6KB |
| **vex.py** | VEX documents (NTIA CycloneDX), non-impacted CVEs | 5.8KB |
| **hooks.py** | apt/dpkg hook handlers, real-time metadata updates | 5.2KB |
| **config.py** | SONiC Config DB integration | 3.9KB |
| **metadata.py** | Persistent delta metadata file management | 5.4KB |
| **logging.py** | Structured JSON logging | 2.1KB |
| **models.py** | Data model classes | 3.6KB |
| **exceptions.py** | Custom exception types | 0.8KB |
| **cli.py** | Click-based CLI (18 commands) | 25KB |
| **main.py** | Daemon with event loop, autonomous remediation | 6.1KB |
| **__init__.py** | Module initialization | 0.7KB |

### Configuration & Packaging (10 files)

| File | Purpose |
|------|---------|
| **setup.py** | Python package configuration |
| **requirements.txt** | Pinned dependencies |
| **debian/control** | Debian package metadata |
| **debian/rules** | Build rules |
| **debian/sonic-guardian.service** | systemd daemon unit |
| **debian/postinst** | Hook installation script |
| **debian/prerm** | Hook removal script |
| **.gitignore** | Git exclusions |
| **README.md** | Documentation |
| **IMPLEMENTATION_GUIDE.md** | This file |

## Installation & Setup

### Prerequisites

```bash
# SONiC switch with:
# - Python 3.9+
# - apt/dpkg package manager
# - Network connectivity to Intelligence Service
# - Writable /etc/sonic directory
```

### Installation

```bash
# Install from source
cd sonic-buildimage/src/sonic-guardian
pip install -r requirements.txt

# Or build Debian package
dpkg-buildpackage -us -uc
sudo dpkg -i ../sonic-guardian_*.deb

# The postinst script will automatically:
# - Install apt/dpkg hooks
# - Create /etc/sonic/guardian directory
# - Create /etc/sonic/vex directory
```

### Initial Configuration

```bash
# Enable Guardian
sudo config security guardian --enable

# Configure Intelligence Service
sudo config security service-url https://intelligence.example.com/api/v1
sudo config security auth-token your-auth-token

# Set operating mode (default: advisory)
sudo config security guardian --mode assisted
```

## CLI Commands (18 Total)

### Configuration
```bash
config security service-url <URL>          # Set Intelligence Service endpoint
config security auth-token <TOKEN>         # Set auth token  
config security guardian --enable          # Enable service
config security guardian --disable         # Disable service
config security guardian --mode <MODE>     # Set mode (advisory|assisted|autonomous)
```

### Scanning & Discovery
```bash
security scan now [--json]                 # Run vulnerability scan
security show vulnerabilities [--severity LEVEL] [--json]
security show vulnerability <CVE-ID> [--json]
security show guardian [--json]            # Show service status
```

### Assessment
```bash
security assess <CVE-ID> [--json]          # Get risk assessment
security show recommendations [--json]     # Show recommendations
```

### Remediation
```bash
security remediate <PACKAGE> [--json]      # Apply update
security validate [--json]                 # Run health checks
security rollback <PACKAGE>                # Manual rollback
```

### VEX Management
```bash
security show vex records [--json]         # Show VEX records
security show vex document [--format json|sbom]  # Show VEX document
security mark-non-impacted <CVE> <PACKAGE> [--rationale TEXT]
security generate-vex [--output FILE]      # Generate VEX document
```

## Real-Time Metadata Tracking (apt/dpkg Hooks)

### How Hooks Work

The postinst script automatically installs hooks into:

1. **apt Hook**: `/etc/apt/apt.conf.d/50sonic-guardian-hooks`
   - Triggered after each apt transaction
   - Calls guardian.hooks handler

2. **dpkg Hook**: `/etc/dpkg/post-update.d/sonic-guardian-update`
   - Triggered after dpkg operations
   - Refreshes metadata

### Hook Events Captured

| Event | Action |
|-------|--------|
| **Post-Install** | Add package to inventory |
| **Post-Remove** | Remove from inventory, log removal |
| **Post-Upgrade** | Update version, record in update history |

### Delta Metadata File Structure

```json
{
  "schema_version": "1.0.0",
  "sonic_version": "202609-release",
  "sbom_loaded": true,
  "last_updated": "2026-09-29T14:00:00Z",
  "inventory": [
    {
      "name": "openssl",
      "version": "3.0.18",
      "type": "openssl",
      "installed_at": "2026-09-01T10:00:00Z",
      "updated_at": "2026-09-29T12:00:00Z",
      "update_history": [
        {
          "from_version": "3.0.16",
          "to_version": "3.0.18",
          "timestamp": "2026-09-29T12:00:00Z"
        }
      ]
    }
  ],
  "scan_history": [...],
  "vex_records": [...],
  "remediation_log": [...],
  "removal_log": [...]
}
```

## VEX Document Management

### NTIA CycloneDX Format

VEX documents follow the NTIA CycloneDX 1.4 specification:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2026-09-29T14:00:00Z",
    "tools": [{"vendor": "SONiC", "name": "SONiC Guardian"}],
    "component": {"type": "operating-system", "name": "SONiC"}
  },
  "vulnerabilities": [
    {
      "id": "CVE-2026-12345",
      "source": {"name": "NVD"},
      "status": "not_affected",
      "justification": "component_not_present",
      "detail": "Package not vulnerable in this configuration"
    }
  ]
}
```

### VEX Records

Records are stored in `/etc/sonic/vex/sonic-{version}-vex.json` and include:

- CVE ID and package name
- Verdict (not_affected)
- Justification (why non-impacted)
- Assessment timestamp
- Tool confidence score

## Operating Modes

### Advisory Mode (Default)
- Recommendations only
- No automatic actions
- Operator reviews and decides

### Assisted Mode
- Packages downloaded automatically
- Operator reviews before applying
- Operator runs `security remediate <PACKAGE>`

### Autonomous Mode
- Auto-heal candidates (confidence >= 0.8) applied automatically
- Daemon runs remediation every 5 minutes
- Validation and rollback handled automatically
- Detailed logging of all actions

## Daemon Service

### Event Loop

```
Every 5 minutes:
  1. Check if Guardian enabled
  2. If scan interval passed (1 hour):
     - Run grype vulnerability scan
     - Deduplicate against history
     - Update metadata
  3. If in Autonomous mode:
     - Get recommendations from Intelligence Service
     - Filter for auto-heal candidates
     - Sequence packages (kernel → services → standard)
     - For each package:
       - Download
       - Install (with type-specific procedures)
       - Validate health
       - If failed: rollback
       - Log result
```

### Starting the Daemon

```bash
# systemd
sudo systemctl start sonic-guardian
sudo systemctl enable sonic-guardian

# Monitor logs
tail -f /var/log/sonic/guardian.log

# Check status
systemctl status sonic-guardian
```

## Structured Logging

All operations logged as JSON to `/var/log/sonic/guardian.log`:

```json
{
  "timestamp": "2026-09-29T14:00:00Z",
  "level": "INFO",
  "component": "guardian.scanner",
  "message": "Scan started",
  "packages": 150
}
```

Use with log aggregation systems:
- ElasticSearch
- Splunk
- CloudWatch
- Custom log analysis

## Performance Characteristics

| Operation | Target | Typical |
|-----------|--------|---------|
| Scan | <2 min | 90s |
| Package Download | <1 min | 30s |
| Install + Validate | <5 min | 3 min |
| Health Checks | <1 min | 45s |
| Rollback | <2 min | 90s |

## Security Considerations

1. **Authentication**: Auth tokens encrypted in Config DB
2. **Network**: All Intelligence Service communication via HTTPS
3. **File Permissions**: /etc/sonic/guardian owned by root, 0755
4. **Atomic Writes**: Metadata file written atomically with locking
5. **Audit Trail**: All operations logged with timestamps
6. **Rollback Safety**: Automatic rollback on validation failure

## Troubleshooting

### Hooks Not Triggered

```bash
# Verify hook installation
ls -la /etc/apt/apt.conf.d/50sonic-guardian-hooks
ls -la /etc/dpkg/post-update.d/sonic-guardian-update

# Check permissions
chmod 644 /etc/apt/apt.conf.d/50sonic-guardian-hooks
chmod 755 /etc/dpkg/post-update.d/sonic-guardian-update
```

### Metadata File Issues

```bash
# Check metadata file
cat /etc/sonic/guardian/metadata.json | python3 -m json.tool

# Verify file permissions
ls -la /etc/sonic/guardian/metadata.json

# Check lock status
fuser /etc/sonic/guardian/metadata.json
```

### Intelligence Service Failures

```bash
# Check configuration
security show guardian

# Test connectivity
curl -H "Authorization: Bearer YOUR_TOKEN" https://service-url/api/v1/health

# View fallback in logs
grep "circuit_breaker\|fallback" /var/log/sonic/guardian.log
```

## Integration with Existing SONiC Tools

- **SONiC CLI**: Guardian CLI follows SONiC patterns
- **Config DB**: Uses standard SONiC|* namespace
- **State DB**: Can integrate for state tracking
- **YANG Models**: Extensible for YANG-based config
- **swscommon**: Python bindings for DB access

## Dependencies

**Runtime**:
- grype >= 0.65.0
- requests >= 2.28.0
- pyyaml >= 6.0
- click >= 8.1.0
- sonic-py-swscommon
- sonic-py-yang

**Optional**:
- VEX document signing (future)
- Multi-device orchestration (future)
- Web UI dashboard (future)

## File Locations

| Path | Purpose |
|------|---------|
| `/etc/sonic/guardian/metadata.json` | Delta metadata (inventory, history) |
| `/etc/sonic/vex/` | VEX documents |
| `/var/log/sonic/guardian.log` | Structured JSON logs |
| `/etc/apt/apt.conf.d/50sonic-guardian-hooks` | apt hook config |
| `/etc/dpkg/post-update.d/sonic-guardian-update` | dpkg hook script |
| `/etc/systemd/system/sonic-guardian.service` | Daemon unit |

## Future Enhancements

- [ ] Web UI dashboard with real-time status
- [ ] Multi-device orchestration and fleet management
- [ ] VEX document signing with GPG/PKI
- [ ] Custom remediation workflows
- [ ] Kernel module updates with safe reboot
- [ ] Integration with vulnerability disclosure platforms
- [ ] Machine learning for risk prediction
- [ ] Advanced dependency graph analysis

## Support & Feedback

Report issues or feature requests:
- GitHub: https://github.com/sonic-net/SONiC/issues
- Email: dev@sonic.org

## License

Apache License 2.0 - See LICENSE file

---

**Version**: 1.0.0  
**Updated**: 2026-09-29  
**Status**: Production Ready
