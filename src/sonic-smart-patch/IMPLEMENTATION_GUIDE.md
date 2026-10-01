# Implementation map

The current architecture and operating instructions are in [README.md](README.md).
Previous local-Grype scaffolding has been replaced; completion of a source file
is not an end-to-end acceptance claim.

| Module | Responsibility |
| --- | --- |
| `collector.py` | Bounded host/container package metadata and allowlisted runtime collectors |
| `agent.py` | Durable checkpoint/delta/heartbeat, exact replay, central ACK, scoped finding cache and STATE_DB |
| `storage.py` | Separate lock, atomic file replace, fsync and transaction-wide serialization |
| `config.py` | Real ConfigDB connector, reboot-persistent configuration and separate secret storage |
| `main.py` | Single-worker synchronization, shutdown and bounded backoff |
| `actions.py` | Approved remote maintenance import, identity/expiry checks, replay protection and result facts |
| `remediation.py` | Exact-version APT transaction resolution, staging, retained rollback and execution gates |
| `maintenance_resources.py` | Separate native systemd service per maintenance command, configurable CPU quota, independent memory/task limits and command deadlines |
| `validation.py` | Baseline-relative interfaces/containers/BGP checks with explicit unknown failures |
| `vex.py` | Evidence-backed, component-scoped CycloneDX VEX export |
| `cli.py`, `plugins/` | Real sonic-utilities integration plus standalone operational commands |
| `smart-patch-manifest.py` | Embedded pre-seal build identity and external completed-artifact binding |

`rules/sonic-smart-patch.mk`, `slave.mk` and `build_debian.sh` connect the optional
Debian package to the image build and publish its release index.
`sonic-smart-patch.yang` describes the ConfigDB table. Full SBOMs and scanner data
remain central. Legacy explicit-assessment APIs never manufacture local fallback
verdicts; the old on-switch scanner interface directs callers to synchronization.

Unimplemented high-impact transaction adapters are explicitly denied: SONiC image
upgrade/rollback, kernel, core libraries and routing packages require a reviewed
image-maintenance procedure. Health validation does not infer reachability or
safety from missing commands. Deployment acceptance must record actual switch
resource measurements, service reachability, central scan results and recovery
behavior separately from unit-test results.
