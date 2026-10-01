# SONiC Guardian

Guardian collects host/container inventory and bounded runtime evidence on a
switch. Grype, vulnerability databases, source-code analysis and AI run in the
intelligence service. No scanner is installed or launched on the switch.

This module is an optional community SONiC enhancement. Enable
`INCLUDE_SONIC_GUARDIAN=y` in the image build; enable `ENABLE_SBOM=y` separately
for build SBOM/provenance. Existing images can install the standalone collector
package without replacing their SONiC image. Such enrollment is explicitly
runtime inventory with unverified artifact provenance until a release is bound
centrally.

## Build and verify

```sh
cd src/sonic-guardian
make test
make deb
# Normal build-image builders with debhelper installed can use:
dpkg-buildpackage -us -uc -b
```

`make deb` produces `../sonic-guardian_2.0.0-4_all.deb` using `dpkg-deb` and the
same runtime sources and assets. The standard SONiC build uses `debian/rules`.
The architecture-independent package requires Python 3.9+, requests, PyYAML and
Click. SONiC provides ConfigDB/STATE_DB connectors and the native command loader.

## Configure a switch

```sh
sudo dpkg -i sonic-guardian_2.0.0-4_all.deb
sudo config security service-url https://MANAGEMENT_SERVER:8443
sudo config security auth-token --token-file /secure/path/device-token
sudo config security setting ca_bundle /etc/sonic/guardian/service-ca.pem
sudo config security guardian --mode advisory
sudo config security guardian enable
sudo security sync --force
```

Use a distinct device token. Certificates are verified against the configured CA;
verification is never disabled. An isolated lab can explicitly opt into HTTP
using `security config setting allow_http true`. Tokens are stored separately in
a root-only file and are not shown or stored in ConfigDB.

On a native SONiC/systemd installation, `config security guardian enable` starts
Guardian and enables its unit at boot. `disable` publishes disabled status before
stopping and disabling the unit. Standalone configurations and explicit test paths
never invoke host systemctl. Direct ConfigDB reloads remain authoritative; deleting
the table disables monitoring and refreshes the fallback without resurrecting old
disk settings.

The standalone `security config ...` and `security show ...` groups expose the
same commands as `config security ...` and `show security ...`. Package install
links real plugins into the installed sonic-utilities package, resolving the
active Python version dynamically. It installs a private YANG model and registers
it in the native model directory through a symlink only when no image-owned model
is present. Removal deletes only that private-model symlink; real schemas from
sonic-yang-models are preserved.

```sh
show security status --json
show security findings
show security finding FINDING_ID
show security evidence FINDING_ID
show security inventory-drift
show security resource-usage
sudo security export-vex
```

A CVE is not an unambiguous finding ID: it may occur in several containers.
The CLI retains current findings, including justified exclusions. It reports
freshness and collection gaps; an empty or partial cache is never advertised as
a clean switch. When the service sends a bounded subset of findings, the CLI
shows the total and directs operators to the complete service view.

## Inventory and evidence protocol

* A checkpoint starts a new epoch at sequence 1. Deltas contain scoped upserts
  and removals; heartbeats retain the acknowledged sequence.
* Component identity separates host/container scope, name and architecture.
  Versions, source versions, distro, PURL and container image digest are retained.
* The digest is SHA256 of components sorted by component_id, JSON encoded with
  sorted object keys, compact separators and ASCII escapes.
* An acknowledgement follows durable central commit. An interrupted HTTP request
  retries the identical journaled envelope. Gaps cause a fresh checkpoint.
* A failed collection scope retains its previous components and reports unknown
  coverage, rather than claiming packages were removed.
* APT hooks only mark inventory dirty. The daemon reconciles after transactions,
  detects container topology changes, and periodically reconciles all scopes.
* Evidence requests select named, read-only collectors (listeners, kernel,
  processes, interfaces, BGP, FEATURE state). Commands, output and durations are
  bounded. Arbitrary commands and secret-bearing configuration dumps are denied.

Each installation creates `/etc/sonic/guardian/device-id` on first enrollment
using an exclusive lock and random UUID. It persists across restarts and is not
included in build manifests. Machine IDs and hostnames can be duplicated in VS
clones and are not used as enrollment identity. An administrator can pre-provision
the file (mode 0600) to preserve an existing enrolled device during migration.
When cloning an already enrolled switch, provision a new identity and token.

Native `show security` commands read an atomic, sanitized `public.json` snapshot
and `public-config.json` projection without sudo. They cannot read or mutate the
private synchronization journal. The public view contains allowed status,
resource, scope and finding fields, with evidence references instead of raw
facts; credentials and maintenance authorization are excluded.

State is stored in `/var/lib/sonic-guardian/state.json` with mode 0600. Reads use a
shared lock without rewriting the file; unchanged transactions avoid replacement
and fsync. A separate `flock` lock
protects the entire read-modify-write transaction; temporary files are fsynced
and atomically renamed. Only one synchronizer operates at a time. Interrupted
maintenance actions are recorded and never silently replayed.

## Evidence time alignment

The agent never changes the switch clock. On verified HTTPS synchronization it
compares the authenticated service timestamp with the request's local midpoint,
records the clock offset and half-round-trip uncertainty, and aligns each newly
collected fact once. It retains `device_collected_at` and the applied offset next
to `collected_at`; later heartbeats/calibrations do not make old facts fresh.
An initial acknowledgement aligns retained observations for the next heartbeat.
Pending envelopes always replay unchanged. Missing/malformed time, an in-flight
clock jump or an expired calibration produces unaligned/unknown time, not an
invented timestamp. Native CLI freshness still uses the local last-sync time.

## Resource budget

The collector systemd unit sets MemoryHigh=80M, MemoryMax=128M, CPUQuota=10%, Nice=15 and
TasksMax=32. These are configured ceilings, not a claim of measured switch usage.
The collector records its CPU time, peak RSS and elapsed collection time. It
uses one subprocess at a time, a component/container budget, per-command time
and output limits, and a collection deadline. It defers collection below the
configured memory threshold. Full reconciliation defaults to 15 minutes and
sync to one minute, with jitter and bounded exponential retry.

Measure both collector usage and the service cgroup on representative switches.
No swap, scanner database or full filesystem walk is required.

Native maintenance commands use separate transient systemd services, each with
MemoryMax=512 MiB, TasksMax=128 and its command deadline enforced by RuntimeMaxSec.
They have no MemoryHigh throttle and no CPU quota by default. This keeps APT
outside the collector's 128 MiB/10% CPU budget. The maintenance runner is used
for native package operations from both daemon and CLI; it also bounds their
health-command subprocesses. Manual collection/CLI parent processes remain
outside the daemon's cgroup, and standalone non-systemd operation does not
establish the native maintenance cgroup guarantee.

The native Guardian daemon and its transient systemd maintenance workers run as
root. Workers invoke package and health commands directly; they do not run `sudo`
inside the daemon. Interactive administration still uses the documented `sudo`
CLI commands. Service mode and explicit maintenance authorization remain separate
from this operating-system execution identity.

## Maintenance modes

Advisory is the default and permits review/planning only. Assisted mode permits
exact-version staging and explicitly approved execution. Autonomous mode also
permits an exact scope/package allowlist policy; an AI recommendation alone never
authorizes a change. Authenticated remote actions still require explicit plan
approval and expiry, exact device/component/target authorization and an idempotent
request ID. Service-side plan binding remains enforced; local inventory freshness
and complete-scope preflight checks follow `maintenance_checks_enabled`.

```sh
sudo security maintenance plan FINDING_ID EXACT_FIXED_VERSION
sudo security maintenance stage LOCAL_PLAN_UUID
sudo security maintenance apply LOCAL_PLAN_UUID --approve
sudo security maintenance rollback LOCAL_PLAN_UUID --approve
```

Maintenance preflight and health checks are optional and **disabled by default**
(`maintenance_checks_enabled=false`). Enable them to require the local version,
inventory/freshness, free-space, dependency-policy, artifact-hash and health checks.
The configured free-space threshold remains 500 MiB but is enforced only while
checks are enabled. Values persist in `SONIC_GUARDIAN|GLOBAL`:

```sh
sudo config security setting maintenance_checks_enabled false
# Enable all local preflight and health checks instead:
sudo config security setting maintenance_checks_enabled true
sudo config security setting maintenance_min_free_mib 500
sudo config security setting maintenance_cpu_quota_percent 0
# Optional example: limit maintenance to 50% of one CPU.
sudo config security setting maintenance_cpu_quota_percent 50
```

On vendor images without native plugin discovery, use the standalone equivalent:

```sh
sudo security config setting maintenance_checks_enabled false
# Or enable the checks:
sudo security config setting maintenance_checks_enabled true
```

`maintenance_min_free_mib` accepts 1–65536 MiB (1 MiB = 1048576 bytes), and
`maintenance_cpu_quota_percent` accepts 0–100. `maintenance_checks_enabled`
accepts exactly `true` or `false` and is displayed by `show security status --json`
(standalone: `security show status --json`). These settings apply to package
maintenance; normal inventory collection retains its resource policy. With checks
enabled, the disk minimum is checked before staging and forward installation. A
free-space threshold does not reserve disk space or guarantee that an arbitrary
package transaction will fit. Rollback does not acquire the new minimum-free-space
gate, so that threshold itself cannot block recovery.
CPU quota zero disables Guardian's maintenance quota; platform and parent-slice
limits still apply. Native maintenance fails if it cannot establish the separate
required execution environment, rather than silently using the collector budget.

CPU quota is distinct from optional health checks `validation_cpu_max_pct`
(default 80% whole-switch utilization), `validation_memory_max_pct` (90%) and
`validation_disk_max_pct` (85%). With checks enabled, these remain independent of
the free-byte minimum. The maintenance command memory/task/deadline bounds and
configured CPU quota apply in either setting. Changing policy does not approve,
retry or execute a maintenance plan.

Package transactions are resolved by APT simulation in both modes, and the target
package must still download and install successfully. With checks enabled, changed
package versions and both forward/rollback `.deb` artifacts must be retained,
the supplied catalog checksum and captured hashes must match, and the simulated
transaction must be unchanged before application. With checks disabled, Guardian
attempts to obtain rollback artifacts but permits staging when an exact previous
package cannot be downloaded. It records `rollback_available=false` and the missing
packages. No partial automatic rollback is attempted when the recovery set is
incomplete: a failed install is reported for manual recovery. Skipped checks are
recorded as skipped, never as passed. APT's configured repository trust and actual
package-manager errors still apply. Native automatic stage/apply/rollback is limited to eligible
host packages. Container changes require manual container/image maintenance;
bounding a Docker client would not establish a limit on the package process
running inside its container.
`rollback_available=true` means the complete staged recovery artifact set was
retained. It does not guarantee restoration, particularly when dependency checks
were disabled and the package manager can change the dependency transaction.

Forward installation and rollback keep APT's `--no-download` flag and set
`Dir::Cache::archives` to the plan's corresponding `forward` or `rollback`
artifact directory. This makes APT reuse the staged archives even when repository
metadata also lists the same package version; supplying a local `.deb` path alone
does not reliably make APT select that copy. This cache selection does not disable
APT dependency resolution: a missing required archive, unresolved dependency or
package-manager error still fails the operation, including when optional checks
are disabled. It does not fetch extra packages during installation.
When enabled, pre/post checks verify configured critical systemd services, CPU/memory/disk
thresholds, running containers, baseline operational interfaces, established BGP
peers, received-prefix counts and available route totals. Prefix loss defaults to
zero tolerance; configured loss tolerance supports deployments with expected
variation. Unknown required measurements fail. Exemptions with a service-issued
validity deadline downgrade to under investigation after expiry or when their
clock/deadline cannot be verified, even if the connection remains fresh. This finding
policy is independent of the maintenance toggle. Failed changes trigger rollback
only when all required rollback artifacts were retained, and record its actual
outcome. Successful package installation remains `pending_reassessment`
until central vulnerability assessment confirms the outcome.

Authentication, supported host-package boundaries, exact authorized target,
operating mode, explicit approval/expiry and idempotence remain mandatory.
Core SONiC, routing, OpenSSL/libc and kernel targets require reviewed SONiC image
maintenance. With checks enabled, dependency policy also rejects new-dependency,
package-removal and protected dependency transactions. This implementation does
not pretend that generic apt/GRUB operations provide safe image rollback.
It generates a maintenance requirement and denies automated execution of those
unsupported transactions.

## Build identity

Before sealing the image, `guardian-manifest.py` embeds a compact manifest with
source revision, architecture/platform, package-database digest, canonical build
parameters and content-addressed Docker image identities. The build identity is
deterministic for those inputs; it contains no random nonce or enrollment UUID. After creating the installer and SBOM/provenance, the build emits
`<image>.guardian.json`, binding their completed hashes to the manifest. The
image does not embed its own hash. The agent makes no trust decision based only
on a local manifest; the central service must verify the release binding.

## Validation scope

The unit suite covers protocol replay/gap recovery, exact digest agreement,
partial coverage, resource guards, concurrency, TLS policy, scope isolation,
health evidence failure, and approved/idempotent maintenance actions. Run the
optional service-contract check with the service's Python environment:

```sh
python3 scripts/check-service-contract.py /path/to/sonic-guardian-intel-svc-hackathon-2026
```

Live-switch installation, central scanner database behavior and real routing
maintenance need separate deployment/integration evidence. Synthetic unit tests
do not establish operational safety of a disruptive image or routing upgrade.
