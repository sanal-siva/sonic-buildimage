# Live acceptance on two SONiC DUTs

These tests execute real SSH commands, actual dpkg transactions through APT, real
Smart Patch synchronization, native CLI commands and the installed SonicYang binding.
They are opt-in and separate from unit tests. Synthetic findings are explicitly
labelled and do not establish a real switch CVE.

The harness changes only Smart Patch settings/service state and two dedicated
file-only packages. It does not change interfaces, routing configuration, kernel,
SONiC images or existing software versions. The fixture packages contain no
maintainer scripts, services, dependencies or trigger declarations:

* `sonic-smart-patch-testprobe`: install 1.0, update to 1.1, remove; verify real APT
  dirty hooks and scoped central inventory deltas independently on both DUTs.
* `smart-patch-testprobe`: exercise actual signed-repository stage/apply/rollback.
  Its name intentionally avoids the `sonic-*` protected core-package policy.

## Prerequisites

* Two authorized switches running the current Smart Patch package, independently
  enrolled with device tokens and a verified service CA.
* The service is reachable on the management address. Its existing real scans
  should be working; the test does not fake the scanner.
* Operator workstation: Python with `requests`; OpenSSH/scp, `sshpass` if using
  password authentication; `gpg`, `gpgv`, `dpkg-deb`, `dpkg-scanpackages` to build
  the signed fixture repository. For remediation seeding, run with the service's
  Python environment so SQLAlchemy is available.
* Switches: passwordless authorized `sudo`, apt/dpkg, `gpgv`, and SonicYang.
  Tests fail when required platform functionality is absent.
* Only this harness should modify the two fixtures. Run tests serially; do not
  use pytest-xdist or another concurrent maintenance workflow.

## Build harmless signed fixtures

```sh
python3 scripts/build-live-test-repo.py --output /tmp/smart-patch-fixture-repo
```

The output directory must be empty. A temporary Ed25519 signing key signs a flat
APT repository; the private key is destroyed. The public key is trusted only for
this temporary file:// repository. `gpgv` verifies the output before use. Socket
restricted sandboxes may need their normal execution approval to let gpg-agent
create its temporary Unix socket; this is not a network operation.

## Run the actual SSH/API suite

Use protected files/environment variables for secrets. The command line contains
only file paths, never password or token values.

```sh
/path/to/service/.venv/bin/python tests/integration/live_acceptance.py \
  --hosts "<sonic-vm-1-ip>" "<sonic-vm-2-ip>" \
  --user admin --password-file /secure/switch-password \
  --known-hosts /secure/verified-known-hosts \
  --server "https://<server-ip>:<server-port>" \
  --token-file /secure/service-admin-token --ca-file /secure/service-ca.pem \
  --fixture-repo /tmp/smart-patch-fixture-repo --allow-mutations \
  --service-root /path/to/sonic-smart-patch-intel-svc-hackathon-2026 \
  --service-database sqlite:////absolute/path/to/service/smart_patch.db \
  --allow-synthetic-service-fixture \
  --output /tmp/smart-patch-live-acceptance.json
```

`SMART_PATCH_SSH_PASSWORD` can replace `--password-file`. `--accept-new-host-keys` is
an explicit first-use alternative to supplying verified host keys; changed keys
are still rejected. Standard agent/key authentication is supported by the `DUT`
transport. The command-line runner prompts for a password if neither password
source is provided.

The explicit database permission creates one labelled `SYNTHETIC-SMART_PATCH-
ACCEPTANCE-NOT-A-CVE` finding for the harmless fixture. It then uses the real
service plan creation/approval/execution APIs and real agent staging/install/
rollback. It removes that finding, evidence, plan and action request afterward.
Without permission to seed this fixture, the full remediation gate fails; it is
not silently counted as passed.

The test report separates actual measurements from synthetic fixture semantics:

1. Native non-sudo show; real ConfigDB validated by installed SonicYang loading the native deployed
   model directory (not an isolated staged model); invalid
   mode rejected by that same binding.
2. Actual install/update/removal and APT hook, sequence/digest/component checks;
   peer inventory unchanged.
3. Service-requested listener evidence observed from each switch.
4. Unreachable endpoint marks results stale; byte-identical pending payload is
   sent on the real recovery connection; restarted daemon actually synchronizes.
5. Memory threshold raised without allocating memory; collection defers, then
   recovers. Actual collector RSS and systemd cgroup values are recorded.
6. Signed APT fixture repository used to retain old/new .debs, separately stage
   without changing installed version, apply exact 1.1 in under five minutes,
   pass real SONiC baseline health, roll back actual 1.0 and preserve the peer.
7. Actual critical service/resource/BGP-prefix health and repeated configured
   collection intervals; unused administratively down interfaces are accepted.
8. Actual daemon autonomous execution against only the two named harmless
   fixtures; advisory/assisted modes do not auto-install, and the protected
   SONiC-name fixture remains unchanged with an image-maintenance requirement.
9. A labelled, test-only post-install validation error causes actual package
   rollback. No real routing/interface/service failure is created.
10. A labelled synthetic service exclusion reaches native and service VEX exports.
11. Cleanup verifies the original non-fixture package inventory and settings.

These scenarios do not prove the complete original specification. The exact
mapping and remaining gaps are recorded in `spec-coverage.json`, including the
reviewed known-CVE corpus, accuracy/coverage targets and full image/boot evidence.
The native VEX test exercises explicit export; it does not claim automatic file
emission or full schema validation. Tests cannot promote partial real scanner
coverage to complete merely to trigger the autonomous fixture.

## Run with pytest

Write a protected JSON file `{"argv": ["--hosts", "<sonic-vm-1-ip>", ...]}` with
the same CLI arguments above (including explicit mutation and synthetic-fixture
flags). Then:

```sh
python3 -m pytest tests/integration/test_live_acceptance.py -v -s \
  --smart-patch-live-config /secure/smart-patch-live-config.json
```

Without this argument, the ten hardware cases are explicitly skipped. A subset
run is reported as `partial` with unexecuted cases, never full acceptance.

## Run with genuine SONiC SpyTest

Use the reviewed runner in `../spytest/run_smart_patch_spytest.py`; do not use the
framework's default SONiC provisioning profile on these switches. The wrapper
pins official source and uses its real generic Linux SSH transport while disabling
image/configuration/port/TGen initialization and recovery. The real native SONiC
checks remain in our shared acceptance helper. See [the exact SpyTest setup and
command](../spytest/README.md), including source audit and verified dependencies.

```sh
/tmp/smart-patch-spytest-venv/bin/python \
  "<path-to-sonic-buildimage>/src/sonic-smart-patch/tests/spytest/run_smart_patch_spytest.py" \
  --source /tmp/smart-patch-official-sonic-mgmt \
  --live-config /secure/smart-patch-live-config.json \
  --logs /tmp/smart-patch-spytest-live
```

Use a distinct report path in the configuration. Add `--collect-only` to verify
collection without connecting to DUTs; collection does not satisfy the hardware
gate. The adapter imports official `spytest.st`, runs the real helper through
that framework, and calls `st.report_pass` only after actual tests and cleanup.

## Recovery and cleanup

Before mutation, each DUT saves root-only configuration/ConfigDB/package and
service-state backups under `/var/lib/sonic-smart-patch-test/smart-patch-acceptance-ID`.
The root-only backup is retained for audit/recovery. Cleanup always runs from a
`finally` block, even after failed tests. It:

* Stops only Smart Patch, removes both fixture packages, removes the dedicated APT
  source/list files and test repository, and removes only fixture plan artifacts.
* Restores the original ConfigDB entry and config file; never reads or exports
  device credentials.
* Forces a new inventory checkpoint to reconcile cleanup and restores the prior
  Smart Patch service running/stopped state.
* Fails acceptance if any original package changed or any fixture remains.

On a controller interruption or lost SSH connection, retain the uploaded helper
in `/tmp/smart-patch-acceptance-ID/remote_probe.py`. Rerun its `cleanup` action:

```sh
# Run locally on the DUT; substitute the run_id recorded in the report.
sudo python3 /tmp/smart-patch-acceptance-ID/remote_probe.py \
  "$(python3 -c 'import base64,json; print(base64.b64encode(json.dumps({"run_id":"smart-patch-acceptance-ID","action":"cleanup"}).encode()).decode())')"
```

Use the actual 12-character hexadecimal ID. Inspect `cleanup.json`; do not erase
recovery backups until restoration has been verified. Real audit events are
retained, including the harmless fixture package changes. They are evidence of
acceptance activity, not real vulnerability findings.
