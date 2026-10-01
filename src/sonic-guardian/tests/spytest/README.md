# Official SpyTest execution without SONiC provisioning

The reviewed framework is official `sonic-net/sonic-mgmt` commit
`01296ee274376cce124f9a4644353b0aa1fa0ced`. The source checkout is currently
`/tmp/guardian-official-sonic-mgmt`; the isolated compatible environment is
`/tmp/guardian-spytest-venv`. `requirements-verified.txt` records its dependencies.
Neither location is installed on a switch.

Use `run_guardian_spytest.py`, not the framework's default SONiC testbed profile.
Default SONiC startup can reset configuration, clear logs, adjust ports or recover
by rebooting. `--skip-init-config` alone does not disable all these paths.

The wrapper creates a two-device testbed using the official **Linux SSH transport
and lifecycle hooks on the actual SONiC switches**. This is genuine SpyTest, with
its real `st.config`, upload API, test execution and results. It intentionally
does not test the framework's SONiC provisioning/initialization paths. Native
SONiC CLI, ConfigDB, installed YANG and actual Guardian behavior remain tested by
the shared real-DUT acceptance helper.

The pinned source was inspected at these locations:

* `spytest/spytest/net.py`: connection startup invokes post-login, early-init and
  post-reboot hooks before normal test session initialization.
* `spytest/apis/common/linux_hooks.py`: init/apply/clear-config, post-reboot,
  clear-logging and set-port-defaults are no-ops. Login only adjusts its own shell
  timeout/terminal width and reads uptime. Actual readiness is checked separately
  by Guardian's health checks; the Linux hook does not establish routing health.
* `spytest/spytest/framework.py`: `--skip-init-checks` bypasses session
  provisioning and port-list/base-config work; `--skip-load-config base` bypasses
  module configuration restore; topology checking and TGen are disabled.
* `spytest/apis/common/sonic_config.py`: ordinary SONiC hooks can rebuild/reset
  configuration and change routing defaults. These hooks are deliberately absent
  from this profile.

The wrapper rejects a different or modified framework revision. It generates no
link, breakout, speed, image, static-management, RPS or config-restore settings.
Environment controls disable date changes, management renewal, recovery/reset,
TGen cleanup, log clearing/support collection, shell-wide sudo, SSH retry helpers
and interface administration. Real helper commands use explicit sudo only for
authorized Guardian/fixture operations. The exact flags/environment are saved in
`guardian-spytest-profile.json` for audit.

The only replaced upstream function is its environment-dump logging hook, which
otherwise writes every environment variable, including passwords. This replacement
and a standard logging filter redact secrets; no transport, lifecycle or test
result function is mocked. Testbed files contain placeholders, logs are private,
and credentials are loaded from protected files referenced by the existing live
configuration. Passwords and service tokens are not command-line arguments.

## Verified local preparation

The official runner imports successfully in the isolated environment, its actual
CLI flags were parsed, the generated two-device testbed validates, and the
`D1 D2 TYPE:linux` topology resolves. Running the command below with a dummy
TEST-NET configuration collected the genuine adapter test with **no DUT
connections and no test execution**. This is setup verification, not a SpyTest
hardware pass.

```sh
/tmp/guardian-spytest-venv/bin/python \
  "<path-to-sonic-buildimage>/src/sonic-guardian/tests/spytest/run_guardian_spytest.py" \
  --source /tmp/guardian-official-sonic-mgmt \
  --live-config /secure/guardian-live-config.json \
  --logs /tmp/guardian-spytest-preflight --collect-only
```

The configuration uses the `{"argv": [...]}` format documented in
`../integration/README.md`. Use an output filename distinct from the direct SSH
run so the two evidence reports remain separate.

## Authorized real execution

After direct acceptance restores the two DUTs, use the same command **without
`--collect-only`**, with a new private log directory:

```sh
/tmp/guardian-spytest-venv/bin/python \
  "<path-to-sonic-buildimage>/src/sonic-guardian/tests/spytest/run_guardian_spytest.py" \
  --source /tmp/guardian-official-sonic-mgmt \
  --live-config /secure/guardian-live-config.json \
  --logs /tmp/guardian-spytest-live
```

The test executes the same actual package/evidence/offline/restart/resource and
signed-APT staging/apply/rollback sequence through official SpyTest transport.
It calls `st.report_pass` only after all tests and cleanup succeed. The report
must show real devices, all cases passed and complete restoration before this
framework gate can be marked complete. Collection success or direct SSH success
alone does not satisfy that gate.
