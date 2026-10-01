#!/usr/bin/env python3
"""Pinned official SpyTest with generic Linux SSH hooks and explicit safe lifecycle.

This wrapper does not mock transports or results. It deliberately disables the
framework's SONiC provisioning hooks; Smart Patch's own real health tests still run.
"""
import argparse
import json
import logging
import os
from pathlib import Path
import runpy
import subprocess
import sys
import yaml

PINNED_COMMIT = "01296ee274376cce124f9a4644353b0aa1fa0ced"

SAFE_ENV = {
    "SPYTEST_ACCESS_DRIVER":"netmiko", "SPYTEST_DATE_SYNC":"0", "SPYTEST_SET_STATIC_IP":"0",
    "SPYTEST_ONREBOOT_RENEW_MGMT_IP":"0", "SPYTEST_RECOVERY_MECHANISMS":"0",
    "SPYTEST_RESET_CONSOLES":"0", "SPYTEST_ONCONSOLE_HANG":"dead",
    "SPYTEST_RECOVERY_CTRL_C":"0", "SPYTEST_RECOVERY_CTRL_Q":"0",
    "SPYTEST_RECOVERY_CR_FAIL":"0", "SPYTEST_CONNECT_DEVICES_RETRY":"0",
    "SPYTEST_SESSION_INIT_TRYSSH":"0", "SPYTEST_SHUTDOWN_FREE_PORTS":"0",
    "SPYTEST_UPDATE_RESERVED_PORTS":"0", "SPYTEST_REDO_BREAKOUT":"0",
    "SPYTEST_KDUMP_ENABLE":"0", "SPYTEST_IFA_ENABLE":"0", "SPYTEST_SYSRQ_ENABLE":"0",
    "SPYTEST_NTP_CONFIG_INIT":"0", "SPYTEST_GENERATE_CERTIFICATE":"0",
    "SPYTEST_GNMI_INIT":"0", "SPYTEST_DETECT_CONCURRENT_ACCESS":"0",
    "SPYTEST_SESSION_TGEN_CLEAN":"0", "SPYTEST_MODULE_EPILOG_ENSURE_SYSTEM_READY":"0",
    "SPYTEST_TECH_SUPPORT_ONERROR":"", "SPYTEST_SYSLOG_ANALYSIS":"0",
    "SPYTEST_RESULTS_PNG":"0", "SPYTEST_SUDO_SHELL":"0", "SPYTEST_CONFIG_SUDO":"0",
    "SPYTEST_FLEX_DUT":"0", "SPYTEST_FLEX_PORT":"0", "SPYTEST_DEBUG_DEVICE_CONNECTION":"0",
    "SPYTEST_NO_CONSOLE_LOG":"0", "SPYTEST_NETMIKO_DEBUG":"", "SPYTEST_API_INSTRUMENT_SUPPORT":"0",
}
SAFE_ARGS = ["--assert=plain", "--skip-init-checks", "--skip-init-config", "--skip-load-config", "base",
             "--load-image", "none", "--topology-check", "skip", "--breakout-mode", "none", "--speed-mode", "none",
             "--skip-tgen", "--tgen-module-init", "0", "--module-epilog-tgen-cleanup", "0",
             "--syslog-check", "none", "--sysinfo-check", "none", "--fetch-core-files", "none", "--get-tech-support", "none",
             "--clear-tech-support", "0", "--save-warmboot", "0", "--random-order", "0",
             "--ui-type", "click", "--faster-init", "0", "--faster-cli", "0", "--tryssh", "0",
             "--feature-enable", "system-status", "--feature-disable", "rest", "--feature-disable", "gnmi",
             "--max-time", "function", "2400", "--max-time", "module", "2700", "--noop"]


def make_testbed(hosts, username):
    devices = {}
    topology = {}
    for index, host in enumerate(hosts, 1):
        name = "smart-patch-dut-"+str(index)
        devices[name] = {"device_type":"linux", "access":{"protocol":"ssh", "ip":host, "port":22},
                         "credentials":{"username":username, "password":"OVERRIDDEN_FROM_PRIVATE_FILE", "altpassword":""},
                         "properties":{"config":"empty", "build":"empty", "services":"none", "params":"none"}}
        topology[name] = {}
    return {"version":2.0, "services":{"none":{"enabled":False}}, "configs":{"empty":{"current":[], "restore":[]}},
            "builds":{"empty":{"current":"", "restore":""}}, "params":{"none":{}},
            "devices":devices, "topology":topology}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Official sonic-mgmt checkout at the reviewed pinned revision")
    parser.add_argument("--live-config", required=True)
    parser.add_argument("--logs", required=True)
    parser.add_argument("--collect-only", action="store_true", help="No DUT connections: official dryrun plus collection only")
    args = parser.parse_args()
    if sys.flags.optimize:
        raise ValueError("Run acceptance with Python assertions enabled (no -O/PYTHONOPTIMIZE)")
    source = Path(args.source).resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != PINNED_COMMIT:
        raise ValueError("Re-audit framework lifecycle before changing pinned SpyTest revision")
    subprocess.run(["git", "-C", str(source), "diff", "--quiet"], check=True)
    subprocess.run(["git", "-C", str(source), "diff", "--cached", "--quiet"], check=True)
    logs = Path(args.logs).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    logs.chmod(0o700)
    os.umask(0o077)
    # Parse our existing authorized live profile. The separate runner controls all
    # SpyTest options; arbitrary provisioning flags are not accepted here.
    sys.path.insert(0, str(Path(__file__).parents[1] / "integration"))
    from live_acceptance import parser as live_parser
    live_args = live_parser().parse_args(json.loads(Path(args.live_config).read_text())["argv"])
    if len(live_args.hosts) != 2 or len(set(live_args.hosts)) != 2:
        raise ValueError("Exactly two distinct DUTs are required")
    password = Path(live_args.password_file).read_text().rstrip("\n") if live_args.password_file else os.getenv("SMART_PATCH_SSH_PASSWORD", "")
    if not password and not args.collect_only:
        raise ValueError("This pinned framework profile requires an explicit protected password source")
    secrets = [password]
    if Path(live_args.token_file).exists():
        secrets.append(Path(live_args.token_file).read_text().strip())
    for name in list(os.environ):
        if name.startswith("SPYTEST_"):
            del os.environ[name]
    os.environ.update(SAFE_ENV)
    os.environ["SPYTEST_OVERRIDE_PASSWORD"] = password or "collect-only-placeholder"
    os.environ["SMART_PATCH_LIVE_CONFIG"] = str(Path(args.live_config).resolve())
    os.environ["SPYTEST_PYTHON"] = sys.executable
    testbed = logs / "smart-patch-testbed.yaml"
    testbed.write_text(yaml.safe_dump(make_testbed(live_args.hosts, live_args.user), sort_keys=False))
    testbed.chmod(0o600)
    original_factory = logging.getLogRecordFactory()
    def redact(message):
        for secret in secrets:
            if secret:
                message = message.replace(secret, "[redacted]")
        return message
    def log_factory(*values, **kwargs):
        record = original_factory(*values, **kwargs)
        record.msg, record.args = redact(record.getMessage()), ()
        return record
    logging.setLogRecordFactory(log_factory)
    sys.path.insert(0, str(source / "spytest"))
    # The upstream runner writes every environment variable to an export log.
    # Only this observability hook is replaced, to prevent credential leakage;
    # lifecycle hooks, transport, framework assertions and tests stay untouched.
    import spytest.main as official_main
    from spytest.ftrace import ftrace_prefix
    def safe_trace_env():
        for name in sorted(os.environ):
            if any(word in name.upper() for word in ("PASSWORD", "TOKEN", "SECRET", "CREDENTIAL", "KEY")):
                continue
            if name.startswith("SPYTEST_") or name in ("SMART_PATCH_LIVE_CONFIG", "LANG", "TZ"):
                ftrace_prefix("export", "export", name, redact(os.environ[name]))
    official_main.trace_env = safe_trace_env
    adapter = Path(__file__).with_name("test_sonic_smart_patch.py").resolve()
    sys.argv = [str(source / "spytest/bin/spytest"), "--testbed-file", str(testbed), "--logs-path", str(logs), *SAFE_ARGS, str(adapter)]
    if args.collect_only:
        sys.argv += ["--collect-only", "--dryrun", "1"]
    profile = {"framework":"official SONiC SpyTest", "revision":revision, "device_transport":"linux SSH on real SONiC devices",
               "sonic_provisioning_hooks_enabled":False, "collect_only":args.collect_only,
               "assertion_engine":"real framework", "lifecycle_args":SAFE_ARGS, "environment":SAFE_ENV}
    (logs / "smart-patch-spytest-profile.json").write_text(json.dumps(profile, indent=2)+"\n")
    runpy.run_path(str(source / "spytest/bin/spytest"), run_name="__main__")


if __name__ == "__main__":
    main()
