"""Genuine SpyTest transport adapter; requires the installed SONiC SpyTest framework.

GUARDIAN_LIVE_CONFIG references the same explicit test configuration JSON used by
pytest SSH acceptance. Credentials come from SpyTest's testbed, not this module.
"""
import json
import os
from pathlib import Path
import shlex
import sys
import pytest

spytest = pytest.importorskip("spytest", reason="Official SONiC SpyTest framework is required")
from spytest import st

sys.path.insert(0, str(Path(__file__).parents[1] / "integration"))
from live_acceptance import DUT, LiveAcceptance, parser


class SpyTestDUT(DUT):
    def __init__(self, name, host):
        self.name, self.host = name, host

    def command(self, argv, check=True, timeout=900):
        text = st.config(self.name, shlex.join(argv), type="click", skip_error_check=not check,
                         max_time=timeout, sudo=False, conf=False)
        return 0, str(text), ""

    def upload(self, path, destination):
        st.upload_file_to_dut(self.name, str(path), destination)

    def close(self):
        # SpyTest owns connection lifecycle.
        pass


def test_guardian_live_acceptance_through_spytest():
    configuration = os.getenv("GUARDIAN_LIVE_CONFIG")
    if not configuration:
        pytest.skip("Set GUARDIAN_LIVE_CONFIG for explicitly authorized two-DUT mutations")
    st.ensure_min_topology("D1", "D2", "TYPE:linux")
    names = st.get_dut_names()
    if len(names) < 2:
        pytest.fail("Guardian acceptance requires two real configured SpyTest DUTs")
    args = parser().parse_args(json.loads(Path(configuration).read_text())["argv"])
    mapping = {st.get_mgmt_ip(name): name for name in names}
    if any(host not in mapping for host in args.hosts):
        pytest.fail("Configured acceptance hosts must match SpyTest testbed management addresses")
    def factory(host, *unused):
        return SpyTestDUT(mapping[host], host)
    lab = LiveAcceptance(args, dut_factory=factory)
    assert lab.run(), "Inspect the structured real-DUT acceptance report"
    st.report_pass("test_case_passed")
