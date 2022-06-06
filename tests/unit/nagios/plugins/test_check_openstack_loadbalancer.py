import collections
import os
import sys
from unittest import mock

from unittest.mock import MagicMock

import pytest

import check_openstack_loadbalancer as check_lb

from nagios_plugin3 import CriticalError, WarnError, UnknownError


FakeLB = collections.namedtuple("FakeLB", "operating_status, provisioning_status")


@pytest.mark.parametrize("args, exp_output", [
    (["-n", "1"], {"1"}), (["-n", "1", "--name", "2"], {"1", "2"})
])
def test_parse_arguments(args, exp_output, monkeypatch, credentials_cnf):
    """Test configuration of argparse.parser"""
    monkeypatch.setattr(sys, "argv", ["", "-c", credentials_cnf, *args])
    _, output = check_lb.parse_arguments()

    assert exp_output == output


@pytest.mark.parametrize("lbs, exp_output", [
    ([("test1", FakeLB("ONLINE", "ACTIVE"))],
     "1/1 passed{}test1 (ONLINE, ACTIVE)".format(os.linesep)),
    ([("test1", FakeLB("ONLINE", "ACTIVE")), ("test2", FakeLB("OFFLINE", "ACTIVE"))],
     "2/2 passed{0}test1 (ONLINE, ACTIVE){0}test2 (OFFLINE, ACTIVE)"
     "".format(os.linesep)),

])
def test_ok_nagios_output(lbs, exp_output):
    """Test converting results to output message."""
    results = check_lb.Results()
    for name, lb in lbs:
        results.add_result(name, lb)

    with mock.patch("check_openstack_loadbalancer.print") as mock_print:
        check_lb.nagios_output(results)
        mock_print.assert_called_once_with("OK: ", exp_output)


@pytest.mark.parametrize("lbs, exp_output", [
    ([("test1", FakeLB("ONLINE", "PENDING_CREATE"))],
     "1/1 in WARNING{}test1 (ONLINE, PENDING_CREATE)".format(os.linesep)),
    ([("test1", FakeLB("ONLINE", "ACTIVE")),
      ("test2", FakeLB("ONLINE", "PENDING_CREATE"))],
     "1/2 in WARNING, 1/2 passed{0}test2 (ONLINE, PENDING_CREATE){0}"
     "test1 (ONLINE, ACTIVE)".format(os.linesep)),

])
def test_warning_nagios_output(lbs, exp_output):
    """Test converting results to output message."""
    results = check_lb.Results()
    for name, lb in lbs:
        results.add_result(name, lb)

    with pytest.raises(WarnError) as error:
        check_lb.nagios_output(results)

    assert str(error.value) == "WARNING: {}".format(exp_output)


@pytest.mark.parametrize("lbs, exp_output", [
    ([("test1", FakeLB("DEGRADED", "PENDING_CREATE"))],
     "1/1 in CRITICAL{}test1 (DEGRADED, PENDING_CREATE)".format(os.linesep)),
    ([("test1", FakeLB("ONLINE", "ACTIVE")),
      ("test2", FakeLB("ONLINE", "PENDING_CREATE")),
      ("test3", FakeLB("DEGRADED", "ACTIVE"))],
     "1/3 in CRITICAL, 1/3 in WARNING, 1/3 passed{0}test3 (DEGRADED, ACTIVE){0}test2 "
     "(ONLINE, PENDING_CREATE){0}test1 (ONLINE, ACTIVE)".format(os.linesep)),

])
def test_critical_nagios_output(lbs, exp_output):
    """Test converting results to output message."""
    results = check_lb.Results()
    for name, lb in lbs:
        results.add_result(name, lb)

    with pytest.raises(CriticalError) as error:
        check_lb.nagios_output(results)

    assert str(error.value) == "CRITICAL: {}".format(exp_output)


@pytest.mark.parametrize("lbs, exp_output", [
    ([("test1", FakeLB("NOT-VALID", "ACTIVE"))],
     "1/1 in UNKNOWN{}test1 (NOT-VALID, ACTIVE)".format(os.linesep)),
])
def test_unknown_nagios_output(lbs, exp_output):
    """Test converting results to output message."""
    results = check_lb.Results()
    for name, lb in lbs:
        results.add_result(name, lb)

    with pytest.raises(UnknownError) as error:
        check_lb.nagios_output(results)

    assert str(error.value) == "UNKNOWN: {}".format(exp_output)


@mock.patch.object(check_lb, "openstack")
def test_check(mock_openstack, credentials):
    """Test check function."""
    mock_openstack.connect.return_value = mock_conn = MagicMock()
    lbs = {
        "1": FakeLB("ONLINE", "ACTIVE"),
        "2": FakeLB("OFFLINE", "PENDING_CREATE"),
        "3": FakeLB("ONLINE", "ERROR"),
    }
    mock_conn.load_balancer.find_load_balancer.side_effect = \
        lambda name_or_id: lbs.get(name_or_id)

    # one OK
    check_lb.check(credentials, ["1"])

    # one OK and one in WARNING
    with pytest.raises(WarnError):
        check_lb.check(credentials, ["1", "2"])

    # one OK, one in WARNING and one in CRITICAL
    with pytest.raises(CriticalError):
        check_lb.check(credentials, ["1", "2", "3"])

    # loadbalancer was not found
    with pytest.raises(CriticalError):
        check_lb.check(credentials, ["99"])
