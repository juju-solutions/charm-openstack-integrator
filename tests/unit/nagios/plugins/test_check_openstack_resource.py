import os
import sys
from unittest import mock
from unittest.mock import MagicMock

import pytest

from nagios_plugin3 import CriticalError, WarnError

from check_openstack_resource import check, parse_arguments


class FakeOpenStackResource:
    def __init__(self, type_, id_, status=None, **kwargs):
        self._type = type_
        self._id = id_
        if status is not None:
            self.status = status
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return "{}-{}".format(self._type, self._id)

    @property
    def type(self):
        return self._type


@pytest.mark.parametrize("args, exp_output", [
    (["--all"], (set(), set(), dict(), True)),
    (["--id", "1", "--id", "2"], ({"1", "2"}, set(), dict(), False)),
    (["-i", "1", "-i", "2"], ({"1", "2"}, set(), dict(), False)),
    (["--all", "--skip-id", "2"], (set(), {"2"}, dict(), True)),
    (["--all", "--skip-id", "2", "--skip-id", "3"],
     (set(), {"2", "3"}, dict(), True)),
    (["--all", "--skip-id", "2", "--select", "a=b"],
     (set(), {"2"}, {"a": "b"}, True))
])
def test_parse_arguments(args, exp_output, monkeypatch, credentials_cnf):
    """Test configuration of argparse.parser"""
    monkeypatch.setattr(sys, "argv", ["", "server", "-c", credentials_cnf, *args])
    output = parse_arguments()

    assert exp_output == output[2:]


@pytest.mark.parametrize("resource,args", [
    ("network", ["-i", "1", "--all"]),
    ("network", ["-i", "1", "--skip-id", "1"]),
    ("network", ["-i", "1", "--select", "a=b"]),
    ("wrong-resource", ["-i", "1"]),
    ("security-group", ["--all"]),
    ("subnet", ["--all"]),
    ("network", ["--skip-id", "1"])
])
def test_parse_arguments_error(resource, args, monkeypatch, credentials_cnf):
    """Test configuration of argparse.parser raise error"""
    monkeypatch.setattr(sys, "argv",
                        ["", resource, "-c", credentials_cnf, *args])

    with pytest.raises(SystemExit):
        parse_arguments()


@pytest.mark.parametrize("servers, check_kwargs, exp_ids", [
    ([{"id_": "1", "status": "ACTIVE"}], {"ids": {}, "check_all": True}, ["1"]),
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": "ACTIVE"}],
     {"ids": {"1"}, "check_all": False}, ["1"]),
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": "ACTIVE"}],
     {"ids": {}, "check_all": True}, ["2", "1"]),
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": "ACTIVE"}],
     {"ids": {}, "skip": {"2"}, "check_all": True}, ["1"]),
])
def test_check_passed(servers, check_kwargs, exp_ids, credentials):
    """Test NRPE check for OpenStack networks that passed."""
    servers = [FakeOpenStackResource("server", **server) for server in servers]
    with mock.patch("check_openstack_resource.openstack") as openstack:
        openstack.connect.return_value = mock_conn = MagicMock()
        mock_conn.compute.servers.return_value = servers
        with mock.patch("check_openstack_resource.print") as mock_print:
            check(credentials, "server", **check_kwargs)
            messages = os.linesep.join("server '{}' is in ACTIVE status"
                                       "".format(_id) for _id in exp_ids)
            output = "servers {0}/{0} passed{1}{2}" \
                     "".format(len(exp_ids), os.linesep, messages)
            mock_print.assert_called_once_with("OK: ", output)


@pytest.mark.parametrize("subnets, ids", [
    ([{"id_": "1"}], {"1"}),
    ([{"id_": "1"}, {"id_": "2"}, {"id_": "3"}], ["2", "1"]),
])
def test_check_passed_by_existence(subnets, ids, credentials):
    """Test NRPE check for OpenStack networks that passed."""
    subnets = [FakeOpenStackResource("subnet", **subnet) for subnet in subnets]
    with mock.patch("check_openstack_resource.openstack") as openstack:
        openstack.connect.return_value = mock_conn = MagicMock()
        mock_conn.network.subnets.return_value = subnets
        with mock.patch("check_openstack_resource.print") as mock_print:
            check(credentials, "subnet", ids=ids)
            messages = os.linesep.join("subnet '{}' exists".format(_id) for _id in ids)
            output = "subnets {0}/{0} passed{1}{2}" \
                     "".format(len(ids), os.linesep, messages)
            mock_print.assert_called_once_with("OK: ", output)


@pytest.mark.parametrize("ports, exp_out", [
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": "UNKNOWN"}],
     "WARNING: ports 1/2 in UNKNOWN, 1/2 passed"),
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "3", "status": "NOT-VALID"},
      {"id_": "3", "status": "UNKNOWN"}],
     "WARNING: ports 2/3 in UNKNOWN, 1/3 passed"),
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": None}],
     "WARNING: ports 1/2 in UNKNOWN, 1/2 passed"),
    ([{"id_": "1", "status": None}, {"id_": "2", "status": None}],
     "WARNING: ports 2/2 in UNKNOWN"),
])
def test_check_unknown_warning(ports, exp_out, credentials):
    """Test NRPE check for OpenStack servers with warning output."""
    ports = [FakeOpenStackResource("port", **port) for port in ports]
    with mock.patch("check_openstack_resource.openstack") as openstack:
        openstack.connect.return_value = mock_conn = MagicMock()
        mock_conn.network.ports.return_value = ports
        with pytest.raises(WarnError) as error:
            check(credentials, "port", ids={port.id for port in ports})

        assert str(error.value).startswith(exp_out)


@pytest.mark.parametrize("servers, ids, exp_out", [
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": "DOWN"}], {"1", "2"},
     "CRITICAL: servers 1/2 are DOWN, 1/2 passed"),
    ([{"id_": "1", "status": "ACTIVE"}], {"1", "2"},
     "CRITICAL: servers 1/2 were not found, 1/2 passed"),
    ([{"id_": "1", "status": "ACTIVE"}, {"id_": "2", "status": "DOWN"},
      {"id_": "3", "status": "UNKNOWN"}, {"id_": "4", "status": "UNKNOWN"}],
     {"1", "2", "3", "4"},
     "CRITICAL: servers 1/4 are DOWN, 2/4 in UNKNOWN, 1/4 passed"),
])
def test_check_critical_error(servers, ids, exp_out, credentials):
    """Test NRPE check for OpenStack servers with critical output."""
    servers = [FakeOpenStackResource("server", **server) for server in servers]
    with mock.patch("check_openstack_resource.openstack") as openstack:
        openstack.connect.return_value = mock_conn = MagicMock()
        mock_conn.compute.servers.return_value = servers
        with pytest.raises(CriticalError) as error:
            check(credentials, "server", ids=ids)

        assert str(error.value).startswith(exp_out)
