import sys
from configparser import ConfigParser
from unittest import mock
from unittest.mock import MagicMock

import openstack
import pytest

sys.path.append("files/nagios/plugins")

import check_openstack_interface  # noqa: E402
import check_openstack_loadbalancer  # noqa: E402

INTERFACES = {}


class FakeOpenStackInterface:
    def __init__(self, interface_type, interface_id, status=None, **kwargs):
        self._interface_type = interface_type
        self._id = interface_id
        if status is not None:
            self.status = status
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return "{}-{}".format(self._interface_type, self._id)

    @property
    def type(self):
        return self._interface_type


def get_id(name):
    return name.split("-")[-1]


@pytest.fixture
def credentials():
    yield {"openstack": {}}


@pytest.fixture
def credentials_cnf(tmpdir, credentials):
    config = ConfigParser()
    config.read_dict(credentials)
    path = tmpdir.join("test.cnf")
    with open(path, "w") as file:
        config.write(file)

    yield path.strpath


@pytest.fixture(autouse=True)
def mock_openstack(monkeypatch):
    global INTERFACES
    fake_connection = MagicMock()
    fake_connection.network.networks.side_effect = lambda: [
        net for net in INTERFACES.values() if net.type == "network"]
    fake_connection.network.subnets.side_effect = lambda: [
        subnet for subnet in INTERFACES.values() if subnet.type == "subnet"]
    fake_connection.network.ports.side_effect = lambda: [
        port for port in INTERFACES.values() if port.type == "port"]

    monkeypatch.setattr(openstack, "connect", lambda: fake_connection)

    yield fake_connection

    INTERFACES.clear()


@pytest.fixture
def add_interface():
    def _add_interface(interface, interface_id, **kwargs):
        global INTERFACES
        INTERFACES.update({
            interface_id: FakeOpenStackInterface(interface, interface_id,
                                                 **kwargs)
        })

    yield _add_interface


@pytest.fixture
def remove_interface():
    def _remove_interface(interface_id):
        global INTERFACES
        del INTERFACES[interface_id]

    yield _remove_interface


def get_check_raises(check_script):
    def check_raises(exp_error, exp_count, *args, **kwargs):
        """run check with checking number of IDs"""
        def comma_join(interfaces):
            assert exp_count == len(interfaces), "Unexpected number of IDs"
            return ",".join(interfaces)

        with mock.patch.object(check_script, "SEPARATOR") as mock_sep:
            mock_sep.join.side_effect = comma_join
            if exp_error:
                with pytest.raises(exp_error):
                    check_script.check(*args, **kwargs)
            else:
                check_script.check(*args, **kwargs)

    return check_raises


@pytest.fixture
def check_interface_raises():
    yield get_check_raises(check_openstack_interface)


@pytest.fixture
def check_loadbalancer_raises():
    yield get_check_raises(check_openstack_loadbalancer)
