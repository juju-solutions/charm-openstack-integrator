from unittest import mock
from unittest.mock import MagicMock

import pytest

from reactive import openstack
from charms.layer.nagios import NAGIOS_PLUGINS_DIR
from charms.reactive import is_flag_set
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.core.hookenv import config


@mock.patch("reactive.openstack.update_nrpe_config")
def test_initial_nrpe_config(mock_update_nrpe_config):
    openstack.initial_nrpe_config()
    assert is_flag_set("nrpe-external-master.initial-config")
    mock_update_nrpe_config.assert_called_once()


@mock.patch("charms.layer.openstack.write_nagios_openstack_cnf")
def test_update_nrpe_config(mock_write_nagios_openstack_cnf, openstack_config):
    nrpe.NRPE.return_value = mock_nrpe_setup = MagicMock()
    NAGIOS_PLUGINS_DIR.__fspath__.return_value = "/test/"
    config.return_value = openstack_config

    # no NRPE checks were added / deleted
    openstack_config.changed.return_value = False
    openstack_config.get.side_effect = {}.get
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_not_called()
    mock_nrpe_setup.remove_check.assert_not_called()
    mock_write_nagios_openstack_cnf.assert_called_once_with()
    mock_write_nagios_openstack_cnf.reset_mock()
    mock_nrpe_setup.reset_mock()
    openstack_config.reset_mock()

    # add NRPE check for kubernetes subnet
    openstack_config.changed.return_value = True
    openstack_config.get.side_effect = {"subnet-id": "1234"}.get
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_called_once_with(
        shortname="kubernetes_subnet",
        description="Check subnets: 1234",
        check_cmd="/test/check_openstack_interface.py subnet "
                  "-c /etc/nagios/openstack.cnf --id 1234"
    )
    assert mock_nrpe_setup.remove_check.call_count == 7
    mock_nrpe_setup.reset_mock()
    openstack_config.reset_mock()

    # add NRPE check for servers
    openstack_config.changed.return_value = True
    openstack_config.get.side_effect = {"nrpe-server-ids": "1,2,3"}.get
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_called_once_with(
        shortname="openstack_servers",
        description="Check servers: 1,2,3",
        check_cmd="/test/check_openstack_interface.py server "
                  "-c /etc/nagios/openstack.cnf --id 1 --id 2 --id 3"
    )
    assert mock_nrpe_setup.remove_check.call_count == 7
    mock_nrpe_setup.reset_mock()
    openstack_config.reset_mock()

    # add NRPE check for servers with skip-ids
    openstack_config.changed.return_value = True
    openstack_config.get.side_effect = {"nrpe-server-ids": "all",
                                        "nrpe-skip-server-ids": "1,2"}.get
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_called_once_with(
        shortname="openstack_servers",
        description="Check servers: all",
        check_cmd="/test/check_openstack_interface.py server "
                  "-c /etc/nagios/openstack.cnf --all --skip-id 1 --skip-id 2"
    )
    assert mock_nrpe_setup.remove_check.call_count == 7
    mock_nrpe_setup.reset_mock()
    openstack_config.reset_mock()

    # raise a ValueError while adding NRPE check
    openstack_config.changed.return_value = True
    openstack_config.get.side_effect = {"nrpe-server-ids": "1,2",
                                        "nrpe-skip-server-ids": "1"}.get
    with pytest.raises(ValueError):
        openstack.update_nrpe_config()

    openstack_config.get.side_effect = {"subnet-id": "all"}.get

    with pytest.raises(ValueError):
        openstack.update_nrpe_config()

    openstack_config.reset_mock()


@mock.patch("charms.layer.openstack.remove_nagios_openstack_cnf")
def test_remove_nrpe_config(mock_remove_nagios_openstack_cnf,
                            openstack_config):
    nrpe.NRPE.return_value = mock_nrpe_setup = MagicMock()
    NAGIOS_PLUGINS_DIR.__fspath__.return_value = "/test/"
    config.return_value = openstack_config

    # no NRPE checks were removed
    openstack_config.get.side_effect = {}.get
    openstack.remove_nrpe_config()
    mock_nrpe_setup.remove_check.assert_not_called()
    mock_remove_nagios_openstack_cnf.assert_called_once_with()
    mock_remove_nagios_openstack_cnf.reset_mock()
    mock_nrpe_setup.reset_mock()

    # remove NRPE check for kubernetes network
    openstack_config.get.side_effect = {"nrpe-server-ids": "1,2,3"}.get
    openstack.remove_nrpe_config()
    mock_nrpe_setup.remove_check.assert_called_once_with(
        shortname="openstack_servers", description="",
        chech_cmd="/test/check_openstack_interface.py server "
                  "-c /etc/nagios/openstack.cnf --id 1 --id 2 --id 3"
    )
    mock_remove_nagios_openstack_cnf.assert_called_once_with()
    mock_remove_nagios_openstack_cnf.reset_mock()
    mock_nrpe_setup.reset_mock()
