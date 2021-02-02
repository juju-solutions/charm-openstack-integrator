from unittest import mock
from unittest.mock import MagicMock

import nrpe_helpers

from reactive import openstack
from charms.reactive import is_flag_set


@mock.patch("reactive.openstack.update_nrpe_config")
def test_initial_nrpe_config(mock_update_nrpe_config):
    openstack.initial_nrpe_config()
    assert is_flag_set("nrpe-external-master.initial-config")
    mock_update_nrpe_config.assert_called_once()


@mock.patch("charms.layer.openstack._get_creds_env")
@mock.patch("charms.layer.openstack.create_nrpe_check_cmd")
@mock.patch("charmhelpers.contrib.charmsupport.nrpe.NRPE")
def test_update_nrpe_config(mock_nrpe, mock_create_nrpe_check_cmd,
                            mock_get_creds_env, config):
    mock_create_nrpe_check_cmd.return_value = "test cmd"
    mock_nrpe_setup = MagicMock()
    mock_nrpe.return_value = mock_nrpe_setup
    mock_get_creds_env.return_value = {}

    # no NRPE checks were added
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_not_called()
    assert mock_nrpe_setup.remove_check.call_count == 8
    mock_nrpe_setup.reset_mock()

    # add NRPE check for kubernetes subnet
    config.get.side_effect = lambda k: {"subnet-id": "1234"}.get(k)
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_called_once_with(
        shortname="kubernetes_subnet",
        description="Check subnets: 1234",
        check_cmd="test cmd"
    )
    assert mock_nrpe_setup.remove_check.call_count == 7
    mock_create_nrpe_check_cmd.assert_any_call(nrpe_helpers.NRPE_CHECKS[0])
    mock_nrpe_setup.reset_mock()
    mock_create_nrpe_check_cmd.reset_mock()

    # add NRPE check for servers
    config.get.side_effect = lambda k: {"nrpe-server-ids": "1,2,3"}.get(k)
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_called_once_with(
        shortname="openstack_servers",
        description="Check servers: 1,2,3",
        check_cmd="test cmd"
    )
    mock_create_nrpe_check_cmd.assert_any_call(nrpe_helpers.NRPE_CHECKS[6])
    assert mock_nrpe_setup.remove_check.call_count == 7
    mock_nrpe_setup.reset_mock()
    mock_create_nrpe_check_cmd.reset_mock()

    # add NRPE check for networks with skip-ids
    test_config = {"nrpe-server-ids": "all", "nrpe-skip-server-ids": "1,2"}
    config.get.side_effect = lambda k: test_config.get(k)
    openstack.update_nrpe_config()
    mock_nrpe_setup.add_check.assert_called_once_with(
        shortname="openstack_servers",
        description="Check servers: all",
        check_cmd="test cmd"
    )
    mock_create_nrpe_check_cmd.assert_any_call(nrpe_helpers.NRPE_CHECKS[6])
    assert mock_nrpe_setup.remove_check.call_count == 7
    mock_nrpe_setup.reset_mock()
    mock_create_nrpe_check_cmd.reset_mock()


@mock.patch("charms.layer.openstack._get_creds_env")
@mock.patch("charms.layer.openstack.create_nrpe_check_cmd")
@mock.patch("charmhelpers.contrib.charmsupport.nrpe.NRPE")
def test_remove_nrpe_config(mock_nrpe, mock_create_nrpe_check_cmd,
                            mock_get_creds_env, config):
    mock_create_nrpe_check_cmd.return_value = "test cmd"
    mock_nrpe_setup = MagicMock()
    mock_nrpe.return_value = mock_nrpe_setup
    mock_get_creds_env.return_value = {}

    # no NRPE checks were removed
    openstack.remove_nrpe_config()
    mock_nrpe_setup.remove_check.assert_not_called()
    mock_nrpe_setup.reset_mock()

    # remove NRPE check for kubernetes network
    config.get.side_effect = lambda k: {"floating-network-id": "1"}.get(k)
    openstack.remove_nrpe_config()
    mock_nrpe_setup.remove_check.assert_called_with(
        shortname="kubernetes_network", description="", chech_cmd="test cmd"
    )
    mock_nrpe_setup.reset_mock()
