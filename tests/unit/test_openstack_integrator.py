from unittest import mock
from unittest.mock import MagicMock

import charms.layer
import reactive

from reactive import openstack
from charms.reactive import clear_flag, is_flag_set, set_flag
from charmhelpers.contrib.charmsupport import nrpe


def test_series_upgrade():
    assert charms.layer.status.blocked.call_count == 0
    reactive.openstack.pre_series_upgrade()
    assert charms.layer.status.blocked.call_count == 1


@mock.patch("reactive.openstack.update_nrpe_config")
def test_initial_nrpe_config(mock_update_nrpe_config):
    clear_flag("nrpe-external-master.initial-config")
    openstack.initial_nrpe_config()
    assert is_flag_set("nrpe-external-master.initial-config")
    mock_update_nrpe_config.assert_called_once()


@mock.patch("charms.layer.openstack")
def test_update_nrpe_config(mock_openstack):
    nrpe.NRPE.return_value = nrpe_setup = MagicMock()

    # no valid NRPE configuration
    mock_openstack.validate_nrpe_configuration.return_value = False

    openstack.update_nrpe_config()
    assert is_flag_set("nrpe-external-master.bad-config")

    # valid NRPE configuration
    mock_openstack.validate_nrpe_configuration.return_value = True

    openstack.update_nrpe_config(True)
    assert not is_flag_set("nrpe-external-master.bad-config")
    mock_openstack.write_nagios_openstack_cnf.assert_called_once_with()
    mock_openstack.update_nrpe_checks_os_resources.assert_called_once_with(
        nrpe_setup, True)


@mock.patch("charms.layer.openstack")
def test_remove_nrpe_config(mock_openstack):
    set_flag("nrpe-external-master.initial-config")
    nrpe.NRPE.return_value = nrpe_setup = MagicMock()

    openstack.remove_nrpe_config()

    mock_openstack.remove_nrpe_checks_os_resources.assert_called_once_with(nrpe_setup)
    mock_openstack.remove_nagios_openstack_cnf.assert_called_once_with()
    assert not is_flag_set("nrpe-external-master.initial-config")
