from unittest import mock
from unittest.mock import patch, MagicMock

import pytest

import charms.unit_test


charms.unit_test.patch_reactive()
charms.unit_test.patch_module('subprocess')
charms.unit_test.patch_module('urllib.request')
charms.unit_test.patch_module('charms.leadership')
patch('time.sleep').start()


@pytest.fixture
def config():
    with mock.patch("charmhelpers.core.hookenv.config") as mock_config:
        mock_config.return_value = _config = MagicMock()
        _config.get.return_value = None
        _config.changed.return_value = True

        yield _config
