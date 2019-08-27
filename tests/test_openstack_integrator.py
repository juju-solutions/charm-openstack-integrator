import pytest
from unittest import mock

from charms.layer import openstack


@pytest.fixture
def urlopen():
    p = mock.patch('charms.layer.openstack.urlopen')
    yield p.start()
    p.stop()


@pytest.fixture
def log_err():
    p = mock.patch('charms.layer.openstack.log_err')
    yield p.start()
    p.stop()


def test_determine_version(urlopen, log_err):
    assert openstack._determine_version({'version': 3}, None) == '3'
    assert not urlopen.called
    assert not log_err.called

    assert openstack._determine_version({}, 'https://endpoint/2') == '2'
    assert openstack._determine_version({}, 'https://endpoint/v2') == '2'
    assert openstack._determine_version({}, 'https://endpoint/v2.0') == '2.0'
    assert not urlopen.called
    assert not log_err.called

    read = urlopen().__enter__().read
    read.return_value = (
        b'{"version": {"id": "v3.12", "status": "stable", '
        b'"updated": "2019-01-22T00:00:00Z", "links": [{"rel": "self", '
        b'"href": "http://10.244.40.88:5000/v3/"}], "media-types": [{'
        b'"base": "application/json", '
        b'"type": "application/vnd.openstack.identity-v3+json"}]}}')
    assert openstack._determine_version({}, 'https://endpoint/') == '3'
    assert not log_err.called

    read.return_value = b'.'
    assert openstack._determine_version({}, 'https://endpoint/') is None
    assert log_err.called

    read.return_value = b'\xff'
    assert openstack._determine_version({}, 'https://endpoint/') is None

    read.return_value = b'{}'
    assert openstack._determine_version({}, 'https://endpoint/') is None
