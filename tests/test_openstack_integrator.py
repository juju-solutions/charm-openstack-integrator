import os
import pytest
import tempfile
from base64 import b64encode
from pathlib import Path
from unittest import mock

from charms.layer import openstack


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with mock.patch(patch_target) as m:
            yield m
    return _fixture


urlopen = patch_fixture('charms.layer.openstack.urlopen')
log_err = patch_fixture('charms.layer.openstack.log_err')
load_creds = patch_fixture('charms.layer.openstack._load_creds')
run = patch_fixture('subprocess.run')


@pytest.fixture
def cert_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = Path(tmpdir) / 'test.crt'
        with mock.patch('charms.layer.openstack.CA_CERT_FILE', cert_file):
            yield cert_file


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


def _b64(s):
    return b64encode(s.encode('utf8')).decode('utf8')


def test_run_with_creds(cert_file, load_creds, run):
    load_creds.return_value = {
        'auth_url': 'auth_url',
        'region': 'region',
        'username': 'username',
        'password': 'password',
        'user_domain_name': 'user_domain_name',
        'project_domain_name': 'project_domain_name',
        'project_name': 'project_name',
        'endpoint_tls_ca': _b64('endpoint_tls_ca'),
        'version': '3',
    }
    with mock.patch.dict(os.environ, {'PATH': 'path'}):
        openstack._run_with_creds('my', 'args')
    assert cert_file.exists()
    assert cert_file.read_text() == 'endpoint_tls_ca\n'
    assert run.call_args == mock.call(('my', 'args'), env={
        'PATH': '/snap/bin:path',
        'OS_AUTH_URL': 'auth_url',
        'OS_USERNAME': 'username',
        'OS_PASSWORD': 'password',
        'OS_REGION_NAME': 'region',
        'OS_USER_DOMAIN_NAME': 'user_domain_name',
        'OS_PROJECT_NAME': 'project_name',
        'OS_PROJECT_DOMAIN_NAME': 'project_domain_name',
        'OS_IDENTITY_API_VERSION': '3',
        'OS_CACERT': str(cert_file),
    }, check=True, stdout=mock.ANY)

    load_creds.return_value['endpoint_tls_ca'] = _b64('foo')
    openstack._run_with_creds('my', 'args')
    assert cert_file.read_text() == 'foo\n'

    load_creds.return_value['endpoint_tls_ca'] = None
    del load_creds.return_value['version']
    openstack._run_with_creds('my', 'args')
    env = run.call_args[1]['env']
    assert env['OS_CACERT'] == str(cert_file)
    assert 'OS_IDENTITY_API_VERSION' not in env

    cert_file.unlink()
    load_creds.return_value['version'] = None
    openstack._run_with_creds('my', 'args')
    env = run.call_args[1]['env']
    assert 'OS_CACERT' not in env
    assert 'OS_IDENTITY_API_VERSION' not in env
