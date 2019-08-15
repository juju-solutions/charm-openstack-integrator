import json
import os
import subprocess
from base64 import b64decode, b64encode
from pathlib import Path

import yaml

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


# When debugging hooks, for some reason HOME is set to /home/ubuntu, whereas
# during normal hook execution, it's /root. Set it here to be consistent.
os.environ['HOME'] = '/root'

CA_CERT_FILE = Path('/etc/openstack-integrator/ca.crt')


def log(msg, *args):
    hookenv.log(msg.format(*args), hookenv.INFO)


def log_err(msg, *args):
    hookenv.log(msg.format(*args), hookenv.ERROR)


def get_credentials():
    """
    Get the credentials from either the config or the hook tool.

    Prefers the config so that it can be overridden.
    """
    config = hookenv.config()

    required_fields = [
        'auth_url',
        'region',
        'username',
        'password',
        'user_domain_name',
        'project_domain_name',
        'project_name',
    ]
    optional_fields = [
        'endpoint_tls_ca',
    ]
    # pre-populate with empty values to avoid key and arg errors
    creds_data = {field: '' for field in required_fields + optional_fields}

    try:
        # try to use Juju's trust feature
        try:
            log('Checking credentials-get for credentials')
            result = subprocess.run(['credential-get'],
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _creds_data = yaml.safe_load(result.stdout.decode('utf8'))
            _merge_if_set(creds_data, _normalize_creds(_creds_data))
        except FileNotFoundError:
            pass  # juju trust not available
        except subprocess.CalledProcessError as e:
            if 'permission denied' not in e.stderr.decode('utf8'):
                raise

        # merge in combined credentials config
        if config['credentials']:
            try:
                log('Using "credentials" config values for credentials')
                _creds_data = b64decode(config['credentials']).decode('utf8')
                _creds_data = json.loads(_creds_data)
                _merge_if_set(creds_data, _normalize_creds(_creds_data))
            except Exception:
                status.blocked('invalid value for credentials config')
                return False

        # merge in individual config
        _merge_if_set(creds_data, _normalize_creds(config))
    except ValueError as e:
        if str(e).startswith('unsupported auth-type'):
            status.blocked(str(e))
            return False

    if all(creds_data[k] for k in required_fields):
        _save_creds(creds_data)
        return True
    else:
        # no creds provided
        status.blocked('missing credentials; '
                       'grant with `juju trust` or set via config')
        return False


def get_user_credentials():
    return _load_creds()


def detect_octavia():
    """
    Determine whether the underlying OpenStack is using Octavia or not.

    Returns True if Octavia is found, and False otherwise.
    """
    catalog = {s['Name'] for s in _openstack('catalog', 'list')}
    return 'octavia' in catalog


def cleanup():
    pass


# Internal helpers


def _merge_if_set(dst, src):
    for k, v in src.items():
        if v:
            dst[k] = v


def _normalize_creds(creds_data):
    if 'endpoint' in creds_data:
        endpoint = creds_data['endpoint']
        region = creds_data['region']
        attrs = creds_data['credential']['attributes']
    else:
        attrs = creds_data
        endpoint = attrs['auth-url']
        region = attrs['region']

    if attrs.get('auth-type') not in ('userpass', None):
        raise ValueError('unsupported auth-type in credentials: '
                         '{}'.format(attrs.get('auth-type')))

    ca_cert = None
    # seems like this might have changed at some point;
    # newer controllers return the latter
    trust_ca_key = {'ca-certificates', 'cacertificates'} & creds_data.keys()
    if trust_ca_key:
        # see K8s commit e3c8a0ceb66816433b095c4d734663e1b1e0e4ea
        # K8s in-tree cloud provider code is not flexible enough
        # to accept multiple certs that could be provided by Juju
        # so we can grab the first one only and hope it is the
        # right one
        ca_certificates = creds_data[trust_ca_key.pop()]
        if ca_certificates:
            ca_cert = ca_certificates[0]
    elif 'endpoint-tls-ca' in creds_data:
        ca_cert = creds_data['endpoint-tls-ca']

    # interface expects it b64 encoded; that seems unnecessary,
    # but we should ensure that it follows the interface docs
    if ca_cert:
        ca_cert = ca_cert.encode('utf8')  # b64 deals with bytes
        try:
            ca_cert = b64decode(ca_cert)
        except Exception:
            pass  # might not be encoded
        ca_cert = b64encode(ca_cert)  # ensure is encoded
        ca_cert = ca_cert.decode('utf8')  # relations deal with strings

    return dict(
        auth_url=endpoint,
        region=region,
        username=attrs['username'],
        password=attrs['password'],
        user_domain_name=attrs['user-domain-name'],
        project_domain_name=attrs['project-domain-name'],
        project_name=attrs.get('project-name', attrs.get('tenant-name')),
        endpoint_tls_ca=ca_cert,
        version=attrs.get('version'),
    )


def _save_creds(creds_data):
    kv().set('charm.openstack.full-creds', creds_data)


def _load_creds():
    return kv().get('charm.openstack.full-creds')


def _run_with_creds(*args):
    creds = _load_creds()
    env = {
        'OS_AUTH_URL': creds['auth_url'],
        'OS_USERNAME': creds['username'],
        'OS_PASSWORD': creds['password'],
        'OS_REGION_NAME': creds['region'],
        'OS_USER_DOMAIN_NAME': creds['user_domain_name'],
        'OS_PROJECT_NAME': creds['project_name'],
        'OS_PROJECT_DOMAIN_NAME': creds['project_domain_name'],
        'OS_AUTH_VERSION': creds['version'],
        'OS_IDENTITY_API_VERSION': creds['version'],
    }
    if creds['endpoint-tls-ca'] and not CA_CERT_FILE.exists():
        ca_cert = b64decode(creds['endpoint-tls-ca'].encode('utf8'))
        CA_CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
        CA_CERT_FILE.write_text(ca_cert + '\n')
    if CA_CERT_FILE.exists():
        env['OS_CACERT'] = str(CA_CERT_FILE)

    result = subprocess.run(args,
                            env=env,
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    return result.stdout.decode('utf8')


def _openstack(*args):
    output = _run_with_creds('openstack', *args, '--format=yaml')
    return yaml.safe_load(output)
