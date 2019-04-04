import json
import os
import subprocess
from base64 import b64decode

import yaml

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


# When debugging hooks, for some reason HOME is set to /home/ubuntu, whereas
# during normal hook execution, it's /root. Set it here to be consistent.
os.environ['HOME'] = '/root'


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

    creds_data = {}

    # try to use Juju's trust feature
    try:
        log('Checking credentials-get for credentials')
        result = subprocess.run(['credential-get'],
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        _creds_data = yaml.load(result.stdout.decode('utf8'))
        creds_data.update(_normalize_creds(_creds_data))
    except FileNotFoundError:
        pass  # juju trust not available
    except subprocess.CalledProcessError as e:
        if 'permission denied' not in e.stderr.decode('utf8'):
            raise

    # try credentials config
    if config['credentials']:
        try:
            log('Using "credentials" config values for credentials')
            _creds_data = b64decode(config['credentials']).decode('utf8')
            creds_data.update(_normalize_creds(json.loads(_creds_data)))
        except Exception:
            status.blocked('invalid value for credentials config')
            return False

    # try individual config
    creds_data.update(_normalize_creds(config))

    if all([config['auth-url'],
            config['username'],
            config['password'],
            config['project-name'],
            config['user-domain-name'],
            config['project-domain-name'],
            config['region']]):
        _save_creds(creds_data)
        return True
    else:
        # no creds provided
        status.blocked('missing credentials; '
                       'grant with `juju trust` or set via config')
        return False


def get_user_credentials():
    return _load_creds()


def cleanup():
    pass


# Internal helpers


def _normalize_creds(creds_data):
    if 'endpoint' in creds_data:
        endpoint = creds_data['endpoint']
        region = creds_data['region']
        attrs = creds_data['credential']['attributes']
    else:
        attrs = creds_data
        endpoint = attrs['auth-url']
        region = attrs['region']

    if 'ca-certificates' in creds_data:
        # see K8s commit e3c8a0ceb66816433b095c4d734663e1b1e0e4ea
        # K8s in-tree cloud provider code is not flexible enough
        # to accept multiple certs that could be provided by Juju
        # so we can grab the first one only and hope it is the
        # right one
        ca_certificates = creds_data.get('ca-certificates')
        ca_cert = ca_certificates[0] if ca_certificates else None
    elif 'endpoint-tls-ca' in creds_data:
        ca_cert = creds_data['endpoint-tls-ca']
    else:
        ca_cert = None

    return dict(
        auth_url=endpoint,
        region=region,
        username=attrs['username'],
        password=attrs['password'],
        user_domain_name=attrs['user-domain-name'],
        project_domain_name=attrs['project-domain-name'],
        project_name=attrs.get('project-name', attrs.get('tenant-name')),
        endpoint_tls_ca=ca_cert,
    )


def _save_creds(creds_data):
    kv().set('charm.openstack.full-creds', creds_data)


def _load_creds():
    return kv().get('charm.openstack.full-creds')
