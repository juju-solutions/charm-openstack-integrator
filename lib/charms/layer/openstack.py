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

    # try credentials config
    if config['credentials']:
        try:
            creds_data = b64decode(config['credentials']).decode('utf8')
            creds_data = json.loads(creds_data)
            log('Using "credentials" config values for credentials')
            _save_creds(creds_data)
            return True
        except Exception:
            status.blocked('invalid value for credentials config')
            return False
    no_creds_msg = 'missing credentials; set credentials config'

    # try individual config
    if any([config['auth-url'],
            config['username'],
            config['password'],
            config['project-name'],
            config['user-domain-name'],
            config['project-domain-name']]):
        log('Using individual config values for credentials')
        _save_creds(config)
        return True

    # try to use Juju's trust feature
    try:
        result = subprocess.run(['credential-get'],
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        creds_data = yaml.load(result.stdout.decode('utf8'))
        log('Using credentials-get for credentials')
        _save_creds(creds_data)
        return True
    except FileNotFoundError:
        pass  # juju trust not available
    except subprocess.CalledProcessError as e:
        if 'permission denied' not in e.stderr.decode('utf8'):
            raise
        no_creds_msg = 'missing credentials access; grant with: juju trust'

    # no creds provided
    status.blocked(no_creds_msg)
    return False


def get_user_credentials():
    return _load_creds()


def cleanup():
    pass

# Internal helpers


def _save_creds(creds_data):
    if 'endpoint' in creds_data:
        endpoint = creds_data['endpoint']
        attrs = creds_data['credential']['attributes']
    else:
        attrs = creds_data
        endpoint = attrs['auth-url']
    kv().set('charm.openstack.full-creds', dict(
        auth_url=endpoint,
        username=attrs['username'],
        password=attrs['password'],
        user_domain_name=attrs['user-domain-name'],
        project_domain_name=attrs['project-domain-name'],
        project_name=attrs.get('project-name', attrs.get('tenant-name')),
    ))


def _load_creds():
    return kv().get('charm.openstack.full-creds')
