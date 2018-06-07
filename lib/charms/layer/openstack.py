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
    no_creds_msg = 'missing credentials; set credentials config'
    config = hookenv.config()
    # try to use Juju's trust feature
    try:
        result = subprocess.run(['credential-get'],
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        creds = yaml.load(result.stdout.decode('utf8'))
        creds_data = creds
        _save_creds(creds_data)
        return True
    except FileNotFoundError:
        pass  # juju trust not available
    except subprocess.CalledProcessError as e:
        if 'permission denied' not in e.stderr.decode('utf8'):
            raise
        no_creds_msg = 'missing credentials access; grant with: juju trust'

    # try credentials config
    if config['credentials']:
        try:
            creds_data = b64decode(config['credentials']).decode('utf8')
            _save_creds(creds_data)
            return True
        except Exception:
            status.blocked('invalid value for credentials config')
            return False

    # no creds provided
    status.blocked(no_creds_msg)
    return False


def get_user_credentials():
    return _load_creds()


def cleanup():
    pass

# Internal helpers


def _save_creds(creds_data):
    attrs = creds_data['credential']['attributes']
    kv().set('charm.openstack.full-creds', dict(
        auth_url=creds_data['endpoint'],
        username=attrs['username'],
        password=attrs['password'],
        user_domain_name=attrs['user-domain-name'],
        project_domain_name=attrs['project-domain-name'],
        project_name=attrs['tenant-name'],
    ))


def _load_creds():
    return kv().get('charm.openstack.full-creds')
