import os
import random
import string
import subprocess
from base64 import b64decode

import yaml
from novaclient import client as novaclient_client
from keystoneclient.v3 import client as keystoneclient_v3
from keystoneauth1.session import Session
from keystoneauth1.identity.v3 import Password

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
        creds_data = creds['credential']['attributes']
        _save_creds(creds_data)
        _create_project_user()
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
            _create_project_user()
            return True
        except Exception:
            status.blocked('invalid value for credentials config')
            return False

    # no creds provided
    status.blocked(no_creds_msg)
    return False


def get_user_credentials():
    return kv().get('charm.openstack.user-creds')


def cleanup():
    _delete_project_user()


# Internal helpers


def _save_creds(creds_data):
    kv().set('charm.openstack.full-creds', dict(
        auth_url=creds_data['endpoint'],
        username=creds_data['username'],
        password=creds_data['password'],
        user_domain_name=creds_data['user-domain-name'],
        project_domain_name=creds_data['project-domain-name'],
        project_name=creds_data['tenant-name'],
    ))


def _load_creds():
    return kv().get('charm.openstack.full-creds')


def _get_keystone_client():
    auth = Password(**_load_creds())
    session = Session(auth=auth, verify=False)
    keystone = keystoneclient_v3.Client(session=session)
    keystone.auth_ref = auth.get_access(session)
    return keystone


def _get_nova_client():
    auth = Password(**_load_creds())
    session = Session(auth=auth, verify=False)
    nova = novaclient_client.Client(2, session=session)
    return nova


def _project_user_username():
    model_uuid_prefix = os.environ['JUJU_MODEL_UUID'].split('-')[0]
    unit_name = hookenv.local_unit().replace('/', '-')
    return 'juju-charm-{}-{}'.format(model_uuid_prefix, unit_name)


def _create_project_user():
    """
    Create a (slightly) more limited user in the project.
    """
    client = _get_keystone_client()
    alphabet = string.ascii_letters + string.digits
    full_creds = _load_creds()
    username = _project_user_username()
    password = ''.join(random.choice(alphabet) for _ in range(20))
    client.users.create(
        name=username,
        password=password,
        domain=full_creds['project_domain_name'],
        default_project=full_creds['project_name'],
    )
    kv().set('charm.openstack.user-creds', dict(
        auth_url=full_creds['endpoint'],
        username=username,
        password=password,
        user_domain_name=full_creds['user_domain_name'],
        project_domain_name=full_creds['project_domain_name'],
        project_name=full_creds['tenant_name'],
    ))


def _delete_project_user():
    client = _get_keystone_client()
    username = _project_user_username()
    client.users.delete(username)
    kv().unset('charm.openstack.user-creds')
