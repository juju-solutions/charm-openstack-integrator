import json
import re
import os
import subprocess
import time
from base64 import b64decode, b64encode
from ipaddress import ip_address, ip_network
from pathlib import Path
from traceback import format_exc
from urllib.request import urlopen

import yaml

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


# When debugging hooks, for some reason HOME is set to /home/ubuntu, whereas
# during normal hook execution, it's /root. Set it here to be consistent.
os.environ['HOME'] = '/root'

CA_CERT_FILE = Path('/etc/openstack-integrator/ca.crt')
MODEL_UUID = os.environ['JUJU_MODEL_UUID']
MODEL_SHORT_ID = MODEL_UUID.split('-')[-1]
config = hookenv.config()


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
    try:
        catalog = {s['Name'] for s in _openstack('catalog', 'list')}
    except Exception:
        log_err('Error while trying to detect Octavia\n{}', format_exc())
        return None
    return 'octavia' in catalog


def manage_loadbalancer(app_name, members):
    log('Managing load balancer for {}', app_name)
    subnet = config['lb-subnet'] or _default_subnet(members)
    fip_net = config['lb-floating-network']
    port = str(config['lb-port'])
    lb_algorithm = config['lb-method']
    manage_secgrps = config['manage-security-groups']
    lb = LoadBalancer.get_or_create(app_name,
                                    port,
                                    subnet,
                                    lb_algorithm,
                                    fip_net,
                                    manage_secgrps)
    lb.update_members(members)
    return lb


def cleanup():
    # note: we don't bother cleaning up the SG because it's a singleton
    # and can be reused in other / future deployments
    for lb in LoadBalancer.get_all():
        try:
            lb.delete()
        except OpenStackLBError:
            # we're dying anyway, so we can't report this, but maybe we can
            # delete the rest
            pass


class OpenStackError(Exception):
    pass


class OpenStackLBError(OpenStackError):
    def __init__(self, action, exc=True):
        action = action[:-1]+'ing'
        if exc:
            log_err('Error {} loadbalancer\n{}', action, format_exc())
        super().__init__('Error while {} load balancer; '
                         'check credential and debug-log'.format(action))


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
        version=_determine_version(attrs, endpoint),
    )


def _save_creds(creds_data):
    kv().set('charm.openstack.full-creds', creds_data)


def _load_creds():
    return kv().get('charm.openstack.full-creds')


def _run_with_creds(*args):
    creds = _load_creds()
    env = {
        'PATH': os.pathsep.join(['/snap/bin', os.environ['PATH']]),
        'OS_AUTH_URL': creds['auth_url'],
        'OS_USERNAME': creds['username'],
        'OS_PASSWORD': creds['password'],
        'OS_REGION_NAME': creds['region'],
        'OS_USER_DOMAIN_NAME': creds['user_domain_name'],
        'OS_PROJECT_NAME': creds['project_name'],
        'OS_PROJECT_DOMAIN_NAME': creds['project_domain_name'],
    }
    if creds.get('version'):
        # version should always be added by _normalize_creds, but it might
        # be empty in which case we shouldn't set the env vars
        env['OS_IDENTITY_API_VERSION'] = creds['version']
    if creds['endpoint_tls_ca']:
        ca_cert = b64decode(creds['endpoint_tls_ca'].encode('utf8'))
        CA_CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
        CA_CERT_FILE.write_text(ca_cert.decode('utf8') + '\n')
    if CA_CERT_FILE.exists():
        env['OS_CACERT'] = str(CA_CERT_FILE)

    result = subprocess.run(args,
                            env=env,
                            check=True,
                            stdout=subprocess.PIPE)
    return result.stdout.decode('utf8')


def _openstack(*args):
    output = _run_with_creds('openstack', *args, '--format=yaml')
    return yaml.safe_load(output)


def _neutron(*args):
    output = _run_with_creds('neutron', *args, '--format=yaml')
    return yaml.safe_load(output)


def _determine_version(attrs, endpoint):
    if attrs.get('version'):
        return str(attrs['version'])

    url_ver = re.search(r'/v?(\d+(.\d+)?)$', endpoint)
    if url_ver:
        return url_ver.group(1)

    with urlopen(endpoint) as fp:
        try:
            info = json.loads(fp.read(600).decode('utf8'))
            return str(info['version']['id']).split('.')[0].lstrip('v')
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as e:
            log_err('Failed to determine API version: {}', e)
            return None


def _default_subnet(members):
    """
    Find the subnet which contains the given address.
    """
    address, _ = members[0]
    address = ip_address(address)
    for subnet_info in _openstack('subnet', 'list'):
        subnet = ip_network(subnet_info['Subnet'])
        if address in subnet:
            return subnet_info['Name']
    else:
        log_err('Unable to find subnet for {}', address)
        raise OpenStackLBError(action='create', exc=False)


class LoadBalancer:
    """
    Base class for wrapper around the OpenStack CLI.
    """
    octavia_available = None

    @classmethod
    def get_or_create(cls, app_name, port, subnet, algorithm, fip_net,
                      manage_secgrps):
        """
        Create a client instance for the given LB.

        Returns the proper subclass depending on whether Octavia is available.
        """
        lb = cls(app_name, port, subnet, algorithm, fip_net, manage_secgrps)
        if not lb.is_created:
            try:
                lb.create()
            except subprocess.CalledProcessError:
                raise OpenStackLBError(action='create')
        return lb

    def __init__(self, app_name, port, subnet, algorithm, fip_net,
                 manage_secgrps):
        self.name = 'openstack-integrator-{}-{}'.format(MODEL_SHORT_ID,
                                                        app_name)
        self.port = port
        self.subnet = subnet
        self.algorithm = algorithm
        self.fip_net = fip_net
        self.manage_secgrps = manage_secgrps
        self._key = 'created_lbs.{}'.format(self.name)
        self.sg_id = None
        self.fip = None
        self.address = None
        self.members = set()
        self.is_created = False
        self._try_load_cached_info()
        self._impl = self._get_impl()

    def _get_impl(self):
        cls = type(self)
        if cls.octavia_available is None:
            cls.octavia_available = detect_octavia()
        if cls.octavia_available:
            return OctaviaLBImpl(self.name,
                                 self.port,
                                 self.subnet,
                                 self.algorithm,
                                 self.fip_net,
                                 self.manage_secgrps)
        else:
            return NeutronLBImpl(self.name,
                                 self.port,
                                 self.subnet,
                                 self.algorithm,
                                 self.fip_net,
                                 self.manage_secgrps)

    def create(self):
        """
        Create this loadbalancer for the first time.
        """
        # we may have a partially created LB, so we need to check
        # whether we successfully got past creating the LB itself, or
        # even if the partial-LB was manually cleaned up by the operator
        lb_info = self._find('load balancers',
                             self._impl.list_loadbalancers())
        if lb_info:
            # list doesn't contain all of the info we need
            lb_info = self._impl.show_loadbalancer()
            log('Found existing load balancer {} ({})',
                self.name, lb_info['id'])
        else:
            lb_info = self._impl.create_loadbalancer()
            log('Created load balancer {} ({})', self.name, lb_info['id'])
            self._wait_lb_not_pending()
        self.address = lb_info['vip_address']

        if self.manage_secgrps:
            sg_id = self._impl.find_secgrp(self.name)
            if sg_id:
                log('Found existing security group {} ({})', self.name, sg_id)
            else:
                sg_id = self._impl.create_secgrp(self.name)
                log('Created security group {} ({})', self.name, sg_id)
            self.sg_id = sg_id
            if self._impl.get_port_sec_enabled():
                self._impl.set_port_secgrp(lb_info['vip_port_id'], sg_id)
                log('Added security group {} ({}) to port {}',
                    self.name, sg_id, lb_info['vip_port_id'])
                self._wait_lb_not_pending()
        else:
            sg_id = self._impl.find_secgrp('default')
            if not sg_id:
                log_err('Unable to find default security group')
                raise OpenStackLBError(action='create', exc=False)
            log('Using default security group ({})', sg_id)
        if not self._find_matching_sg_rule(sg_id):
            self._impl.create_sg_rule(sg_id, self.address)
            log('Added rule for {}:{} to security group {} ({})',
                self.address, self.port, self.name, sg_id)
        else:
            log('Found matching rule for {}:{} on security group {} ({})',
                self.address, self.port, self.name, sg_id)

        if not self._find('listeners', self._impl.list_listeners()):
            self._impl.create_listener()
            log('Created listener for {}:{}', self.address, self.port)
            self._wait_lb_not_pending()
        else:
            log('Found existing listener for {}:{}', self.address, self.port)

        if not self._find('pools', self._impl.list_pools()):
            self._impl.create_pool()
            log('Created pool {} using {}', self.name, self.algorithm)
            self._wait_lb_not_pending()
            self._wait_pool_not_pending()
        else:
            log('Found existing pool {}', self.name)

        if self.fip_net:
            for fip in self._impl.list_fips():
                # why are these keys so inconsistent? :(
                if fip['Fixed IP Address'] == self.address:
                    self.fip = fip['Floating IP Address']
                    log('Found existing FIP for {} -> {}',
                        self.fip, self.address)
                    break
            else:
                self.fip = self._impl.create_fip(self.address,
                                                 lb_info['vip_port_id'])
                log('Created FIP for {} -> {}', self.fip, self.address)

        self.members = self._impl.list_members()
        if self.members:
            log('Found existing members: {}', self.members)

        self._update_cached_info()
        self.is_created = True

    def _wait_not_pending(self, show_func):
        for retry in range(30):
            lb_status = show_func()['provisioning_status']
            if not lb_status.startswith('PENDING_'):
                break
            time.sleep(2)
        if lb_status != 'ACTIVE':
            log_err('Invalid status when creating load balancer {}: {}',
                    self.name, lb_status)
            raise OpenStackLBError(action=('update' if self.is_created else
                                           'create'), exc=False)

    def _wait_lb_not_pending(self):
        self._wait_not_pending(self._impl.show_loadbalancer)

    def _wait_pool_not_pending(self):
        if not isinstance(self._impl, NeutronLBImpl):
            self._wait_not_pending(self._impl.show_pool)

    def _find_matching_sg_rule(self, sg_id):
        address = ip_address(self.address)
        port = int(self.port)
        for rule in self._impl.list_sg_rules(sg_id):
            if rule['Port Range']:
                port_min, port_max = rule['Port Range'].split(':')
                port_match = int(port_min) <= int(port) <= int(port_max)
            else:
                port_match = True
            ip_match = address in ip_network(rule['IP Range'] or '0.0.0.0/0')
            if port_match and ip_match:
                return True
        return False

    def _find(self, description, items):
        """
        Find the single item from the list whose 'name' field matches our
        name.  The description is used for the error message.
        """
        results = []
        for item in items:
            if item['name'] == self.name:
                results.append(item)
        if len(results) > 1:
            log_err('Multiple {} found: {}', description, self.name)
            raise OpenStackLBError(action='create', exc=False)
        return results[0] if results else None

    def update_members(self, members):
        """
        Add or remove members to the load balancer to match the given set.
        """
        members = set(members)
        if self.members == members:
            return

        try:
            removed_members = self.members - members
            for member in removed_members:
                self._impl.delete_member(member)
                log('Removed member: {}', member)
                self._wait_pool_not_pending()

            added_members = members - self.members
            for member in added_members:
                self._impl.create_member(member)
                log('Added member: {}', member)
                self._wait_pool_not_pending()
        except subprocess.CalledProcessError:
            raise OpenStackLBError(action='update')

        self.members = members
        self._update_cached_info()

    def delete(self):
        """
        Delete this loadbalancer and all of its resources.
        """
        try:
            # this would be easier if we could rely on --cascade,
            # but it's not available with neutron
            if self.fip:
                self._impl.delete_fip()
            for member in self.members:
                self._impl.delete_member(member)
            self._impl.delete_pool()
            self._impl.delete_listener()
            if self.sg_id:
                self._impl.delete_secgrp()
            self._impl.delete_loadbalancer()
        except subprocess.CalledProcessError:
            raise OpenStackLBError(action='delete')

    def _try_load_cached_info(self):
        info = kv().get(self._key)
        if info:
            self.sg_id = info['sg_id']
            self.fip = info['fip']
            self.address = info['address']
            self.members = {tuple(m) for m in info['members']}
            self.is_created = True

    def _update_cached_info(self):
        kv().set(self._key, {
            'sg_id': self.sg_id,
            'fip': self.fip,
            'address': self.address,
            'members': list(self.members),
        })


class BaseLBImpl:
    def __init__(self, name, port, subnet, algorithm, fip_net, manage_secgrps):
        self.name = name
        self.port = port
        self.subnet = subnet
        self.algorithm = algorithm
        self.fip_net = fip_net
        self.manage_secgrps = manage_secgrps
        self._project_id = kv().get('project_id')

    @property
    def project_id(self):
        if not self._project_id:
            creds = _load_creds()
            project = creds['project_name']
            project_domain = creds['project_domain_name']
            self._project_id = _openstack('project', 'show',
                                          '--domain', project_domain,
                                          project)['id']
            kv().set('project_id', self._project_id)
        return self._project_id

    def find_secgrp(self, name):
        secgrps = {sg['Name']: sg
                   for sg in _openstack('security', 'group', 'list',
                                        '--project', self.project_id)}
        return secgrps.get(name, {}).get('ID')

    def create_secgrp(self, name):
        sg_info = _openstack('security', 'group', 'create', name)
        return sg_info['id']

    def delete_secgrp(self, sg_id):
        _openstack('security', 'group', 'delete', sg_id)

    def list_sg_rules(self, sg_id):
        return _openstack('security', 'group', 'rule', 'list',
                          sg_id, '--ingress', '--protocol=tcp')

    def create_sg_rule(self, sg_id, address):
        _openstack('security', 'group', 'rule', 'create',
                   '--ingress',
                   '--protocol', 'tcp',
                   '--remote-ip', address,
                   '--dst-port', self.port,
                   sg_id)

    def get_port_sec_enabled(self):
        subnet_info = _openstack('subnet', 'show', self.subnet)
        network_info = _openstack('network', 'show', subnet_info['network_id'])
        return network_info['port_security_enabled']

    def set_port_secgrp(self, port_id, sg_id):
        _openstack('port', 'set', '--security-group', sg_id, port_id)

    def list_fips(self):
        return _openstack('floating', 'ip', 'list')

    def create_fip(self, address, port_id):
        fip = _openstack('floating', 'ip', 'create',
                         '--fixed-ip-address', address,
                         '--port', port_id,
                         self.fip_net)
        return fip['floating_ip_address']

    def delete_fip(self, fip):
        _openstack('floating', 'ip', 'delete', fip)

    def list_loadbalancers(self):
        raise NotImplementedError()

    def create_loadbalancer(self):
        raise NotImplementedError()

    def show_loadbalancer(self):
        raise NotImplementedError()

    def list_listeners(self):
        raise NotImplementedError()

    def create_listener(self):
        raise NotImplementedError()

    def delete_listener(self):
        raise NotImplementedError()

    def list_pools(self):
        raise NotImplementedError()

    def show_pool(self):
        raise NotImplementedError()

    def create_pool(self):
        raise NotImplementedError()

    def delete_pool(self):
        raise NotImplementedError()

    def list_members(self):
        raise NotImplementedError()

    def create_member(self, member):
        raise NotImplementedError()

    def delete_member(self, member):
        raise NotImplementedError()


class OctaviaLBImpl(BaseLBImpl):
    """
    Subclass with implementations specific to Octavia-enabled clouds.
    """
    def list_loadbalancers(self):
        return _openstack('loadbalancer', 'list')

    def create_loadbalancer(self):
        return _openstack('loadbalancer', 'create',
                          '--name', self.name,
                          '--vip-subnet-id', self.subnet)

    def show_loadbalancer(self):
        return _openstack('loadbalancer', 'show', self.name)

    def list_listeners(self):
        return _openstack('loadbalancer', 'listener', 'list')

    def create_listener(self):
        return _openstack('loadbalancer', 'listener', 'create',
                          '--name', self.name,
                          '--protocol', 'HTTPS',
                          '--protocol-port', self.port,
                          self.name)

    def delete_listener(self):
        _openstack('loadbalancer', 'listener', 'delete', self.name)

    def list_pools(self):
        return _openstack('loadbalancer', 'pool', 'list')

    def show_pool(self):
        return _openstack('loadbalancer', 'pool', 'show', self.name)

    def create_pool(self):
        return _openstack('loadbalancer', 'pool', 'create',
                          '--name', self.name,
                          '--listener', self.name,
                          '--lb-algorithm', self.algorithm,
                          '--protocol', 'HTTPS')

    def delete_pool(self):
        _openstack('loadbalancer', 'pool', 'delete', self.name)

    def list_members(self):
        return {(m['address'], m['protocol_port'])
                for m in _openstack('loadbalancer', 'member',
                                    'list', self.name)}

    def create_member(self, member):
        addr, port = member
        _openstack('loadbalancer', 'member', 'create',
                   '--name', addr,
                   '--address', addr,
                   '--protocol-port', port,
                   '--subnet-id', self.subnet,
                   self.name)

    def delete_member(self, member):
        addr, _ = member
        # nb: can't use _openstack() because member delete appears to be the
        # only command that doesn't support --format=yaml
        _run_with_creds('openstack', 'loadbalancer',
                        'member', 'delete', self.name, addr)


class NeutronLBImpl(BaseLBImpl):
    """
    Subclass with implementations specific to non-Octavia-enabled clouds.
    """
    def list_loadbalancers(self):
        return _neutron('lbaas-loadbalancer-list')

    def create_loadbalancer(self):
        return _neutron('lbaas-loadbalancer-create',
                        '--name', self.name,
                        self.subnet)

    def show_loadbalancer(self):
        return _neutron('lbaas-loadbalancer-show', self.name)

    def list_listeners(self):
        return _neutron('lbaas-listener-list')

    def create_listener(self):
        return _neutron('lbaas-listener-create',
                        '--name', self.name,
                        '--protocol', 'HTTPS',
                        '--protocol-port', self.port,
                        '--loadbalancer', self.name)

    def delete_listener(self):
        _neutron('lbaas-listener-delete', self.name)

    def list_pools(self):
        return _neutron('lbaas-pool-list')

    def show_pool(self):
        return _neutron('lbaas-pool-show', self.name)

    def create_pool(self):
        return _neutron('lbaas-pool-create',
                        '--name', self.name,
                        '--listener', self.name,
                        '--lb-algorithm', self.algorithm,
                        '--protocol', 'HTTPS')

    def delete_pool(self):
        _neutron('lbaas-pool-delete', self.name)

    def list_members(self):
        return {(m['address'], m['protocol_port'])
                for m in _neutron('lbaas-member-list', self.name)}

    def create_member(self, member):
        addr, port = member
        _neutron('lbaas-member-create',
                 '--name', addr,
                 '--address', addr,
                 '--protocol-port', port,
                 '--subnet', self.subnet,
                 self.name)

    def delete_member(self, member):
        addr, _ = member
        _neutron('lbaas-member-delete', addr, self.name)
