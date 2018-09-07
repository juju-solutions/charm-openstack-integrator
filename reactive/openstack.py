from charmhelpers.core import hookenv
from charms.reactive import (
    hook,
    when_all,
    when_any,
    when_not,
    is_flag_set,
    toggle_flag,
    clear_flag,
)
from charms.reactive.relations import endpoint_from_name

from charms import layer


@when_any('config.changed.credentials')
def update_creds():
    clear_flag('charm.openstack.creds.set')


@when_not('charm.openstack.creds.set')
def get_creds():
    toggle_flag('charm.openstack.creds.set', layer.openstack.get_credentials())


@when_all('charm.openstack.creds.set')
@when_not('endpoint.clients.requests-pending')
def no_requests():
    layer.status.active('ready')


@when_all('charm.openstack.creds.set')
@when_any('endpoint.clients.requests-pending',
          'config.changed')
def handle_requests():
    clients = endpoint_from_name('clients')
    config_change = is_flag_set('config.changed')
    config = hookenv.config()
    if config['manage-security-groups'] and not config['node-security-group']:
        layer.status.blocked('node-security-group config required if '
                             'manage-security-groups is True')
        return
    requests = clients.all_requests if config_change else clients.new_requests
    for request in requests:
        layer.status.maintenance(
            'granting request for {}'.format(request.unit_name))
        creds = layer.openstack.get_user_credentials()
        request.set_credentials(**creds)
        request.set_lbaas_config(config['subnet-id'],
                                 config['floating-network-id'],
                                 config['lb-method'],
                                 config['manage-security-groups'],
                                 config['node-security-group'])
        layer.openstack.log('Finished request for {}', request.unit_name)
    clients.mark_completed()


@hook('stop')
def cleanup():
    layer.openstack.cleanup()
