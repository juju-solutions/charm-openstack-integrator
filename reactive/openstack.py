from charms.reactive import (
    hook,
    when_all,
    when_any,
    when_not,
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
    openstack = endpoint_from_name('openstack')
    layer.openstack.cleanup(openstack.relation_ids)
    layer.status.active('ready')


@when_all('charm.openstack.creds.set',
          'endpoint.clients.requests-pending')
def handle_requests():
    openstack = endpoint_from_name('openstack')
    for request in openstack.requests:
        layer.status.maintenance(
            'granting request for {}'.format(request.unit_name))
        if not request.has_credentials:
            creds = layer.openstack.get_user_credentials()
            request.set_credentials(creds)
        layer.openstack.log('Finished request for {}', request.unit_name)
    openstack.mark_completed()


@hook('stop')
def cleanup():
    layer.openstack.cleanup()
