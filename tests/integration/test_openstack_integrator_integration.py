import logging

import pytest

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    """Build and deploy openstack-integrator in bundle."""
    bundle = ops_test.render_bundle("tests/data/bundle.yaml", series="focal")
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)

    openstack_integrator = await ops_test.build_charm(".")
    await ops_test.model.deploy(openstack_integrator, to="lxd:0", trust=True)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)


async def test_add_relations(ops_test):
    """Test adding openstack-integrator relations.

    This will test adding relations
    `openstack-integrator:clients kubernetes-control-plane:openstack` and
    `openstack-integrator:clients kubernetes-worker:openstack`.
    """
    await ops_test.model.relate(
        "openstack-integrator:clients", "kubernetes-control-plane:openstack"
    )
    await ops_test.model.relate(
        "openstack-integrator:clients", "kubernetes-worker:openstack"
    )
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)


async def test_status_messages(ops_test):
    """Validate that the status messages are correct."""
    expected_messages = {
        "kubernetes-control-plane": "Kubernetes control-plane running.",
        "kubernetes-worker": "Kubernetes worker running.",
        "openstack-integrator": "Ready",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message
