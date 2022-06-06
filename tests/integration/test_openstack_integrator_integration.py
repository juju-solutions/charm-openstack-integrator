import logging
import os

import pytest

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test):
    """Build and deploy openstack-integrator in bundle."""
    # deploy base k8s bundle
    bundle = ops_test.render_bundle("tests/data/bundle.yaml", series="focal")
    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)

    # deploy openstack-integrator
    openstack_integrator = await ops_test.build_charm(".")
    await ops_test.model.deploy(openstack_integrator, to="lxd:0", trust=True)
    await ops_test.model.wait_for_idle(wait_for_active=True)

    # deploy nrpe and nagios
    await ops_test.model.deploy("nrpe", channel="latest/edge")
    await ops_test.model.deploy("nagios", channel="latest/edge", to="lxd:0")
    apps = [app for app in ops_test.model.applications if app != "nrpe"]
    await ops_test.model.wait_for_idle(apps=apps, wait_for_active=True)


@pytest.mark.skip_if_deployed
async def test_k8s_relations(ops_test):
    """Test relate k8s with openstack-integrator.

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
    await ops_test.model.wait_for_idle(
        apps=["openstack-integrator", "kubernetes-control-plane", "kubernetes-worker"],
        wait_for_active=True,
    )


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


@pytest.mark.skip_if_deployed
async def test_nrpe_relations(ops_test):
    """Test relate nrpe with openstack-integrator."""
    await ops_test.model.relate(
        "nrpe:monitors", "nagios:monitors"
    )
    await ops_test.model.relate(
        "openstack-integrator:nrpe-external-master", "nrpe:nrpe-external-master"
    )
    await ops_test.model.wait_for_idle(
        apps=["openstack-integrator", "nrpe", "nagios"], wait_for_active=True
    )


async def test_check_nrpe_checks(ops_test):
    """Validate that all checks were configured."""
    exp_checks = {
        "check-openstack-floating-ips":
            "/usr/lib/nagios/plugins/check_openstack_interface.py floating-ip "
            "-c /etc/nagios/openstack.cnf --all",
        "check-openstack-networks":
            "/usr/lib/nagios/plugins/check_openstack_interface.py network -c "
            "/etc/nagios/openstack.cnf --all",
        "check-openstack-ports":
            "/usr/lib/nagios/plugins/check_openstack_interface.py port -c "
            "/etc/nagios/openstack.cnf --all",
        "check-openstack-servers":
            "/usr/lib/nagios/plugins/check_openstack_interface.py server -c "
            "/etc/nagios/openstack.cnf --all"
    }
    nrpe_unit = ops_test.model.applications["nrpe"].units[0]
    action = await nrpe_unit.run_action("list-nrpe-checks")
    result = await action.wait()  # wait for result
    checks = result.data.get("results", {}).get("checks")

    assert result.data.get("status") == "completed"
    for name, cmd in exp_checks.items():
        assert checks.get(name) == cmd


async def test_bad_nrpe_configuration(ops_test):
    """Test block workload status."""
    app = "openstack-integrator"
    unit = ops_test.model.applications[app].units[0]
    await ops_test.model.applications[app].set_config(
        {"nrpe-skip-floating-ip-ids": "all"})
    await ops_test.model.wait_for_idle(apps=[app], status="blocked")

    await unit.run("hooks/config-changed")  # run config-changed hook
    await unit.run("hooks/update-status")  # run update-status hook
    assert ops_test.model.applications[app].status == "blocked"

    # restore configuration
    await ops_test.model.applications[app].set_config({"nrpe-skip-floating-ip-ids": ""})
    await ops_test.model.wait_for_idle(apps=[app], wait_for_active=True)


async def test_removing_nrpe_check(ops_test):
    """Test removing check-openstack-floating-ips check."""
    app = "openstack-integrator"
    await ops_test.model.applications[app].set_config({"nrpe-floating-ip-ids": ""})
    await ops_test.model.wait_for_idle(apps=[app], wait_for_active=True)

    nrpe_unit = ops_test.model.applications["nrpe"].units[0]
    action = await nrpe_unit.run_action("list-nrpe-checks")
    result = await action.wait()  # wait for result
    checks = result.data.get("results", {})

    assert result.data.get("status") == "completed"
    assert "check-openstack-floating-ips" not in checks

    # restore configuration
    await ops_test.model.applications[app].set_config({"nrpe-floating-ip-ids": "all"})
    await ops_test.model.wait_for_idle(apps=[app], wait_for_active=True)


async def test_run_check(ops_test):
    """Test run check-openstack-servers."""
    nrpe_unit = ops_test.model.applications["nrpe"].units[0]
    action = await nrpe_unit.run_action("run-nrpe-check",
                                        name="check-openstack-servers")
    result = await action.wait()  # wait for result
    check_output = result.data.get("results", {}).get("check-output")

    status = await ops_test.model.get_status()
    for machine in status.get("machines", {}).values():
        exp_alert = "server '{}' is in ACTIVE status".format(machine.instance_id)
        assert exp_alert in check_output


async def test_run_lb_check(ops_test):
    """Test run check-openstack-loadbalancer."""
    if not os.environ.get("TEST_LB_ID"):
        pytest.skip("no test loadbalancer ID provided")

    nrpe_unit = ops_test.model.applications["nrpe"].units[0]
    action = await nrpe_unit.run_action("run-nrpe-check",
                                        name="check-openstack-loadbalancers")
    result = await action.wait()  # wait for result
    check_output = result.data.get("results", {}).get("check-output")
    lb_ids = os.environ.get("TEST_LB_ID", "").split(",")
    for lb_id in lb_ids:
        assert "{} (ONLINE, ACTIVE)".format(lb_id) in check_output
