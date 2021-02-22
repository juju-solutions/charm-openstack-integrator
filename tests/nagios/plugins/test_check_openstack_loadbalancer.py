import collections
import sys

import pytest

from nagios_plugin3 import CriticalError, WarnError

sys.path.append("files/nagios/plugins")

from check_openstack_loadbalancer import check  # noqa: E402


FakeLB = collections.namedtuple("FakeLB",
                                "provisioning_status operating_status")


@pytest.mark.parametrize("lbs,names,exp_error", [
    ({"lb_1": FakeLB("ACTIVE", "ONLINE")}, ["lb_1", "lb_2"], CriticalError),
    ({"lb_1": FakeLB("ACTIVE", "ONLINE"),
      "lb_2": FakeLB("ACTIVE", "ONLINE")}, ["lb_1", "lb_2"], None),
    ({"lb_1": FakeLB("ACTIVE", "ONLINE"),
      "lb_2": FakeLB("ACTIVE", "ONLINE")}, ["lb_1"], None),
    ({"lb_1": FakeLB("PENDING_UPDATE", "OFFLINE"),
      "lb_2": FakeLB("ACTIVE", "ONLINE")}, ["lb_1"], WarnError),
    ({"lb_1": FakeLB("DELETED", "OFFLINE"),
      "lb_2": FakeLB("ACTIVE", "ONLINE")}, ["lb_1", "lb_2"], CriticalError),
    ({"lb_1": FakeLB("ACTIVE", "ONLINE"),
      "lb_2": FakeLB("ERROR", "ERROR")}, ["lb_1", "lb_2"], CriticalError),
    ({}, ["lb_1", "lb_2"], CriticalError),
])
def test_check(lbs, names, exp_error, loadbalancers, credentials):
    """Test NRPE check for OpenStack loadbalancer."""
    loadbalancers.update(lbs)
    if exp_error:
        with pytest.raises(exp_error):
            check(credentials, names)
    else:
        check(credentials, names)
