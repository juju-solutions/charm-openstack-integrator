import collections

# NOTE (rgildein): This namedtuple is used to define NRPE check. Composed of:
#                  name - NRPE check shortname
#                  interface - OpenStack interface to be checked
#                  config - option name defined in config.yaml
#                  config_skip - option name define in config.yaml
#                  all - if the option in config.yaml can be `all`
NrpeCheck = collections.namedtuple(
    "NRPE_CHECK", "name interface config config_skip all")

NRPE_BASE_OS_CHECKS = [
    NrpeCheck("kubernetes_subnet", "subnet", "subnet-id", None, False),
    NrpeCheck("kubernetes_network", "network", "floating-network-id",
              None, False),
    NrpeCheck("openstack_networks", "network", "nrpe-network-ids",
              "nrpe-skip-network-ids", True),
    NrpeCheck("openstack_subnets", "subnet", "nrpe-subnet-ids", None, False),
    NrpeCheck("openstack_ports", "port", "nrpe-port-ids", "nrpe-skip-port-ids",
              True),
    NrpeCheck("openstack_floating_ips", "floating-ip", "nrpe-floating-ip-ids",
              "nrpe-skip-floating-ip-ids", True),
    NrpeCheck("openstack_servers", "server", "nrpe-server-ids",
              "nrpe-skip-server-ids", True),
    NrpeCheck("openstack_security_groups", "security-group",
              "nrpe-security-group-ids", None, False),
]

NRPE_LOADBALANCER_CHECK = NrpeCheck("openstack_loadbalancers", "loadbalancer",
                                    None, None, False)

NRPE_OPENSTACK_INTERFACE = "check_openstack_interface.py"
NRPE_OPENSTACK_LOADBALANCER = "check_openstack_loadbalancer.py"
NRPE_CONFIG_FLAGS_CHANGED = [
    *["config.changed.{}".format(check.config) for check in NRPE_BASE_OS_CHECKS],
    *["config.changed.{}".format(check.config_skip) for check in NRPE_BASE_OS_CHECKS
      if check.config_skip],
    "loadbalancers.changed",
]
