import collections

# NOTE (rgildein): This namedtuple is used to define NRPE check. Composed of:
#                  name - NRPE check shortname
#                  resource - OpenStack resource to be checked
#                  config - option name defined in config.yaml
#                  config_skip - option name define in config.yaml
#                  all - if the option in config.yaml can be `all`
NrpeCheck = collections.namedtuple(
    "NRPE_CHECK", "name resource config config_skip all")

NRPE_CHECKS = [
    NrpeCheck("kubernetes_subnet", "subnet", "subnet-id", None, False),
    NrpeCheck("kubernetes_network", "network", "floating-network-id",
              None, False),
    NrpeCheck("openstack_networks", "network", "nrpe-network-ids", None, False),
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
NRPE_OPENSTACK_RESOURCE = "check_openstack_resource.py"
NRPE_CONFIG_FLAGS_CHANGED = [
    *["config.changed.{}".format(check.config) for check in NRPE_CHECKS],
    *["config.changed.{}".format(check.config_skip) for check in NRPE_CHECKS
      if check.config_skip]
]
