# Overview

This charm acts as a proxy to OpenStack and provides an [interface][] to provide
a set of credentials for a somewhat limited project user to the applications that
are related to this charm.

## Usage

This charm is a component of Charmed Kubernetes. For full information,
please visit the [official Charmed Kubernetes docs](https://www.ubuntu.com/kubernetes/docs/charm-openstack-integrator).

## Nagios

This charm uses NRPE checks that are able to monitor servers, networks, subnets,
floating-ips, security-groups and ports. These checks can be set through
configuration using the "nrpe-<resource_type>-ids" (e.g. "nrpe-server-ids")
option to monitor specific resources defined by IDs. The 
"nrpe-<resource_type>-ids" option could be defined as "all", however it is
only allowed for servers, networks, floating-ips and ports. Along with option
"nrpe-<resource_type>-ids" set to value "all" it's possible to used
"nrpe-skip-<resource_type>-ids" to set up resources, which will be skipped.

The script itself to check the OpenStack resource also supports the
possibility to use the select parameter, which serves as a filter. 
(`--select name=data-port` can be used to filter out ports named "data-port")
However this option is not configurable through the configuration.

[interface]: https://github.com/juju-solutions/interface-openstack-integration
