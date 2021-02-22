#!/usr/bin/env python3

# Copyright (C) 2021 Canonical Ltd.

# Authors:
#   Robert Gildein <robert.gildein@canonical.com>


import argparse
from configparser import ConfigParser

import openstack
from nagios_plugin3 import try_check, CriticalError, WarnError


SEPARATOR = ","


def _parse_arguments():
    """Parse the check arguments and credentials to OpenStack.
    :returns: credentials, set IDs,
    :rtype: Tuple[configparser.ConfigParser, set]
    """
    credentials = ConfigParser()
    parser = argparse.ArgumentParser("check_openstack_loadbalancer")
    parser.add_argument(
        "-c", "--credential", required=True, type=argparse.FileType("r"),
        help="path to OpenStack credential cnf file")
    parser.add_argument(
        "-n", "--name", action="append", type=str, default=[],
        help="check specific name (can be used multiple times)")
    args = parser.parse_args()
    credentials.read_file(args.credential)

    return credentials, set(args.name)


def check(credentials, names):
    """Check OpenStack loadbalancer.
    :param credentials: OpenStack credentials
    :type credentials: configparser.ConfigParser
    :param names: OpenStack loadbalancer names that will be check
    :type names: Set[str]
    :raise nagios_plugin3.CriticalError: if loadbalancer not found
    :raise nagios_plugin3.CriticalError: if loadbalancer is in critical state
    :raise nagios_plugin3.WarningError: if loadbalancer is in pending state
    """
    notfound, warning, critical = set(), set(), set()
    connection = openstack.connect(**credentials["openstack"])
    for name in names:
        lb = connection.load_balancer.find_load_balancer(name_or_id=name)
        if lb is None:
            notfound.add(name)
        elif (lb.provisioning_status == "ACTIVE" and
              lb.operating_status == "ONLINE"):
            continue
        elif lb.provisioning_status in \
                ["PENDING_CREATE", "PENDING_UPDATE", "PENDING_DELETE"]:
            warning.add(name)
        else:
            critical.add(name)

    if notfound.union(critical):
        raise CriticalError("loadbalancers \"{}\" not found and \"{}\" in "
                            "critical state "
                            "({}/{})".format(SEPARATOR.join(notfound),
                                             SEPARATOR.join(critical),
                                             len(notfound.union(critical)),
                                             len(names)))

    if warning:
        raise WarnError("loadbalancers \"{}\" are in pending state "
                        "({}/{})".format(SEPARATOR.join(warning), len(warning),
                                         len(names)))

    print("OK - All loadbalancers passed. ({count}/{count}) "
          "IDs: {names}".format(count=len(names), names=SEPARATOR.join(names)))


def main():
    credentials, names = _parse_arguments()
    try_check(credentials, names)


if __name__ == "__main__":
    main()
