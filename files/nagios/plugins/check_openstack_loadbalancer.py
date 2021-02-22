#!/usr/bin/env python3

# Copyright (C) 2021 Canonical Ltd.

# Authors:
#   Robert Gildein <robert.gildein@canonical.com>


import argparse
from configparser import ConfigParser

import openstack
from nagios_plugin3 import try_check, CriticalError, WarningError


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
        "-i", "--id", action="append", type=str, default=[],
        help="check specific id or name (can be used multiple times)")
    args = parser.parse_args()
    credentials.read_file(args.credential)

    return credentials, set(args.id)


def check(credentials, ids):
    """Check OpenStack loadbalancer.
    :param credentials: OpenStack credentials
    :type credentials: configparser.ConfigParser
    :param ids: OpenStack loadbalancer IDs that will be check
    :type ids: Set[str]
    :raise nagios_plugin3.CriticalError: if loadbalancer not found
    :raise nagios_plugin3.CriticalError: if loadbalancer is in critical state
    :raise nagios_plugin3.WarningError: if loadbalancer is in pending state
    """
    notfound, warning, critical = set(), set(), set()
    connection = openstack.connect(**credentials["openstack"])
    for name_or_id in ids:
        lb = connection.load_balancer.find_load_balancer(name_or_id=name_or_id)
        if lb is None:
            notfound.add(name_or_id)
        elif (lb.provisioning_status == "ACTIVE" and
              lb.operating_status == "ONLINE"):
            continue
        elif lb.provisioning_status in \
                ["PENDING_CREATE", "PENDING_UPDATE", "PENDING_DELETE"]:
            warning.add(name_or_id)
        else:
            critical.add(name_or_id)

    if notfound.union(critical):
        raise CriticalError(
            "loadbalancers \"{}\" not found and \"{}\" in critical state "
            "({}/{})".format(SEPARATOR.join(notfound),
                             SEPARATOR.join(critical),
                             len(notfound.union(critical)),
                             len(ids)))

    if warning:
        WarningError("loadbalancers \"{}\" are in pending state "
                     "({}/{})".format(SEPARATOR.join(warning),
                                      len(warning),
                                      len(ids)))

    print("OK - All loadbalancers passed. ({count}/{count}) "
          "IDs: {ids}".format(count=len(ids), ids=SEPARATOR.join(ids)))


def main():
    credentials, ids = _parse_arguments()
    try_check(credentials, ids)


if __name__ == "__main__":
    main()
