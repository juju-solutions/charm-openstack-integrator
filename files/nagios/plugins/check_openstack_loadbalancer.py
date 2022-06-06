#!/usr/bin/env python3

# Copyright (C) 2021 Canonical Ltd.

# Authors:
#   Robert Gildein <robert.gildein@canonical.com>


import argparse
import os
from configparser import ConfigParser

import openstack
from nagios_plugin3 import try_check, CriticalError, WarnError, UnknownError


SEPARATOR = ","
TITLES = [
    (3, "{}/{} in UNKNOWN"),
    (99, "{}/{} were not found"),
    (2, "{}/{} in CRITICAL"),
    (1, "{}/{} in WARNING"),
    (0, "{}/{} passed")
]
NAGIOS_STATUS_OK = 0
NAGIOS_STATUS_WARNING = 1
NAGIOS_STATUS_CRITICAL = 2
NAGIOS_STATUS_UNKNOWN = 3
STATE = {
    NAGIOS_STATUS_OK: "OK",
    NAGIOS_STATUS_WARNING: "WARNING",
    NAGIOS_STATUS_CRITICAL: "CRITICAL",
}
LB_STATE = {
    ("ONLINE", "ACTIVE"): NAGIOS_STATUS_OK,
    ("ONLINE", "DELETED"): NAGIOS_STATUS_CRITICAL,
    ("ONLINE", "ERROR"): NAGIOS_STATUS_CRITICAL,
    ("ONLINE", "PENDING_CREATE"): NAGIOS_STATUS_WARNING,
    ("ONLINE", "PENDING_UPDATE"): NAGIOS_STATUS_WARNING,
    ("ONLINE", "PENDING_DELETE"): NAGIOS_STATUS_WARNING,
    ("DRAINING", "ACTIVE"): NAGIOS_STATUS_WARNING,
    ("DRAINING", "DELETED"): NAGIOS_STATUS_CRITICAL,
    ("DRAINING", "ERROR"): NAGIOS_STATUS_CRITICAL,
    ("DRAINING", "PENDING_CREATE"): NAGIOS_STATUS_CRITICAL,
    ("DRAINING", "PENDING_UPDATE"): NAGIOS_STATUS_CRITICAL,
    ("DRAINING", "PENDING_DELETE"): NAGIOS_STATUS_CRITICAL,
    ("OFFLINE", "ACTIVE"): NAGIOS_STATUS_OK,
    ("OFFLINE", "DELETED"): NAGIOS_STATUS_CRITICAL,
    ("OFFLINE", "ERROR"): NAGIOS_STATUS_CRITICAL,
    ("OFFLINE", "PENDING_CREATE"): NAGIOS_STATUS_WARNING,
    ("OFFLINE", "PENDING_UPDATE"): NAGIOS_STATUS_WARNING,
    ("OFFLINE", "PENDING_DELETE"): NAGIOS_STATUS_WARNING,
    ("DEGRADED", "ACTIVE"): NAGIOS_STATUS_CRITICAL,
    ("DEGRADED", "DELETED"): NAGIOS_STATUS_CRITICAL,
    ("DEGRADED", "ERROR"): NAGIOS_STATUS_CRITICAL,
    ("DEGRADED", "PENDING_CREATE"): NAGIOS_STATUS_CRITICAL,
    ("DEGRADED", "PENDING_UPDATE"): NAGIOS_STATUS_CRITICAL,
    ("DEGRADED", "PENDING_DELETE"): NAGIOS_STATUS_CRITICAL,
    ("ERROR", "ACTIVE"): NAGIOS_STATUS_CRITICAL,
    ("ERROR", "DELETED"): NAGIOS_STATUS_CRITICAL,
    ("ERROR", "ERROR"): NAGIOS_STATUS_CRITICAL,
    ("ERROR", "PENDING_CREATE"): NAGIOS_STATUS_CRITICAL,
    ("ERROR", "PENDING_UPDATE"): NAGIOS_STATUS_CRITICAL,
    ("ERROR", "PENDING_DELETE"): NAGIOS_STATUS_CRITICAL,
    ("NO_MONITOR", "ACTIVE"): NAGIOS_STATUS_CRITICAL,
    ("NO_MONITOR", "DELETED"): NAGIOS_STATUS_CRITICAL,
    ("NO_MONITOR", "ERROR"): NAGIOS_STATUS_CRITICAL,
    ("NO_MONITOR", "PENDING_CREATE"): NAGIOS_STATUS_CRITICAL,
    ("NO_MONITOR", "PENDING_UPDATE"): NAGIOS_STATUS_CRITICAL,
    ("NO_MONITOR", "PENDING_DELETE"): NAGIOS_STATUS_CRITICAL,
}


class Results:
    def __init__(self):
        self.exit_code = 0
        self.lbs = {
            NAGIOS_STATUS_OK: [],
            NAGIOS_STATUS_WARNING: [],
            NAGIOS_STATUS_CRITICAL: [],
            NAGIOS_STATUS_UNKNOWN: [],
            99: []
        }
        self._messages = []

    @property
    def messages(self):
        return [message for _, message
                in sorted(self._messages, key=lambda msg: msg[0], reverse=True)]

    @property
    def count(self):
        return len(self._messages)

    def add_result(self, name, lb=None):
        if not lb:
            exit_code = NAGIOS_STATUS_CRITICAL
            msg = "LB {} was not found".format(name)
            self.lbs[99].append(name)
        else:
            exit_code = LB_STATE.get((lb.operating_status, lb.provisioning_status), 3)
            lb_status = "({}, {})".format(lb.operating_status, lb.provisioning_status)
            msg = "{} {}".format(name, lb_status)
            self.lbs[exit_code].append(name)

        self._messages.append((exit_code, msg))
        self.exit_code = max(exit_code, self.exit_code)


def parse_arguments():
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
        "-n", "--name", required=True, action="append", type=str,
        help="check specific name (can be used multiple times)")
    args = parser.parse_args()
    credentials.read_file(args.credential)

    return credentials, set(args.name)


def _create_title(results):
    """Get output title."""
    titles = []

    for state, message in TITLES:
        if results.lbs[state]:
            titles.append(message.format(len(results.lbs[state]), results.count))

    return ", ".join(titles)


def nagios_output(results):
    """Convert checks results to nagios format."""
    messages = os.linesep.join(results.messages)
    title = _create_title(results)
    output = "{}{}{}".format(title, os.linesep, messages)

    # all checks passed
    if results.exit_code == NAGIOS_STATUS_OK:
        print("OK: ", output)
    # some checks with WARNING ERROR
    elif results.exit_code == NAGIOS_STATUS_WARNING:
        raise WarnError("WARNING: {}".format(output))
    # some checks with CRITICAL ERROR
    elif results.exit_code == NAGIOS_STATUS_CRITICAL:
        raise CriticalError("CRITICAL: {}".format(output))
    # some checks with UNKNOWN ERROR
    elif results.exit_code == NAGIOS_STATUS_UNKNOWN:
        raise UnknownError("UNKNOWN: {}".format(output))
    # raise UnknownError if for not valid exit_code
    else:
        raise UnknownError("UNKNOWN: not valid exit_code {} {}"
                           "".format(results.exit_code, output))


def check(credentials, names):
    """Check OpenStack loadbalancer.

    :param credentials: OpenStack credentials
    :type credentials: configparser.ConfigParser
    :param names: OpenStack loadbalancer names that will be checked
    :type names: Set[str]
    :raise nagios_plugin3.CriticalError: if loadbalancer not found
    :raise nagios_plugin3.CriticalError: if loadbalancer is in critical state
    :raise nagios_plugin3.WarnError: if loadbalancer is in warning state
    :raise nagios_plugin3.UnknownError: if loadbalancer is in unknown state
    """
    results = Results()
    connection = openstack.connect(**credentials["openstack"])
    for name in names:
        lb = connection.load_balancer.find_load_balancer(name_or_id=name)
        results.add_result(name, lb)

    nagios_output(results)


def main():
    credentials, names = parse_arguments()
    try_check(check, credentials, names)


if __name__ == "__main__":
    main()
