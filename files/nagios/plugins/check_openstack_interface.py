#!/usr/bin/env python3

# Copyright (C) 2021 Canonical Ltd.

# Authors:
#   Robert Gildein <robert.gildein@canonical.com>

import argparse
import os
from configparser import ConfigParser

import openstack
from nagios_plugin3 import try_check, UnknownError, CriticalError, WarnError


SEPARATOR = ","
OK_MESSAGE = "{}/{} passed"
WARNING_MESSAGE = "{}/{} in UNKNOWN"
DOWN_MESSAGE = "{}/{} are DOWN"
NOT_FOUND_MESSAGE = "{}/{} were not found"
NAGIOS_STATUS_OK = 0
NAGIOS_STATUS_WARNING = 1
NAGIOS_STATUS_CRITICAL = 2
NAGIOS_STATUS_UNKNOWN = 3
NAGIOS_STATUS = {
    NAGIOS_STATUS_OK: "OK",
    NAGIOS_STATUS_WARNING: "WARNING",
    NAGIOS_STATUS_CRITICAL: "CRITICAL",
    NAGIOS_STATUS_UNKNOWN: "UNKNOWN",
}
INTERFACE = {
    "network": lambda conn: conn.network.networks(),
    "floating-ip": lambda conn: conn.network.ips(),
    "server": lambda conn: conn.compute.servers(),
    "port": lambda conn: conn.network.ports(),
    "security-group": lambda conn: conn.network.security_groups(),
    "subnet": lambda conn: conn.network.subnets(),
}
INTERFACE_BY_EXISTENCE = ["security-group", "subnet"]


class Results:
    def __init__(self):
        self.exit_code = 0
        self.ok = []
        self.warning = []
        self.critical = []
        self.not_found = []
        self._messages = []

    @property
    def messages(self):
        return [message for _, message in sorted(self._messages, reverse=True)]

    @property
    def count(self):
        return len(self._messages)

    def add_result(self, type_, id_, status=None, exists=True):
        if status == "ACTIVE":
            self.ok.append(id_)
            exit_code = NAGIOS_STATUS_OK
            message = "{} '{}' is in {} status".format(type_, id_, status)
        elif status == "DOWN":
            self.critical.append(id_)
            exit_code = NAGIOS_STATUS_CRITICAL
            message = "{} '{}' is in {} status".format(type_, id_, status)
        elif not status and exists and type_ in INTERFACE_BY_EXISTENCE:
            self.ok.append(id_)
            exit_code = NAGIOS_STATUS_OK
            message = "{} '{}' exists".format(type_, id_)
        elif not exists:
            self.not_found.append(id_)
            exit_code = NAGIOS_STATUS_CRITICAL
            message = "{} '{}' was not found".format(type_, id_)
        else:
            self.warning.append(id_)
            exit_code = NAGIOS_STATUS_WARNING
            message = "{} '{}' is in {} status".format(type_, id_, status)

        self.exit_code = max(exit_code, self.exit_code)
        self._messages.append((exit_code, message))


def _interface_filter(interface, skip, select):
    """Apply `--skip` and `--select` parameter to interface.

    :param interface: OpenStack interface, e.g. network, port, ...
    :type: Any
    :param skip: OpenStack interface IDs that will be skipped [None]
    :type skip: Set[str]
    :param select: values for OpenStack interfaces filtering [None]
    :type select: Dict[str, str]
    :returns: a Boolean value to identify whether this interface is used
    :rtype: bool
    """
    if interface.id in (skip or {}):
        return False

    for key, value in (select or {}).items():
        if getattr(interface, key, None) != value:
            return False

    return True


def parse_arguments():
    """Parse the check arguments and connect to OpenStack.

    :returns: credentials, interface name, set IDs,
              set IDs to skip, values to filter when using `--all`
              and check all flag
    :rtype: Tuple[configparser.ConfigParser, str, set, set, dict, bool]
    """
    credentials = ConfigParser()
    parser = argparse.ArgumentParser("check_openstack_interface")
    parser.add_argument("interface", type=str, help="interface type")
    parser.add_argument("-c", "--credential", required=True,
                        type=argparse.FileType("r"),
                        help="path to OpenStack credential cnf file")
    parser.add_argument("--all", action="store_true", help="check all")
    parser.add_argument("-i", "--id", action="append", type=str, default=[],
                        help="check specific id (can be used multiple times)")
    parser.add_argument("--skip-id", action="append", type=str, default=[],
                        help="skip specific id (can be used multiple times)")
    parser.add_argument("--select", action="append", type=str, default=[],
                        help="use `--select` together with `--all`"
                             "(e.g. --select subnet=<id>)")
    args = parser.parse_args()

    if args.interface not in INTERFACE:
        parser.error("'{}' interface is not supported".format(args.interface))

    if args.all and args.interface in INTERFACE_BY_EXISTENCE:
        parser.error("flag '--all' is not supported with "
                     "interface {}".format(args.interface))
    if args.all and args.id:
        parser.error("--all/--id' are mutually exclusive")
    elif not args.all and not args.id:
        parser.error("at least one of --all/--id' parameters must be entered")
    elif not args.all and args.skip_id:
        parser.error("'--skip-id' must be used with '--all'")
    elif not args.all and args.select:
        parser.error("'--select' must be used with '--all'")

    credentials.read_file(args.credential)

    return (credentials, args.interface, set(args.id), set(args.skip_id),
            dict(arg.split("=", 1) for arg in args.select), args.all)


def _create_title(interface_type, results):
    """Get output title."""
    titles = []

    if results.not_found:
        titles.append(NOT_FOUND_MESSAGE.format(len(results.not_found), results.count))

    if results.critical:
        titles.append(DOWN_MESSAGE.format(len(results.critical), results.count))

    if results.warning:
        titles.append(WARNING_MESSAGE.format(len(results.warning), results.count))

    if results.ok:
        titles.append(OK_MESSAGE.format(len(results.ok), results.count))

    return "{}s {}".format(interface_type, ", ".join(titles))


def nagios_output(interface_type, results):
    """Convert checks results to nagios format."""
    messages = os.linesep.join(results.messages)
    title = _create_title(interface_type, results)
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


def check(credentials, interface_type, ids, skip=None, select=None, check_all=False):
    """Check OpenStack interface.

    :param credentials: OpenStack credentials
    :type credentials: configparser.ConfigParser
    :param interface_type: OpenStack interface type
    :type interface_type: str
    :param ids: OpenStack interface IDs that will be checked
    :type ids: Set[str]
    :param skip: OpenStack interface IDs that will be skipped
    :type skip: Set[str]
    :param select: values for OpenStack interfaces filtering
    :type select: Dict[str, str]
    :param check_all: flag to checking all OpenStack interfaces
    :type check_all: bool
    :raise nagios_plugin3.UnknownError: if interface not valid status
    :raise nagios_plugin3.CriticalError: if interface not found
    :raise nagios_plugin3.CriticalError: if interface status is DOWN
    """
    results = Results()
    connection = openstack.connect(**credentials["openstack"])
    interfaces = INTERFACE[interface_type](connection)
    checked_ids = []

    for interface in interfaces:
        if interface.id not in ids and not check_all:
            continue
        elif check_all and not _interface_filter(interface, skip, select):
            continue

        checked_ids.append(interface.id)
        if interface_type not in INTERFACE_BY_EXISTENCE:
            interface_status = getattr(interface, "status", "UNKNOWN")
            results.add_result(interface_type, interface.id, interface_status)
        else:
            results.add_result(interface_type, interface.id)

    for id_ in ids:
        if id_ not in checked_ids:
            results.add_result(interface_type, id_, exists=False)

    nagios_output(interface_type, results)


def main():
    args = parse_arguments()
    try_check(check, *args)


if __name__ == "__main__":
    main()
