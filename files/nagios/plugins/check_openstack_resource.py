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
RESOURCES = {
    "network": lambda conn: conn.network.networks(),
    "floating-ip": lambda conn: conn.network.ips(),
    "server": lambda conn: conn.compute.servers(),
    "port": lambda conn: conn.network.ports(),
    "security-group": lambda conn: conn.network.security_groups(),
    "subnet": lambda conn: conn.network.subnets(),
}
RESOURCE_BY_EXISTENCE = ["network", "security-group", "subnet"]


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
        elif not status and exists and type_ in RESOURCE_BY_EXISTENCE:
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


def _resource_filter(resource, skip, select):
    """Apply `--skip` and `--select` parameter to resource.

    :param resource: OpenStack resource, e.g. network, port, ...
    :type: Any
    :param skip: OpenStack resource IDs that will be skipped [None]
    :type skip: Set[str]
    :param select: values for OpenStack resources filtering [None]
    :type select: Dict[str, str]
    :returns: a Boolean value to identify whether this resource is used
    :rtype: bool
    """
    if resource.id in (skip or {}):
        return False

    for key, value in (select or {}).items():
        if getattr(resource, key, None) != value:
            return False

    return True


def parse_arguments():
    """Parse the check arguments and connect to OpenStack.

    :returns: credentials, resource name, set IDs,
              set IDs to skip, values to filter when using `--all`
              and check all flag
    :rtype: Tuple[configparser.ConfigParser, str, set, set, dict, bool]
    """
    credentials = ConfigParser()
    parser = argparse.ArgumentParser("check_openstack_resource")
    parser.add_argument("resource", type=str, help="resource type")
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

    if args.resource not in RESOURCES:
        parser.error("'{}' resource is not supported".format(args.resource))

    if args.all and args.resource in RESOURCE_BY_EXISTENCE:
        parser.error("flag '--all' is not supported with "
                     "resource {}".format(args.resource))
    if args.all and args.id:
        parser.error("--all/--id' are mutually exclusive")
    elif not args.all and not args.id:
        parser.error("at least one of --all/--id' parameters must be entered")
    elif not args.all and args.skip_id:
        parser.error("'--skip-id' must be used with '--all'")
    elif not args.all and args.select:
        parser.error("'--select' must be used with '--all'")

    credentials.read_file(args.credential)

    return (credentials, args.resource, set(args.id), set(args.skip_id),
            dict(arg.split("=", 1) for arg in args.select), args.all)


def _create_title(resource_type, results):
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

    return "{}s {}".format(resource_type, ", ".join(titles))


def nagios_output(resource_type, results):
    """Convert checks results to nagios format."""
    messages = os.linesep.join(results.messages)
    title = _create_title(resource_type, results)
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


def check(credentials, resource_type, ids, skip=None, select=None, check_all=False):
    """Check OpenStack resource.

    :param credentials: OpenStack credentials
    :type credentials: configparser.ConfigParser
    :param resource_type: OpenStack resource type
    :type resource_type: str
    :param ids: OpenStack resource IDs that will be checked
    :type ids: Set[str]
    :param skip: OpenStack resource IDs that will be skipped
    :type skip: Set[str]
    :param select: values for OpenStack resources filtering
    :type select: Dict[str, str]
    :param check_all: flag to checking all OpenStack resources
    :type check_all: bool
    :raise nagios_plugin3.UnknownError: if resource not valid status
    :raise nagios_plugin3.CriticalError: if resource not found
    :raise nagios_plugin3.CriticalError: if resource status is DOWN
    """
    results = Results()
    connection = openstack.connect(**credentials["openstack"])
    resources = RESOURCES[resource_type](connection)
    checked_ids = []

    for resource in resources:
        if resource.id not in ids and not check_all:
            continue
        elif check_all and not _resource_filter(resource, skip, select):
            continue

        checked_ids.append(resource.id)
        if resource_type not in RESOURCE_BY_EXISTENCE:
            resource_status = getattr(resource, "status", "UNKNOWN")
            results.add_result(resource_type, resource.id, resource_status)
        else:
            results.add_result(resource_type, resource.id)

    for id_ in ids:
        if id_ not in checked_ids:
            results.add_result(resource_type, id_, exists=False)

    nagios_output(resource_type, results)


def main():
    args = parse_arguments()
    try_check(check, *args)


if __name__ == "__main__":
    main()
