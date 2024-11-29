#!/opt/opsview/monitoringscripts/venv3/bin/python
# pylint: disable=too-many-lines
"""
Opsview Monitor check_sentinel plugin.

Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys
import signal
import traceback
import argparse
import logging


from collections import namedtuple

from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights
from plugnpy import cachemanager
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient

from plugnpy.exception import ParamError, ParamErrorWithHelp, ResultError
from plugnpy.cachemanager import CacheManagerUtils
from plugnpy import Check, Metric, Parser

# Constants
METRIC_TYPE_CUSTOM = "Custom"

ModeUsage = namedtuple(
    "ModeUsage",
    "metric_type metric_info arguments_optional arguments_required unit "
    "interval plugin_class default_warning default_critical",
)
ResourceVariable = namedtuple("ResourceVariable", "name default_value arguments")
ResourceArgument = namedtuple("ResourceArgument", "long_param help_text resource_key")


class PluginClassBase:
    """Generic Plugin base class to provide generic call api method (to allow mocking in test harness)"""

    imported_modules = {}

    def call_api(self, func, *args, **kwargs):  # pylint: disable=no-self-use
        """Generic method to call any API function."""
        return func(*args, **kwargs)

    @classmethod
    def convert_label_name(cls, name):
        """Convert metric label name to performance data name."""
        return name.lower().replace(" ", "_")


class SentinelCheckExit(Exception):
    """Exception thrown when a check has to return a specific status code with supplied message."""

    def __init__(self, status, message):
        super().__init__(status, message)
        self.status = status
        self.message = message


class SentinelAPI:
    """Class representing the connection to Microsoft Sentinel via Azure SDK."""

    def __init__(self, args):
        self.args = args
        self.credentials = DefaultAzureCredential()
        self.subscription_id = args.subscription_id
        self.resource_group_name = args.resource_group
        self.workspace_name = args.workspace_name
        self.client = SecurityInsights(
            credential=self.credentials,
            subscription_id=self.subscription_id,
        )

    def list_lighthouse_sentinel_workspaces(self):
        """List all Sentinel workspaces accessible via Azure Lighthouse."""
        subscriptions_client = SubscriptionClient(self.credentials)
        subscriptions = CacheManagerUtils.get_via_cachemanager(
            no_cachemanager=False,  # TODO: Add argument to disable cache manager
            key="subscriptions",
            ttl=3600,
            func=subscriptions_client.subscriptions.list,
        )

        sentinel_workspaces = []

        for subscription in subscriptions:
            subscription_id = subscription.subscription_id
            resource_client = ResourceManagementClient(self.credentials, subscription_id)
            log_analytics_client = LogAnalyticsManagementClient(self.credentials, subscription_id)

            resource_groups = CacheManagerUtils.get_via_cachemanager(
                no_cachemanager=False,  # TODO: Add argument to disable cache manager
                key=f"resource_groups_{subscription_id}",
                ttl=3600,
                func=resource_client.resource_groups.list,
            )

            for rg in resource_groups:
                resource_group_name = rg.name

                workspaces = CacheManagerUtils.get_via_cachemanager(
                    no_cachemanager=False,  # TODO: Add argument to disable cache manager
                    key=f"workspaces_{subscription_id}_{resource_group_name}",
                    ttl=300,
                    func=log_analytics_client.workspaces.list_by_resource_group,
                    resource_group_name=resource_group_name,
                )

                for workspace in workspaces:
                    workspace_name = workspace.name

                    # Check if Sentinel is enabled on the workspace
                    sentinel_client = SecurityInsights(
                        credential=self.credentials,
                        subscription_id=subscription_id,
                    )

                    try:
                        sentinel_client.entities.list(resource_group_name, workspace_name)
                        # If no exception, Sentinel is enabled
                        sentinel_workspaces.append(
                            {
                                "subscription_id": subscription_id,
                                "resource_group_name": resource_group_name,
                                "workspace_name": workspace_name,
                            }
                        )
                    except Exception:
                        # Sentinel is not enabled on this workspace
                        pass

        return sentinel_workspaces

    def get_incidents(self):
        """Retrieve incidents from Microsoft Sentinel."""
        incidents = self.client.incidents.list(
            resource_group_name=self.resource_group_name,
            workspace_name=self.workspace_name,
        )
        return list(incidents)

    # Additional methods can be added here to interact with other Sentinel resources.


class SentinelCheck(PluginClassBase):
    """Class for Sentinel checks."""

    def __init__(
        self,
        warning,
        critical,
        metric_type,
        metric_info,
        unit,
        interval,
        args,
    ):
        self._args = args
        self._warning = warning
        self._critical = critical
        self._metric_type = metric_type
        self._unit = unit
        self._interval = interval
        self._api = SentinelAPI(args)

        self._expected_workspaces = set()
        if hasattr(args, "expected_workspaces") and args.expected_workspaces:
            self._expected_workspaces = set(
                [ws.strip() for ws in args.expected_workspaces.split(",")]
            )

        try:
            if metric_type == METRIC_TYPE_CUSTOM:
                check_metric_method, num_thresholds = [
                    value.strip() for value in metric_info.split(";")
                ]
                self._check_metric_method = getattr(self, check_metric_method)
                self._num_thresholds = int(num_thresholds)
            else:
                raise ParamError(f"Unsupported metric type '{metric_type}'")
        except (ValueError, AttributeError) as exc:
            raise ParamError(f"Invalid metric info '{metric_info}': {exc}") from exc

        self._user_warnings, self._user_criticals = self._get_user_thresholds(args)

    def _get_user_thresholds(self, args):
        """List the thresholds for warnings and criticals as supplied by the user."""
        values = []
        for threshold_type in ["warning", "critical"]:
            threshold = getattr(args, threshold_type)
            value = None
            if threshold is not None and threshold != "":
                value = [val.strip() for val in threshold.split(",")]
                if len(value) != self._num_thresholds:
                    raise ParamError(
                        f"Number of {threshold_type} thresholds provided must match number of metrics"
                    )
            values.append(value)
        warning, critical = values  # pylint: disable=unbalanced-tuple-unpacking
        return warning, critical

    def _get_thresholds(self, position, converted_label):
        """Get the warning and critical thresholds."""
        warning = ""
        if self._user_warnings is not None:
            warning = self._user_warnings[position]
        elif converted_label in self._warning:
            warning = self._warning[converted_label]
        critical = ""
        if self._user_criticals is not None:
            critical = self._user_criticals[position]
        elif converted_label in self._critical:
            critical = self._critical[converted_label]
        return warning, critical

    def check(self):
        """Construct and present the results of the check using plugnpy library."""
        check = Check()
        try:
            metrics = self._check_metric_method()
            for metric in metrics:
                check.add_metric_obj(metric)
        except SentinelCheckExit as exc:
            if exc.status == Metric.STATUS_OK:
                check.exit_ok(exc.message)
            elif exc.status == Metric.STATUS_WARNING:
                check.exit_warning(exc.message)
            elif exc.status == Metric.STATUS_CRITICAL:
                check.exit_critical(exc.message)
            else:
                check.exit_unknown(exc.message)
        check.final()

    def check_open_incidents(self):
        """Check the number of open (new + active) incidents in Sentinel."""
        incidents = self.call_api(self._api.get_incidents)
        active_incidents = len([i for i in incidents if i.properties.status.lower() == "active"])
        new_incidents = len([i for i in incidents if i.properties.status.lower() == "new"])
        open_incidents = active_incidents + new_incidents
        label = "Open Incidents"
        metric_name = self.convert_label_name(label)
        warning, critical = self._get_thresholds(0, metric_name)
        metrics = [
            Metric(
                metric_name,
                open_incidents,
                self._unit,
                warning,
                critical,
                display_name=label,
                summary_precision=0,
                perf_data_precision=0,
            )
        ]
        return metrics

    def check_new_incidents(self):
        """Check the number of new incidents in Sentinel."""
        incidents = self.call_api(self._api.get_incidents)
        new_incidents = len([i for i in incidents if i.properties.status.lower() == "new"])
        label = "New Incidents"
        metric_name = self.convert_label_name(label)
        warning, critical = self._get_thresholds(0, metric_name)
        metrics = [
            Metric(
                metric_name,
                new_incidents,
                self._unit,
                warning,
                critical,
                display_name=label,
                summary_precision=0,
                perf_data_precision=0,
            )
        ]
        return metrics

    def check_lighthouse_sentinels(self):
        """Check that Sentinel workspaces are accessible via Azure Lighthouse."""
        sentinel_workspaces = self.call_api(self._api.list_lighthouse_sentinel_workspaces)
        total_workspaces = len(sentinel_workspaces)

        label = "Accessible Sentinel Workspaces"
        metric_name = self.convert_label_name(label)
        warning, critical = self._get_thresholds(0, metric_name)

        metrics = [
            Metric(
                metric_name,
                total_workspaces,
                self._unit,
                warning,
                critical,
                display_name=label,
                summary_precision=0,
                perf_data_precision=0,
            )
        ]

        # Optionally, check if total_workspaces is less than expected
        expected_workspaces = self._expected_workspaces
        if expected_workspaces:
            expected_count = len(expected_workspaces)
            if total_workspaces < expected_count:
                sentinel_workspace_names = set(
                    [w.get("workspace_name") for w in sentinel_workspaces]
                )
                missing = sorted(expected_workspaces - sentinel_workspace_names)
                missing_str = ",".join(missing)
                raise SentinelCheckExit(
                    Metric.STATUS_CRITICAL,
                    f"Expected {expected_count} workspaces, but found {total_workspaces}. Missing: {missing_str}",
                )
            elif total_workspaces > expected_count:
                sentinel_workspace_names = set(
                    [w.get("workspace_name") for w in sentinel_workspaces]
                )
                extra = sorted(sentinel_workspace_names - expected_workspaces)
                extra_str = ",".join(extra)
                raise SentinelCheckExit(
                    Metric.STATUS_WARNING,
                    f"Expected {expected_count} workspaces, but found {total_workspaces}. Extra: {extra_str}",
                )

        return metrics


# Define how each mode works, pointing to the correct Objects
MODE_MAPPING = {
    "Sentinel.Incidents": ModeUsage(
        "Custom",
        "check_open_incidents; 1",
        [],  # No optional arguments
        [
            "AZURE_SUBSCRIPTION_ID",
            "AZURE_RESOURCE_GROUP",
            "AZURE_WORKSPACE_NAME",
        ],  # Required arguments
        "",
        300,
        SentinelCheck,
        {},
        {},
    ),
    "Sentinel.Incidents": ModeUsage(
        "Custom",
        "check_new_incidents; 1",
        [],  # No optional arguments
        [
            "AZURE_SUBSCRIPTION_ID",
            "AZURE_RESOURCE_GROUP",
            "AZURE_WORKSPACE_NAME",
        ],  # Required arguments
        "",
        300,
        SentinelCheck,
        {},
        {},
    ),
    "Sentinel.LighthouseCheck": ModeUsage(
        "Custom",
        "check_lighthouse_sentinels; 1",
        ["EXPECTED_WORKSPACES"],  # Optional argument
        [],  # No required arguments
        "",
        300,
        SentinelCheck,
        {},
        {},
    ),
}

# Define additional arguments that ArgParse can take in if needed by a mode
RESOURCE_VARIABLES = [
    ResourceVariable(
        "AZURE_CREDENTIALS",
        "Azure Credentials",
        arguments=[
            # Using DefaultAzureCredential, so explicit credentials may not be needed
        ],
    ),
    ResourceVariable(
        "AZURE_RESOURCE_DETAILS",
        "",
        arguments=[
            ResourceArgument(
                "--subscription-id",
                "The Azure subscription ID",
                "AZURE_SUBSCRIPTION_ID",
            ),
            ResourceArgument(
                "--resource-group",
                "The Azure resource group name",
                "AZURE_RESOURCE_GROUP",
            ),
            ResourceArgument(
                "--workspace-name",
                "The Azure Sentinel workspace name",
                "AZURE_WORKSPACE_NAME",
            ),
        ],
    ),
    ResourceVariable(
        "EXPECTED_WORKSPACES",
        "",
        arguments=[
            ResourceArgument(
                "--expected-workspaces",
                "Optional comma-separated list of expected workspace names",
                "EXPECTED_WORKSPACES",
            ),
        ],
    ),
]


def run_check(args, mode_usage):
    """Run the check based on the mode selected with the supplied arguments."""
    try:
        check_class = mode_usage.plugin_class(
            mode_usage.default_warning,
            mode_usage.default_critical,
            mode_usage.metric_type,
            mode_usage.metric_info,
            mode_usage.unit,
            mode_usage.interval,
            args,
        )
    except KeyError as exc:
        raise ParamError(f"Invalid Plugin: {mode_usage.plugin_class}") from exc
    check_class.check()


def get_all_help_arguments():
    """Get all the arguments which we want to display in the help text."""
    help_arguments = []
    for variable in RESOURCE_VARIABLES:
        for arg in variable.arguments:
            if arg.long_param:
                help_arguments.append(arg)
    return sorted(help_arguments)


def get_all_mode_arguments(mode):
    """Get all the arguments which we want for a specific mode."""
    args = []
    mode_usage = MODE_MAPPING[mode]
    all_variable_args = [
        arg for arg_list in [var.arguments for var in RESOURCE_VARIABLES] for arg in arg_list
    ]
    all_mode_args = mode_usage.arguments_optional + mode_usage.arguments_required
    for mode_arg in [arg for arg in all_variable_args if arg.resource_key in all_mode_args]:
        required = mode_arg.resource_key in mode_usage.arguments_required
        args.append((mode_arg, required))
    return sorted(args)


def get_args(modes):
    """Get the plugin arguments from command line."""
    description = "Opsview plugin for monitoring Microsoft Sentinel."

    parser = Parser(
        description=description,
        add_help=False,
        copystr="Copyright (C) 2024 ITRS Group Ltd. All rights reserved",
        usage="%(prog)s -m MODE [-h] (Optional Arguments) (Mode Specific Flags)",
        conflict_handler="resolve",
    )
    required = parser.add_argument_group("required arguments")
    required.add_argument(
        "-m",
        "--mode",
        help=(
            "Mode for the plugin to run (the service check). If no mode "
            "specified, all valid modes will be listed at the bottom of the help "
            "text below"
        ),
    )
    parser.add_argument("-w", "--warning", help="The warning levels (comma separated)")
    parser.add_argument("-c", "--critical", help="The critical levels (comma separated)")
    parser.add_argument("-L", "--last-service-check", help="Last time this service check was run")
    parser.add_argument("-C", "--check-interval", help="Service check check interval")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode")
    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-cachemanager", action="store_true", help="Test mode")

    # Get Mode out
    args, _ = parser.parse_known_args()
    mode_dict = {}
    for mode in sorted(modes):
        group = mode[: mode.index(".")]
        if group in mode_dict:
            mode_dict[group].append(mode)
        else:
            mode_dict[group] = [mode]
    valid_modes_string = "Valid modes:"
    for group_mode in mode_dict.values():
        for mode in group_mode:
            valid_modes_string += f"\n  - {mode}"
        valid_modes_string += "\n"
    mode_specific_args = parser.add_argument_group("all mode specific arguments")

    if not args.mode:
        if args.help:
            for arg in get_all_help_arguments():
                mode_specific_args.add_argument(arg.long_param, help=arg.help_text)
            help_text = parser.format_help() + f"\n{valid_modes_string}"
        else:
            help_text = (
                parser.format_usage()
                + f"error: argument -m/--mode is required, {valid_modes_string}"
            )
        raise ParamErrorWithHelp(help_text)

    if args.mode not in modes:
        help_text = f"Invalid mode: '{args.mode}', {valid_modes_string}"
        if args.help:
            help_text = f"{parser.format_help()}\n{help_text}"
        raise ParamErrorWithHelp(help_text)

    req_mode_specific_args = parser.add_argument_group(
        f"'{args.mode}' mode specific arguments - required"
    )
    opt_mode_specific_args = parser.add_argument_group(
        f"'{args.mode}' mode specific arguments - optional"
    )

    # Add arguments defined in RESOURCE_VARIABLES for this mode
    for arg, required in get_all_mode_arguments(args.mode):
        if required:
            req_mode_specific_args.add_argument(arg.long_param, help=arg.help_text, required=True)
        else:
            opt_mode_specific_args.add_argument(arg.long_param, help=arg.help_text)

    if args.help:
        raise ParamErrorWithHelp(parser.format_help())

    args = parser.parse_args()

    for arg, required in get_all_mode_arguments(args.mode):
        arg_name = arg.long_param.lstrip("--").replace("-", "_")
        value = getattr(args, arg_name, None)
        if required and not value:
            raise ParamError(f"Required argument '{arg.long_param}' cannot be empty")

    return args


def init_logger(debug: bool):
    """Initialize the logger for the plugin.

    Args:
        debug (bool): Whether to enable debug logging.
    """
    level = logging.DEBUG if debug else logging.ERROR
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    meraki_logger = logging.getLogger("meraki")
    meraki_logger.setLevel(level)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)


def handle_exit(sig, frame):  # pylint: disable=unused-argument
    """Gracefully handle SIGTERM exits."""
    raise SystemExit


def main():
    """Main function."""
    debug = True
    try:
        signal.signal(signal.SIGTERM, handle_exit)
        args = get_args(MODE_MAPPING.keys())
        debug = args.debug
        init_logger(debug)

        try:
            mode_usage = MODE_MAPPING[args.mode]

        except KeyError as exc:
            raise ParamError(f"Invalid mode: '{args.mode}'") from exc

        run_check(args, mode_usage)
        sys.exit(0)

    except (ResultError, ParamError) as ex:
        ex = str(ex).replace("|", "\\pipe")
        print(f"METRIC UNKNOWN - {ex}")
        sys.exit(3)
    except KeyboardInterrupt:
        sys.exit(3)
    except ParamErrorWithHelp as ex:
        print(ex)
        sys.exit(3)
    except Exception as ex:  # pylint: disable=broad-except
        print(f"METRIC UNKNOWN - {ex}")
        if debug:
            traceback.print_exc()
        sys.exit(3)


if __name__ == "__main__":
    main()
