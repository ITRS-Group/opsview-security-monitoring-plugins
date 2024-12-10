import pytest
import argparse
from enum import Enum
from typing import Dict, List, Union
from dataclasses import dataclass
from collections import namedtuple
from unittest.mock import patch
from check_sentinel.check_sentinel import SentinelCheck, SentinelCheckExit, METRIC_TYPE_CUSTOM

from plugnpy import Metric
from plugnpy.exception import ParamError


class IncidentStatus(Enum):
    """Enumeration of possible Sentinel incident statuses."""

    OPEN = "open"
    NEW = "new"
    CLOSED = "closed"
    ACTIVE = "active"
    RESOLVED = "resolved"


class ErrorType(Enum):
    """Enumeration of possible Sentinel error types (that we've added cover for!)."""

    NO_SENTINEL = "Failed to resolve table or column expression named 'SecurityIncident'"
    ACCESS_DENIED = "Access denied"


MOCK_SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"
MOCK_TENANT = "22222222-2222-2222-2222-222222222222"
MOCK_CLIENT = "33333333-3333-3333-3333-333333333333"

INCIDENT_METHOD_METRICS = {
    "check_open_incidents": "open_incidents",
    "check_new_incidents": "new_incidents",
    "check_closed_incidents": "closed_incidents",
    "check_active_incidents": "active_incidents",
    "check_resolved_incidents": "resolved_incidents",
}


@dataclass
class CheckIncidentsMetricExpectation:
    """Expected values for metrics in check_incidents derivative tests."""

    total_incidents: int
    query_failures: int
    no_sentinel: int


@dataclass
class WorkspaceTestCase:
    """Test case data for workspace tests."""

    workspace_ids: List[str]
    mock_data: List[Union[List[int], str, None]]
    method: str
    expected_metrics: CheckIncidentsMetricExpectation


@pytest.fixture
def sentinel_args():
    """Fixture for common SentinelCheck arguments."""
    return argparse.Namespace(
        client_id=MOCK_CLIENT,
        tenant_id=MOCK_TENANT,
        subscription_id=MOCK_SUBSCRIPTION,
        resource_group="test-resource-group",
        workspace_name="test-workspace-name",
        client_secret="test-client-secret",
        warning=None,
        critical=None,
    )


class TestSentinelIncidents:
    """Test class for Sentinel incident checking functionality."""

    @staticmethod
    def create_incidents_mock_query_response(data: List[Union[List[int], str, None]]) -> Dict:
        """Create mock query response for Sentinel incidents with proper typing and structure."""
        MockTable = namedtuple("Table", ["name", "rows"])
        results = {}

        for workspace_id, item in enumerate(data):
            if isinstance(item, str):
                results[f"ws{workspace_id}"] = (
                    "NO_SENTINEL" if ErrorType.NO_SENTINEL.value in item else "UNKNOWN_ERROR"
                )
            elif isinstance(item, list) and item:
                results[f"ws{workspace_id}"] = [MockTable("PrimaryResult", [[item[0]]])]
            elif item is None:
                results[f"ws{workspace_id}"] = [MockTable("PrimaryResult", [])]
        return results

    @pytest.mark.parametrize(
        "status",
        [
            IncidentStatus.OPEN,
            IncidentStatus.NEW,
            IncidentStatus.CLOSED,
            IncidentStatus.ACTIVE,
            IncidentStatus.RESOLVED,
        ],
    )
    def test_successful_incident_queries(self, sentinel_args, status):
        """Test successful incident queries for all status types."""
        workspace_ids = ["ws1", "ws2"]
        mock_data = [[5], [3]]
        expected = CheckIncidentsMetricExpectation(
            total_incidents=8, query_failures=0, no_sentinel=0
        )

        self._run_incident_test(
            sentinel_args, workspace_ids, mock_data, f"check_{status.value}_incidents", expected
        )

    def test_mixed_query_results(self, sentinel_args):
        """Test handling of mixed success/failure results."""
        workspace_ids = ["ws1", "ws2", "ws3", "ws4"]
        mock_data = [[10], ErrorType.NO_SENTINEL.value, ErrorType.ACCESS_DENIED.value, None]
        expected = CheckIncidentsMetricExpectation(
            total_incidents=10, query_failures=1, no_sentinel=1
        )

        self._run_incident_test(
            sentinel_args, workspace_ids, mock_data, "check_open_incidents", expected
        )

    def test_no_workspaces(self, sentinel_args):
        """Test handling of no workspaces."""
        self._run_incident_test(
            sentinel_args, [], [], "check_open_incidents", CheckIncidentsMetricExpectation(0, 0, 0)
        )

    def _run_incident_test(
        self,
        sentinel_args: argparse.Namespace,
        workspace_ids: List[str],
        mock_data: List[Union[List[int], str, None]],
        method: str,
        expected: CheckIncidentsMetricExpectation,
    ):
        """Helper method to run incident tests."""
        with patch("check_sentinel.SentinelAPI.query_all_workspaces") as mock_query_all, patch(
            "check_sentinel.SentinelAPI.get_all_workspace_ids"
        ) as mock_get_workspace_ids:

            mock_get_workspace_ids.return_value = workspace_ids
            mock_query_all.return_value = self.create_incidents_mock_query_response(mock_data)

            check = SentinelCheck({}, {}, "Custom", f"{method}; 3", "", 300, sentinel_args)
            metrics = getattr(check, method)()

            # Debug information
            print("\nTest Debug Information:")
            print(f"Method: {method}")
            print(f"Available metric names: {[m.name for m in metrics]}")
            print(f"Expected metrics: {expected}")
            print(f"Actual metrics: {[(m.name, m.value) for m in metrics]}")

            self._verify_metrics(metrics, method, expected)

    def _verify_metrics(
        self, metrics: List[Metric], method: str, expected: CheckIncidentsMetricExpectation
    ):
        """Helper method to verify metrics."""
        metric_values = {m.name: m.value for m in metrics}
        metric_name = INCIDENT_METHOD_METRICS[method]

        assert (
            metric_name in metric_values
        ), f"Expected metric '{metric_name}' not found in {list(metric_values.keys())}"
        assert (
            metric_values[metric_name] == expected.total_incidents
        ), f"Expected {expected.total_incidents} total incidents, got {metric_values[metric_name]}"
        assert (
            metric_values["query_failures"] == expected.query_failures
        ), f"Expected {expected.query_failures} query failures, got {metric_values.get('query_failures', 'missing')}"
        assert (
            metric_values["workspaces_without_sentinel"] == expected.no_sentinel
        ), f"Expected {expected.no_sentinel} workspaces without Sentinel, got {metric_values.get('workspaces_without_sentinel', 'missing')}"


class TestSentinelErrorHandling:
    """Test class for error handling scenarios."""

    def test_empty_filter_raises_error(self, sentinel_args):
        """Test that empty filter raises ValueError."""
        check = SentinelCheck({}, {}, "Custom", "check_incidents; 3", "", 300, sentinel_args)
        with pytest.raises(ValueError, match="Filter parameter cannot be empty"):
            check.check_incidents("   ", "Test Label")

    def test_invalid_metric_type(self, sentinel_args):
        """Test handling of invalid metric type."""
        with pytest.raises(ParamError):
            SentinelCheck({}, {}, "InvalidType", "", "", 300, sentinel_args)

    @pytest.mark.parametrize(
        "error_msg,expected_type",
        [
            (ErrorType.NO_SENTINEL.value, "NO_SENTINEL"),
            (ErrorType.ACCESS_DENIED.value, "UNKNOWN_ERROR"),
            ("Random error", "UNKNOWN_ERROR"),
        ],
    )
    def test_error_classification(self, sentinel_args, error_msg, expected_type):
        """Test classification of different error types."""
        test_instance = TestSentinelIncidents()
        workspace_ids = ["ws1"]
        mock_data = [error_msg]
        expected = CheckIncidentsMetricExpectation(
            total_incidents=0,
            query_failures=1 if expected_type == "UNKNOWN_ERROR" else 0,
            no_sentinel=1 if expected_type == "NO_SENTINEL" else 0,
        )

        with patch("check_sentinel.SentinelAPI.query_all_workspaces") as mock_query_all, patch(
            "check_sentinel.SentinelAPI.get_all_workspace_ids"
        ) as mock_get_workspace_ids:

            mock_get_workspace_ids.return_value = workspace_ids
            mock_query_all.return_value = test_instance.create_incidents_mock_query_response(
                mock_data
            )

            check = SentinelCheck(
                {}, {}, "Custom", "check_open_incidents; 3", "", 300, sentinel_args
            )
            metrics = check.check_open_incidents()
            test_instance._verify_metrics(metrics, "check_open_incidents", expected)


class TestLighthouseSentinelCheck:
    """Test class for Lighthouse Sentinel checking functionality."""

    @staticmethod
    def create_mock_workspaces(workspace_names):
        """Helper to create mock workspaces from a list of workspace names."""
        return [
            {
                "subscription_id": f"sub{i}",
                "resource_group_name": f"rg{i}",
                "workspace_name": name,
            }
            for i, name in enumerate(workspace_names, start=1)
        ]

    @patch("check_sentinel.SentinelAPI.list_lighthouse_sentinel_workspaces")
    @pytest.mark.parametrize(
        "mock_workspace_names, expected_workspaces_arg, expected_value, expected_status, expected_message",
        [
            ([], "", 0, Metric.STATUS_OK, None),
            (["ws1", "ws2"], "ws1,ws2", 2, Metric.STATUS_OK, None),
            (
                ["ws1"],
                "ws1,ws2",
                1,
                Metric.STATUS_CRITICAL,
                "Expected 2 workspaces, but found 1. Missing: ['ws2']",
            ),
            (
                ["ws1", "ws2", "ws3"],
                "ws1,ws2",
                3,
                Metric.STATUS_WARNING,
                "Expected 2 workspaces, but found 3. Extra: ['ws3']",
            ),
        ],
    )
    def test_check_lighthouse_sentinels(
        self,
        mock_list_workspaces,
        sentinel_args,
        mock_workspace_names,
        expected_workspaces_arg,
        expected_value,
        expected_status,
        expected_message,
    ):
        """Test the check_lighthouse_sentinels method."""
        mock_workspaces = self.create_mock_workspaces(mock_workspace_names)
        mock_list_workspaces.return_value = mock_workspaces
        sentinel_args.expected_workspaces = expected_workspaces_arg

        check = SentinelCheck(
            {}, {}, "Custom", "check_lighthouse_sentinels; 1", "", 300, sentinel_args
        )

        if expected_status == Metric.STATUS_OK:
            metrics = check.check_lighthouse_sentinels()
            assert len(metrics) == 1
            assert metrics[0].value == expected_value
            assert metrics[0].display_name == "Accessible Sentinel Workspaces"
        else:
            with pytest.raises(SentinelCheckExit) as exc_info:
                check.check_lighthouse_sentinels()
            assert exc_info.value.status == expected_status
            assert expected_message in exc_info.value.message


@pytest.fixture
def sentinel_args_with_thresholds():
    """Fixture for SentinelCheck arguments including warning and critical thresholds."""
    return argparse.Namespace(
        client_id=MOCK_CLIENT,
        tenant_id=MOCK_TENANT,
        subscription_id=MOCK_SUBSCRIPTION,
        resource_group="test-resource-group",
        workspace_name="test-workspace",
        client_secret="mock-secret",
        warning="5",
        critical="10",
    )


def mock_incident_query(num_incidents):
    """Helper to mock an incidents query result with a given number of incidents."""
    # Constructing the same data structure as the code expects for success
    MockTable = namedtuple("Table", ["name", "rows"])
    return {"ws1": [MockTable("PrimaryResult", [[num_incidents]])]}


class TestStatusEvaluation:
    """Tests that verify the plugin exits with correct status based on thresholds."""

    @patch("check_sentinel.SentinelAPI.query_all_workspaces")
    @patch("check_sentinel.SentinelAPI.get_all_workspace_ids", return_value=["ws1"])
    def test_ok_status(self, mock_get_wids, mock_query, sentinel_args_with_thresholds):
        # 3 incidents, warning=5, critical=10 => Should be OK (exit 0)
        mock_query.return_value = mock_incident_query(3)

        check = SentinelCheck(
            {},
            {},
            METRIC_TYPE_CUSTOM,
            "check_open_incidents; 1",
            "",
            300,
            sentinel_args_with_thresholds,
        )

        with patch("sys.exit") as mock_exit:
            try:
                check.check_open_incidents()
                # After calling check methods, we must finalize.
                # The plugin’s main code calls check.final(), but here we are testing just the method directly.
                # To mimic full run, create a Check object and finalize:
                from plugnpy import Check

                c = Check()
                for m in check.check_open_incidents():
                    c.add_metric_obj(m)
                c.final()
            except SystemExit:
                pass
            mock_exit.assert_called_once_with(0)

    @patch("check_sentinel.SentinelAPI.query_all_workspaces")
    @patch("check_sentinel.SentinelAPI.get_all_workspace_ids", return_value=["ws1"])
    def test_warning_status(self, mock_get_wids, mock_query, sentinel_args_with_thresholds):
        # 8 incidents, warning=5, critical=10 => Should be WARNING (exit 1)
        mock_query.return_value = mock_incident_query(8)

        check = SentinelCheck(
            {},
            {},
            METRIC_TYPE_CUSTOM,
            "check_open_incidents; 1",
            "",
            300,
            sentinel_args_with_thresholds,
        )

        with patch("sys.exit") as mock_exit:
            try:
                from plugnpy import Check

                c = Check()
                for m in check.check_open_incidents():
                    c.add_metric_obj(m)
                c.final()
            except SystemExit:
                pass
            mock_exit.assert_called_once_with(1)

    @patch("check_sentinel.SentinelAPI.query_all_workspaces")
    @patch("check_sentinel.SentinelAPI.get_all_workspace_ids", return_value=["ws1"])
    def test_critical_status(self, mock_get_wids, mock_query, sentinel_args_with_thresholds):
        # 12 incidents, warning=5, critical=10 => Should be CRITICAL (exit 2)
        mock_query.return_value = mock_incident_query(12)

        check = SentinelCheck(
            {},
            {},
            METRIC_TYPE_CUSTOM,
            "check_open_incidents; 1",
            "",
            300,
            sentinel_args_with_thresholds,
        )

        with patch("sys.exit") as mock_exit:
            try:
                from plugnpy import Check

                c = Check()
                for m in check.check_open_incidents():
                    c.add_metric_obj(m)
                c.final()
            except SystemExit:
                pass
            mock_exit.assert_called_once_with(2)
