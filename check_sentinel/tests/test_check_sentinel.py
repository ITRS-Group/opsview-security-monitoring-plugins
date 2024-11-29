import pytest
import argparse
from check_sentinel import SentinelCheck, SentinelCheckExit
from plugnpy import Metric
from plugnpy.exception import ParamError
from unittest.mock import patch
from collections import namedtuple


# Define reusable fixtures and helper functions
@pytest.fixture
def sentinel_args():
    """Fixture for common SentinelCheck arguments."""
    return argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )


def create_mock_incidents(status_list):
    """Helper to create mock incidents from a list of statuses."""
    MockIncident = namedtuple("MockIncident", ["properties"])
    MockProperties = namedtuple("Properties", ["status"])
    return [MockIncident(MockProperties(status=status)) for status in status_list]


def assert_metrics(metrics, expected_value, expected_display_name=None):
    """Helper to assert metrics' value and optionally display_name."""
    assert len(metrics) == 1
    assert metrics[0].value == expected_value
    if expected_display_name:
        assert metrics[0].display_name == expected_display_name


def create_mock_workspaces(workspace_names):
    """Helper to create mock workspaces from a list of workspace names."""
    return [
        {"subscription_id": f"sub{i}", "resource_group_name": f"rg{i}", "workspace_name": name}
        for i, name in enumerate(workspace_names, start=1)
    ]


# Tests start here
def test_sentinel_check_init(sentinel_args):
    """Test initialization of SentinelCheck."""
    check = SentinelCheck({}, {}, "Custom", "check_open_incidents; 1", "", 300, sentinel_args)
    assert check._args.subscription_id == sentinel_args.subscription_id
    assert check._num_thresholds == 1


def test_invalid_metric_type(sentinel_args):
    """Test handling of invalid metric type."""
    with pytest.raises(ParamError):
        SentinelCheck({}, {}, "InvalidType", "", "", 300, sentinel_args)


@patch("check_sentinel.SentinelAPI.get_incidents")
@pytest.mark.parametrize(
    "mock_data, method, expected_value, display_name",
    [
        ([], "check_open_incidents", 0, "Open Incidents"),  # No incidents
        (["New", "new", "Active", "Closed"], "check_open_incidents", 3, "Open Incidents"),  # 3 open
        (["Closed", "Closed", "Closed"], "check_open_incidents", 0, "Open Incidents"),  # All closed
        ([], "check_new_incidents", 0, "New Incidents"),  # No new incidents
        (["New", "new", "Active", "Closed"], "check_new_incidents", 2, "New Incidents"),  # 2 new
        (["Closed", "Closed", "Closed"], "check_new_incidents", 0, "New Incidents"),  # All closed
    ],
)
def test_check_incidents(
    mock_get_incidents, sentinel_args, mock_data, method, expected_value, display_name
):
    """Test check_open_incidents and check_new_incidents using parameterized tests."""
    # Mock data
    incidents = create_mock_incidents(mock_data)
    mock_get_incidents.return_value = incidents

    # Initialize SentinelCheck
    check = SentinelCheck({}, {}, "Custom", f"{method}; 1", "", 300, sentinel_args)

    # Call the appropriate method dynamically
    metrics = getattr(check, method)()
    assert_metrics(metrics, expected_value, display_name)


@patch("check_sentinel.SentinelAPI.list_lighthouse_sentinel_workspaces")
@pytest.mark.parametrize(
    "mock_workspace_names, expected_workspaces_arg, expected_value, expected_status, expected_message",
    [
        # Test case 1: No accessible workspaces, no expected workspaces
        ([], "", 0, Metric.STATUS_OK, None),
        # Test case 2: Accessible workspaces match expected workspaces
        (["ws1", "ws2"], "ws1,ws2", 2, Metric.STATUS_OK, None),
        # Test case 3: Some expected workspaces missing
        (
            ["ws1"],
            "ws1,ws2",
            1,
            Metric.STATUS_CRITICAL,
            "Expected 2 workspaces, but found 1. Missing: ws2",
        ),
        # Test case 4: No accessible workspaces, but expected workspaces provided
        ([], "ws1", 0, Metric.STATUS_CRITICAL, "Expected 1 workspaces, but found 0. Missing: ws1"),
        # Test case 5: More accessible workspaces than expected
        (
            ["ws1", "ws2", "ws3"],
            "ws1,ws2",
            3,
            Metric.STATUS_WARNING,
            "Expected 2 workspaces, but found 3. Extra: ws3",
        ),
        # Test case 6: No expected workspaces provided
        (["ws1", "ws2"], "", 2, Metric.STATUS_OK, None),
    ],
)
def test_check_lighthouse_sentinels(
    mock_list_workspaces,
    sentinel_args,
    mock_workspace_names,
    expected_workspaces_arg,
    expected_value,
    expected_status,
    expected_message,
):
    """Test the check_lighthouse_sentinels method with various scenarios."""
    # Mock data
    mock_workspaces = create_mock_workspaces(mock_workspace_names)
    mock_list_workspaces.return_value = mock_workspaces

    # Set expected workspaces
    sentinel_args.expected_workspaces = expected_workspaces_arg

    # Initialize SentinelCheck
    check = SentinelCheck({}, {}, "Custom", "check_lighthouse_sentinels; 1", "", 300, sentinel_args)

    # Call the method and handle exceptions
    if expected_status == Metric.STATUS_OK:
        metrics = check.check_lighthouse_sentinels()
        assert_metrics(
            metrics,
            expected_value=expected_value,
            expected_display_name="Accessible Sentinel Workspaces",
        )
    else:
        with pytest.raises(SentinelCheckExit) as exc_info:
            check.check_lighthouse_sentinels()
        assert exc_info.value.status == expected_status
        assert expected_message in exc_info.value.message
