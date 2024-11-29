import pytest
import argparse
from check_sentinel import SentinelCheck
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
