import pytest
import argparse
from check_sentinel import SentinelCheck
from plugnpy.exception import ParamError
from unittest.mock import patch
from collections import namedtuple


def test_sentinel_check_init():
    """Test initialization of SentinelCheck."""
    args = argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )
    check = SentinelCheck({}, {}, "Custom", "check_open_incidents; 1", "", 300, args)
    assert check._args.subscription_id == "test_subscription_id"
    assert check._num_thresholds == 1


def test_invalid_metric_type():
    """Test handling of invalid metric type."""
    args = argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )
    with pytest.raises(ParamError):
        SentinelCheck({}, {}, "InvalidType", "", "", 300, args)


@patch("check_sentinel.SentinelAPI.get_incidents")
def test_check_open_incidents_with_no_incidents(mock_get_incidents):
    """Test the check_incidents method with no incidents."""
    mock_get_incidents.return_value = []  # Return an empty list for incidents
    args = argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )
    check = SentinelCheck({}, {}, "Custom", "check_open_incidents; 1", "", 300, args)
    metrics = check.check_open_incidents()
    assert len(metrics) == 1
    assert metrics[0].value == 0  # Since we mocked no incidents


@patch("check_sentinel.SentinelAPI.get_incidents")
def test_check_open_incidents_with_some_incidents(mock_get_incidents):
    """Test the check_open_incidents method with some incidents."""
    # Mock incidents with different statuses
    MockIncident = namedtuple("MockIncident", ["properties"])
    MockProperties = namedtuple("Properties", ["status"])

    incidents = [
        MockIncident(MockProperties(status="New")),
        MockIncident(MockProperties(status="new")),
        MockIncident(MockProperties(status="Active")),
        MockIncident(MockProperties(status="Closed")),
    ]
    mock_get_incidents.return_value = incidents

    args = argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )
    check = SentinelCheck({}, {}, "Custom", "check_open_incidents; 1", "", 300, args)
    metrics = check.check_open_incidents()
    assert len(metrics) == 1
    assert metrics[0].value == 3  # There are 3 open incidents
    assert metrics[0].display_name == "Open Incidents"


@patch("check_sentinel.SentinelAPI.get_incidents")
def test_check_new_incidents_with_no_incidents(mock_get_incidents):
    """Test the check_new_incidents method with no incidents."""
    mock_get_incidents.return_value = []
    args = argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )
    check = SentinelCheck({}, {}, "Custom", "check_new_incidents; 1", "", 300, args)
    metrics = check.check_new_incidents()
    assert len(metrics) == 1
    assert metrics[0].value == 0


@patch("check_sentinel.SentinelAPI.get_incidents")
def test_check_new_incidents_with_some_incidents(mock_get_incidents):
    """Test the check_new_incidents method with some incidents."""
    # Mock incidents with different statuses
    MockIncident = namedtuple("MockIncident", ["properties"])
    MockProperties = namedtuple("Properties", ["status"])

    incidents = [
        MockIncident(MockProperties(status="New")),
        MockIncident(MockProperties(status="new")),
        MockIncident(MockProperties(status="Active")),
        MockIncident(MockProperties(status="Closed")),
    ]
    mock_get_incidents.return_value = incidents

    args = argparse.Namespace(
        subscription_id="test_subscription_id",
        resource_group="test_resource_group",
        workspace_name="test_workspace_name",
        warning=None,
        critical=None,
    )
    check = SentinelCheck({}, {}, "Custom", "check_new_incidents; 1", "", 300, args)
    metrics = check.check_new_incidents()
    assert len(metrics) == 1
    assert metrics[0].value == 2  # There are 2 new incidents
    assert metrics[0].display_name == "New Incidents"
