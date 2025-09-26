import pytest
from unittest.mock import MagicMock

# Import the class we want to test
from nimbulite.actions.ec2 import EC2Actions, DENY_ALL_POLICY_DOCUMENT

# --- Test Fixtures ---

@pytest.fixture
def sample_instance_finding_event():
    """Provides a generic sample finding event involving an EC2 instance."""
    return {
        "Id": "finding-abc-123",
        "Resource": {
            "InstanceDetails": {
                "InstanceId": "i-0123456789abcdef0"
            }
        }
    }

@pytest.fixture
def sample_dns_rebind_event():
    """Provides a sample finding event for credential exfiltration."""
    return {
        "Id": "finding-xyz-789",
        "Resource": {
            "InstanceDetails": {
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::123456789012:instance-profile/compromised-role"
                }
            }
        }
    }

# --- Tests for tag_instance ---

def test_tag_instance_success(mocker, sample_instance_finding_event):
    """Tests that tag_instance correctly calls the EC2 client on success."""
    mock_ec2_client = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client

    result = EC2Actions.tag_instance(mock_session, sample_instance_finding_event, {})

    assert result is True
    mock_ec2_client.create_tags.assert_called_once_with(
        Resources=["i-0123456789abcdef0"],
        Tags=[{"Key": "NimbuliteFindingId", "Value": "finding-abc-123"}]
    )

def test_tag_instance_boto3_fails(mocker, sample_instance_finding_event, caplog):
    """Tests that tag_instance handles Boto3 exceptions correctly."""
    mock_ec2_client = MagicMock()
    mock_ec2_client.create_tags.side_effect = Exception("AWS API Error")
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client

    result = EC2Actions.tag_instance(mock_session, sample_instance_finding_event, {})

    assert result is False
    assert "An error occurred" in caplog.text
    assert "AWS API Error" in caplog.text

def test_tag_instance_no_instance_id(mocker, caplog):
    """Tests that tag_instance fails gracefully if the instance ID is missing."""
    mock_session = MagicMock()
    # An empty event that is missing the required fields
    empty_event = {"Id": "finding-no-instance"}

    result = EC2Actions.tag_instance(mock_session, empty_event, {})

    assert result is False
    assert "Could not find InstanceId" in caplog.text


# --- Tests for isolate_instance ---

def test_isolate_instance_success(mocker, sample_instance_finding_event):
    """Tests that isolate_instance correctly calls the EC2 client on success."""
    mock_ec2_client = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client

    params = {"isolation_security_group_id": "sg-isolated123"}
    result = EC2Actions.isolate_instance(mock_session, sample_instance_finding_event, params)

    assert result is True
    mock_ec2_client.modify_instance_attribute.assert_called_once_with(
        InstanceId="i-0123456789abcdef0",
        Groups=["sg-isolated123"]
    )

def test_isolate_instance_boto3_fails(mocker, sample_instance_finding_event, caplog):
    """Tests that isolate_instance handles Boto3 exceptions correctly."""
    mock_ec2_client = MagicMock()
    mock_ec2_client.modify_instance_attribute.side_effect = Exception("AWS API Error")
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client

    params = {"isolation_security_group_id": "sg-isolated123"}
    result = EC2Actions.isolate_instance(mock_session, sample_instance_finding_event, params)

    assert result is False
    assert "An error occurred" in caplog.text
    assert "AWS API Error" in caplog.text

def test_isolate_instance_no_sgid_param(mocker, sample_instance_finding_event, caplog):
    """Tests that isolate_instance fails gracefully if the sgid param is missing."""
    mock_session = MagicMock()
    # Empty params dict
    params = {}

    result = EC2Actions.isolate_instance(mock_session, sample_instance_finding_event, params)

    assert result is False
    # Corrected the assertion to match the actual log output
    assert "Action requires 'isolation_security_group_id' parameter" in caplog.text


# --- Tests for invalidate_iam_role_credentials ---

def test_invalidate_iam_role_credentials_success(mocker, sample_dns_rebind_event):
    """
    Tests that the action correctly calls the IAM client when everything works.
    """
    mock_iam_client = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_iam_client

    result = EC2Actions.invalidate_iam_role_credentials(mock_session, sample_dns_rebind_event, {})

    assert result is True
    mock_iam_client.put_role_policy.assert_called_once_with(
        RoleName="compromised-role",
        PolicyName="Nimbulite-Quarantine-finding-xyz-789",
        PolicyDocument=DENY_ALL_POLICY_DOCUMENT
    )

def test_invalidate_iam_role_credentials_boto3_fails(mocker, sample_dns_rebind_event, caplog):
    """
    Tests that the action correctly handles an exception from Boto3.
    """
    mock_iam_client = MagicMock()
    mock_iam_client.put_role_policy.side_effect = Exception("AWS API Error")
    mock_session = MagicMock()
    mock_session.client.return_value = mock_iam_client

    result = EC2Actions.invalidate_iam_role_credentials(mock_session, sample_dns_rebind_event, {})

    assert result is False
    assert "An error occurred" in caplog.text
    assert "AWS API Error" in caplog.text

