import pytest
from unittest.mock import MagicMock, patch

from nimbulite.engine import Engine

# --- Test Fixtures ---

@pytest.fixture
def sample_config():
    """Provides a sample configuration dictionary, mimicking the YAML file."""
    return {
        "findings_to_playbook_map": {
            "ec2": [
                {
                    "finding": "Impact:EC2/PortSweep",
                    "playbook": "InstanceCompromise",
                    "enabled": True,
                },
                {
                    "finding": "UnauthorizedAccess:EC2/SSHBruteForce",
                    "enabled": True,
                    "conditional_on": "resource_role",
                    "conditions": [
                        {"if": "ACTOR", "then": "InstanceCompromise"},
                        {"if": "TARGET", "then": "InboundBruteForce"},
                    ],
                },
            ]
        },
        "playbooks": [
            {
                "name": "InstanceCompromise",
                "steps": [
                    {"action": "TagInstance", "enabled": True},
                    {"action": "IsolateInstance", "enabled": True},
                ],
            },
            {
                "name": "InboundBruteForce",
                "steps": [{"action": "BlockMaliciousIP", "enabled": True}],
            },
        ],
    }

@pytest.fixture
def simple_finding_event():
    """A simple finding that maps to one playbook."""
    return {"Id": "finding-1", "Type": "Impact:EC2/PortSweep"}

@pytest.fixture
def actor_finding_event():
    """A conditional finding where the instance is the ACTOR."""
    return {
        "Id": "finding-2",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Service": {"ResourceRole": "ACTOR"},
    }

@pytest.fixture
def target_finding_event():
    """A conditional finding where the instance is the TARGET."""
    return {
        "Id": "finding-3",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Service": {"ResourceRole": "TARGET"},
    }

@pytest.fixture
def unknown_finding_event():
    """A finding that does not have a playbook mapping."""
    return {"Id": "finding-4", "Type": "Unmapped:EC2/SomeNewFinding"}


# --- Engine Tests ---

def test_engine_initialization_success(sample_config):
    """Tests that the engine can be initialized with a valid config."""
    try:
        Engine(config=sample_config)
    except ValueError:
        pytest.fail("Engine initialization failed with a valid config.")

def test_engine_initialization_fails_with_bad_config():
    """Tests that the engine raises an error for invalid configurations."""
    with pytest.raises(ValueError, match="Configuration cannot be empty"):
        Engine(config={})

    with pytest.raises(ValueError, match="missing required top-level keys"):
        Engine(config={"playbooks": []})


@patch("nimbulite.engine.EC2Actions")
def test_process_simple_finding(MockEC2Actions, sample_config, simple_finding_event):
    """Tests the end-to-end processing for a simple finding to playbook mapping."""
    mock_actions_instance = MockEC2Actions.return_value
    mock_actions_instance.tag_instance.return_value = True
    mock_actions_instance.isolate_instance.return_value = True

    engine = Engine(config=sample_config)
    result = engine.process_finding(simple_finding_event)

    assert result["playbook_executed"] == "InstanceCompromise"
    assert result["actions_executed"] == 2
    mock_actions_instance.tag_instance.assert_called_once()
    mock_actions_instance.isolate_instance.assert_called_once()


@patch("nimbulite.engine.EC2Actions")
def test_process_conditional_actor(MockEC2Actions, sample_config, actor_finding_event):
    """Tests that a conditional finding correctly maps to the 'ACTOR' playbook."""
    mock_actions_instance = MockEC2Actions.return_value
    mock_actions_instance.tag_instance.return_value = True
    mock_actions_instance.isolate_instance.return_value = True

    engine = Engine(config=sample_config)
    result = engine.process_finding(actor_finding_event)

    assert result["playbook_executed"] == "InstanceCompromise"
    assert result["actions_executed"] == 2


@patch("nimbulite.engine.EC2Actions")
def test_process_conditional_target(MockEC2Actions, sample_config, target_finding_event):
    """Tests that a conditional finding correctly maps to the 'TARGET' playbook."""
    mock_actions_instance = MockEC2Actions.return_value
    # We don't have BlockMaliciousIP in EC2Actions, so we can add it to the mock
    mock_actions_instance.block_malicious_ip.return_value = True
    
    # Update the dispatcher in the engine instance to know about the new mock method
    engine = Engine(config=sample_config)
    engine._action_dispatcher["BlockMaliciousIP"] = mock_actions_instance.block_malicious_ip
    
    result = engine.process_finding(target_finding_event)

    assert result["playbook_executed"] == "InboundBruteForce"
    assert result["actions_executed"] == 1
    mock_actions_instance.block_malicious_ip.assert_called_once()


@patch("nimbulite.engine.EC2Actions")
def test_engine_halts_on_action_failure(MockEC2Actions, sample_config, simple_finding_event, caplog):
    """Tests that playbook execution stops if a step returns False."""
    mock_actions_instance = MockEC2Actions.return_value
    # Configure the first action to fail
    mock_actions_instance.tag_instance.return_value = False

    engine = Engine(config=sample_config)
    result = engine.process_finding(simple_finding_event)

    assert result["playbook_executed"] == "InstanceCompromise"
    assert result["actions_executed"] == 0
    assert "Action 'TagInstance' failed. Halting playbook execution." in caplog.text
    # Ensure the second action was never called
    mock_actions_instance.isolate_instance.assert_not_called()

@patch("nimbulite.engine.EC2Actions")
def test_unknown_finding_is_skipped(MockEC2Actions, sample_config, unknown_finding_event, caplog):
    """Tests that a finding with no mapping is skipped gracefully."""
    mock_actions_instance = MockEC2Actions.return_value
    
    engine = Engine(config=sample_config)
    result = engine.process_finding(unknown_finding_event)

    assert result["status"] == "skipped"
    assert "No playbook found for finding type" in caplog.text
    # Ensure no actions were ever attempted
    assert not mock_actions_instance.mock_calls
