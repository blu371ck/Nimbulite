import logging

import boto3

from . import actions

logger = logging.getLogger(__name__)


class Engine:
    """The main Nimbulite remediation engine."""

    def __init__(self, config: dict):
        """
        Initializes the engine with a user-provided configuration.

        Args:
            config: A dictionary parsed from the user's YAML file.
        """
        if not config:
            raise ValueError("Configuration cannot be empty.")

        if "findings_to_playbook_map" not in config or "playbooks" not in config:
            raise ValueError("Configuration is missing required top-level keys.")

        self._config = config

        self._session = boto3.Session()

        self._action_dispatcher = {
            "TagInstance": actions.tag_instance,
            "IsolateInstance": actions.isolate_instance,
            "RevokeIamCredentials": actions.revoke_iam_credentials,
            "CreateSnapshots": actions.create_snapshots,
            "ObtainInstanceMetadata": actions.obtain_instance_metadata,
            "SendNotification": actions.send_notification,
            "RunGuardDutyMalwareScan": actions.run_guardduty_malware_scan,
            "TerminateAndReplaceInstance": actions.terminate_and_replace_instance,
        }
        logger.info("Nimbulite Engine initialized successfully.")

    def _find_playbook_for_finding(self, finding_event: dict):
        """Looks up the appropriate playbook name for a given finding."""
        finding_type = finding_event.get("Type")
        if not finding_type:
            logger.warning("Finding event is missing a 'Type' field.")
            return None

        mappings = self._config.get("findings_to_playbook_map", {}).get("ec2", [])

        for mapping in mappings:
            if mapping.get("finding") == finding_type:
                if "conditional_on" in mapping:
                    key = mapping["conditional_on"]
                    actual_value = finding_event.get("Service", {}).get("ResourceRole")

                    if not actual_value:
                        logger.warning(
                            f"Conditional finding '{finding_type}' is missing the '{key}' field in the event."
                        )
                        return None

                    for condition in mapping.get("conditions", []):
                        if condition.get("if") == actual_value:
                            return condition.get("then")
                else:
                    return mapping.get("playbook")

        return None

    def process_finding(self, finding_event: dict):
        """
        Processes a single GuardDuty finding event and executes the appropriate playbook.
        """
        finding_id = finding_event.get("Id")
        finding_type = finding_event.get("Type")
        logger.info(f"Processing finding ID: {finding_id} (Type: {finding_type})")

        playbook_name = self._find_playbook_for_finding(finding_event)

        if not playbook_name:
            logger.warning(
                f"No playbook found for finding type '{finding_type}'. Skipping."
            )
            return {"status": "skipped", "reason": "No playbook found"}

        logger.info(f"Found matching playbook: '{playbook_name}'")

        playbook_steps = []
        for p in self._config.get("playbooks", []):
            if p.get("name") == playbook_name:
                playbook_steps = p.get("steps", [])
                break

        if not playbook_steps:
            logger.warning(
                f"Playbook '{playbook_name}' is defined but has no steps. Skipping."
            )
            return {"status": "skipped", "reason": "Playbook has no steps"}

        logger.info("--- Executing Playbook Actions ---")
        actions_executed = 0
        for step in playbook_steps:
            if step.get("enabled"):
                action_name = step.get("action")
                action_func = self._action_dispatcher.get(action_name)

                if action_func:
                    try:
                        # Execute the action and check its return status
                        success = action_func(self._session, finding_event)
                        if success:
                            actions_executed += 1
                        else:
                            # If a critical action fails, stop the playbook
                            logger.error(
                                f"Action '{action_name}' failed. Halting playbook execution."
                            )
                            break
                    except Exception as e:
                        logger.critical(
                            f"An unhandled exception occurred while executing action '{action_name}': {e}"
                        )
                        logger.error(
                            f"Halting playbook execution due to unhandled exception."
                        )
                        break
                else:
                    logger.warning(
                        f"No action function found for '{action_name}'. Skipping."
                    )

        logger.info("-----------------------------------")

        return {
            "status": "processed",
            "playbook_executed": playbook_name,
            "actions_executed": actions_executed,
        }
