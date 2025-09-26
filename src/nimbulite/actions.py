import logging

import boto3
from boto3.session import Session

logger = logging.getLogger(__name__)


def tag_instance(session: Session, finding_event: dict) -> bool:
    """
    Applies a security tag to an EC2 instance.
    Returns True on success, False on failure.
    """
    logger.info("Executing action: TagInstance")
    try:
        instance_id = (
            finding_event.get("Resource", {})
            .get("InstanceDetails", {})
            .get("InstanceId")
        )
        if not instance_id:
            logger.error("Could not find InstanceId in the finding event.")
            return False

        finding_id = finding_event.get("Id")

        ec2 = session.client("ec2")
        logger.info(f"Tagging instance {instance_id} with finding ID {finding_id}...")

        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "NimbuliteFindingId", "Value": str(finding_id)},
            ],
        )
        logger.info(f"Instance {instance_id} tagged successfully.")
        return True

    except Exception as e:
        logger.error(f"An error occurred while tagging instance: {e}")
        return False


# --- Placeholder functions for other actions ---


def isolate_instance(session, finding_event: dict) -> bool:
    logger.info("Executing action: IsolateInstance (Not Yet Implemented)")
    return True  # Return True for now to allow playbook to continue


def revoke_iam_credentials(session, finding_event: dict) -> bool:
    logger.info("Executing action: RevokeIamCredentials (Not Yet Implemented)")
    return True


def create_snapshots(session, finding_event: dict) -> bool:
    logger.info("Executing action: CreateSnapshots (Not Yet Implemented)")
    return True


def obtain_instance_metadata(session, finding_event: dict) -> bool:
    logger.info("Executing action: ObtainInstanceMetadata (Not Yet Implemented)")
    return True


def send_notification(session, finding_event: dict) -> bool:
    logger.info("Executing action: SendNotification (Not Yet Implemented)")
    return True


def run_guardduty_malware_scan(session, finding_event: dict) -> bool:
    logger.info("Executing action: RunGuardDutyMalwareScan (Not Yet Implemented)")
    return True


def terminate_and_replace_instance(session, finding_event: dict) -> bool:
    logger.info("Executing action: TerminateAndReplaceInstance (Not Yet Implemented)")
    return True
