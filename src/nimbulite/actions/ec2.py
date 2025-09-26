import logging
from typing import Optional

import boto3
import json
from boto3.session import Session

logger = logging.getLogger(__name__)

DENY_ALL_POLICY_DOCUMENT = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }
    ]
})


class EC2Actions:
    """Static class to nest all actions."""

    @staticmethod
    def tag_instance(
        session: Session, finding_event: dict, params: Optional[dict]
    ) -> bool:
        """
        Applies a security tag to an EC2 instance.
        Returns True on success, False on failure.

        Args:
            session: Boto3 Session to build clients with.
            finding_event: Dictionary passed from GuardDuty event.
            params: Dictionary of key/value parameters. (Optional)
        Returns:
            True/False based on completion of assigned task.
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
            logger.info(
                f"Tagging instance {instance_id} with finding ID {finding_id}..."
            )

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

    @staticmethod
    def isolate_instance(session, finding_event: dict, params: Optional[dict]) -> bool:
        """
        Isolates an EC2 instance by replacing its security group with a single, restrictive one.
        Requires 'isolation_security_group_id' in the playbook step's 'with' block.
        
        Args:
            session: Boto3 Session to build clients with.
            finding_event: Dictionary passed from GuardDuty event.
            params: Dictionary of key/value parameters. (Optional)
        Returns:
            True/False based on completion of assigned task.
        """
        logger.info("Executing action: IsolateInstance")

        isolation_sg_id = params.get("isolation_security_group_id")
        if not isolation_sg_id:
            logger.error(
                "Action requires 'isolation_security_group_id' parameter in the playbook, but it was not found."
            )
            return False

        try:
            instance_id = (
                finding_event.get("Resource", {})
                .get("InstanceDetails", {})
                .get("InstanceId")
            )
            if not instance_id:
                logger.error("Could not find InstanceId in the finding event.")
                return False

            ec2 = session.client("ec2")
            logger.info(
                f"Isolating instance {instance_id} with security group {isolation_sg_id}..."
            )

            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[
                    isolation_sg_id
                ],  # This will replace all existing security groups
            )

            logger.info(f"Instance {instance_id} isolated successfully.")
            return True
        except Exception as e:
            logger.error(f"An error occurred while isolating instance: {e}")
            return False
        

    @staticmethod
    def invalidate_iam_role_credentials(session, finding_event: dict, params: Optional[dict]) -> bool:
        """
        Invalidates the temporary credentials of a compromised EC2 instance by attaching
        a 'deny all' policy to its IAM role.

        Args:
            session: Boto3 Session to build clients with.
            finding_event: Dictionary passed from GuardDuty event.
            params: Dictionary of key/value parameters. (Optional)
        Returns:
            True/False based on completion of assigned task.
        """
        logger.info("Executing action: RevokeIamCredentials")

        try:
            iam_instance_profile = finding_event.get("Resource", {}).get("InstanceDetails", {}).get("IamInstanceProfile", {}).get("Arn")
            if not iam_instance_profile:
                logger.error("Could not find an IamInstanceProfile ARN in the finding event.")    
                return False
            
            role_name = iam_instance_profile.split("/")[-1]
            logger.info(f"Found IAM role to invalidate: {role_name}")

            iam = session.client("iam")
            policy_name = f"Nimbulite-Quarantine-{finding_event.get('Id')}"
            logger.info(f"Creating and attaching deny-all policy '{policy_name}' to role '{role_name}'...")

            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=DENY_ALL_POLICY_DOCUMENT
            )

            logger.info(f"Successfully attached eny-all policy to role '{role_name}'. Credentials are now invalid.")
            return True

        except Exception as e:
            logger.error(f"An error occurred while invalidating IAM role credentials: {e}")
            return False


    # --- Placeholder functions for other actions ---
    @staticmethod
    def create_snapshots(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: CreateSnapshots (Not Yet Implemented)")
        return True

    @staticmethod
    def obtain_instance_metadata(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: ObtainInstanceMetadata (Not Yet Implemented)")
        return True

    @staticmethod
    def send_notification(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: SendNotification (Not Yet Implemented)")
        return True

    @staticmethod
    def run_guardduty_malware_scan(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: RunGuardDutyMalwareScan (Not Yet Implemented)")
        return True

    @staticmethod
    def terminate_and_replace_instance(
        session, finding_event: dict, params: dict
    ) -> bool:
        logger.info(
            "Executing action: TerminateAndReplaceInstance (Not Yet Implemented)"
        )
        return True

    @staticmethod
    def block_malicious_ip(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: BlockMaliciousIP (Not Yet Implemented)")
        return True

    @staticmethod
    def remediate_security_group(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: RemediateSecurityGroup (Not Yet Implemented)")
        return True

    @staticmethod
    def remove_public_access_rule(session, finding_event: dict, params: dict) -> bool:
        logger.info("Executing action: RemovePublicAccessRule (Not Yet Implemented)")
        return True
