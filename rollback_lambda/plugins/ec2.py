"""
EC2 remediation plugin.
Handles: EC2_IMDSV2_DISABLED, EC2_PUBLIC_SNAPSHOT, VPC_NO_FLOW_LOGS
"""
import boto3
import json

ec2 = boto3.client("ec2")
iam = boto3.client("iam")
sts = boto3.client("sts")

SUPPORTED_RULES = [
    "EC2_IMDSV2_DISABLED",
    "EC2_PUBLIC_SNAPSHOT",
    "VPC_NO_FLOW_LOGS",
]


def _get_account_id():
    return sts.get_caller_identity()["Account"]


def _get_or_create_flow_log_role():
    """
    Return ARN of an IAM role that allows VPC flow logs to publish to CloudWatch.
    Creates the role if it doesn't exist.
    """
    role_name = "CSPM-VPCFlowLogsRole"
    assume_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    })
    inline_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }]
    })

    try:
        role = iam.get_role(RoleName=role_name)["Role"]
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_policy,
            Description="CSPM auto-created role for VPC flow logs"
        )["Role"]
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="CSPM-FlowLogsPolicy",
            PolicyDocument=inline_policy
        )

    return role["Arn"]


def remediate(rule_id, resource_id, snapshot):

    if rule_id == "EC2_IMDSV2_DISABLED":
        instance_id = resource_id

        # Save current metadata options before changing
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        instance = reservations[0]["Instances"][0]
        old_metadata_opts = instance.get("MetadataOptions", {})
        old_http_tokens = old_metadata_opts.get("HttpTokens", "optional")

        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpEndpoint="enabled"
        )
        return {
            "instance_id": instance_id,
            "old_http_tokens": old_http_tokens,
            "action": f"Enforced IMDSv2 (HttpTokens=required) on instance {instance_id}"
        }

    elif rule_id == "EC2_PUBLIC_SNAPSHOT":
        snapshot_id = resource_id

        # Save current permissions before changing
        perms = ec2.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission"
        )["CreateVolumePermissions"]
        was_public = any(p.get("Group") == "all" for p in perms)

        # Remove the public 'all' group permission
        ec2.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
            OperationType="remove",
            GroupNames=["all"]
        )
        return {
            "snapshot_id": snapshot_id,
            "was_public": was_public,
            "action": f"Made snapshot {snapshot_id} private (removed public access)"
        }

    elif rule_id == "VPC_NO_FLOW_LOGS":
        vpc_id = resource_id

        # Check if any flow logs already exist for this VPC
        existing = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )["FlowLogs"]
        old_flow_logs = [fl["FlowLogId"] for fl in existing]

        # Get or create the IAM role for flow logs
        role_arn = _get_or_create_flow_log_role()
        log_group_name = f"/cspm/vpc-flow-logs/{vpc_id}"

        result = ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=role_arn
        )

        flow_log_ids = result.get("FlowLogIds", [])
        return {
            "vpc_id": vpc_id,
            "flow_log_ids": flow_log_ids,
            "log_group_name": log_group_name,
            "old_flow_logs": old_flow_logs,
            "action": f"Created VPC flow logs for {vpc_id} → CloudWatch log group {log_group_name}"
        }


def rollback(rule_id, resource_id, rollback_config):

    if rule_id == "EC2_IMDSV2_DISABLED":
        instance_id = rollback_config.get("instance_id", resource_id)
        old_http_tokens = rollback_config.get("old_http_tokens", "optional")
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens=old_http_tokens,
            HttpEndpoint="enabled"
        )
        return {"action": f"Restored IMDSv2 setting to HttpTokens={old_http_tokens} on {instance_id}"}

    elif rule_id == "EC2_PUBLIC_SNAPSHOT":
        snapshot_id = rollback_config.get("snapshot_id", resource_id)
        was_public = rollback_config.get("was_public", False)
        if was_public:
            ec2.modify_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute="createVolumePermission",
                OperationType="add",
                GroupNames=["all"]
            )
        return {"action": f"Restored snapshot {snapshot_id} to {'public' if was_public else 'private'}"}

    elif rule_id == "VPC_NO_FLOW_LOGS":
        # Delete the flow logs we created
        flow_log_ids = rollback_config.get("flow_log_ids", [])
        if flow_log_ids:
            ec2.delete_flow_logs(FlowLogIds=flow_log_ids)
        return {"action": f"Deleted CSPM-created flow logs {flow_log_ids} from {rollback_config.get('vpc_id', resource_id)}"}
