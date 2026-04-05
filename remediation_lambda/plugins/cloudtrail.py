"""
CloudTrail remediation plugin.
Handles: CT_DISABLED, CT_NOT_MULTI_REGION, CT_NO_KMS, CT_LOG_VALIDATION_OFF
"""
import boto3
import json
from datetime import datetime

ct  = boto3.client("cloudtrail")
s3  = boto3.client("s3")
kms = boto3.client("kms")
sts = boto3.client("sts")

SUPPORTED_RULES = [
    "CT_DISABLED",
    "CT_NOT_MULTI_REGION",
    "CT_NO_KMS",
    "CT_LOG_VALIDATION_OFF"
]


def _get_account_id():
    return sts.get_caller_identity()["Account"]


def _get_first_trail():
    trails = ct.describe_trails()["trailList"]
    return trails[0] if trails else None


def remediate(rule_id, resource_id, snapshot):

    if rule_id == "CT_DISABLED":
        # Create a new CloudTrail with a dedicated S3 bucket
        account_id = _get_account_id()
        bucket_name = f"cspm-cloudtrail-logs-{account_id}"
        region = boto3.session.Session().region_name

        # Create S3 bucket for trail logs
        try:
            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": region})
        except s3.exceptions.BucketAlreadyOwnedByYou:
            pass

        # Attach bucket policy required by CloudTrail
        bucket_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "AWSCloudTrailAclCheck", "Effect": "Allow",
                 "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket_name}"},
                {"Sid": "AWSCloudTrailWrite", "Effect": "Allow",
                 "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Action": "s3:PutObject",
                 "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                 "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}}
            ]
        })
        s3.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)

        # Create and start the trail
        trail = ct.create_trail(
            Name="cspm-auto-trail",
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True
        )
        ct.start_logging(Name=trail["TrailARN"])

        return {
            "trail_arn": trail["TrailARN"],
            "bucket_name": bucket_name,
            "created_trail": True,
            "action": f"Created CloudTrail 'cspm-auto-trail' logging to s3://{bucket_name}"
        }

    elif rule_id == "CT_NOT_MULTI_REGION":
        trail = _get_first_trail()
        if not trail:
            return {"action": "No trail found"}
        old_multi_region = trail.get("IsMultiRegionTrail", False)
        ct.update_trail(Name=trail["Name"], IsMultiRegionTrail=True)
        return {
            "trail_name": trail["Name"],
            "old_multi_region": old_multi_region,
            "action": f"Enabled multi-region on trail {trail['Name']}"
        }

    elif rule_id == "CT_NO_KMS":
        trail = _get_first_trail()
        if not trail:
            return {"action": "No trail found"}
        old_kms = trail.get("KmsKeyId")
        # Create a new KMS key for CloudTrail
        key = kms.create_key(
            Description="CSPM auto-created key for CloudTrail encryption",
            KeyUsage="ENCRYPT_DECRYPT"
        )
        key_id = key["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName="alias/cspm-cloudtrail-key", TargetKeyId=key_id)
        ct.update_trail(Name=trail["Name"], KMSKeyId=key_id)
        return {
            "trail_name": trail["Name"],
            "old_kms_key": old_kms,
            "new_kms_key": key_id,
            "action": f"Created KMS key and enabled encryption on trail {trail['Name']}"
        }

    elif rule_id == "CT_LOG_VALIDATION_OFF":
        trail = _get_first_trail()
        if not trail:
            return {"action": "No trail found"}
        old_validation = trail.get("LogFileValidationEnabled", False)
        ct.update_trail(Name=trail["Name"], EnableLogFileValidation=True)
        return {
            "trail_name": trail["Name"],
            "old_validation": old_validation,
            "action": f"Enabled log file validation on trail {trail['Name']}"
        }


def rollback(rule_id, resource_id, rollback_config):

    if rule_id == "CT_DISABLED":
        # Delete the auto-created trail and bucket
        trail_arn = rollback_config.get("trail_arn")
        bucket_name = rollback_config.get("bucket_name")
        if trail_arn:
            try:
                ct.stop_logging(Name=trail_arn)
                ct.delete_trail(Name=trail_arn)
            except:
                pass
        return {"action": f"Deleted auto-created trail and logs bucket"}

    elif rule_id == "CT_NOT_MULTI_REGION":
        trail_name = rollback_config.get("trail_name")
        old = rollback_config.get("old_multi_region", False)
        ct.update_trail(Name=trail_name, IsMultiRegionTrail=old)
        return {"action": f"Restored multi-region to {old} on {trail_name}"}

    elif rule_id == "CT_NO_KMS":
        trail_name = rollback_config.get("trail_name")
        old_kms = rollback_config.get("old_kms_key")
        if old_kms:
            ct.update_trail(Name=trail_name, KMSKeyId=old_kms)
        else:
            ct.update_trail(Name=trail_name, KMSKeyId="")
        return {"action": f"Restored KMS config on {trail_name}"}

    elif rule_id == "CT_LOG_VALIDATION_OFF":
        trail_name = rollback_config.get("trail_name")
        old = rollback_config.get("old_validation", False)
        ct.update_trail(Name=trail_name, EnableLogFileValidation=old)
        return {"action": f"Restored log validation to {old} on {trail_name}"}
