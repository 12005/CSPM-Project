"""
S3 remediation plugin.
Handles: S3_PUBLIC_ACL, S3_BLOCK_PUBLIC_DISABLED, S3_NO_ENCRYPTION,
         S3_NO_VERSIONING, S3_ALLOWS_HTTP, S3_NO_LOGGING, S3_NO_MFA_DELETE
"""
import boto3
import json

s3 = boto3.client("s3")

SUPPORTED_RULES = [
    "S3_PUBLIC_ACL",
    "S3_BLOCK_PUBLIC_DISABLED",
    "S3_NO_ENCRYPTION",
    "S3_NO_VERSIONING",
    "S3_ALLOWS_HTTP",
    "S3_NO_LOGGING",
    "S3_NO_MFA_DELETE",
]


def remediate(rule_id, resource_id, snapshot):
    bucket = resource_id

    if rule_id == "S3_PUBLIC_ACL":
        current_acl = s3.get_bucket_acl(Bucket=bucket)
        old_grants = current_acl.get("Grants", [])
        s3.put_bucket_acl(Bucket=bucket, ACL="private")
        return {
            "bucket": bucket,
            "old_grants": old_grants,
            "action": f"Set ACL to private on {bucket}"
        }

    elif rule_id == "S3_BLOCK_PUBLIC_DISABLED":
        try:
            current = s3.get_bucket_public_access_block(Bucket=bucket)
            old_config = current["PublicAccessBlockConfiguration"]
        except Exception:
            old_config = {"BlockPublicAcls": False, "IgnorePublicAcls": False,
                          "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        return {
            "bucket": bucket,
            "old_config": old_config,
            "action": f"Enabled all block public access settings on {bucket}"
        }

    elif rule_id == "S3_NO_ENCRYPTION":
        try:
            current = s3.get_bucket_encryption(Bucket=bucket)
            old_encryption = current["ServerSideEncryptionConfiguration"]
        except Exception:
            old_encryption = None
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        )
        return {
            "bucket": bucket,
            "old_encryption": old_encryption,
            "action": f"Enabled AES256 encryption on {bucket}"
        }

    elif rule_id == "S3_NO_VERSIONING":
        current = s3.get_bucket_versioning(Bucket=bucket)
        old_status = current.get("Status", "Never enabled")
        s3.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"}
        )
        return {
            "bucket": bucket,
            "old_status": old_status,
            "action": f"Enabled versioning on {bucket}"
        }

    elif rule_id == "S3_ALLOWS_HTTP":
        # Save existing bucket policy before modifying
        try:
            existing = s3.get_bucket_policy(Bucket=bucket)
            old_policy = existing["Policy"]
        except Exception:
            old_policy = None

        https_statement = {
            "Sid": "CSPM-DenyHTTP",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket}",
                f"arn:aws:s3:::{bucket}/*"
            ],
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}
            }
        }

        if old_policy:
            policy_doc = json.loads(old_policy)
            # Remove any existing CSPM-DenyHTTP to avoid duplicates
            policy_doc["Statement"] = [
                s for s in policy_doc["Statement"]
                if s.get("Sid") != "CSPM-DenyHTTP"
            ]
            policy_doc["Statement"].append(https_statement)
        else:
            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [https_statement]
            }

        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))
        return {
            "bucket": bucket,
            "old_policy": old_policy,
            "action": f"Added deny-HTTP bucket policy to {bucket}"
        }

    elif rule_id == "S3_NO_LOGGING":
        # Save current logging config before enabling
        try:
            current = s3.get_bucket_logging(Bucket=bucket)
            old_logging = current.get("LoggingEnabled")
        except Exception:
            old_logging = None

        # Log to a dedicated prefix in the same bucket
        log_prefix = "cspm-access-logs/"
        s3.put_bucket_logging(
            Bucket=bucket,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": bucket,
                    "TargetPrefix": log_prefix
                }
            }
        )
        return {
            "bucket": bucket,
            "old_logging": old_logging,
            "log_prefix": log_prefix,
            "action": f"Enabled server access logging on {bucket} (prefix: {log_prefix})"
        }

    elif rule_id == "S3_NO_MFA_DELETE":
        # Save current versioning/mfa_delete state
        current = s3.get_bucket_versioning(Bucket=bucket)
        old_mfa_delete = current.get("MFADelete", "Disabled")
        old_versioning = current.get("Status", "Suspended")
        # MFA Delete can only be enabled by the root account via AWS CLI/SDK
        # We record the state; actual enabling requires MFA serial + token
        # so we raise a clear error rather than silently failing
        raise NotImplementedError(
            "S3_NO_MFA_DELETE requires root account credentials and an MFA token "
            "to enable — this cannot be automated. Please enable MFA Delete manually "
            "using the root account: aws s3api put-bucket-versioning "
            f"--bucket {bucket} --versioning-configuration "
            "Status=Enabled,MFADelete=Enabled --mfa 'arn:... TOKEN'"
        )


def rollback(rule_id, resource_id, rollback_config):
    bucket = rollback_config["bucket"]

    if rule_id == "S3_PUBLIC_ACL":
        old_grants = rollback_config.get("old_grants", [])
        if old_grants:
            s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Grants": old_grants, "Owner": {"ID": ""}})
        return {"action": f"Restored previous ACL on {bucket}"}

    elif rule_id == "S3_BLOCK_PUBLIC_DISABLED":
        old_config = rollback_config.get("old_config", {})
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=old_config)
        return {"action": f"Restored previous block public access config on {bucket}"}

    elif rule_id == "S3_NO_ENCRYPTION":
        old = rollback_config.get("old_encryption")
        if old:
            s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration=old)
        else:
            s3.delete_bucket_encryption(Bucket=bucket)
        return {"action": f"Restored previous encryption state on {bucket}"}

    elif rule_id == "S3_NO_VERSIONING":
        old_status = rollback_config.get("old_status", "Never enabled")
        if old_status in ("Never enabled", "Suspended"):
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
        return {"action": f"Restored versioning to '{old_status}' on {bucket}"}

    elif rule_id == "S3_ALLOWS_HTTP":
        old_policy = rollback_config.get("old_policy")
        if old_policy:
            s3.put_bucket_policy(Bucket=bucket, Policy=old_policy)
        else:
            try:
                s3.delete_bucket_policy(Bucket=bucket)
            except Exception:
                pass
        return {"action": f"Restored previous bucket policy on {bucket}"}

    elif rule_id == "S3_NO_LOGGING":
        old_logging = rollback_config.get("old_logging")
        if old_logging:
            s3.put_bucket_logging(
                Bucket=bucket,
                BucketLoggingStatus={"LoggingEnabled": old_logging}
            )
        else:
            s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={})
        return {"action": f"Restored previous logging config on {bucket}"}

    elif rule_id == "S3_NO_MFA_DELETE":
        return {"action": "S3_NO_MFA_DELETE rollback is manual — MFA Delete requires root credentials"}
