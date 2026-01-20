import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client("s3")

def scan_s3():
    findings = []

    try:
        buckets = s3_client.list_buckets()["Buckets"]
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return findings

    for bucket in buckets:
        bucket_name = bucket["Name"]

        bucket_data = {
            "bucket_name": bucket_name,
            "public_access_block": None,
            "acl_public": False,
            "encryption_enabled": True
        }

        # 1️⃣ Public Access Block (CLIENT API)
        try:
            response = s3_client.get_public_access_block(
                Bucket=bucket_name
            )
            bucket_data["public_access_block"] = response["PublicAccessBlockConfiguration"]
        except ClientError as e:
            # Happens if BPA is never configured
            bucket_data["public_access_block"] = "NOT_CONFIGURED"

        # 2️⃣ ACL check
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl["Grants"]:
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers"):
                    bucket_data["acl_public"] = True
        except ClientError:
            pass

        # 3️⃣ Encryption check
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError:
            bucket_data["encryption_enabled"] = False

        findings.append(bucket_data)

    return findings
