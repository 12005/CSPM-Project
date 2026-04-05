import boto3
import json

s3 = boto3.client("s3")

def scan_s3():
    results = []

    for b in s3.list_buckets()["Buckets"]:
        name   = b["Name"]
        region = _get_region(name)

        # ACL public (CIS 2.1.5)
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public_acl = any(
                g["Grantee"].get("URI", "").endswith("AllUsers")
                for g in acl["Grants"]
            )
        except:
            public_acl = False

        # Encryption (CIS 2.1.1)
        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except:
            encrypted = False

        # Block public access — all 4 flags (CIS 2.1.5)
        try:
            pab = s3.get_bucket_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            block_public            = cfg.get("BlockPublicAcls", False)
            ignore_public_acls      = cfg.get("IgnorePublicAcls", False)
            block_public_policy     = cfg.get("BlockPublicPolicy", False)
            restrict_public_buckets = cfg.get("RestrictPublicBuckets", False)
            fully_blocked = all([
                block_public, ignore_public_acls,
                block_public_policy, restrict_public_buckets
            ])
        except:
            block_public  = False
            fully_blocked = False

        # FIX #2 — single call for versioning + mfa_delete (CIS 2.1.3)
        try:
            v          = s3.get_bucket_versioning(Bucket=name)
            versioning = v.get("Status") == "Enabled"
            mfa_delete = v.get("MFADelete") == "Enabled"
        except:
            versioning = False
            mfa_delete = False

        # FIX #1 — correct allows_http logic (CIS 2.1.2)
        # Default True: HTTP is allowed unless a Deny-on-SecureTransport=false exists
        allows_http = True
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Deny":
                    continue
                bool_cond = stmt.get("Condition", {}).get("Bool", {})
                # AWS header keys are case-insensitive — check both casings
                secure = (
                    bool_cond.get("aws:SecureTransport")
                    or bool_cond.get("aws:securetransport")
                )
                if secure is not None and str(secure).lower() == "false":
                    allows_http = False
                    break
        except:
            # No bucket policy at all = HTTP is allowed
            allows_http = True

        # Server access logging (CIS 2.1.4)
        try:
            logging_resp    = s3.get_bucket_logging(Bucket=name)
            logging_enabled = "LoggingEnabled" in logging_resp
        except:
            logging_enabled = False

        results.append({
            "bucket":          name,
            "region":          region,
            "public_acl":      public_acl,
            "encrypted":       encrypted,
            "block_public":    block_public,
            "fully_blocked":   fully_blocked,
            "versioning":      versioning,
            "mfa_delete":      mfa_delete,
            "allows_http":     allows_http,
            "logging_enabled": logging_enabled,
        })

    return results


def _get_region(bucket_name):
    try:
        loc = s3.get_bucket_location(Bucket=bucket_name)
        return loc["LocationConstraint"] or "us-east-1"
    except:
        return "unknown"
