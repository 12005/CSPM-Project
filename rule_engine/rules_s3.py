def evaluate_s3(buckets):
    findings = []

    for bucket in buckets:
        if bucket["acl_public"]:
            findings.append({
                "service": "S3",
                "resource_id": bucket["bucket_name"],
                "rule_id": "S3_PUBLIC",
                "severity": "CRITICAL",
                "risk_score": 95
            })

        if not bucket["encryption_enabled"]:
            findings.append({
                "service": "S3",
                "resource_id": bucket["bucket_name"],
                "rule_id": "S3_NO_ENCRYPTION",
                "severity": "MEDIUM",
                "risk_score": 40
            })

    return findings
