def evaluate_iam(iam_data):
    findings = []

    for user in iam_data:
        if user["admin_policy_attached"]:
            findings.append({
                "service": "IAM",
                "resource_id": user["user_name"],
                "rule_id": "IAM_ADMIN",
                "severity": "HIGH",
                "risk_score": 80
            })

        if not user["mfa_enabled"]:
            findings.append({
                "service": "IAM",
                "resource_id": user["user_name"],
                "rule_id": "IAM_NO_MFA",
                "severity": "MEDIUM",
                "risk_score": 50
            })

    return findings
