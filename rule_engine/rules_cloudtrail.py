def evaluate_cloudtrail(ct):
    findings = []

    if not ct["trail_exists"]:
        findings.append({
            "service": "CloudTrail",
            "resource_id": "account",
            "rule_id": "CT_DISABLED",
            "severity": "CRITICAL",
            "risk_score": 90
        })

    elif not ct["multi_region"]:
        findings.append({
            "service": "CloudTrail",
            "resource_id": "account",
            "rule_id": "CT_NOT_MULTI",
            "severity": "HIGH",
            "risk_score": 70
        })

    return findings
