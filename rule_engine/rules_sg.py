def evaluate_sg(sgs):
    findings = []

    for sg in sgs:
        if sg["open_all"]:
            findings.append({
                "service": "EC2",
                "resource_id": sg["group_id"],
                "rule_id": "SG_ALL_OPEN",
                "severity": "CRITICAL",
                "risk_score": 90
            })

        if sg["open_ssh"]:
            findings.append({
                "service": "EC2",
                "resource_id": sg["group_id"],
                "rule_id": "SG_SSH_OPEN",
                "severity": "HIGH",
                "risk_score": 70
            })

    return findings
