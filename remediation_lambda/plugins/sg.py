"""
Security Group remediation plugin.
Handles: SG_OPEN_ALL, SG_OPEN_SSH, SG_OPEN_RDP, SG_DEFAULT_OPEN
"""
import boto3

ec2 = boto3.client("ec2")

SUPPORTED_RULES = ["SG_OPEN_ALL", "SG_OPEN_SSH", "SG_OPEN_RDP", "SG_DEFAULT_OPEN"]


def remediate(rule_id, resource_id, snapshot):
    """
    Remove offending ingress rules from the security group.
    Returns rollback_config containing the removed rules so they can be restored.
    """
    sg_id = resource_id
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    removed_rules = []
    rules_to_remove = []

    for rule in sg.get("IpPermissions", []):
        protocol  = rule.get("IpProtocol")
        from_port = rule.get("FromPort")

        for ip in rule.get("IpRanges", []):
            if ip.get("CidrIp") == "0.0.0.0/0":
                if rule_id == "SG_OPEN_ALL" and protocol == "-1":
                    rules_to_remove.append(rule)
                    removed_rules.append(rule)
                elif rule_id == "SG_OPEN_SSH" and from_port == 22:
                    rules_to_remove.append(rule)
                    removed_rules.append(rule)
                elif rule_id == "SG_OPEN_RDP" and from_port == 3389:
                    rules_to_remove.append(rule)
                    removed_rules.append(rule)
                elif rule_id == "SG_DEFAULT_OPEN":
                    rules_to_remove.append(rule)
                    removed_rules.append(rule)

        # Also check IPv6 ranges for completeness
        for ip6 in rule.get("Ipv6Ranges", []):
            if ip6.get("CidrIpv6") == "::/0":
                if rule_id == "SG_OPEN_ALL" and protocol == "-1":
                    if rule not in rules_to_remove:
                        rules_to_remove.append(rule)
                        removed_rules.append(rule)
                elif rule_id == "SG_OPEN_SSH" and from_port == 22:
                    if rule not in rules_to_remove:
                        rules_to_remove.append(rule)
                        removed_rules.append(rule)
                elif rule_id == "SG_OPEN_RDP" and from_port == 3389:
                    if rule not in rules_to_remove:
                        rules_to_remove.append(rule)
                        removed_rules.append(rule)
                elif rule_id == "SG_DEFAULT_OPEN":
                    if rule not in rules_to_remove:
                        rules_to_remove.append(rule)
                        removed_rules.append(rule)

    if rules_to_remove:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=rules_to_remove
        )

    return {
        "sg_id": sg_id,
        "removed_rules": removed_rules,
        "action": f"Removed {len(removed_rules)} ingress rule(s) from {sg_id}"
    }


def rollback(rule_id, resource_id, rollback_config):
    """Re-add the ingress rules that were removed during remediation."""
    sg_id = rollback_config["sg_id"]
    removed_rules = rollback_config.get("removed_rules", [])

    if removed_rules:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=removed_rules
        )
    return {"action": f"Restored {len(removed_rules)} ingress rule(s) to {sg_id}"}
