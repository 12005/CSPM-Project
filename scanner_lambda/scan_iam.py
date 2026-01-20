import boto3
from datetime import datetime, timezone

iam = boto3.client("iam")

def scan_iam():
    findings = []

    users = iam.list_users()["Users"]

    for user in users:
        username = user["UserName"]

        user_data = {
            "user_name": username,
            "admin_policy_attached": False,
            "mfa_enabled": True
        }

        # Check attached policies
        policies = iam.list_attached_user_policies(UserName=username)
        for policy in policies["AttachedPolicies"]:
            if policy["PolicyName"] == "AdministratorAccess":
                user_data["admin_policy_attached"] = True

        # MFA check
        mfa = iam.list_mfa_devices(UserName=username)
        if len(mfa["MFADevices"]) == 0:
            user_data["mfa_enabled"] = False

        findings.append(user_data)

    return findings
