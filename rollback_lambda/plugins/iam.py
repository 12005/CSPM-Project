"""
IAM remediation plugin.
Handles: IAM_NO_MFA, IAM_ADMIN, IAM_MULTI_KEYS, IAM_KEY_OLD, IAM_INLINE_POLICY,
         IAM_KEY_UNUSED, IAM_STALE_USER, IAM_WILDCARD_POLICY,
         IAM_NO_PASSWORD_POLICY, IAM_PASSWORD_SHORT, IAM_PASSWORD_NO_UPPER,
         IAM_PASSWORD_NO_LOWER, IAM_PASSWORD_NO_NUMBER, IAM_PASSWORD_NO_SYMBOL,
         IAM_PASSWORD_NO_EXPIRY, IAM_PASSWORD_REUSE,
         IAM_ROLE_WILDCARD_TRUST,
         IAM_ROOT_KEYS, IAM_ROOT_NO_MFA, IAM_ROOT_ACTIVE (manual-only, logged)
"""
import boto3
import json
from datetime import datetime, timezone

iam = boto3.client("iam")

SUPPORTED_RULES = [
    "IAM_NO_MFA",
    "IAM_ADMIN",
    "IAM_MULTI_KEYS",
    "IAM_KEY_OLD",
    "IAM_INLINE_POLICY",
    "IAM_KEY_UNUSED",
    "IAM_STALE_USER",
    "IAM_WILDCARD_POLICY",
    "IAM_NO_PASSWORD_POLICY",
    "IAM_PASSWORD_SHORT",
    "IAM_PASSWORD_NO_UPPER",
    "IAM_PASSWORD_NO_LOWER",
    "IAM_PASSWORD_NO_NUMBER",
    "IAM_PASSWORD_NO_SYMBOL",
    "IAM_PASSWORD_NO_EXPIRY",
    "IAM_PASSWORD_REUSE",
    "IAM_ROLE_WILDCARD_TRUST",
    "IAM_ROOT_KEYS",
    "IAM_ROOT_NO_MFA",
    "IAM_ROOT_ACTIVE",
]

# Deny-all policy applied to users without MFA
MFA_ENFORCE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "DenyAllWithoutMFA",
        "Effect": "Deny",
        "NotAction": [
            "iam:CreateVirtualMFADevice",
            "iam:EnableMFADevice",
            "iam:GetUser",
            "iam:ListMFADevices",
            "iam:ListVirtualMFADevices",
            "iam:ResyncMFADevice",
            "sts:GetSessionToken"
        ],
        "Resource": "*",
        "Condition": {
            "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
        }
    }]
})

# Strong password policy baseline (CIS AWS Foundations Benchmark)
STRONG_PASSWORD_POLICY = {
    "MinimumPasswordLength":        14,
    "RequireUppercaseCharacters":   True,
    "RequireLowercaseCharacters":   True,
    "RequireNumbers":               True,
    "RequireSymbols":               True,
    "MaxPasswordAge":               90,
    "PasswordReusePrevention":      24,
    "AllowUsersToChangePassword":   True,
    "HardExpiry":                   False,
}


def _get_current_password_policy():
    """Return current password policy dict, or None if none exists."""
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return None
    except Exception:
        return None


def remediate(rule_id, resource_id, snapshot):
    username = resource_id

    # ── Existing rules ────────────────────────────────────────────────────────

    if rule_id == "IAM_NO_MFA":
        policy_name = "CSPM-EnforceMFA"
        try:
            iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=MFA_ENFORCE_POLICY
            )
        except Exception:
            pass
        return {
            "username": username,
            "policy_name": policy_name,
            "action": f"Attached MFA enforcement deny policy to {username}. User must set up MFA to regain access."
        }

    elif rule_id == "IAM_ADMIN":
        try:
            iam.detach_user_policy(
                UserName=username,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
        except iam.exceptions.NoSuchEntityException:
            pass
        return {
            "username": username,
            "detached_policy": "arn:aws:iam::aws:policy/AdministratorAccess",
            "action": f"Detached AdministratorAccess from {username}"
        }

    elif rule_id == "IAM_MULTI_KEYS":
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        active_keys = sorted(
            [k for k in keys if k["Status"] == "Active"],
            key=lambda k: k["CreateDate"]
        )
        deactivated = []
        for key in active_keys[:-1]:
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive"
            )
            deactivated.append(key["AccessKeyId"])
        return {
            "username": username,
            "deactivated_keys": deactivated,
            "action": f"Deactivated {len(deactivated)} excess access key(s) for {username}"
        }

    elif rule_id == "IAM_KEY_OLD":
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        deactivated = []
        for key in keys:
            if key["Status"] == "Active":
                age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age > 90:
                    iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key["AccessKeyId"],
                        Status="Inactive"
                    )
                    deactivated.append({"key_id": key["AccessKeyId"], "age_days": age})
        return {
            "username": username,
            "deactivated_keys": deactivated,
            "action": f"Deactivated {len(deactivated)} old access key(s) for {username}"
        }

    elif rule_id == "IAM_INLINE_POLICY":
        policy_names = iam.list_user_policies(UserName=username)["PolicyNames"]
        deleted = []
        saved_policies = {}
        for policy_name in policy_names:
            doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
            saved_policies[policy_name] = doc["PolicyDocument"]
            iam.delete_user_policy(UserName=username, PolicyName=policy_name)
            deleted.append(policy_name)
        return {
            "username": username,
            "deleted_policies": deleted,
            "saved_policy_documents": saved_policies,
            "action": f"Deleted {len(deleted)} inline policy/policies from {username}"
        }

    # ── New rules ─────────────────────────────────────────────────────────────

    elif rule_id == "IAM_KEY_UNUSED":
        # Deactivate all active keys unused for 45+ days
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        deactivated = []
        for key in keys:
            if key["Status"] == "Active":
                try:
                    lu = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    last_used = lu["AccessKeyLastUsed"].get("LastUsedDate")
                    if last_used:
                        days_unused = (datetime.now(timezone.utc) - last_used).days
                    else:
                        days_unused = 999  # never used
                except Exception:
                    days_unused = 999
                if days_unused > 45:
                    iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key["AccessKeyId"],
                        Status="Inactive"
                    )
                    deactivated.append({"key_id": key["AccessKeyId"], "days_unused": days_unused})
        return {
            "username": username,
            "deactivated_keys": deactivated,
            "action": f"Deactivated {len(deactivated)} unused access key(s) for {username}"
        }

    elif rule_id == "IAM_STALE_USER":
        # Disable console access (delete login profile) for inactive user
        had_console = False
        try:
            iam.get_login_profile(UserName=username)
            had_console = True
            iam.delete_login_profile(UserName=username)
        except iam.exceptions.NoSuchEntityException:
            pass
        return {
            "username": username,
            "had_console": had_console,
            "action": f"Deleted login profile (console access) for stale user {username}"
        }

    elif rule_id == "IAM_WILDCARD_POLICY":
        # Save all inline policies, then rewrite them removing wildcard actions
        policy_names = iam.list_user_policies(UserName=username)["PolicyNames"]
        saved_policies = {}
        rewritten = []
        for policy_name in policy_names:
            doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
            original_doc = doc["PolicyDocument"]
            saved_policies[policy_name] = original_doc

            # Remove statements that have wildcard Allow actions
            new_statements = []
            for stmt in original_doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if stmt.get("Effect") == "Allow" and "*" in actions:
                    # Strip the wildcard — replace with empty list to neutralise
                    # but preserve the statement structure for rollback awareness
                    continue
                new_statements.append(stmt)

            new_doc = dict(original_doc)
            new_doc["Statement"] = new_statements
            iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(new_doc)
            )
            rewritten.append(policy_name)

        return {
            "username": username,
            "saved_policy_documents": saved_policies,
            "rewritten_policies": rewritten,
            "action": f"Removed wildcard actions from {len(rewritten)} inline policy/policies on {username}"
        }

    elif rule_id == "IAM_ROLE_WILDCARD_TRUST":
        # resource_id is the role name
        role_name = resource_id
        role = iam.get_role(RoleName=role_name)["Role"]
        old_trust = role["AssumeRolePolicyDocument"]

        # Remove statements with wildcard principal
        new_statements = [
            stmt for stmt in old_trust.get("Statement", [])
            if stmt.get("Principal") != "*"
            and not (
                isinstance(stmt.get("Principal"), dict)
                and any(
                    v == "*" or (isinstance(v, list) and "*" in v)
                    for v in stmt["Principal"].values()
                )
            )
        ]
        new_trust = dict(old_trust)
        new_trust["Statement"] = new_statements

        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(new_trust)
        )
        return {
            "role_name": role_name,
            "old_trust_policy": json.dumps(old_trust),
            "action": f"Removed wildcard principal from trust policy on role {role_name}"
        }

    # ── Password policy rules — all share one update_account_password_policy call ──

    elif rule_id in (
        "IAM_NO_PASSWORD_POLICY",
        "IAM_PASSWORD_SHORT",
        "IAM_PASSWORD_NO_UPPER",
        "IAM_PASSWORD_NO_LOWER",
        "IAM_PASSWORD_NO_NUMBER",
        "IAM_PASSWORD_NO_SYMBOL",
        "IAM_PASSWORD_NO_EXPIRY",
        "IAM_PASSWORD_REUSE",
    ):
        old_policy = _get_current_password_policy()

        # Start from current policy and patch only what's needed,
        # so we don't overwrite other settings that are already correct.
        new_policy = {
            "MinimumPasswordLength":      old_policy.get("MinimumPasswordLength", 8)      if old_policy else 8,
            "RequireUppercaseCharacters": old_policy.get("RequireUppercaseCharacters", False) if old_policy else False,
            "RequireLowercaseCharacters": old_policy.get("RequireLowercaseCharacters", False) if old_policy else False,
            "RequireNumbers":             old_policy.get("RequireNumbers", False)          if old_policy else False,
            "RequireSymbols":             old_policy.get("RequireSymbols", False)          if old_policy else False,
            "MaxPasswordAge":             old_policy.get("MaxPasswordAge", 0)              if old_policy else 0,
            "PasswordReusePrevention":    old_policy.get("PasswordReusePrevention", 0)     if old_policy else 0,
            "AllowUsersToChangePassword": old_policy.get("AllowUsersToChangePassword", True) if old_policy else True,
            "HardExpiry":                 old_policy.get("HardExpiry", False)              if old_policy else False,
        }

        # Apply the specific fix for this rule
        if rule_id == "IAM_NO_PASSWORD_POLICY":
            new_policy = dict(STRONG_PASSWORD_POLICY)
        elif rule_id == "IAM_PASSWORD_SHORT":
            new_policy["MinimumPasswordLength"] = max(new_policy["MinimumPasswordLength"], 14)
        elif rule_id == "IAM_PASSWORD_NO_UPPER":
            new_policy["RequireUppercaseCharacters"] = True
        elif rule_id == "IAM_PASSWORD_NO_LOWER":
            new_policy["RequireLowercaseCharacters"] = True
        elif rule_id == "IAM_PASSWORD_NO_NUMBER":
            new_policy["RequireNumbers"] = True
        elif rule_id == "IAM_PASSWORD_NO_SYMBOL":
            new_policy["RequireSymbols"] = True
        elif rule_id == "IAM_PASSWORD_NO_EXPIRY":
            new_policy["MaxPasswordAge"] = 90
        elif rule_id == "IAM_PASSWORD_REUSE":
            new_policy["PasswordReusePrevention"] = 24

        iam.update_account_password_policy(**new_policy)
        return {
            "rule_id": rule_id,
            "old_policy": json.dumps(old_policy) if old_policy else None,
            "action": f"Updated account password policy to fix {rule_id}"
        }

    # ── Root account rules — cannot be automated, raise clear error ──────────

    elif rule_id in ("IAM_ROOT_KEYS", "IAM_ROOT_NO_MFA", "IAM_ROOT_ACTIVE"):
        raise NotImplementedError(
            f"{rule_id} requires manual action on the AWS root account. "
            "Root account changes cannot be made programmatically via IAM APIs. "
            "Please action this directly in the AWS Console."
        )


def rollback(rule_id, resource_id, rollback_config):
    username = rollback_config.get("username", resource_id)

    if rule_id == "IAM_NO_MFA":
        policy_name = rollback_config.get("policy_name", "CSPM-EnforceMFA")
        try:
            iam.delete_user_policy(UserName=username, PolicyName=policy_name)
        except Exception:
            pass
        return {"action": f"Removed MFA enforcement policy from {username}"}

    elif rule_id == "IAM_ADMIN":
        iam.attach_user_policy(
            UserName=username,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        return {"action": f"Re-attached AdministratorAccess to {username}"}

    elif rule_id in ("IAM_MULTI_KEYS", "IAM_KEY_OLD", "IAM_KEY_UNUSED"):
        deactivated = rollback_config.get("deactivated_keys", [])
        reactivated = []
        for key in deactivated:
            key_id = key if isinstance(key, str) else key.get("key_id")
            iam.update_access_key(UserName=username, AccessKeyId=key_id, Status="Active")
            reactivated.append(key_id)
        return {"action": f"Re-activated {len(reactivated)} access key(s) for {username}"}

    elif rule_id == "IAM_INLINE_POLICY":
        saved = rollback_config.get("saved_policy_documents", {})
        for policy_name, doc in saved.items():
            iam.put_user_policy(UserName=username, PolicyName=policy_name,
                PolicyDocument=json.dumps(doc) if isinstance(doc, dict) else doc)
        return {"action": f"Restored {len(saved)} inline policy/policies to {username}"}

    elif rule_id == "IAM_STALE_USER":
        had_console = rollback_config.get("had_console", False)
        if had_console:
            # Recreate login profile with a temporary password — user must reset on next login
            try:
                iam.create_login_profile(
                    UserName=username,
                    Password="Temp@1234!Cspm",
                    PasswordResetRequired=True
                )
            except iam.exceptions.EntityAlreadyExistsException:
                pass
        return {"action": f"Restored console access for {username} (password reset required)"}

    elif rule_id in ("IAM_WILDCARD_POLICY", "IAM_INLINE_POLICY"):
        saved = rollback_config.get("saved_policy_documents", {})
        for policy_name, doc in saved.items():
            iam.put_user_policy(UserName=username, PolicyName=policy_name,
                PolicyDocument=json.dumps(doc) if isinstance(doc, dict) else doc)
        return {"action": f"Restored {len(saved)} original inline policy/policies to {username}"}

    elif rule_id == "IAM_ROLE_WILDCARD_TRUST":
        role_name = rollback_config.get("role_name", resource_id)
        old_trust = rollback_config.get("old_trust_policy")
        if old_trust:
            iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=old_trust)
        return {"action": f"Restored original trust policy on role {role_name}"}

    elif rule_id in (
        "IAM_NO_PASSWORD_POLICY",
        "IAM_PASSWORD_SHORT",
        "IAM_PASSWORD_NO_UPPER",
        "IAM_PASSWORD_NO_LOWER",
        "IAM_PASSWORD_NO_NUMBER",
        "IAM_PASSWORD_NO_SYMBOL",
        "IAM_PASSWORD_NO_EXPIRY",
        "IAM_PASSWORD_REUSE",
    ):
        old_policy_str = rollback_config.get("old_policy")
        if old_policy_str:
            old_policy = json.loads(old_policy_str)
            # Filter to only keys accepted by the API
            allowed_keys = {
                "MinimumPasswordLength", "RequireUppercaseCharacters",
                "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols",
                "MaxPasswordAge", "PasswordReusePrevention",
                "AllowUsersToChangePassword", "HardExpiry"
            }
            clean = {k: v for k, v in old_policy.items() if k in allowed_keys}
            # MaxPasswordAge=0 means no expiry — API rejects 0, must delete instead
            if clean.get("MaxPasswordAge", 1) == 0:
                clean.pop("MaxPasswordAge", None)
            iam.update_account_password_policy(**clean)
        else:
            # No policy existed before — delete it
            try:
                iam.delete_account_password_policy()
            except Exception:
                pass
        return {"action": f"Restored previous password policy for {rule_id}"}

    elif rule_id in ("IAM_ROOT_KEYS", "IAM_ROOT_NO_MFA", "IAM_ROOT_ACTIVE"):
        return {"action": f"{rule_id} requires manual action — no automated rollback possible"}
