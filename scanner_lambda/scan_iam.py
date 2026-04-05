import boto3
from datetime import datetime, timezone

iam = boto3.client("iam")

def scan_iam():
    return {
        "users":           _scan_users(),
        "root":            _scan_root(),
        "password_policy": _scan_password_policy(),
        "roles":           _scan_roles(),
    }


# ── USERS ──────────────────────────────────────────────────────────────────────
def _scan_users():
    users_data = []

    # FIX #5 — paginate list_users (default truncates at 100)
    paginator = iam.get_paginator("list_users")
    users = [u for page in paginator.paginate() for u in page["Users"]]

    for user in users:
        username = user["UserName"]
        now      = datetime.now(timezone.utc)

        # MFA
        mfa_enabled = len(
            iam.list_mfa_devices(UserName=username)["MFADevices"]
        ) > 0

        # Attached policies — check by ARN (exact match)
        attached = iam.list_attached_user_policies(
            UserName=username
        )["AttachedPolicies"]
        admin = any(
            p["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess"
            for p in attached
        )

        # Inline policies — check for wildcard actions
        inline_names    = iam.list_user_policies(UserName=username)["PolicyNames"]
        wildcard_inline = False
        for pname in inline_names:
            doc = iam.get_user_policy(
                UserName=username, PolicyName=pname
            )["PolicyDocument"]
            for stmt in doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if stmt.get("Effect") == "Allow" and "*" in actions:
                    wildcard_inline = True

        # Access keys
        keys        = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        active_keys = [k for k in keys if k["Status"] == "Active"]
        key_ages    = [(now - k["CreateDate"]).days for k in active_keys]

        # Key last used (stale key detection)
        key_last_used_days = []
        for k in active_keys:
            try:
                lu        = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                last_used = lu["AccessKeyLastUsed"].get("LastUsedDate")
                if last_used:
                    key_last_used_days.append((now - last_used).days)
                else:
                    key_last_used_days.append(999)  # never used
            except:
                key_last_used_days.append(None)

        # Last login (CIS 1.12 — stale users)
        password_last_used = user.get("PasswordLastUsed")
        days_since_login   = None
        if password_last_used:
            days_since_login = (now - password_last_used).days

        # Console access
        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except:
            has_console = False

        users_data.append({
            "user":                username,
            "mfa_enabled":         mfa_enabled,
            "admin":               admin,
            "inline_policy_count": len(inline_names),
            "wildcard_inline":     wildcard_inline,
            "active_key_count":    len(active_keys),
            "key_ages":            key_ages,
            "key_last_used_days":  key_last_used_days,
            "days_since_login":    days_since_login,
            "has_console":         has_console,
            "password_last_used":  str(password_last_used) if password_last_used else None,
        })

    return users_data


# ── ROOT ACCOUNT ───────────────────────────────────────────────────────────────
def _scan_root():
    """CIS 1.1, 1.4, 1.5 — root MFA, root access keys, root recent activity."""
    try:
        summary     = iam.get_account_summary()["SummaryMap"]
        cred_report = _get_credential_report()

        root_row = next(
            (r for r in cred_report if r.get("user") == "<root_account>"), {}
        )

        root_keys_active = summary.get("AccountAccessKeysPresent", 0) > 0
        root_mfa         = summary.get("AccountMFAEnabled", 0) == 1

        root_last_used    = root_row.get("password_last_used", "no_information")
        root_used_recently = False
        if root_last_used not in ("no_information", "N/A", "not_supported", ""):
            try:
                last_dt = datetime.fromisoformat(
                    root_last_used.replace("Z", "+00:00")
                )
                root_used_recently = (
                    datetime.now(timezone.utc) - last_dt
                ).days < 30
            except:
                pass

        return {
            "root_keys_active":   root_keys_active,
            "root_mfa_enabled":   root_mfa,
            "root_used_recently": root_used_recently,
        }
    except Exception as e:
        print(f"Root scan error: {e}")
        return {
            "root_keys_active":   False,
            "root_mfa_enabled":   True,
            "root_used_recently": False,
        }


def _get_credential_report():
    """Generate and parse the IAM credential report."""
    import csv, io, time
    try:
        for _ in range(5):
            resp = iam.generate_credential_report()
            if resp["State"] == "COMPLETE":
                break
            time.sleep(2)
        report = iam.get_credential_report()["Content"].decode("utf-8")
        return list(csv.DictReader(io.StringIO(report)))
    except Exception as e:
        print(f"Credential report error: {e}")
        return []


# ── PASSWORD POLICY ────────────────────────────────────────────────────────────
def _scan_password_policy():
    """CIS 1.8–1.11 — password policy checks."""
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
        return {
            "exists":             True,
            "min_length":         p.get("MinimumPasswordLength", 0),
            "require_uppercase":  p.get("RequireUppercaseCharacters", False),
            "require_lowercase":  p.get("RequireLowercaseCharacters", False),
            "require_numbers":    p.get("RequireNumbers", False),
            "require_symbols":    p.get("RequireSymbols", False),
            "max_age":            p.get("MaxPasswordAge", 0),
            "reuse_prevention":   p.get("PasswordReusePrevention", 0),
            "allow_users_change": p.get("AllowUsersToChangePassword", False),
        }
    except iam.exceptions.NoSuchEntityException:
        return {"exists": False}
    except Exception as e:
        print(f"Password policy error: {e}")
        return {"exists": False}


# ── ROLES ──────────────────────────────────────────────────────────────────────
def _scan_roles():
    """Check for overly permissive role trust policies."""
    roles_data = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                trust              = role.get("AssumeRolePolicyDocument", {})
                wildcard_principal = False
                for stmt in trust.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if principal == "*":
                        wildcard_principal = True
                    elif isinstance(principal, dict):
                        for v in principal.values():
                            if v == "*" or (isinstance(v, list) and "*" in v):
                                wildcard_principal = True

                if wildcard_principal:
                    roles_data.append({
                        "role_name":          role["RoleName"],
                        "wildcard_principal": True,
                    })
    except Exception as e:
        print(f"Roles scan error: {e}")
    return roles_data
