"""
IAM Rules — CIS AWS Foundations Benchmark aligned
Each finding: (rule_id, severity, resource)

CIS Coverage:
  1.1  Root no MFA                   → IAM_ROOT_NO_MFA        CRITICAL
  1.4  Root access keys exist        → IAM_ROOT_KEYS           CRITICAL
  1.5  Root used recently            → IAM_ROOT_ACTIVE         HIGH
  1.7  No MFA on console users       → IAM_NO_MFA              MEDIUM
  1.8  Password policy too weak      → IAM_WEAK_PASSWORD_*     MEDIUM
  1.12 Credentials unused 45+ days   → IAM_STALE_USER          MEDIUM
  1.13 Access key unused 45+ days    → IAM_KEY_UNUSED          MEDIUM
  1.14 Key older than 90 days        → IAM_KEY_OLD             MEDIUM
  1.15 Multiple active keys          → IAM_MULTI_KEYS          MEDIUM
  1.16 Admin policy directly attached→ IAM_ADMIN               HIGH
  1.17 Inline wildcard policy        → IAM_WILDCARD_POLICY     HIGH
  NEW  Role with wildcard principal  → IAM_ROLE_WILDCARD_TRUST HIGH
"""

def evaluate_iam(data):
    f = []

    # data is now a dict with users, root, password_policy, roles
    if isinstance(data, list):
        # backwards compat — old flat list format
        return _evaluate_users_legacy(data)

    f += _evaluate_root(data.get("root", {}))
    f += _evaluate_password_policy(data.get("password_policy", {}))
    f += _evaluate_users(data.get("users", []))
    f += _evaluate_roles(data.get("roles", []))

    return f


def _evaluate_root(root):
    f = []
    if not root:
        return f

    # CIS 1.4 — root access keys must not exist
    if root.get("root_keys_active"):
        f.append(("IAM_ROOT_KEYS", "CRITICAL", "root"))

    # CIS 1.1 — root must have MFA
    if not root.get("root_mfa_enabled"):
        f.append(("IAM_ROOT_NO_MFA", "CRITICAL", "root"))

    # CIS 1.5 — root should not be used for day-to-day (used in last 30 days)
    if root.get("root_used_recently"):
        f.append(("IAM_ROOT_ACTIVE", "HIGH", "root"))

    return f


def _evaluate_password_policy(pp):
    f = []
    if not pp:
        return f

    # CIS 1.8 — no password policy at all
    if not pp.get("exists"):
        f.append(("IAM_NO_PASSWORD_POLICY", "MEDIUM", "account"))
        return f

    # CIS 1.8 — min length < 14
    if pp.get("min_length", 0) < 14:
        f.append(("IAM_PASSWORD_SHORT", "MEDIUM", "account"))

    # CIS 1.9 — must require uppercase
    if not pp.get("require_uppercase"):
        f.append(("IAM_PASSWORD_NO_UPPER", "MEDIUM", "account"))

    # CIS 1.9 — must require lowercase
    if not pp.get("require_lowercase"):
        f.append(("IAM_PASSWORD_NO_LOWER", "MEDIUM", "account"))

    # CIS 1.9 — must require numbers
    if not pp.get("require_numbers"):
        f.append(("IAM_PASSWORD_NO_NUMBER", "MEDIUM", "account"))

    # CIS 1.9 — must require symbols
    if not pp.get("require_symbols"):
        f.append(("IAM_PASSWORD_NO_SYMBOL", "MEDIUM", "account"))

    # CIS 1.10 — max age should be 90 days or less
    max_age = pp.get("max_age", 0)
    if max_age == 0 or max_age > 90:
        f.append(("IAM_PASSWORD_NO_EXPIRY", "MEDIUM", "account"))

    # CIS 1.11 — prevent reuse of last 24 passwords
    if pp.get("reuse_prevention", 0) < 24:
        f.append(("IAM_PASSWORD_REUSE", "MEDIUM", "account"))

    return f


def _evaluate_users(users):
    f = []
    for u in users:
        name = u["user"]

        # CIS 1.7 — console user without MFA
        if u.get("has_console") and not u.get("mfa_enabled"):
            f.append(("IAM_NO_MFA", "MEDIUM", name))

        # CIS 1.16 — AdministratorAccess directly attached
        if u.get("admin"):
            f.append(("IAM_ADMIN", "HIGH", name))

        # CIS 1.17 — inline policy with wildcard action
        if u.get("wildcard_inline"):
            f.append(("IAM_WILDCARD_POLICY", "HIGH", name))

        # CIS 1.15 — more than one active key
        if u.get("active_key_count", 0) > 1:
            f.append(("IAM_MULTI_KEYS", "MEDIUM", name))

        # CIS 1.14 — key older than 90 days
        for age in u.get("key_ages", []):
            if age > 90:
                f.append(("IAM_KEY_OLD", "MEDIUM", name))

        # CIS 1.13 — key unused for 45+ days
        for days_unused in u.get("key_last_used_days", []):
            if days_unused is not None and days_unused > 45:
                f.append(("IAM_KEY_UNUSED", "MEDIUM", name))

        # CIS 1.12 — user credentials unused for 45+ days
        days_since = u.get("days_since_login")
        if days_since is not None and days_since > 45:
            f.append(("IAM_STALE_USER", "MEDIUM", name))

        # Legacy inline policy count check
        if u.get("inline_policy_count", 0) > 0 and not u.get("wildcard_inline"):
            f.append(("IAM_INLINE_POLICY", "LOW", name))

    return f


def _evaluate_roles(roles):
    f = []
    for role in roles:
        if role.get("wildcard_principal"):
            f.append(("IAM_ROLE_WILDCARD_TRUST", "HIGH", role["role_name"]))
    return f


def _evaluate_users_legacy(users):
    """Backwards compat for old flat scan format."""
    f = []
    for u in users:
        if not u.get("mfa_enabled"):
            f.append(("IAM_NO_MFA", "MEDIUM", u["user"]))
        if u.get("admin"):
            f.append(("IAM_ADMIN", "HIGH", u["user"]))
        if u.get("active_key_count", 0) > 1:
            f.append(("IAM_MULTI_KEYS", "MEDIUM", u["user"]))
        for age in u.get("key_ages", []):
            if age > 90:
                f.append(("IAM_KEY_OLD", "MEDIUM", u["user"]))
        if u.get("inline_policy_count", 0) > 0:
            f.append(("IAM_INLINE_POLICY", "MEDIUM", u["user"]))
    return f
