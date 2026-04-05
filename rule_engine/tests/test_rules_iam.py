"""
Tests for rules_iam.py — pure function, no mocking needed.
"""
import pytest
from rules_iam import evaluate_iam

# ── Helpers ────────────────────────────────────────────────────────────────────

CLEAN_ROOT = {
    "root_mfa_enabled": True,
    "root_keys_active": False,
    "root_used_recently": False,
}

STRONG_PASSWORD_POLICY = {
    "exists": True,
    "min_length": 14,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_symbols": True,
    "max_age": 90,
    "reuse_prevention": 24,
}

CLEAN_USER = {
    "user": "alice",
    "has_console": True,
    "mfa_enabled": True,
    "admin": False,
    "wildcard_inline": False,
    "active_key_count": 1,
    "key_ages": [30],
    "key_last_used_days": [10],
    "days_since_login": 10,
    "inline_policy_count": 0,
}

def _data(root=None, pp=None, users=None, roles=None):
    return {
        "root":            root  or CLEAN_ROOT,
        "password_policy": pp    or STRONG_PASSWORD_POLICY,
        "users":           users or [],
        "roles":           roles or [],
    }

def rule_ids(findings):
    return [f[0] for f in findings]


# ── Root ───────────────────────────────────────────────────────────────────────

class TestRoot:
    def test_root_keys_active(self):
        f = evaluate_iam(_data(root={**CLEAN_ROOT, "root_keys_active": True}))
        assert ("IAM_ROOT_KEYS", "CRITICAL", "root") in f

    def test_root_no_mfa(self):
        f = evaluate_iam(_data(root={**CLEAN_ROOT, "root_mfa_enabled": False}))
        assert ("IAM_ROOT_NO_MFA", "CRITICAL", "root") in f

    def test_root_used_recently(self):
        f = evaluate_iam(_data(root={**CLEAN_ROOT, "root_used_recently": True}))
        assert ("IAM_ROOT_ACTIVE", "HIGH", "root") in f

    def test_clean_root_no_findings(self):
        f = evaluate_iam(_data(root=CLEAN_ROOT))
        assert not any(r in rule_ids(f) for r in ["IAM_ROOT_KEYS", "IAM_ROOT_NO_MFA", "IAM_ROOT_ACTIVE"])

    def test_empty_root_no_crash(self):
        f = evaluate_iam(_data(root={}))
        assert isinstance(f, list)


# ── Password policy ────────────────────────────────────────────────────────────

class TestPasswordPolicy:
    def test_no_policy(self):
        f = evaluate_iam(_data(pp={"exists": False}))
        assert ("IAM_NO_PASSWORD_POLICY", "MEDIUM", "account") in f

    def test_no_policy_stops_further_checks(self):
        f = evaluate_iam(_data(pp={"exists": False}))
        assert "IAM_PASSWORD_SHORT" not in rule_ids(f)

    def test_short_password(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "min_length": 8}))
        assert ("IAM_PASSWORD_SHORT", "MEDIUM", "account") in f

    def test_no_uppercase(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "require_uppercase": False}))
        assert ("IAM_PASSWORD_NO_UPPER", "MEDIUM", "account") in f

    def test_no_lowercase(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "require_lowercase": False}))
        assert ("IAM_PASSWORD_NO_LOWER", "MEDIUM", "account") in f

    def test_no_numbers(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "require_numbers": False}))
        assert ("IAM_PASSWORD_NO_NUMBER", "MEDIUM", "account") in f

    def test_no_symbols(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "require_symbols": False}))
        assert ("IAM_PASSWORD_NO_SYMBOL", "MEDIUM", "account") in f

    def test_max_age_zero(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "max_age": 0}))
        assert ("IAM_PASSWORD_NO_EXPIRY", "MEDIUM", "account") in f

    def test_max_age_too_high(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "max_age": 180}))
        assert ("IAM_PASSWORD_NO_EXPIRY", "MEDIUM", "account") in f

    def test_max_age_exactly_90_is_ok(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "max_age": 90}))
        assert "IAM_PASSWORD_NO_EXPIRY" not in rule_ids(f)

    def test_low_reuse_prevention(self):
        f = evaluate_iam(_data(pp={**STRONG_PASSWORD_POLICY, "reuse_prevention": 5}))
        assert ("IAM_PASSWORD_REUSE", "MEDIUM", "account") in f

    def test_strong_policy_no_findings(self):
        f = evaluate_iam(_data(pp=STRONG_PASSWORD_POLICY))
        password_rules = [r for r in rule_ids(f) if r.startswith("IAM_PASSWORD") or r == "IAM_NO_PASSWORD_POLICY"]
        assert password_rules == []

    def test_empty_policy_no_crash(self):
        f = evaluate_iam(_data(pp={}))
        assert isinstance(f, list)


# ── Users ──────────────────────────────────────────────────────────────────────

class TestUsers:
    def test_console_user_no_mfa(self):
        user = {**CLEAN_USER, "has_console": True, "mfa_enabled": False}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_NO_MFA", "MEDIUM", "alice") in f

    def test_non_console_user_no_mfa_is_ok(self):
        user = {**CLEAN_USER, "has_console": False, "mfa_enabled": False}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_NO_MFA" not in rule_ids(f)

    def test_admin_user(self):
        user = {**CLEAN_USER, "admin": True}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_ADMIN", "HIGH", "alice") in f

    def test_wildcard_inline_policy(self):
        user = {**CLEAN_USER, "wildcard_inline": True, "inline_policy_count": 1}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_WILDCARD_POLICY", "HIGH", "alice") in f

    def test_multiple_active_keys(self):
        user = {**CLEAN_USER, "active_key_count": 2}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_MULTI_KEYS", "MEDIUM", "alice") in f

    def test_one_active_key_is_ok(self):
        user = {**CLEAN_USER, "active_key_count": 1}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_MULTI_KEYS" not in rule_ids(f)

    def test_old_key(self):
        user = {**CLEAN_USER, "key_ages": [91]}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_KEY_OLD", "MEDIUM", "alice") in f

    def test_key_exactly_90_days_is_ok(self):
        user = {**CLEAN_USER, "key_ages": [90]}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_KEY_OLD" not in rule_ids(f)

    def test_unused_key(self):
        user = {**CLEAN_USER, "key_last_used_days": [46]}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_KEY_UNUSED", "MEDIUM", "alice") in f

    def test_recently_used_key_is_ok(self):
        user = {**CLEAN_USER, "key_last_used_days": [10]}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_KEY_UNUSED" not in rule_ids(f)

    def test_key_last_used_none_no_crash(self):
        user = {**CLEAN_USER, "key_last_used_days": [None]}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_KEY_UNUSED" not in rule_ids(f)

    def test_stale_user(self):
        user = {**CLEAN_USER, "days_since_login": 46}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_STALE_USER", "MEDIUM", "alice") in f

    def test_active_user_is_ok(self):
        user = {**CLEAN_USER, "days_since_login": 10}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_STALE_USER" not in rule_ids(f)

    def test_inline_policy_no_wildcard(self):
        user = {**CLEAN_USER, "inline_policy_count": 1, "wildcard_inline": False}
        f = evaluate_iam(_data(users=[user]))
        assert ("IAM_INLINE_POLICY", "LOW", "alice") in f

    def test_inline_wildcard_does_not_double_fire_inline_policy(self):
        # wildcard_inline=True should fire IAM_WILDCARD_POLICY but NOT IAM_INLINE_POLICY
        user = {**CLEAN_USER, "inline_policy_count": 1, "wildcard_inline": True}
        f = evaluate_iam(_data(users=[user]))
        assert "IAM_INLINE_POLICY" not in rule_ids(f)
        assert "IAM_WILDCARD_POLICY" in rule_ids(f)

    def test_clean_user_no_findings(self):
        f = evaluate_iam(_data(users=[CLEAN_USER]))
        assert rule_ids(f) == []

    def test_multiple_users_isolated(self):
        bob = {**CLEAN_USER, "user": "bob", "admin": True}
        f = evaluate_iam(_data(users=[CLEAN_USER, bob]))
        assert ("IAM_ADMIN", "HIGH", "bob") in f
        assert not any(fid == "IAM_ADMIN" and res == "alice" for fid, _, res in f)


# ── Roles ──────────────────────────────────────────────────────────────────────

class TestRoles:
    def test_wildcard_principal(self):
        roles = [{"role_name": "bad-role", "wildcard_principal": True}]
        f = evaluate_iam(_data(roles=roles))
        assert ("IAM_ROLE_WILDCARD_TRUST", "HIGH", "bad-role") in f

    def test_safe_role_no_finding(self):
        roles = [{"role_name": "good-role", "wildcard_principal": False}]
        f = evaluate_iam(_data(roles=roles))
        assert "IAM_ROLE_WILDCARD_TRUST" not in rule_ids(f)


# ── Legacy format ──────────────────────────────────────────────────────────────

class TestLegacyFormat:
    def test_legacy_list_no_mfa(self):
        users = [{"user": "alice", "mfa_enabled": False, "admin": False,
                  "active_key_count": 1, "key_ages": [], "inline_policy_count": 0}]
        f = evaluate_iam(users)
        assert ("IAM_NO_MFA", "MEDIUM", "alice") in f

    def test_legacy_list_admin(self):
        users = [{"user": "alice", "mfa_enabled": True, "admin": True,
                  "active_key_count": 1, "key_ages": [], "inline_policy_count": 0}]
        f = evaluate_iam(users)
        assert ("IAM_ADMIN", "HIGH", "alice") in f


# ── Full clean account ─────────────────────────────────────────────────────────

def test_fully_clean_account_zero_findings():
    data = _data(
        root=CLEAN_ROOT,
        pp=STRONG_PASSWORD_POLICY,
        users=[CLEAN_USER],
        roles=[{"role_name": "safe-role", "wildcard_principal": False}],
    )
    assert evaluate_iam(data) == []
