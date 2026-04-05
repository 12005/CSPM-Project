"""
Tests for rules_cloudtrail.py — pure function, no mocking needed.
"""
from rules_cloudtrail import evaluate_cloudtrail

# ── Helpers ────────────────────────────────────────────────────────────────────

FULLY_ENABLED = {
    "enabled":        True,
    "multi_region":   True,
    "log_validation": True,
    "kms_encrypted":  True,
}

DISABLED = {
    "enabled":        False,
    "multi_region":   False,
    "log_validation": False,
    "kms_encrypted":  False,
}

def rule_ids(findings):
    return [f[0] for f in findings]


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestCloudTrail:
    def test_disabled_raises_critical(self):
        f = evaluate_cloudtrail(DISABLED)
        assert ("CT_DISABLED", "CRITICAL", "account") in f

    def test_disabled_does_not_raise_other_rules(self):
        # When CT is off, only CT_DISABLED should fire — not multi_region, kms, etc.
        f = evaluate_cloudtrail(DISABLED)
        assert "CT_NOT_MULTI_REGION"   not in rule_ids(f)
        assert "CT_NO_KMS"             not in rule_ids(f)
        assert "CT_LOG_VALIDATION_OFF" not in rule_ids(f)

    def test_not_multi_region(self):
        ct = {**FULLY_ENABLED, "multi_region": False}
        f = evaluate_cloudtrail(ct)
        assert ("CT_NOT_MULTI_REGION", "HIGH", "account") in f

    def test_no_kms(self):
        ct = {**FULLY_ENABLED, "kms_encrypted": False}
        f = evaluate_cloudtrail(ct)
        assert ("CT_NO_KMS", "HIGH", "account") in f

    def test_log_validation_off(self):
        ct = {**FULLY_ENABLED, "log_validation": False}
        f = evaluate_cloudtrail(ct)
        assert ("CT_LOG_VALIDATION_OFF", "MEDIUM", "account") in f

    def test_fully_enabled_no_findings(self):
        assert evaluate_cloudtrail(FULLY_ENABLED) == []

    def test_all_weak_except_enabled(self):
        ct = {"enabled": True, "multi_region": False, "log_validation": False, "kms_encrypted": False}
        f = evaluate_cloudtrail(ct)
        assert "CT_NOT_MULTI_REGION"   in rule_ids(f)
        assert "CT_NO_KMS"             in rule_ids(f)
        assert "CT_LOG_VALIDATION_OFF" in rule_ids(f)
        assert "CT_DISABLED"           not in rule_ids(f)

    def test_severities_correct(self):
        ct = {"enabled": True, "multi_region": False, "log_validation": False, "kms_encrypted": False}
        f = evaluate_cloudtrail(ct)
        sev = {fid: s for fid, s, _ in f}
        assert sev["CT_NOT_MULTI_REGION"]   == "HIGH"
        assert sev["CT_NO_KMS"]             == "HIGH"
        assert sev["CT_LOG_VALIDATION_OFF"] == "MEDIUM"

    def test_resource_is_always_account(self):
        f = evaluate_cloudtrail(DISABLED)
        for _, _, resource in f:
            assert resource == "account"
