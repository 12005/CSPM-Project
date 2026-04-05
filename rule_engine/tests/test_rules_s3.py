"""
Tests for rules_s3.py — pure function, no mocking needed.
"""
from rules_s3 import evaluate_s3

# ── Helpers ────────────────────────────────────────────────────────────────────

CLEAN_BUCKET = {
    "bucket":        "my-bucket",
    "region":        "ap-south-1",
    "public_acl":    False,
    "encrypted":     True,
    "block_public":  True,
    "fully_blocked": True,
    "versioning":    True,
    "mfa_delete":    True,
    "allows_http":   False,
    "logging_enabled": True,
}

def rule_ids(findings):
    return [f[0] for f in findings]


# ── Individual rules ───────────────────────────────────────────────────────────

class TestS3Rules:
    def test_public_acl(self):
        b = {**CLEAN_BUCKET, "public_acl": True}
        f = evaluate_s3([b])
        assert ("S3_PUBLIC_ACL", "CRITICAL", "my-bucket") in f

    def test_block_public_disabled(self):
        b = {**CLEAN_BUCKET, "fully_blocked": False, "block_public": False}
        f = evaluate_s3([b])
        assert ("S3_BLOCK_PUBLIC_DISABLED", "HIGH", "my-bucket") in f

    def test_block_public_fully_blocked_overrides(self):
        # fully_blocked=True should suppress S3_BLOCK_PUBLIC_DISABLED even if block_public=False
        b = {**CLEAN_BUCKET, "fully_blocked": True, "block_public": False}
        f = evaluate_s3([b])
        assert "S3_BLOCK_PUBLIC_DISABLED" not in rule_ids(f)

    def test_no_encryption(self):
        b = {**CLEAN_BUCKET, "encrypted": False}
        f = evaluate_s3([b])
        assert ("S3_NO_ENCRYPTION", "MEDIUM", "my-bucket") in f

    def test_allows_http(self):
        b = {**CLEAN_BUCKET, "allows_http": True}
        f = evaluate_s3([b])
        assert ("S3_ALLOWS_HTTP", "MEDIUM", "my-bucket") in f

    def test_no_logging(self):
        b = {**CLEAN_BUCKET, "logging_enabled": False}
        f = evaluate_s3([b])
        assert ("S3_NO_LOGGING", "LOW", "my-bucket") in f

    def test_no_versioning(self):
        b = {**CLEAN_BUCKET, "versioning": False}
        f = evaluate_s3([b])
        assert ("S3_NO_VERSIONING", "LOW", "my-bucket") in f

    def test_no_mfa_delete_on_versioned_bucket(self):
        b = {**CLEAN_BUCKET, "versioning": True, "mfa_delete": False}
        f = evaluate_s3([b])
        assert ("S3_NO_MFA_DELETE", "LOW", "my-bucket") in f

    def test_no_mfa_delete_not_checked_when_no_versioning(self):
        b = {**CLEAN_BUCKET, "versioning": False, "mfa_delete": False}
        f = evaluate_s3([b])
        assert "S3_NO_MFA_DELETE" not in rule_ids(f)

    def test_clean_bucket_no_findings(self):
        f = evaluate_s3([CLEAN_BUCKET])
        assert f == []

    def test_empty_bucket_list(self):
        assert evaluate_s3([]) == []

    def test_multiple_buckets_isolated(self):
        bad  = {**CLEAN_BUCKET, "bucket": "bad-bucket",  "public_acl": True}
        good = {**CLEAN_BUCKET, "bucket": "good-bucket"}
        f = evaluate_s3([bad, good])
        assert any(res == "bad-bucket"  for _, _, res in f)
        assert not any(res == "good-bucket" for _, _, res in f)

    def test_worst_case_bucket_all_findings(self):
        b = {
            "bucket":          "worst-bucket",
            "region":          "ap-south-1",
            "public_acl":      True,
            "encrypted":       False,
            "block_public":    False,
            "fully_blocked":   False,
            "versioning":      False,
            "mfa_delete":      False,
            "allows_http":     True,
            "logging_enabled": False,
        }
        f = evaluate_s3([b])
        expected = [
            "S3_PUBLIC_ACL", "S3_BLOCK_PUBLIC_DISABLED", "S3_NO_ENCRYPTION",
            "S3_ALLOWS_HTTP", "S3_NO_LOGGING", "S3_NO_VERSIONING",
        ]
        for rule in expected:
            assert rule in rule_ids(f), f"{rule} not raised for worst-case bucket"

    def test_severities_correct(self):
        b = {**CLEAN_BUCKET, "public_acl": True, "fully_blocked": False,
             "encrypted": False, "allows_http": True, "logging_enabled": False, "versioning": False}
        f = evaluate_s3([b])
        sev = {fid: s for fid, s, _ in f}
        assert sev["S3_PUBLIC_ACL"]            == "CRITICAL"
        assert sev["S3_BLOCK_PUBLIC_DISABLED"] == "HIGH"
        assert sev["S3_NO_ENCRYPTION"]         == "MEDIUM"
        assert sev["S3_ALLOWS_HTTP"]           == "MEDIUM"
        assert sev["S3_NO_LOGGING"]            == "LOW"
        assert sev["S3_NO_VERSIONING"]         == "LOW"
