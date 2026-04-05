"""
S3 Rules — CIS AWS Foundations Benchmark aligned

CIS Coverage:
  2.1.1  No SSE encryption          → S3_NO_ENCRYPTION        MEDIUM
  2.1.2  HTTP access allowed        → S3_ALLOWS_HTTP          MEDIUM
  2.1.3  No versioning              → S3_NO_VERSIONING        LOW
  2.1.3  No MFA delete              → S3_NO_MFA_DELETE        LOW
  2.1.4  No server access logging   → S3_NO_LOGGING           LOW
  2.1.5  Public ACL                 → S3_PUBLIC_ACL           CRITICAL
  2.1.5  Block public not fully set → S3_BLOCK_PUBLIC_DISABLED HIGH
"""

def evaluate_s3(buckets):
    f = []
    for b in buckets:
        name = b["bucket"]

        # CIS 2.1.5 — public ACL
        if b.get("public_acl"):
            f.append(("S3_PUBLIC_ACL", "CRITICAL", name))

        # CIS 2.1.5 — block public access not fully enabled
        if not b.get("fully_blocked", b.get("block_public", False)):
            f.append(("S3_BLOCK_PUBLIC_DISABLED", "HIGH", name))

        # CIS 2.1.1 — no encryption
        if not b.get("encrypted"):
            f.append(("S3_NO_ENCRYPTION", "MEDIUM", name))

        # CIS 2.1.2 — HTTP access allowed (no enforced HTTPS policy)
        if b.get("allows_http"):
            f.append(("S3_ALLOWS_HTTP", "MEDIUM", name))

        # CIS 2.1.4 — server access logging disabled
        if not b.get("logging_enabled"):
            f.append(("S3_NO_LOGGING", "LOW", name))

        # CIS 2.1.3 — versioning not enabled
        if not b.get("versioning"):
            f.append(("S3_NO_VERSIONING", "LOW", name))

        # CIS 2.1.3 extended — MFA delete not enabled (only on versioned buckets)
        if b.get("versioning") and not b.get("mfa_delete"):
            f.append(("S3_NO_MFA_DELETE", "LOW", name))

    return f
