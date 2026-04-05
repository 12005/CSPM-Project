"""
CSPM Audit Trail
Writes immutable audit log entries to CSPM-AuditLog DynamoDB table.
Called from Remediation Lambda, Rollback Lambda, and Rule Engine.
"""
import boto3
import uuid
from datetime import datetime, timezone

ddb = boto3.resource("dynamodb")
audit_table = ddb.Table("CSPM-AuditLog")


def log(action, rule_id, resource_id, finding_id, actor="system", detail=None, status="SUCCESS"):
    """
    Write a single audit log entry.
    
    action:      REMEDIATED | ROLLED_BACK | AUTO_REMEDIATED | AUTO_RESOLVED |
                 FINDING_OPENED | FINDING_CLOSED | CONFIG_CHANGED
    rule_id:     e.g. IAM_ADMIN
    resource_id: e.g. Jeyanth
    finding_id:  SHA256 finding ID
    actor:       email of user who triggered, or "system" for automated
    detail:      dict with extra context (action taken, old config, etc.)
    status:      SUCCESS | FAILED
    """
    try:
        now = datetime.now(timezone.utc)
        audit_table.put_item(Item={
            "audit_id":    str(uuid.uuid4()),
            "timestamp":   now.isoformat(),
            "date":        now.strftime("%Y-%m-%d"),   # for GSI queries by date
            "action":      action,
            "rule_id":     rule_id,
            "resource_id": resource_id,
            "finding_id":  finding_id,
            "actor":       actor,
            "detail":      str(detail or {}),
            "status":      status
        })
    except Exception as e:
        # Never let audit logging crash the main flow
        print(f"Audit log failed (non-fatal): {e}")


def log_config_change(key, old_value, new_value, actor="system"):
    """Log when AUTO_REMEDIATE is toggled or exclusions are changed."""
    try:
        audit_table.put_item(Item={
            "audit_id":    str(uuid.uuid4()),
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "date":        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "action":      "CONFIG_CHANGED",
            "rule_id":     "N/A",
            "resource_id": key,
            "finding_id":  "N/A",
            "actor":       actor,
            "detail":      str({"key": key, "old": old_value, "new": new_value}),
            "status":      "SUCCESS"
        })
    except Exception as e:
        print(f"Audit log failed (non-fatal): {e}")
