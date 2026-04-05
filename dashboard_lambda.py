import json
import boto3
from datetime import datetime, timezone

ddb = boto3.resource("dynamodb")
table = ddb.Table("CSPM-Findings")
sfn = boto3.client("stepfunctions")
sts = boto3.client("sts")

# Fill in your Step Functions ARN after creating it
SFN_ARN = "arn:aws:states:ap-south-1:344988461546:stateMachine:CSPM-RemediationWorkflow"

# Latest snapshot key tracker (stored in DynamoDB meta table or passed in)
SNAPSHOT_BUCKET = "cspm-snapshots-v1"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Content-Type": "application/json"
}

REMEDIATION_DESCRIPTIONS = {
    "SG_OPEN_ALL":              "Revoke all inbound rules from 0.0.0.0/0",
    "SG_OPEN_SSH":              "Revoke SSH (port 22) inbound rule from 0.0.0.0/0",
    "SG_OPEN_RDP":              "Revoke RDP (port 3389) inbound rule from 0.0.0.0/0",
    "SG_DEFAULT_OPEN":          "Revoke all open rules on default security group",
    "S3_PUBLIC_ACL":            "Set bucket ACL to private",
    "S3_BLOCK_PUBLIC_DISABLED": "Enable all 4 block public access settings",
    "S3_NO_ENCRYPTION":         "Enable AES256 server-side encryption",
    "S3_NO_VERSIONING":         "Enable bucket versioning",
    "S3_ALLOWS_HTTP":           "Add bucket policy to deny non-HTTPS requests",
    "S3_NO_LOGGING":            "Enable S3 server access logging",
    "S3_NO_MFA_DELETE":         "Enable MFA delete on versioned bucket",
    "CT_DISABLED":              "Create CloudTrail with dedicated S3 bucket and start logging",
    "CT_NOT_MULTI_REGION":      "Enable multi-region trail",
    "CT_NO_KMS":                "Create KMS key and enable CloudTrail encryption",
    "CT_LOG_VALIDATION_OFF":    "Enable log file validation",
    "IAM_NO_MFA":               "Enforce MFA for console user",
    "IAM_ADMIN":                "Detach AdministratorAccess policy",
    "IAM_MULTI_KEYS":           "Deactivate all but the newest access key",
    "IAM_KEY_OLD":              "Deactivate access keys older than 90 days",
    "IAM_KEY_UNUSED":           "Deactivate access key unused for 45+ days",
    "IAM_STALE_USER":           "Disable console access for inactive user",
    "IAM_INLINE_POLICY":        "Delete all inline policies",
    "IAM_WILDCARD_POLICY":      "Remove wildcard actions from inline policy",
    "IAM_ROOT_KEYS":            "Delete root account access keys immediately",
    "IAM_ROOT_NO_MFA":          "Enable MFA on root account",
    "IAM_ROOT_ACTIVE":          "Stop using root account for day-to-day operations",
    "IAM_NO_PASSWORD_POLICY":   "Create IAM account password policy",
    "IAM_PASSWORD_SHORT":       "Set minimum password length to 14 characters",
    "IAM_PASSWORD_NO_EXPIRY":   "Set maximum password age to 90 days",
    "IAM_PASSWORD_REUSE":       "Set password reuse prevention to 24",
    "EC2_IMDSV2_DISABLED":      "Enforce IMDSv2 (HttpTokens=required) on instance",
    "EC2_EBS_NOT_ENCRYPTED":    "Encrypt EBS root volume",
    "EC2_PUBLIC_SNAPSHOT":      "Make EBS snapshot private",
    "VPC_NO_FLOW_LOGS":         "Enable VPC flow logs",
}

def compute_posture_score(severity_counts):
    deductions = (
        severity_counts.get("CRITICAL", 0) * 10 +
        severity_counts.get("HIGH", 0) * 5 +
        severity_counts.get("MEDIUM", 0) * 2
    )
    return max(0, 100 - deductions)

def lambda_handler(event, context):
    print("EVENT:", json.dumps(event))
    raw_path = event.get("rawPath") or event.get("path", "/")
    path = raw_path
    for p in ["/summary", "/findings", "/remediate", "/rollback", "/approve", "/config", "/audit", "/trends", "/scan"]:
        if raw_path.endswith(p):
            path = p
            break
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    try:
        if path == "/summary"   and method == "GET":  return handle_summary()
        if path == "/findings"  and method == "GET":  return handle_findings(event.get("queryStringParameters") or {})
        if path == "/remediate" and method == "POST": return handle_remediate(json.loads(event.get("body") or "{}"))
        if path == "/rollback"  and method == "POST": return handle_rollback(json.loads(event.get("body") or "{}"))
        if path == "/approve"   and method == "GET":  return handle_approve(event.get("queryStringParameters") or {})
        if path == "/config"    and method == "GET":  return handle_get_config()
        if path == "/config"    and method == "POST": return handle_post_config(json.loads(event.get("body") or "{}"))
        if path == "/audit"     and method == "GET":  return handle_audit(event.get("queryStringParameters") or {})
        if path == "/trends"    and method == "GET":  return handle_trends()
        if path == "/scan"      and method == "POST": return handle_scan()
        return resp(404, {"error": "Not found", "path": path})
    except Exception as e:
        print(f"Error: {e}")
        return resp(500, {"error": str(e)})


def handle_summary():
    items = table.scan().get("Items", [])
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    service_counts  = {"IAM": 0, "S3": 0, "SG": 0, "CT": 0}
    status_counts   = {"OPEN": 0, "RESOLVED": 0}
    service_map     = {"IAM": "IAM", "S3": "S3", "SG": "SG", "CT": "CT"}
    for item in items:
        sev = item.get("severity", "")
        if sev in severity_counts: severity_counts[sev] += 1
        prefix = item.get("rule_id", "").split("_")[0]
        svc = service_map.get(prefix, prefix)
        if svc in service_counts: service_counts[svc] += 1
        status = item.get("status", "OPEN")
        if status in status_counts: status_counts[status] += 1
    return resp(200, {
        "posture_score":   compute_posture_score(severity_counts),
        "total_findings":  len(items),
        "severity_counts": severity_counts,
        "service_counts":  service_counts,
        "status_counts":   status_counts
    })


def handle_findings(params):
    items = table.scan().get("Items", [])
    service_map = {"IAM": "IAM", "S3": "S3", "SG": "SG", "CT": "CT"}
    now = datetime.now(timezone.utc)
    for item in items:
        prefix = item.get("rule_id", "").split("_")[0]
        item["service"] = service_map.get(prefix, prefix)
        item["remediation_description"] = REMEDIATION_DESCRIPTIONS.get(item.get("rule_id", ""), "Manual remediation required")
        item["can_remediate"] = item.get("rule_id", "") in REMEDIATION_DESCRIPTIONS
        item["can_rollback"]  = item.get("status") == "RESOLVED" and bool(item.get("rollback_config"))
        # Compute age in days from first_seen
        try:
            first_seen = datetime.fromisoformat(item["first_seen"].replace("Z", "+00:00"))
            item["days_open"] = (now - first_seen).days
        except Exception:
            item["days_open"] = 0
    sf = params.get("severity"); stf = params.get("status"); svcf = params.get("service")
    if sf:   items = [i for i in items if i.get("severity") == sf]
    if stf:  items = [i for i in items if i.get("status")   == stf]
    if svcf: items = [i for i in items if i.get("service")  == svcf]
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))
    return resp(200, {"findings": items, "count": len(items)})


def handle_remediate(body):
    finding_id = body.get("finding_id")
    if not finding_id:
        return resp(400, {"error": "finding_id required"})
    item = table.get_item(Key={"finding_id": finding_id}).get("Item")
    if not item:
        return resp(404, {"error": "Finding not found"})

    # Get the latest snapshot key from S3
    s3_client = boto3.client("s3")
    try:
        objects = s3_client.list_objects_v2(Bucket=SNAPSHOT_BUCKET)
        latest = sorted(objects.get("Contents", []), key=lambda x: x["LastModified"], reverse=True)
        snapshot_key = latest[0]["Key"] if latest else ""
    except:
        snapshot_key = ""

    actor = "dashboard-user"

    sfn_input = {
        "finding_id":               finding_id,
        "rule_id":                  item["rule_id"],
        "resource_id":              item["resource_id"],
        "severity":                 item["severity"],
        "snapshot_key":             snapshot_key,
        "actor":                    actor,
        "remediation_description":  REMEDIATION_DESCRIPTIONS.get(item["rule_id"], "Remediate issue")
    }
    execution = sfn.start_execution(
        stateMachineArn=SFN_ARN,
        input=json.dumps(sfn_input)
    )
    return resp(200, {"message": "Remediation started", "execution_arn": execution["executionArn"]})


def handle_rollback(body):
    finding_id = body.get("finding_id")
    if not finding_id:
        return resp(400, {"error": "finding_id required"})
    rollback_lambda = boto3.client("lambda")
    actor = "dashboard-user"
    result = rollback_lambda.invoke(
        FunctionName="CSPM-RollbackLambda",
        Payload=json.dumps({"finding_id": finding_id, "actor": actor})
    )
    payload = json.loads(result["Payload"].read())
    return resp(200, payload)


def handle_approve(params):
    """Called when user clicks Approve/Reject link in CRITICAL remediation email."""
    token  = params.get("token")
    action = params.get("action", "approve")
    if not token:
        return resp(400, {"error": "token required"})
    try:
        if action == "approve":
            sfn.send_task_success(taskToken=token, output=json.dumps({"approved": True}))
            return resp(200, {"message": "Remediation approved. Fix is running now."})
        else:
            sfn.send_task_failure(taskToken=token, error="RemediationRejected", cause="User rejected via email")
            return resp(200, {"message": "Remediation rejected. No changes made."})
    except Exception as e:
        return resp(500, {"error": str(e)})


def resp(status_code, body):
    return {"statusCode": status_code, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


# ── TRENDS endpoint ──────────────────────────────────────────────────────────
def handle_trends():
    try:
        result = trends_table.scan()
        items = result.get("Items", [])
        items.sort(key=lambda x: x.get("timestamp", ""))

        # Aggregate into hourly buckets — avoids sending 1000s of raw scan rows
        # to the frontend. Each bucket = one hour, averaged/maxed appropriately.
        buckets = {}
        for item in items:
            # Key = first 13 chars of ISO timestamp: "2026-03-29T14"
            hour_key = (item.get("timestamp", "") or item.get("date", ""))[:13]
            if not hour_key:
                continue
            if hour_key not in buckets:
                buckets[hour_key] = {
                    "hour_key":      hour_key,
                    "date":          item.get("date", ""),
                    "scores":        [],
                    "total_findings":[],
                    "critical":      [],
                    "high":          [],
                    "medium":        [],
                    "low":           [],
                    "raw_count":     0,
                }
            b = buckets[hour_key]
            b["scores"].append(int(item.get("posture_score", 0)))
            b["total_findings"].append(int(item.get("total_findings", 0)))
            b["critical"].append(int(item.get("critical", 0)))
            b["high"].append(int(item.get("high", 0)))
            b["medium"].append(int(item.get("medium", 0)))
            b["low"].append(int(item.get("low", 0)))
            b["raw_count"] += 1

        clean = []
        for hour_key in sorted(buckets):
            b = buckets[hour_key]
            clean.append({
                "date":           b["date"],
                "timestamp":      hour_key,
                "posture_score":  round(sum(b["scores"]) / len(b["scores"])),
                "total_findings": max(b["total_findings"]),
                "critical":       max(b["critical"]),
                "high":           max(b["high"]),
                "medium":         max(b["medium"]),
                "low":            max(b["low"]),
                "raw_count":      b["raw_count"],
            })

        return resp(200, {"trends": clean, "raw_count": len(items)})
    except Exception as e:
        return resp(500, {"error": str(e)})


# ── AUDIT endpoint ───────────────────────────────────────────────────────────
def handle_audit(params):
    try:
        limit = int(params.get("limit", 50))
        result = audit_table.scan()
        items = result.get("Items", [])
        items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return resp(200, {"logs": items[:limit], "count": len(items)})
    except Exception as e:
        return resp(500, {"error": str(e)})


# ── SCAN endpoint ────────────────────────────────────────────────────────────
SCANNER_FUNCTION_NAME = "CSPM-ScannerLambda"

def handle_scan():
    try:
        lambda_client = boto3.client("lambda")
        lambda_client.invoke(
            FunctionName=SCANNER_FUNCTION_NAME,
            InvocationType="Event"   # async — fire and forget
        )
        return resp(200, {"message": "Scan triggered — results will appear in ~30 seconds"})
    except Exception as e:
        return resp(500, {"error": str(e)})


# ── CONFIG endpoints (appended) ───────────────────────────────────────────────
config_table = ddb.Table("CSPM-Config")
audit_table  = ddb.Table("CSPM-AuditLog")
trends_table = ddb.Table("CSPM-Trends")

def handle_get_config():
    try:
        ar = config_table.get_item(Key={"config_key": "AUTO_REMEDIATE"}).get("Item", {})
        ex = config_table.get_item(Key={"config_key": "EXCLUSIONS"}).get("Item", {})
        return resp(200, {
            "auto_remediate": ar.get("enabled", False),
            "exclusions":     list(ex.get("resources", []))
        })
    except Exception as e:
        return resp(500, {"error": str(e)})

def handle_post_config(body):
    try:
        if "auto_remediate" in body:
            old_val = config_table.get_item(Key={"config_key": "AUTO_REMEDIATE"}).get("Item", {}).get("enabled", False)
            new_val = bool(body["auto_remediate"])
            config_table.put_item(Item={
                "config_key": "AUTO_REMEDIATE",
                "enabled":    new_val,
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
            if old_val != new_val:
                import uuid
                audit_table.put_item(Item={
                    "audit_id":    str(uuid.uuid4()),
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "date":        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "action":      "CONFIG_CHANGED",
                    "rule_id":     "N/A",
                    "resource_id": "AUTO_REMEDIATE",
                    "finding_id":  "N/A",
                    "actor":       "dashboard-user",
                    "detail":      str({"old": old_val, "new": new_val}),
                    "status":      "SUCCESS"
                })
        if "exclusions" in body:
            old_ex = config_table.get_item(Key={"config_key": "EXCLUSIONS"}).get("Item", {}).get("resources", [])
            new_ex = list(body["exclusions"])
            config_table.put_item(Item={
                "config_key": "EXCLUSIONS",
                "resources":  new_ex,
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
            import uuid
            audit_table.put_item(Item={
                "audit_id":    str(uuid.uuid4()),
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "date":        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "action":      "CONFIG_CHANGED",
                "rule_id":     "N/A",
                "resource_id": "EXCLUSIONS",
                "finding_id":  "N/A",
                "actor":       "dashboard-user",
                "detail":      str({"old": old_ex, "new": new_ex}),
                "status":      "SUCCESS"
            })
        return resp(200, {"message": "Config updated"})
    except Exception as e:
        return resp(500, {"error": str(e)})
