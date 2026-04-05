import json
import boto3
import hashlib
from datetime import datetime, timezone, timedelta
from boto3.dynamodb.conditions import Attr

from rules_iam import evaluate_iam
from rules_s3 import evaluate_s3
from rules_ec2 import evaluate_ec2
from rules_cloudtrail import evaluate_cloudtrail

s3_client  = boto3.client("s3")
ddb          = boto3.resource("dynamodb")
table        = ddb.Table("CSPM-Findings")
config_table = ddb.Table("CSPM-Config")
trends_table = ddb.Table("CSPM-Trends")
cloudwatch = boto3.client("cloudwatch")
sns        = boto3.client("sns")
sfn        = boto3.client("stepfunctions")

SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:344988461546:CSPM-Alerts"
SFN_ARN       = "arn:aws:states:ap-south-1:344988461546:stateMachine:CSPM-RemediationWorkflow"
SNAPSHOT_BUCKET = "cspm-snapshots-v1"

RULE_DESCRIPTIONS = {
    "CT_DISABLED":              "CloudTrail is not enabled — all API activity is unlogged.",
    "CT_NOT_MULTI_REGION":      "CloudTrail is single-region only.",
    "CT_NO_KMS":                "CloudTrail logs are not KMS encrypted.",
    "CT_LOG_VALIDATION_OFF":    "CloudTrail log file validation is disabled.",
    "SG_OPEN_ALL":              "Security group allows ALL traffic from 0.0.0.0/0.",
    "SG_OPEN_SSH":              "Security group allows SSH from 0.0.0.0/0.",
    "SG_DEFAULT_OPEN":          "Default security group has open inbound rules.",
    "S3_PUBLIC_ACL":            "S3 bucket has a public ACL.",
    "S3_NO_ENCRYPTION":         "S3 bucket has no server-side encryption.",
    "S3_BLOCK_PUBLIC_DISABLED": "S3 bucket public access block is not enabled.",
    "S3_NO_VERSIONING":         "S3 bucket versioning is disabled.",
    "IAM_NO_MFA":               "IAM user does not have MFA enabled.",
    "IAM_ADMIN":                "IAM user has AdministratorAccess policy attached.",
    "IAM_MULTI_KEYS":           "IAM user has more than one active access key.",
    "IAM_KEY_OLD":              "IAM user has an access key older than 90 days.",
    "IAM_INLINE_POLICY":        "IAM user has inline policies attached.",
}


def make_finding_id(rule_id, resource_id):
    raw = f"{rule_id}#{resource_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:36]


def compute_posture_score(severity_counts):
    deductions = (
        severity_counts.get("CRITICAL", 0) * 10 +
        severity_counts.get("HIGH", 0) * 5 +
        severity_counts.get("MEDIUM", 0) * 2
    )
    return max(0, 100 - deductions)


def write_trend(posture_score, severity_counts, total, auto_resolved, auto_remediated):
    """Write posture score snapshot to CSPM-Trends for historical chart."""
    try:
        now = datetime.now(timezone.utc)
        trends_table.put_item(Item={
            "date":             now.strftime("%Y-%m-%d"),
            "timestamp":        now.isoformat(),
            "posture_score":    posture_score,
            "total_findings":   total,
            "critical":         severity_counts.get("CRITICAL", 0),
            "high":             severity_counts.get("HIGH", 0),
            "medium":           severity_counts.get("MEDIUM", 0),
            "low":              severity_counts.get("LOW", 0),
            "auto_resolved":    auto_resolved,
            "auto_remediated":  auto_remediated
        })
        print(f"Trend written: score={posture_score}, total={total}")
    except Exception as e:
        print(f"Failed to write trend (non-fatal): {e}")


def get_config():
    """Load AUTO_REMEDIATE setting and exclusion list from CSPM-Config table."""
    try:
        resp = config_table.get_item(Key={"config_key": "AUTO_REMEDIATE"})
        auto_remediate = resp.get("Item", {}).get("enabled", False)
    except:
        auto_remediate = False

    try:
        resp = config_table.get_item(Key={"config_key": "EXCLUSIONS"})
        exclusions = set(resp.get("Item", {}).get("resources", []))
    except:
        exclusions = set()

    return auto_remediate, exclusions


def get_latest_snapshot_key():
    """Find the most recent snapshot in S3."""
    try:
        objects = s3_client.list_objects_v2(Bucket=SNAPSHOT_BUCKET)
        latest = sorted(objects.get("Contents", []), key=lambda x: x["LastModified"], reverse=True)
        return latest[0]["Key"] if latest else ""
    except:
        return ""


def get_unresolved_critical_count():
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    try:
        response = table.scan(
            FilterExpression=(
                Attr("severity").eq("CRITICAL") &
                Attr("status").eq("OPEN") &
                Attr("first_seen").lt(cutoff)
            ),
            Select="COUNT"
        )
        return response.get("Count", 0)
    except:
        return 0


def get_resolved_count_since_last_scan():
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    try:
        response = table.scan(
            FilterExpression=(
                Attr("status").eq("RESOLVED") &
                Attr("last_seen").gt(cutoff)
            ),
            Select="COUNT"
        )
        return response.get("Count", 0)
    except:
        return 0


def auto_resolve_stale_findings(current_finding_ids, now_ts):
    """
    Scan DynamoDB for OPEN findings that are NOT in the current scan.
    If a finding no longer exists in AWS, mark it RESOLVED automatically.
    """
    try:
        result = table.scan(
            FilterExpression=Attr("status").eq("OPEN")
        )
        open_findings = result.get("Items", [])

        resolved_count = 0
        for item in open_findings:
            fid = item["finding_id"]
            if fid not in current_finding_ids:
                table.update_item(
                    Key={"finding_id": fid},
                    UpdateExpression="SET #st = :resolved, last_seen = :ts, remediation_action = :action",
                    ExpressionAttributeNames={"#st": "status"},
                    ExpressionAttributeValues={
                        ":resolved": "RESOLVED",
                        ":ts":       now_ts,
                        ":action":   "Auto-resolved: misconfig no longer detected in scan"
                    }
                )
                resolved_count += 1
                print(f"Auto-resolved: {item['rule_id']} on {item['resource_id']}")

        if resolved_count:
            print(f"Auto-resolved {resolved_count} finding(s) that no longer exist in AWS")
        return resolved_count
    except Exception as e:
        print(f"Error during auto-resolve: {e}")
        return 0


def trigger_auto_remediation(new_findings, snapshot_key):
    """
    For each new finding not in the exclusion list,
    start a Step Functions execution to auto-remediate.
    Only called when AUTO_REMEDIATE is ON.
    """
    _, exclusions = get_config()
    triggered = 0
    for rule, severity, resource in new_findings:
        if resource in exclusions:
            print(f"Skipping auto-remediate for excluded resource: {resource}")
            continue
        finding_id = make_finding_id(rule, resource)
        try:
            sfn.start_execution(
                stateMachineArn=SFN_ARN,
                input=json.dumps({
                    "finding_id":              finding_id,
                    "rule_id":                 rule,
                    "resource_id":             resource,
                    "severity":                severity,
                    "snapshot_key":            snapshot_key,
                    "remediation_description": RULE_DESCRIPTIONS.get(rule, "Auto-remediate")
                })
            )
            triggered += 1
            print(f"Auto-remediation triggered: {rule} on {resource}")
        except Exception as e:
            print(f"Failed to trigger auto-remediation for {rule}/{resource}: {e}")
    return triggered


def publish_sns_alert(new_critical_findings, posture_score, total_findings):
    if not new_critical_findings:
        return
    count = len(new_critical_findings)
    subject = f"[CSPM] {count} NEW CRITICAL Finding{'s' if count>1 else ''} Detected"
    lines = [
        "="*60, "CSPM SECURITY ALERT", "="*60,
        f"Account:        344988461546",
        f"Region:         ap-south-1",
        f"Time:           {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Posture Score:  {posture_score}/100",
        f"Total Findings: {total_findings}", "",
        f"NEW CRITICAL FINDINGS ({count}):", "-"*60,
    ]
    for rule, severity, resource in new_critical_findings:
        desc = RULE_DESCRIPTIONS.get(rule, "No description available.")
        lines += [f"Rule:     {rule}", f"Resource: {resource}", f"Detail:   {desc}", ""]
    lines += ["-"*60, "View your dashboard:", "https://d18e670z7gh807.cloudfront.net", "="*60]
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message="\n".join(lines))
        print(f"SNS alert sent: {count} critical finding(s)")
    except Exception as e:
        print(f"Failed to send SNS alert: {e}")


def lambda_handler(event, context):
    bucket = event["detail"]["bucket"]
    key    = event["detail"]["key"]

    data = json.loads(s3_client.get_object(Bucket=bucket, Key=key)["Body"].read())

    findings = []
    findings += evaluate_iam(data["services"]["iam"])
    findings += evaluate_s3(data["services"]["s3"])
    findings += evaluate_ec2(data["services"]["ec2"])
    findings += evaluate_cloudtrail(data["services"]["cloudtrail"])

    # Load config
    auto_remediate, exclusions = get_config()
    print(f"Config: auto_remediate={auto_remediate}, exclusions={exclusions}")

    # ── Write findings to DynamoDB with idempotency ───────────────────────────
    new_count    = 0
    new_critical = []
    new_findings_for_auto_remediate = []
    now_ts = datetime.now(timezone.utc).isoformat()
    current_finding_ids = set()

    for rule, severity, resource in findings:
        finding_id = make_finding_id(rule, resource)
        current_finding_ids.add(finding_id)
        try:
            table.put_item(
                Item={
                    "finding_id":  finding_id,
                    "resource_id": resource,
                    "first_seen":  now_ts,
                    "last_seen":   now_ts,
                    "rule_id":     rule,
                    "severity":    severity,
                    "status":      "OPEN"
                },
                ConditionExpression="attribute_not_exists(finding_id)"
            )
            new_count += 1
            if severity == "CRITICAL":
                new_critical.append((rule, severity, resource))
            new_findings_for_auto_remediate.append((rule, severity, resource))
        except ddb.meta.client.exceptions.ConditionalCheckFailedException:
            table.update_item(
                Key={"finding_id": finding_id},
                UpdateExpression="SET last_seen = :ts",
                ExpressionAttributeValues={":ts": now_ts}
            )

    existing_count = len(findings) - new_count
    print(f"Findings: {len(findings)} total | {new_count} new | {existing_count} existing | {len(new_critical)} new critical")

    # ── AUTO-RESOLVE: mark findings RESOLVED if no longer in AWS ─────────────
    auto_resolved = auto_resolve_stale_findings(current_finding_ids, now_ts)

    # ── AUTO-REMEDIATE: trigger Step Functions for new findings if mode is ON ─
    auto_remediated = 0
    if auto_remediate and new_findings_for_auto_remediate:
        snapshot_key = get_latest_snapshot_key()
        auto_remediated = trigger_auto_remediation(new_findings_for_auto_remediate, snapshot_key)
        print(f"Auto-remediated {auto_remediated} finding(s)")
    elif auto_remediate:
        print("Auto-remediate ON but no new findings to remediate")
    else:
        print("Auto-remediate OFF — skipping auto-remediation")

    # ── SNS alert for new critical findings ──────────────────────────────────
    publish_sns_alert(new_critical, compute_posture_score(
        {"CRITICAL": sum(1 for _,s,_ in findings if s=="CRITICAL"),
         "HIGH": sum(1 for _,s,_ in findings if s=="HIGH"),
         "MEDIUM": sum(1 for _,s,_ in findings if s=="MEDIUM")}
    ), len(findings))

    # ── Build metric counters ─────────────────────────────────────────────────
    severity_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    service_counts   = {}
    resource_counts  = {}
    service_severity = {}
    service_map      = {"IAM": "IAM", "S3": "S3", "SG": "SG", "CT": "CT"}

    for rule, severity, resource in findings:
        if severity in severity_counts: severity_counts[severity] += 1
        prefix  = rule.split("_")[0]
        service = service_map.get(prefix, prefix)
        service_counts[service]   = service_counts.get(service, 0) + 1
        resource_counts[resource] = resource_counts.get(resource, 0) + 1
        key2d = (service, severity)
        service_severity[key2d]   = service_severity.get(key2d, 0) + 1

    posture_score        = compute_posture_score(severity_counts)
    unresolved_critical  = get_unresolved_critical_count()
    resolved_this_window = get_resolved_count_since_last_scan()

    # ── CloudWatch metrics ────────────────────────────────────────────────────
    metric_data = [
        {"MetricName": "SecurityPostureScore",       "Value": float(posture_score), "Unit": "None"},
        {"MetricName": "TotalFindings",              "Value": len(findings),        "Unit": "Count"},
        {"MetricName": "FindingsOpened",             "Value": new_count,            "Unit": "Count"},
        {"MetricName": "FindingsResolved",           "Value": resolved_this_window, "Unit": "Count"},
        {"MetricName": "FindingsAutoResolved",       "Value": auto_resolved,        "Unit": "Count"},
        {"MetricName": "FindingsAutoRemediated",     "Value": auto_remediated,      "Unit": "Count"},
        {"MetricName": "UnresolvedCriticalFindings", "Value": unresolved_critical,  "Unit": "Count"},
    ]
    for sev, count in severity_counts.items():
        metric_data.append({"MetricName": "FindingsBySeverity",
            "Dimensions": [{"Name": "Severity", "Value": sev}], "Value": count, "Unit": "Count"})
    for service, count in service_counts.items():
        metric_data.append({"MetricName": "FindingsByService",
            "Dimensions": [{"Name": "Service", "Value": service}], "Value": count, "Unit": "Count"})
    for (service, severity), count in service_severity.items():
        metric_data.append({"MetricName": "FindingsByServiceAndSeverity",
            "Dimensions": [{"Name": "Service", "Value": service}, {"Name": "Severity", "Value": severity}],
            "Value": count, "Unit": "Count"})
    top_resources = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for resource, count in top_resources:
        metric_data.append({"MetricName": "FindingsByResource",
            "Dimensions": [{"Name": "ResourceId", "Value": resource[:256]}], "Value": count, "Unit": "Count"})

    def chunks(lst, n):
        for i in range(0, len(lst), n): yield lst[i:i+n]
    for batch in chunks(metric_data, 20):
        cloudwatch.put_metric_data(Namespace="CSPM", MetricData=batch)

    print(f"Published {len(metric_data)} metrics | Score: {posture_score}/100 | Auto-resolved: {auto_resolved} | Auto-remediated: {auto_remediated}")

    # Write historical trend snapshot
    write_trend(posture_score, severity_counts, len(findings), auto_resolved, auto_remediated)

    return {
        "findings":        len(findings),
        "new":             new_count,
        "auto_resolved":   auto_resolved,
        "auto_remediated": auto_remediated,
        "posture_score":   posture_score
    }
