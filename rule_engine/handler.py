import json
import boto3
import uuid
from datetime import datetime, timezone

from rules_s3 import evaluate_s3
from rules_sg import evaluate_sg
from rules_iam import evaluate_iam
from rules_cloudtrail import evaluate_cloudtrail

# AWS clients
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
cloudwatch = boto3.client("cloudwatch")

# DynamoDB table
table = dynamodb.Table("CSPM-Findings")

def lambda_handler(event, context):
   
    snapshot_bucket = event["detail"]["bucket"]
    snapshot_key = event["detail"]["key"]

    print(f"Processing snapshot s3://{snapshot_bucket}/{snapshot_key}")

    # Load snapshot from S3
    response = s3.get_object(
        Bucket=snapshot_bucket,
        Key=snapshot_key
    )
    snapshot = json.loads(response["Body"].read())

    findings = []

    # Apply rules
    findings += evaluate_s3(snapshot["services"]["s3"])
    findings += evaluate_sg(snapshot["services"]["security_groups"])
    findings += evaluate_iam(snapshot["services"]["iam"])
    findings += evaluate_cloudtrail(snapshot["services"]["cloudtrail"])

    # Store findings in DynamoDB
    for f in findings:
        item = {
            "finding_id": str(uuid.uuid4()),
            "resource_id": f["resource_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": f["service"],
            "rule_id": f["rule_id"],
            "severity": f["severity"],
            "risk_score": f["risk_score"],
            "status": "OPEN",
            "snapshot_path": f"s3://{snapshot_bucket}/{snapshot_key}"
        }
        table.put_item(Item=item)

    # 🔢 Count findings by severity (for dashboard)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    total = len(findings)

    # 📊 Publish metrics to CloudWatch
    cloudwatch.put_metric_data(
        Namespace="CSPM",
        MetricData=[
            {
                "MetricName": "TotalFindings",
                "Value": total,
                "Unit": "Count"
            },
            {
                "MetricName": "CriticalFindings",
                "Value": critical,
                "Unit": "Count"
            },
            {
                "MetricName": "HighFindings",
                "Value": high,
                "Unit": "Count"
            },
            {
                "MetricName": "MediumFindings",
                "Value": medium,
                "Unit": "Count"
            }
        ]
    )

    print(
        f"Findings created: {total} | "
        f"Critical: {critical}, High: {high}, Medium: {medium}"
    )

    return {
        "statusCode": 200,
        "findings_created": total
    }
