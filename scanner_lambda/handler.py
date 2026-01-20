import json
import boto3
from datetime import datetime, timezone

from scan_s3 import scan_s3
from scan_sg import scan_security_groups
from scan_iam import scan_iam
from scan_cloudtrail import scan_cloudtrail

# AWS clients
s3_client = boto3.client("s3")
eventbridge = boto3.client("events")

# Snapshot bucket name
SNAPSHOT_BUCKET = "cspm-snapshots-v1"

def lambda_handler(event, context):
    print("CSPM Scan started")

    # Collect scan data
    scan_result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "account_id": context.invoked_function_arn.split(":")[4],
        "region": context.invoked_function_arn.split(":")[3],
        "services": {
            "s3": scan_s3(),
            "security_groups": scan_security_groups(),
            "iam": scan_iam(),
            "cloudtrail": scan_cloudtrail()
        }
    }

    # Build directory structure: <year>/<month>/<day>/<time>.json
    now = datetime.now(timezone.utc)

    s3_key = (
        f"{now.year}/"
        f"{now.month:02d}/"
        f"{now.day:02d}/"
        f"{now.strftime('%H-%M-%S')}.json"
    )
    
    s3_client.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=s3_key,
        Body=json.dumps(scan_result, indent=2),
        ContentType="application/json"
    )

    print(f"Snapshot stored at s3://{SNAPSHOT_BUCKET}/{s3_key}")

    eventbridge.put_events(
        Entries=[
            {
                "Source": "cspm.scanner",
                "DetailType": "SnapshotCreated",
                "Detail": json.dumps({
                    "bucket": SNAPSHOT_BUCKET,
                    "key": s3_key
                })
            }
        ]
    )

    print("EventBridge event emitted: SnapshotCreated")
    print("CSPM Scan completed")

    return {
        "statusCode": 200,
        "message": "Scan completed, snapshot stored, event emitted",
        "snapshot_location": f"s3://{SNAPSHOT_BUCKET}/{s3_key}"
    }
