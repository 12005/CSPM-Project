import json
import boto3
from datetime import datetime, timezone

from scan_iam import scan_iam
from scan_s3 import scan_s3
from scan_ec2 import scan_ec2
from scan_cloudtrail import scan_cloudtrail

s3_client    = boto3.client("s3")
eventbridge  = boto3.client("events")

SNAPSHOT_BUCKET = "cspm-snapshots-v1"


# FIX #7 — datetime serializer so json.dumps never crashes on datetime objects
def _json_default(obj):
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def lambda_handler(event, context):
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "iam":        scan_iam(),
            "s3":         scan_s3(),
            "ec2":        scan_ec2(),
            "cloudtrail": scan_cloudtrail(),
        }
    }

    now = datetime.now(timezone.utc)
    key = f"{now.year}/{now.month:02d}/{now.day:02d}/{now.strftime('%H-%M-%S')}.json"

    s3_client.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot, indent=2, default=_json_default),
    )

    eventbridge.put_events(
        Entries=[{
            "Source":     "cspm.scanner",
            "DetailType": "SnapshotCreated",
            "Detail":     json.dumps({"bucket": SNAPSHOT_BUCKET, "key": key}),
        }]
    )

    return {"status": "ok"}
