"""
Remediation Lambda — orchestrator v2 with audit trail.
"""
import json
import boto3
from datetime import datetime, timezone

import plugins
import audit_trail

ddb       = boto3.resource("dynamodb")
table     = ddb.Table("CSPM-Findings")
s3_client = boto3.client("s3")
sfn       = boto3.client("stepfunctions")

SNAPSHOT_BUCKET = "cspm-snapshots-v1"


def lambda_handler(event, context):
    print("REMEDIATION EVENT:", json.dumps(event))

    rule_id      = event["rule_id"]
    resource_id  = event["resource_id"]
    finding_id   = event["finding_id"]
    task_token   = event.get("task_token")
    snapshot_key = event.get("snapshot_key", "")
    actor        = event.get("actor", "system")   # email if triggered from dashboard

    snapshot = load_snapshot(snapshot_key)
    plugin   = plugins.get_plugin(rule_id)

    if not plugin:
        result = {"success": False, "error": f"No plugin for rule {rule_id}"}
        audit_trail.log("REMEDIATED", rule_id, resource_id, finding_id,
                        actor=actor, detail=result, status="FAILED")
        finish(task_token, finding_id, result, success=False)
        return result

    try:
        rollback_config = plugin.remediate(rule_id, resource_id, snapshot)
        now_ts = datetime.now(timezone.utc).isoformat()

        table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="""
                SET #st = :resolved,
                    remediated_at = :ts,
                    rollback_config = :rc,
                    remediation_action = :action,
                    snapshot_key = :sk,
                    remediated_by = :actor
            """,
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":resolved": "RESOLVED",
                ":ts":       now_ts,
                ":rc":       json.dumps(rollback_config),
                ":action":   rollback_config.get("action", "Remediated"),
                ":sk":       snapshot_key,
                ":actor":    actor
            }
        )

        # Determine if auto or manual
        action_type = "AUTO_REMEDIATED" if actor == "system" else "REMEDIATED"
        audit_trail.log(action_type, rule_id, resource_id, finding_id,
                        actor=actor, detail=rollback_config, status="SUCCESS")

        result = {"success": True, "rule_id": rule_id, "resource_id": resource_id,
                  "action": rollback_config.get("action")}
        print(f"Remediation SUCCESS: {result}")
        finish(task_token, finding_id, result, success=True)
        return result

    except Exception as e:
        result = {"success": False, "rule_id": rule_id, "resource_id": resource_id, "error": str(e)}
        audit_trail.log("REMEDIATED", rule_id, resource_id, finding_id,
                        actor=actor, detail={"error": str(e)}, status="FAILED")
        print(f"Remediation FAILED: {result}")
        finish(task_token, finding_id, result, success=False)
        return result


def load_snapshot(snapshot_key):
    if not snapshot_key:
        return {}
    try:
        obj = s3_client.get_object(Bucket=SNAPSHOT_BUCKET, Key=snapshot_key)
        return json.loads(obj["Body"].read())
    except Exception as e:
        print(f"Could not load snapshot {snapshot_key}: {e}")
        return {}


def finish(task_token, finding_id, result, success):
    if not task_token:
        return
    try:
        if success:
            sfn.send_task_success(taskToken=task_token, output=json.dumps(result))
        else:
            sfn.send_task_failure(taskToken=task_token, error="RemediationFailed",
                cause=result.get("error", "Unknown"))
    except Exception as e:
        print(f"Step Functions callback failed: {e}")
