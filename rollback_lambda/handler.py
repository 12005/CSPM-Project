"""
Rollback Lambda v2 with audit trail.
"""
import json
import boto3
from datetime import datetime, timezone

import plugins
import audit_trail

ddb   = boto3.resource("dynamodb")
table = ddb.Table("CSPM-Findings")


def lambda_handler(event, context):
    print("ROLLBACK EVENT:", json.dumps(event))

    finding_id = event["finding_id"]
    actor      = event.get("actor", "system")

    resp = table.get_item(Key={"finding_id": finding_id})
    item = resp.get("Item")
    if not item:
        return {"success": False, "error": f"Finding {finding_id} not found"}

    rule_id         = item["rule_id"]
    resource_id     = item["resource_id"]
    rollback_config = json.loads(item.get("rollback_config", "{}"))

    if not rollback_config:
        return {"success": False, "error": "No rollback config saved"}

    plugin = plugins.get_plugin(rule_id)
    if not plugin:
        return {"success": False, "error": f"No rollback plugin for {rule_id}"}

    try:
        result = plugin.rollback(rule_id, resource_id, rollback_config)
        now_ts = datetime.now(timezone.utc).isoformat()

        table.update_item(
            Key={"finding_id": finding_id},
            UpdateExpression="""
                SET #st = :open,
                    rolled_back_at = :ts,
                    rollback_action = :action,
                    rolled_back_by = :actor
            """,
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":open":   "OPEN",
                ":ts":     now_ts,
                ":action": result.get("action", "Rolled back"),
                ":actor":  actor
            }
        )

        audit_trail.log("ROLLED_BACK", rule_id, resource_id, finding_id,
                        actor=actor, detail=result, status="SUCCESS")

        final = {"success": True, "rule_id": rule_id,
                 "resource_id": resource_id, "action": result.get("action")}
        print(f"Rollback SUCCESS: {final}")
        return final

    except Exception as e:
        audit_trail.log("ROLLED_BACK", rule_id, resource_id, finding_id,
                        actor=actor, detail={"error": str(e)}, status="FAILED")
        result = {"success": False, "rule_id": rule_id, "error": str(e)}
        print(f"Rollback FAILED: {result}")
        return result
