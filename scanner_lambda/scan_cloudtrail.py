import boto3

ct = boto3.client("cloudtrail")

def scan_cloudtrail():
    # FIX #3 — excludeShadowTrails avoids duplicates from other regions
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    if not trails:
        return {
            "enabled":        False,
            "multi_region":   False,
            "log_validation": False,
            "kms_encrypted":  False,
        }

    # Prefer the multi-region trail; fall back to first available
    trail = next((t for t in trails if t.get("IsMultiRegionTrail")), trails[0])

    # FIX #3 — use TrailARN instead of Name; Name can fail for cross-region trails
    status = ct.get_trail_status(Name=trail["TrailARN"])

    return {
        "enabled":        status["IsLogging"],
        "multi_region":   trail["IsMultiRegionTrail"],
        "log_validation": trail.get("LogFileValidationEnabled", False),
        "kms_encrypted":  bool(trail.get("KmsKeyId")),
    }
