import boto3

cloudtrail = boto3.client("cloudtrail")

def scan_cloudtrail():
    result = {
        "trail_exists": False,
        "multi_region": False,
        "logging": False
    }

    trails = cloudtrail.describe_trails()["trailList"]

    if not trails:
        return result

    trail = trails[0]
    result["trail_exists"] = True
    result["multi_region"] = trail.get("IsMultiRegionTrail", False)

    status = cloudtrail.get_trail_status(Name=trail["Name"])
    result["logging"] = status.get("IsLogging", False)

    return result
