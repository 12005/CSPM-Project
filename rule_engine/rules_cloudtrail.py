def evaluate_cloudtrail(ct):
    f = []
    if not ct["enabled"]:
        f.append(("CT_DISABLED", "CRITICAL", "account"))
    if ct["enabled"] and not ct["multi_region"]:
        f.append(("CT_NOT_MULTI_REGION", "HIGH", "account"))
    if ct["enabled"] and not ct["kms_encrypted"]:
        f.append(("CT_NO_KMS", "HIGH", "account"))
    if ct["enabled"] and not ct["log_validation"]:
        f.append(("CT_LOG_VALIDATION_OFF", "MEDIUM", "account"))
    return f
