"""
Tests for rules_ec2.py — pure function, no mocking needed.
"""
from rules_ec2 import evaluate_ec2

# ── Helpers ────────────────────────────────────────────────────────────────────

CLEAN_SG = {
    "sg_id":         "sg-clean",
    "sg_name":       "my-sg",
    "vpc_id":        "vpc-1",
    "open_ssh":      False,
    "open_rdp":      False,
    "open_all":      False,
    "open_all_ipv6": False,
    "is_default":    False,
}

CLEAN_INSTANCE = {
    "instance_id":     "i-clean",
    "state":           "running",
    "public_ip":       None,
    "imdsv2_required": True,
    "root_encrypted":  True,
}

CLEAN_VPC = {
    "vpc_id":            "vpc-clean",
    "is_default":        False,
    "flow_logs_enabled": True,
    "cidr":              "10.0.0.0/16",
}

CLEAN_SNAP = {
    "snapshot_id": "snap-clean",
    "is_public":   False,
    "encrypted":   True,
}

def _data(sgs=None, instances=None, vpcs=None, ebs=None):
    return {
        "security_groups": sgs       or [],
        "instances":       instances or [],
        "vpcs":            vpcs      or [],
        "ebs":             ebs       or [],
    }

def rule_ids(findings):
    return [f[0] for f in findings]


# ── Security groups ────────────────────────────────────────────────────────────

class TestSecurityGroups:
    def test_open_all_ipv4(self):
        sg = {**CLEAN_SG, "open_all": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert ("SG_OPEN_ALL", "CRITICAL", "sg-clean") in f

    def test_open_all_ipv6(self):
        sg = {**CLEAN_SG, "open_all_ipv6": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert ("SG_OPEN_ALL", "CRITICAL", "sg-clean") in f

    def test_open_ssh(self):
        sg = {**CLEAN_SG, "open_ssh": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert ("SG_OPEN_SSH", "HIGH", "sg-clean") in f

    def test_open_rdp(self):
        sg = {**CLEAN_SG, "open_rdp": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert ("SG_OPEN_RDP", "HIGH", "sg-clean") in f

    def test_default_sg_with_open_ssh(self):
        sg = {**CLEAN_SG, "is_default": True, "open_ssh": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert ("SG_DEFAULT_OPEN", "HIGH", "sg-clean") in f

    def test_default_sg_with_open_all(self):
        sg = {**CLEAN_SG, "is_default": True, "open_all": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert ("SG_DEFAULT_OPEN", "HIGH", "sg-clean") in f

    def test_default_sg_clean_no_default_open(self):
        sg = {**CLEAN_SG, "is_default": True}
        f = evaluate_ec2(_data(sgs=[sg]))
        assert "SG_DEFAULT_OPEN" not in rule_ids(f)

    def test_clean_sg_no_findings(self):
        f = evaluate_ec2(_data(sgs=[CLEAN_SG]))
        assert rule_ids(f) == []


# ── EC2 instances ──────────────────────────────────────────────────────────────

class TestInstances:
    def test_imdsv2_not_required(self):
        inst = {**CLEAN_INSTANCE, "imdsv2_required": False}
        f = evaluate_ec2(_data(instances=[inst]))
        assert ("EC2_IMDSV2_DISABLED", "MEDIUM", "i-clean") in f

    def test_imdsv2_required_no_finding(self):
        f = evaluate_ec2(_data(instances=[CLEAN_INSTANCE]))
        assert "EC2_IMDSV2_DISABLED" not in rule_ids(f)

    def test_root_volume_not_encrypted(self):
        inst = {**CLEAN_INSTANCE, "root_encrypted": False}
        f = evaluate_ec2(_data(instances=[inst]))
        assert ("EC2_EBS_NOT_ENCRYPTED", "MEDIUM", "i-clean") in f

    def test_root_volume_encrypted_no_finding(self):
        f = evaluate_ec2(_data(instances=[CLEAN_INSTANCE]))
        assert "EC2_EBS_NOT_ENCRYPTED" not in rule_ids(f)

    def test_clean_instance_no_findings(self):
        f = evaluate_ec2(_data(instances=[CLEAN_INSTANCE]))
        assert rule_ids(f) == []


# ── VPCs ───────────────────────────────────────────────────────────────────────

class TestVPCs:
    def test_no_flow_logs(self):
        vpc = {**CLEAN_VPC, "flow_logs_enabled": False}
        f = evaluate_ec2(_data(vpcs=[vpc]))
        assert ("VPC_NO_FLOW_LOGS", "MEDIUM", "vpc-clean") in f

    def test_flow_logs_enabled_no_finding(self):
        f = evaluate_ec2(_data(vpcs=[CLEAN_VPC]))
        assert "VPC_NO_FLOW_LOGS" not in rule_ids(f)

    def test_default_vpc_in_use(self):
        vpc = {**CLEAN_VPC, "is_default": True}
        f = evaluate_ec2(_data(vpcs=[vpc]))
        assert ("VPC_DEFAULT_IN_USE", "LOW", "vpc-clean") in f

    def test_non_default_vpc_no_low_finding(self):
        f = evaluate_ec2(_data(vpcs=[CLEAN_VPC]))
        assert "VPC_DEFAULT_IN_USE" not in rule_ids(f)

    def test_clean_vpc_no_findings(self):
        f = evaluate_ec2(_data(vpcs=[CLEAN_VPC]))
        assert rule_ids(f) == []


# ── EBS snapshots ──────────────────────────────────────────────────────────────

class TestEBSSnapshots:
    def test_public_snapshot(self):
        snap = {**CLEAN_SNAP, "is_public": True}
        f = evaluate_ec2(_data(ebs=[snap]))
        assert ("EC2_PUBLIC_SNAPSHOT", "CRITICAL", "snap-clean") in f

    def test_unencrypted_snapshot(self):
        snap = {**CLEAN_SNAP, "encrypted": False}
        f = evaluate_ec2(_data(ebs=[snap]))
        assert ("EC2_SNAPSHOT_NOT_ENCRYPTED", "MEDIUM", "snap-clean") in f

    def test_public_and_unencrypted_both_fire(self):
        snap = {**CLEAN_SNAP, "is_public": True, "encrypted": False}
        f = evaluate_ec2(_data(ebs=[snap]))
        assert "EC2_PUBLIC_SNAPSHOT"        in rule_ids(f)
        assert "EC2_SNAPSHOT_NOT_ENCRYPTED" in rule_ids(f)

    def test_clean_snapshot_no_findings(self):
        f = evaluate_ec2(_data(ebs=[CLEAN_SNAP]))
        assert rule_ids(f) == []


# ── Legacy flat list format ────────────────────────────────────────────────────

class TestLegacyFormat:
    def test_legacy_open_ssh(self):
        sgs = [{"sg_id": "sg-1", "open_ssh": True, "open_all": False, "is_default": False}]
        f = evaluate_ec2(sgs)
        assert ("SG_OPEN_SSH", "HIGH", "sg-1") in f

    def test_legacy_open_all(self):
        sgs = [{"sg_id": "sg-1", "open_ssh": False, "open_all": True, "is_default": False}]
        f = evaluate_ec2(sgs)
        assert ("SG_OPEN_ALL", "CRITICAL", "sg-1") in f

    def test_legacy_clean(self):
        sgs = [{"sg_id": "sg-1", "open_ssh": False, "open_all": False, "is_default": False}]
        f = evaluate_ec2(sgs)
        assert f == []


# ── Fully clean account ────────────────────────────────────────────────────────

def test_fully_clean_no_findings():
    data = _data(
        sgs=[CLEAN_SG],
        instances=[CLEAN_INSTANCE],
        vpcs=[CLEAN_VPC],
        ebs=[CLEAN_SNAP],
    )
    assert evaluate_ec2(data) == []

def test_empty_data_no_crash():
    assert evaluate_ec2(_data()) == []
