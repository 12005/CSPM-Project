"""
EC2/VPC Rules — CIS AWS Foundations Benchmark aligned

CIS Coverage:
  5.1   SG open SSH to 0.0.0.0/0   → SG_OPEN_SSH                HIGH
  5.2   SG open RDP to 0.0.0.0/0   → SG_OPEN_RDP                HIGH
  5.3   Default SG open            → SG_DEFAULT_OPEN             HIGH
  5.4   SG allows all traffic      → SG_OPEN_ALL                 CRITICAL
  5.6   IMDSv2 not enforced        → EC2_IMDSV2_DISABLED         MEDIUM
  2.2.1 Public EBS snapshot        → EC2_PUBLIC_SNAPSHOT         CRITICAL
  2.2.1 Unencrypted EBS snapshot   → EC2_SNAPSHOT_NOT_ENCRYPTED  MEDIUM
  2.2.2 EBS volume not encrypted   → EC2_EBS_NOT_ENCRYPTED       MEDIUM
  3.9   VPC flow logs disabled     → VPC_NO_FLOW_LOGS            MEDIUM
  NEW   Default VPC in use         → VPC_DEFAULT_IN_USE          LOW
"""

def evaluate_ec2(data):
    f = []

    # Backwards compat — old flat list of security groups
    if isinstance(data, list):
        return _evaluate_sgs_legacy(data)

    f += _evaluate_sgs(data.get("security_groups", []))
    f += _evaluate_instances(data.get("instances", []))
    f += _evaluate_vpcs(data.get("vpcs", []))
    f += _evaluate_ebs(data.get("ebs", []))

    return f


def _evaluate_sgs(sgs):
    f = []
    for sg in sgs:
        rid = sg["sg_id"]

        # CIS 5.4 — all traffic open to world (IPv4 or IPv6)
        if sg.get("open_all") or sg.get("open_all_ipv6"):
            f.append(("SG_OPEN_ALL", "CRITICAL", rid))

        # CIS 5.1 — SSH open to world
        if sg.get("open_ssh"):
            f.append(("SG_OPEN_SSH", "HIGH", rid))

        # CIS 5.2 — RDP open to world
        if sg.get("open_rdp"):
            f.append(("SG_OPEN_RDP", "HIGH", rid))

        # CIS 5.3 — default SG with any open rule
        if sg.get("is_default") and (
            sg.get("open_ssh") or sg.get("open_rdp") or sg.get("open_all")
        ):
            f.append(("SG_DEFAULT_OPEN", "HIGH", rid))

    return f


def _evaluate_instances(instances):
    f = []
    for inst in instances:
        rid = inst["instance_id"]

        # CIS 5.6 — IMDSv2 not required
        if not inst.get("imdsv2_required"):
            f.append(("EC2_IMDSV2_DISABLED", "MEDIUM", rid))

        # CIS 2.2.2 — root EBS volume not encrypted
        if not inst.get("root_encrypted"):
            f.append(("EC2_EBS_NOT_ENCRYPTED", "MEDIUM", rid))

    return f


def _evaluate_vpcs(vpcs):
    f = []
    for vpc in vpcs:
        rid = vpc["vpc_id"]

        # CIS 3.9 — VPC flow logs disabled
        if not vpc.get("flow_logs_enabled"):
            f.append(("VPC_NO_FLOW_LOGS", "MEDIUM", rid))

        # Best practice — avoid using the default VPC
        if vpc.get("is_default"):
            f.append(("VPC_DEFAULT_IN_USE", "LOW", rid))

    return f


def _evaluate_ebs(snapshots):
    f = []
    for snap in snapshots:
        rid = snap["snapshot_id"]

        # CIS 2.2.1 — public snapshot
        if snap.get("is_public"):
            f.append(("EC2_PUBLIC_SNAPSHOT", "CRITICAL", rid))

        # FIX #4 — unencrypted snapshot (new rule, scan_ec2 now always appends)
        if not snap.get("encrypted"):
            f.append(("EC2_SNAPSHOT_NOT_ENCRYPTED", "MEDIUM", rid))

    return f


def _evaluate_sgs_legacy(sgs):
    """Backwards compat for old flat scan format."""
    f = []
    for sg in sgs:
        if sg.get("open_ssh"):
            f.append(("SG_OPEN_SSH", "HIGH", sg["sg_id"]))
        if sg.get("open_all"):
            f.append(("SG_OPEN_ALL", "CRITICAL", sg["sg_id"]))
        if sg.get("is_default") and (sg.get("open_ssh") or sg.get("open_all")):
            f.append(("SG_DEFAULT_OPEN", "HIGH", sg["sg_id"]))
    return f
