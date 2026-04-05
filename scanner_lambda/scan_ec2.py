import boto3

ec2 = boto3.client("ec2")

def scan_ec2():
    return {
        "security_groups": _scan_security_groups(),
        "instances":       _scan_instances(),
        "vpcs":            _scan_vpcs(),
        "ebs":             _scan_ebs(),
    }


# ── SECURITY GROUPS ────────────────────────────────────────────────────────────
def _scan_security_groups():
    results = []

    # FIX #6 — paginate to avoid silent truncation in large accounts
    paginator = ec2.get_paginator("describe_security_groups")
    sgs = [sg for page in paginator.paginate() for sg in page["SecurityGroups"]]

    for sg in sgs:
        open_ssh      = False
        open_rdp      = False
        open_all      = False
        open_all_ipv6 = False

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            protocol  = rule.get("IpProtocol")

            for ip in rule.get("IpRanges", []):
                if ip["CidrIp"] == "0.0.0.0/0":
                    if protocol == "-1":
                        open_all = True
                    if from_port == 22:
                        open_ssh = True
                    if from_port == 3389:
                        open_rdp = True

            for ip in rule.get("Ipv6Ranges", []):
                if ip.get("CidrIpv6") == "::/0":
                    if protocol == "-1":
                        open_all_ipv6 = True
                    if from_port == 22:
                        open_ssh = True
                    if from_port == 3389:
                        open_rdp = True

        results.append({
            "sg_id":         sg["GroupId"],
            "sg_name":       sg["GroupName"],
            "vpc_id":        sg.get("VpcId", ""),
            "open_ssh":      open_ssh,
            "open_rdp":      open_rdp,
            "open_all":      open_all,
            "open_all_ipv6": open_all_ipv6,
            "is_default":    sg["GroupName"] == "default",
        })

    return results


# ── EC2 INSTANCES ──────────────────────────────────────────────────────────────
def _scan_instances():
    results = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    if inst["State"]["Name"] == "terminated":
                        continue

                    instance_id = inst["InstanceId"]

                    # CIS 5.6 — IMDSv2 enforcement
                    metadata_opts   = inst.get("MetadataOptions", {})
                    imdsv2_required = metadata_opts.get("HttpTokens") == "required"

                    public_ip = inst.get("PublicIpAddress")

                    # CIS 2.2.2 — EBS root volume encrypted
                    root_encrypted = True
                    for mapping in inst.get("BlockDeviceMappings", []):
                        vol_id = mapping.get("Ebs", {}).get("VolumeId")
                        if vol_id:
                            try:
                                vol = ec2.describe_volumes(
                                    VolumeIds=[vol_id]
                                )["Volumes"][0]
                                if not vol.get("Encrypted"):
                                    root_encrypted = False
                            except:
                                pass

                    results.append({
                        "instance_id":     instance_id,
                        "state":           inst["State"]["Name"],
                        "public_ip":       public_ip,
                        "imdsv2_required": imdsv2_required,
                        "root_encrypted":  root_encrypted,
                    })
    except Exception as e:
        print(f"Instance scan error: {e}")
    return results


# ── VPCs ───────────────────────────────────────────────────────────────────────
def _scan_vpcs():
    results = []
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            vpc_id     = vpc["VpcId"]
            is_default = vpc.get("IsDefault", False)

            # CIS 3.9 — VPC flow logs
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]
            flow_logs_enabled = len(flow_logs) > 0

            results.append({
                "vpc_id":            vpc_id,
                "is_default":        is_default,
                "flow_logs_enabled": flow_logs_enabled,
                "cidr":              vpc.get("CidrBlock", ""),
            })
    except Exception as e:
        print(f"VPC scan error: {e}")
    return results


# ── EBS SNAPSHOTS ──────────────────────────────────────────────────────────────
def _scan_ebs():
    results = []
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
        for snap in snapshots:
            # CIS 2.2.1 — public snapshots
            perms = ec2.describe_snapshot_attribute(
                SnapshotId=snap["SnapshotId"],
                Attribute="createVolumePermission"
            )["CreateVolumePermissions"]
            is_public = any(p.get("Group") == "all" for p in perms)

            # FIX #4 — always append; track encryption too
            results.append({
                "snapshot_id": snap["SnapshotId"],
                "is_public":   is_public,
                "encrypted":   snap.get("Encrypted", False),
            })
    except Exception as e:
        print(f"EBS snapshot scan error: {e}")
    return results
