import boto3

ec2 = boto3.client("ec2")

def scan_security_groups():
    results = []

    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        sg_info = {
            "group_id": sg["GroupId"],
            "group_name": sg["GroupName"],
            "open_ssh": False,
            "open_all": False
        }

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")

                if cidr == "0.0.0.0/0":
                    if from_port == 22:
                        sg_info["open_ssh"] = True
                    if from_port == 0 and to_port == 65535:
                        sg_info["open_all"] = True

        results.append(sg_info)

    return results
