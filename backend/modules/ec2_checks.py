def check_open_security_groups(session, scan_meta_data):
    print("check_open_security_groups")
    ec2 = session.client("ec2")
    all_sgs = ec2.describe_security_groups()["SecurityGroups"]
    open_sgs = []
    open_sg_attached_to_ec2 = 0
    open_sg_attached_to_rds = 0

    # Get EC2 and RDS associations
    ec2_instances = ec2.describe_instances()
    sg_to_ec2 = {}
    for reservation in ec2_instances["Reservations"]:
        for instance in reservation["Instances"]:
            for sg in instance.get("SecurityGroups", []):
                sg_to_ec2.setdefault(sg["GroupId"], []).append(
                    {
                        "instance_id": instance["InstanceId"],
                        "instance_name": next(
                            (
                                tag["Value"]
                                for tag in instance.get("Tags", [])
                                if tag["Key"] == "Name"
                            ),
                            "",
                        ),
                        "region": session.region_name,
                    }
                )

    try:
        rds = session.client("rds")
        db_instances = rds.describe_db_instances()["DBInstances"]
    except Exception:
        db_instances = []

    sg_to_rds = {}
    for db in db_instances:
        for sg in db.get("VpcSecurityGroups", []):
            sg_to_rds.setdefault(sg["VpcSecurityGroupId"], []).append(
                {
                    "db_instance_id": db["DBInstanceIdentifier"],
                    "db_instance_name": db.get("DBName", ""),
                    "region": session.region_name,
                }
            )

    for sg in all_sgs:
        open_ports = []

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")

            if from_port is None:
                continue  # skip non-port-based rules

            # Normalize port range
            port_range = (
                range(from_port, to_port + 1) if to_port is not None else [from_port]
            )

            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    # Skip if only 80 or 443 are open
                    if all(p in [80, 443] for p in port_range):
                        continue
                    # open_ports.extend([p for p in port_range if p not in [80, 443]])
                    # if any(p not in [80, 443] for p in port_range):
                    if from_port == to_port:
                        open_ports.append(f"{from_port}")
                    else:
                        open_ports.append(f"{from_port}-{to_port}")

        if open_ports:
            group_id = sg.get("GroupId")
            if sg_to_ec2.get(group_id):
                open_sg_attached_to_ec2 += 1
            if sg_to_rds.get(group_id):
                open_sg_attached_to_rds += 1

            open_sgs.append(
                {
                    "resource_name": sg.get("GroupName"),
                    "group_id": group_id,
                    # "arn": f"arn:aws:ec2:{session.region_name}::security-group/{group_id}",
                    "description": sg.get("Description"),
                    "vpc_id": sg.get("VpcId"),
                    # "region": session.region_name,
                    "open_ports": sorted(set(open_ports)),
                    "attached_ec2": sg_to_ec2.get(group_id, [{}]),
                    "attached_rds": sg_to_rds.get(group_id, [{}]),
                }
            )
    scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(all_sgs)
    scan_meta_data["affected"] = scan_meta_data["affected"] + len(open_sgs)
    scan_meta_data["High"] = scan_meta_data["High"] + len(open_sgs)
    scan_meta_data["services_scanned"].append("Security Group")

    return {
        "check_name": "Open Security Groups",
        "service": "EC2",
        "problem_statement": "Security groups with inbound access open to the entire internet (0.0.0.0/0).",
        "severity_score": 90,
        "severity_level": "High",
        "resources_affected": open_sgs,
        "recommendation": "Restrict access to known IP ranges only.",
        "additional_info": {
            "total_scanned": len(all_sgs),
            "affected": len(open_sgs),
            "Number of Security Group attached to EC2": open_sg_attached_to_ec2,
            "Number of Security Group attached to RDS": open_sg_attached_to_rds,
        },
    }


def find_unused_security_groups(session, scan_meta_data):
    print("find_unused_security_groups")
    ec2 = session.client("ec2")
    all_sgs = {
        sg["GroupId"]: sg for sg in ec2.describe_security_groups()["SecurityGroups"]
    }
    used_sgs = set()

    for eni in ec2.describe_network_interfaces()["NetworkInterfaces"]:
        for sg in eni["Groups"]:
            used_sgs.add(sg["GroupId"])

    unused_sgs_ids = set(all_sgs.keys()) - used_sgs
    unused_sgs = []

    for sg_id in unused_sgs_ids:
        sg = all_sgs[sg_id]
        unused_sgs.append(
            {
                "resource_name": sg.get("GroupName"),
                "group_id": sg.get("GroupId"),
                # "arn": f"arn:aws:ec2:{session.region_name}::security-group/{sg.get('GroupId')}",
                "description": sg.get("Description"),
                "vpc_id": sg.get("VpcId"),
                # "region": session.region_name,
            }
        )
    scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(all_sgs)
    scan_meta_data["affected"] = scan_meta_data["affected"] + len(unused_sgs)
    scan_meta_data["Low"] = scan_meta_data["Low"] + len(unused_sgs)

    return {
        "check_name": "Unused Security Groups",
        "service": "EC2",
        "problem_statement": "Security groups not attached to any network interfaces.",
        "severity_score": 30,
        "severity_level": "Low",
        "resources_affected": unused_sgs,
        "recommendation": "Review and delete unused security groups.",
        "additional_info": {
            "total_scanned": len(all_sgs),
            "affected": len(unused_sgs),
        },
    }


def ec2_with_public_ips(session, scan_meta_data):
    print("ec2_with_public_ips")
    ec2 = session.client("ec2")
    instances = ec2.describe_instances()
    public_instances = []

    for res in instances["Reservations"]:
        for inst in res["Instances"]:
            if inst.get("PublicIpAddress"):
                public_instances.append(
                    {
                        "resource_name": inst.get("InstanceId"),
                        "instance_type": inst.get("InstanceType"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "launch_time": str(inst.get("LaunchTime")),
                        # "region": session.region_name,
                        # "arn": f"arn:aws:ec2:{session.region_name}::{inst.get('InstanceId')}",
                    }
                )
    scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(instances)
    scan_meta_data["affected"] = scan_meta_data["affected"] + len(public_instances)
    scan_meta_data["Medium"] = scan_meta_data["Medium"] + len(public_instances)
    scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "EC2 Instances with Public IPs",
        "service": "EC2",
        "problem_statement": "EC2 instances are publicly accessible.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": public_instances,
        "recommendation": "Review necessity of public IPs and use bastion hosts or VPNs.",
        "additional_info": {
            "total_scanned": len(instances),
            "affected": len(public_instances),
        },
    }


def unencrypted_ebs_volumes(session, scan_meta_data):
    print("unencrypted_ebs_volumes")

    ec2 = session.client("ec2")

    volumes = ec2.describe_volumes()["Volumes"]

    # ---- Build instance_id -> instance_name map ----
    instances = ec2.describe_instances()
    instance_name_map = {}

    for reservation in instances["Reservations"]:
        for instance in reservation["Instances"]:
            name = None
            for tag in instance.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
                    break
            instance_name_map[instance["InstanceId"]] = name

    unencrypted = []

    for vol in volumes:
        if not vol["Encrypted"]:
            attached_instances = []

            for attachment in vol.get("Attachments", []):
                instance_id = attachment.get("InstanceId")
                attached_instances.append(
                    {
                        "instance_id": instance_id,
                        "instance_name": instance_name_map.get(instance_id),
                    }
                )

            unencrypted.append(
                {
                    "resource_name": vol.get("VolumeId"),
                    "size": vol.get("Size"),
                    "state": vol.get("State"),
                    "az": vol.get("AvailabilityZone"),
                    "create_time": str(vol.get("CreateTime")),
                    "attached_ec2s": attached_instances,
                }
            )

    scan_meta_data["total_scanned"] += len(volumes)
    scan_meta_data["affected"] += len(unencrypted)
    scan_meta_data["Medium"] += len(unencrypted)
    scan_meta_data["services_scanned"].append("EBS")

    return {
        "check_name": "Unencrypted EBS Volumes",
        "service": "EC2",
        "problem_statement": "EBS volumes are not encrypted at rest.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": unencrypted,
        "recommendation": "Enable encryption by default and migrate data to encrypted volumes.",
        "additional_info": {
            "total_scanned": len(volumes),
            "affected": len(unencrypted),
        },
    }


# def unencrypted_ebs_volumes(session, scan_meta_data):
#     print("unencrypted_ebs_volumes")
#     ec2 = session.client("ec2")
#     volumes = ec2.describe_volumes()["Volumes"]
#     unencrypted = []

#     for vol in volumes:
#         if not vol["Encrypted"]:
#             unencrypted.append(
#                 {
#                     "resource_name": vol.get("VolumeId"),
#                     "size": vol.get("Size"),
#                     "state": vol.get("State"),
#                     "az": vol.get("AvailabilityZone"),
#                     "create_time": str(vol.get("CreateTime")),
#                     # "region": session.region_name,
#                     # "arn": f"arn:aws:ec2:{session.region_name}::volume/{vol.get('VolumeId')}",
#                 }
#             )

#     scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(volumes)
#     scan_meta_data["affected"] = scan_meta_data["affected"] + len(unencrypted)
#     scan_meta_data["Medium"] = scan_meta_data["Medium"] + len(unencrypted)
#     scan_meta_data["services_scanned"].append("EBS")

#     return {
#         "check_name": "Unencrypted EBS Volumes",
#         "service": "EC2",
#         "problem_statement": "EBS volumes are not encrypted at rest.",
#         "severity_score": 60,
#         "severity_level": "Medium",
#         "resources_affected": unencrypted,
#         "recommendation": "Enable encryption by default and migrate data to encrypted volumes.",
#         "additional_info": {
#             "total_scanned": len(volumes),
#             "affected": len(unencrypted),
#         },
#     }


def check_ec2_termination_protection(session, scan_meta_data):
    print("check_ec2_termination_protection")
    ec2 = session.client("ec2")
    resources = []

    try:
        reservations = ec2.describe_instances()["Reservations"]
    except Exception as e:
        print(f"Error describing EC2 instances: {e}")
        reservations = []

    instances = []
    for reservation in reservations:
        for instance in reservation["Instances"]:
            instances.append(instance)

    for instance in instances:
        instance_id = instance.get("InstanceId")
        try:
            attr = ec2.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute="disableApiTermination"
            )
            protection_enabled = attr["DisableApiTermination"]["Value"]
            if not protection_enabled:
                resources.append(
                    {
                        "resource_name": instance_id,
                        "instance_type": instance.get("InstanceType"),
                        "state": instance.get("State", {}).get("Name"),
                        "launch_time": str(instance.get("LaunchTime")),
                        # "region": session.region_name,
                        # "arn": f"arn:aws:ec2:{session.region_name}:{account_id}:instance/{instance_id}",
                    }
                )
        except Exception as e:
            print(f"Error checking termination protection for {instance_id}: {e}")

    scan_meta_data["total_scanned"] += len(instances)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "EC2 Termination Protection",
        "service": "EC2",
        "problem_statement": "EC2 instances without termination protection can be accidentally terminated.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable termination protection on critical EC2 instances to prevent accidental deletion.",
        "additional_info": {
            "total_scanned": len(instances),
            "affected": len(resources),
        },
    }
