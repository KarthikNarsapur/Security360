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
        # Skip default security groups — they can't be deleted and are always "unused" in new VPCs
        if sg.get("GroupName") == "default":
            continue
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


def check_overly_permissive_outbound_sg(session, scan_meta_data):
    print("check_overly_permissive_outbound_sg")
    ec2 = session.client("ec2")
    all_sgs = ec2.describe_security_groups()["SecurityGroups"]
    permissive_sgs = []

    for sg in all_sgs:
        # Skip default security groups — they always have allow-all outbound
        if sg.get("GroupName") == "default":
            continue

        for perm in sg.get("IpPermissionsEgress", []):
            ip_protocol = perm.get("IpProtocol", "")

            # Check for allow-all outbound: protocol -1 (all) with 0.0.0.0/0
            if ip_protocol == "-1":
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        permissive_sgs.append({
                            "resource_name": sg.get("GroupName"),
                            "group_id": sg.get("GroupId"),
                            "vpc_id": sg.get("VpcId"),
                            "description": sg.get("Description"),
                            "outbound_rule": "All traffic to 0.0.0.0/0",
                        })
                        break
                else:
                    for ipv6_range in perm.get("Ipv6Ranges", []):
                        if ipv6_range.get("CidrIpv6") == "::/0":
                            permissive_sgs.append({
                                "resource_name": sg.get("GroupName"),
                                "group_id": sg.get("GroupId"),
                                "vpc_id": sg.get("VpcId"),
                                "description": sg.get("Description"),
                                "outbound_rule": "All traffic to ::/0",
                            })
                            break

    scan_meta_data["total_scanned"] += len(all_sgs)
    scan_meta_data["affected"] += len(permissive_sgs)
    scan_meta_data["Low"] += len(permissive_sgs)
    if "Security Group" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Security Group")

    return {
        "check_name": "Overly Permissive Outbound Security Groups",
        "service": "EC2",
        "problem_statement": "Security groups allow all outbound traffic to the internet (0.0.0.0/0), which can enable data exfiltration.",
        "severity_score": 35,
        "severity_level": "Low",
        "resources_affected": permissive_sgs,
        "recommendation": "Restrict outbound rules to only required destinations and ports. Use VPC endpoints for AWS service access.",
        "additional_info": {"total_scanned": len(all_sgs), "affected": len(permissive_sgs)},
    }


def check_ec2_iam_role_attached(session, scan_meta_data):
    print("check_ec2_iam_role_attached")
    ec2 = session.client("ec2")
    reservations = ec2.describe_instances().get("Reservations", [])
    resources_affected = []

    all_instances = []
    for reservation in reservations:
        for instance in reservation["Instances"]:
            # Skip terminated instances
            if instance.get("State", {}).get("Name") == "terminated":
                continue
            all_instances.append(instance)

            iam_profile = instance.get("IamInstanceProfile")
            if not iam_profile:
                instance_name = next(
                    (tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"),
                    "",
                )
                resources_affected.append({
                    "resource_name": instance["InstanceId"],
                    "instance_name": instance_name,
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "launch_time": str(instance.get("LaunchTime")),
                    "issue": "EC2 instance has no IAM instance profile attached.",
                })

    scan_meta_data["total_scanned"] += len(all_instances)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Medium"] += len(resources_affected)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "EC2 Instances Without IAM Role",
        "service": "EC2",
        "problem_statement": "EC2 instances without an IAM instance profile may rely on hardcoded access keys for AWS API access.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Attach an IAM instance profile with least-privilege permissions to all EC2 instances instead of using access keys.",
        "additional_info": {"total_scanned": len(all_instances), "affected": len(resources_affected)},
    }


def check_ec2_userdata_secrets(session, scan_meta_data):
    print("check_ec2_userdata_secrets")
    import base64
    import re

    ec2 = session.client("ec2")
    reservations = ec2.describe_instances().get("Reservations", [])
    resources_affected = []

    # Patterns that indicate hardcoded secrets
    secret_patterns = [
        (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "AWS Access Key ID"),
        (re.compile(r"(?:aws_secret_access_key|secret_key|secretkey)\s*[=:]\s*\S+", re.IGNORECASE), "AWS Secret Key reference"),
        (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE), "Password"),
        (re.compile(r"(?:api_key|apikey|api-key)\s*[=:]\s*\S+", re.IGNORECASE), "API Key"),
        (re.compile(r"(?:token|auth_token|access_token)\s*[=:]\s*\S+", re.IGNORECASE), "Token"),
        (re.compile(r"(?:private_key|privatekey)\s*[=:]\s*\S+", re.IGNORECASE), "Private Key reference"),
        (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", re.IGNORECASE), "Private Key block"),
    ]

    all_instances = []
    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance.get("State", {}).get("Name") == "terminated":
                continue
            all_instances.append(instance)

            instance_id = instance["InstanceId"]
            try:
                userdata_response = ec2.describe_instance_attribute(
                    InstanceId=instance_id, Attribute="userData"
                )
                userdata_encoded = userdata_response.get("UserData", {}).get("Value", "")

                if not userdata_encoded:
                    continue

                try:
                    userdata = base64.b64decode(userdata_encoded).decode("utf-8", errors="replace")
                except Exception:
                    continue

                found_secrets = []
                for pattern, label in secret_patterns:
                    if pattern.search(userdata):
                        found_secrets.append(label)

                if found_secrets:
                    instance_name = next(
                        (tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"),
                        "",
                    )
                    resources_affected.append({
                        "resource_name": instance_id,
                        "instance_name": instance_name,
                        "instance_type": instance.get("InstanceType"),
                        "secrets_found": ", ".join(found_secrets),
                        "issue": f"UserData contains potential secrets: {', '.join(found_secrets)}.",
                    })

            except Exception as e:
                print(f"Error checking UserData for {instance_id}: {e}")
                continue

    scan_meta_data["total_scanned"] += len(all_instances)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["High"] += len(resources_affected)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "Hardcoded Secrets in EC2 User Data",
        "service": "EC2",
        "problem_statement": "EC2 instance User Data contains hardcoded secrets such as access keys, passwords, or private keys.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "recommendation": "Remove secrets from User Data. Use IAM roles, AWS Secrets Manager, or SSM Parameter Store instead.",
        "additional_info": {"total_scanned": len(all_instances), "affected": len(resources_affected)},
    }


def check_efs_access_points(session, scan_meta_data):
    print("check_efs_access_points")
    efs = session.client("efs")
    file_systems = efs.describe_file_systems().get("FileSystems", [])
    resources = []

    for fs in file_systems:
        fs_id = fs["FileSystemId"]
        access_points = efs.describe_access_points(FileSystemId=fs_id).get("AccessPoints", [])
        if not access_points:
            resources.append({
                "resource_name": fs_id,
                "name": fs.get("Name", "Unnamed"),
                "lifecycle_state": fs.get("LifeCycleState"),
                "issue": "No access points configured.",
            })

    scan_meta_data["total_scanned"] += len(file_systems)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "EFS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EFS")

    return {
        "check_name": "EFS Access Points",
        "service": "EFS",
        "problem_statement": "EFS file systems have no access points configured, lacking fine-grained access control.",
        "severity_score": 35,
        "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Create EFS access points to enforce user identity, root directory, and POSIX permissions for applications.",
        "additional_info": {"total_scanned": len(file_systems), "affected": len(resources)},
    }


def check_efs_security_groups(session, scan_meta_data):
    print("check_efs_security_groups")
    efs = session.client("efs")
    ec2 = session.client("ec2")
    file_systems = efs.describe_file_systems().get("FileSystems", [])
    resources = []

    for fs in file_systems:
        fs_id = fs["FileSystemId"]
        mount_targets = efs.describe_mount_targets(FileSystemId=fs_id).get("MountTargets", [])

        for mt in mount_targets:
            mt_id = mt["MountTargetId"]
            sg_ids = efs.describe_mount_target_security_groups(MountTargetId=mt_id).get("SecurityGroups", [])
            if not sg_ids:
                continue
            try:
                sgs = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
            except Exception:
                continue

            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            resources.append({
                                "resource_name": fs_id,
                                "name": fs.get("Name", "Unnamed"),
                                "mount_target": mt_id,
                                "security_group": sg["GroupId"],
                                "open_port": f"{perm.get('FromPort', 'all')}-{perm.get('ToPort', 'all')}",
                                "issue": f"Mount target SG {sg['GroupId']} allows inbound from 0.0.0.0/0.",
                            })
                            break

    scan_meta_data["total_scanned"] += len(file_systems)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "EFS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EFS")

    return {
        "check_name": "EFS Security Groups Restricted",
        "service": "EFS",
        "problem_statement": "EFS mount targets have security groups allowing inbound traffic from anywhere (0.0.0.0/0).",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Restrict EFS mount target security groups to specific VPC CIDR ranges or application security groups only.",
        "additional_info": {"total_scanned": len(file_systems), "affected": len(resources)},
    }


def check_ec2_imdsv2(session, scan_meta_data):
    print("check_ec2_imdsv2")
    ec2 = session.client("ec2")
    resources = []
    all_inst = []
    for res in ec2.describe_instances().get("Reservations", []):
        for inst in res["Instances"]:
            if inst.get("State", {}).get("Name") == "terminated": continue
            all_inst.append(inst)
            if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
                resources.append({"resource_name": inst["InstanceId"], "instance_name": name, "http_tokens": inst.get("MetadataOptions", {}).get("HttpTokens", "optional"), "issue": "IMDSv2 not enforced."})

    scan_meta_data["total_scanned"] += len(all_inst)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "EC2" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("EC2")
    return {"check_name": "EC2 IMDSv2 Not Enforced", "service": "EC2", "problem_statement": "EC2 instances do not require IMDSv2.", "severity_score": 75, "severity_level": "High", "resources_affected": resources, "recommendation": "Set HttpTokens to 'required' for all instances.", "additional_info": {"total_scanned": len(all_inst), "affected": len(resources)}}


def check_ebs_default_encryption(session, scan_meta_data):
    print("check_ebs_default_encryption")
    ec2 = session.client("ec2")
    resources = []
    enabled = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
    if not enabled:
        resources.append({"resource_name": "EBS Default Encryption", "issue": "Account-level EBS default encryption is not enabled."})

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "EBS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("EBS")
    return {"check_name": "EBS Default Encryption", "service": "EC2", "problem_statement": "EBS default encryption is not enabled at account level.", "severity_score": 60, "severity_level": "Medium", "resources_affected": resources, "recommendation": "Enable EBS encryption by default.", "additional_info": {"total_scanned": 1, "affected": len(resources)}}


def check_public_ebs_snapshots(session, scan_meta_data):
    print("check_public_ebs_snapshots")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources = []
    account_id = sts.get_caller_identity()["Account"]
    snaps = ec2.describe_snapshots(OwnerIds=[account_id]).get("Snapshots", [])
    for snap in snaps:
        try:
            attrs = ec2.describe_snapshot_attribute(SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission")
            if any(p.get("Group") == "all" for p in attrs.get("CreateVolumePermissions", [])):
                resources.append({"resource_name": snap["SnapshotId"], "volume_id": snap.get("VolumeId"), "issue": "Snapshot is publicly shared."})
        except Exception: pass

    scan_meta_data["total_scanned"] += len(snaps)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "EBS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("EBS")
    return {"check_name": "Public EBS Snapshots", "service": "EC2", "problem_statement": "EBS snapshots are publicly shared.", "severity_score": 85, "severity_level": "High", "resources_affected": resources, "recommendation": "Remove public sharing from EBS snapshots.", "additional_info": {"total_scanned": len(snaps), "affected": len(resources)}}


def check_stopped_instances(session, scan_meta_data):
    print("check_stopped_instances")
    ec2 = session.client("ec2")
    resources = []
    for res in ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]).get("Reservations", []):
        for inst in res["Instances"]:
            reason = inst.get("StateTransitionReason", "")
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
            resources.append({"resource_name": inst["InstanceId"], "instance_name": name, "instance_type": inst.get("InstanceType"), "stopped_reason": reason, "issue": "Instance is in stopped state."})

    scan_meta_data["total_scanned"] += len(resources)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "EC2" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("EC2")
    return {"check_name": "Stopped EC2 Instances", "service": "EC2", "problem_statement": "EC2 instances are in stopped state, wasting resources.", "severity_score": 20, "severity_level": "Low", "resources_affected": resources, "recommendation": "Terminate or restart stopped instances.", "additional_info": {"total_scanned": len(resources), "affected": len(resources)}}


def check_unattached_ebs_volumes(session, scan_meta_data):
    print("check_unattached_ebs_volumes")
    ec2 = session.client("ec2")
    resources = []
    vols = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}]).get("Volumes", [])
    for vol in vols:
        resources.append({"resource_name": vol["VolumeId"], "size_gb": vol.get("Size"), "volume_type": vol.get("VolumeType"), "create_time": str(vol.get("CreateTime")), "issue": "Volume is not attached to any instance."})

    scan_meta_data["total_scanned"] += len(vols)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "EBS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("EBS")
    return {"check_name": "Unattached EBS Volumes", "service": "EC2", "problem_statement": "EBS volumes are not attached to any instance.", "severity_score": 15, "severity_level": "Low", "resources_affected": resources, "recommendation": "Delete unattached volumes or attach them.", "additional_info": {"total_scanned": len(vols), "affected": len(resources)}}
