import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_vpc_default_sg_traffic(session):
    print("Checking VPC default security group traffic rules")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        response = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )

        securityGroups = response.get("SecurityGroups", [])

        for sg in securityGroups:
            sg_id = sg["GroupId"]
            vpc_id = sg["VpcId"]
            sg_name = sg.get("GroupName", "default")
            sg_desc = sg.get("Description", "")
            owner_id = sg.get("OwnerId", "")
            tags = sg.get("Tags", [])

            has_issues = False
            issues = []

            for perm in sg.get("IpPermissions", []):
                if perm.get("IpRanges"):
                    issues.append("Allows inbound traffic from IP ranges")
                    has_issues = True
                    break

                for user_group_pair in perm.get("UserIdGroupPairs", []):
                    if user_group_pair.get("GroupId") != sg_id:
                        issues.append(
                            f"Allows inbound traffic from another security group {user_group_pair.get('GroupId')}"
                        )
                        has_issues = True
                        break
                if has_issues:
                    break

            if sg.get("IpPermissionsEgress"):
                if len(sg.get("IpPermissionsEgress")) > 0:
                    issues.append("Allows outbound traffic")
                    has_issues = True

            if has_issues:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": sg_id,
                        "resource_name": sg_name,
                        "description": sg_desc,
                        "vpc_id": vpc_id,
                        "owner_id": owner_id,
                        "region": region,
                        "tags": tags,
                        "inbound_rule_count": len(sg.get("IpPermissions", [])),
                        "outbound_rule_count": len(sg.get("IpPermissionsEgress", [])),
                        "issue": ", ".join(issues),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(response.get("SecurityGroups", []))
        print(total_scanned)
        affected = len(resources_affected)
        print(affected)
        return {
            "id": "EC2.2",
            "check_name": "VPC Default Security Group Traffic",
            "problem_statement": "VPC default security groups should not allow inbound or outbound traffic",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "recommendation": "Restrict inbound and outbound rules on the default security group to prevent unintended traffic.",
            "status": "passed" if affected == 0 else "failed",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to VPC service in AWS Console",
                "2. Go to Security Groups",
                "3. Select the default security group",
                "4. Remove all inbound rules except self-referencing rule",
                "5. Remove all outbound rules",
                "6. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking default security groups: {e}")
        return None


def check_vpc_flow_logs_enabled(session):
    # EC2.6
    print("Checking VPC flow logging configuration")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        vpcs = ec2.describe_vpcs().get("Vpcs", [])

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            cidr_blocks = [
                cidr.get("CidrBlock") for cidr in vpc.get("CidrBlockAssociationSet", [])
            ]
            is_default = vpc.get("IsDefault", False)
            tags = vpc.get("Tags", [])

            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            ).get("FlowLogs", [])

            has_reject_logging = False
            for log in flow_logs:
                if log["TrafficType"] == "REJECT" and log["FlowLogStatus"] == "ACTIVE":
                    has_reject_logging = True
                    break

            if not has_reject_logging:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": vpc_id,
                        "cidr_blocks": cidr_blocks,
                        "is_default_vpc": is_default,
                        "tags": tags,
                        "found_flow_logs_count": len(flow_logs),
                        "issue": "VPC flow logging not enabled for REJECT traffic",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(vpcs)
        affected = len(resources_affected)
        return {
            "id": "EC2.6",
            "check_name": "VPC Flow Logging",
            "problem_statement": "VPC flow logging should be enabled in all VPCs for REJECT traffic",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "recommendation": "Enable VPC flow logging for REJECT traffic in all VPCs",
            "status": "passed" if affected == 0 else "failed",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to VPC service in AWS Console",
                "2. Select the VPC",
                "3. Go to Flow Logs tab",
                "4. Click 'Create flow log'",
                "5. Set traffic type to 'Reject'",
                "6. Select destination (CloudWatch Logs/S3)",
                "7. Configure IAM role if needed",
                "8. Click 'Create flow log'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking VPC flow logs: {e}")
        return None


def check_ebs_default_encryption(session):
    # EC2.7
    print("Checking EBS default encryption configuration")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        response = ec2.get_ebs_encryption_by_default()
        encryption_enabled = response.get("EbsEncryptionByDefault", False)

        if not encryption_enabled:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "issue": "EBS default encryption not enabled",
                    "region": region,
                    "encryption_enabled": encryption_enabled,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)
        return {
            "id": "EC2.7",
            "check_name": "EBS Default Encryption",
            "problem_statement": "EBS default encryption should be enabled at account level",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable EBS default encryption for the AWS account",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to EC2 service in AWS Console",
                "2. Go to EC2 Dashboard",
                "3. Under 'Account Attributes', select 'EBS Encryption'",
                "4. Click 'Manage'",
                "5. Enable 'Enable EBS encryption by default'",
                "6. Optionally select default KMS key",
                "7. Click 'Update EBS encryption'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EBS default encryption: {e}")
        return None


def check_ec2_imdsv2_enabled(session):
    # EC2.8
    print("Checking EC2 Instance Metadata Service Version 2 configuration")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        instances = ec2.describe_instances().get("Reservations", [])

        for reservation in instances:
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                metadata_options = instance.get("MetadataOptions", {})

                if metadata_options.get("HttpTokens") != "required":
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": instance_id,
                            "issue": "IMDSv2 not enforced (HttpTokens not set to required)",
                            "region": region,
                            "instance_type": instance.get("InstanceType", "Unknown"),
                            "launch_time": (
                                instance.get("LaunchTime").isoformat()
                                if instance.get("LaunchTime")
                                else "Unknown"
                            ),
                            "metadata_options": metadata_options,
                            "private_ip": instance.get("PrivateIpAddress", "N/A"),
                            "public_ip": instance.get("PublicIpAddress", "N/A"),
                            "availability_zone": instance.get("Placement", {}).get(
                                "AvailabilityZone", "Unknown"
                            ),
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = sum(len(r["Instances"]) for r in instances)
        affected = len(resources_affected)
        return {
            "id": "EC2.8",
            "check_name": "EC2 IMDSv2 Enforcement",
            "problem_statement": "EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "recommendation": "Enforce IMDSv2 for all EC2 instances",
            "status": "passed" if affected == 0 else "failed",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to EC2 service in AWS Console",
                "2. Select the instance",
                "3. Go to 'Actions' > 'Instance settings' > 'Modify instance metadata options'",
                "4. Set 'Metadata version' to 'V2 only (token required)'",
                "5. Optionally set 'Metadata response hop limit'",
                "6. Click 'Save'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EC2 IMDS configuration: {e}")
        return None


def check_network_acl_restricted_ports(session):
    # EC2.21
    print("Checking Network ACLs for unrestricted SSH/RDP access")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []
    total_scanned = 0
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        network_acls = ec2.describe_network_acls().get("NetworkAcls", [])

        for acl in network_acls:
            acl_id = acl["NetworkAclId"]
            is_default = acl["IsDefault"]
            vpc_id = acl.get("VpcId", "Unknown")

            if is_default:
                continue

            total_scanned = total_scanned + 1
            for entry in acl.get("Entries", []):
                if not entry.get("Egress") and entry.get("RuleAction") == "allow":
                    cidr = entry.get("CidrBlock", "")
                    protocol = entry.get("Protocol", "")
                    port_range = entry.get("PortRange", {})

                    from_port = port_range.get("From", 0)
                    to_port = port_range.get("To", 0)

                    if (
                        (cidr == "0.0.0.0/0" or cidr == "::/0")
                        and protocol == "6"
                        and (
                            (from_port <= 22 <= to_port)
                            or (from_port <= 3389 <= to_port)
                        )
                    ):

                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": acl_id,
                                "vpc_id": vpc_id,
                                "issue": f"Allows unrestricted ingress to port range {from_port}-{to_port} from {cidr}",
                                "region": region,
                                "rule_number": entry.get("RuleNumber"),
                                "rule_action": entry.get("RuleAction"),
                                "protocol": protocol,
                                "cidr_block": cidr,
                                "egress": entry.get("Egress"),
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                        break
        affected = len(resources_affected)
        return {
            "id": "EC2.21",
            "check_name": "Network ACL Restricted Ports",
            "problem_statement": "Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or 3389",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "recommendation": "Restrict SSH/RDP access in Network ACLs to specific IP ranges",
            "status": "passed" if affected == 0 else "failed",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to VPC service in AWS Console",
                "2. Go to Network ACLs",
                "3. Select the problematic Network ACL",
                "4. Edit inbound rules",
                "5. Remove or modify rules allowing 0.0.0.0/0 to ports 22/3389",
                "6. Add rules with restricted source IP ranges",
                "7. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Network ACLs: {e}")
        return None


def check_ec2_security_group_restricted_admin_ports(session):
    # EC2.53
    print("Checking EC2 security groups for unrestricted admin ports")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        security_groups = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "N/A")
            vpc_id = sg.get("VpcId", "N/A")
            is_affected = False

            for permission in sg.get("IpPermissions", []):
                if is_affected:
                    break

                ip_protocol = permission.get("IpProtocol", "")
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                if (
                    from_port is None
                    or to_port is None
                    or ip_protocol not in ["tcp", "-1"]
                ):
                    continue

                if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                    for ip_range in permission.get("IpRanges", []):
                        cidr_ip = ip_range.get("CidrIp", "")
                        if cidr_ip == "0.0.0.0/0":
                            is_affected = True
                            resources_affected.append(
                                {
                                    "account_id": account_id,
                                    "resource_id": sg_id,
                                    "resource_name": sg_name,
                                    "vpc_id": vpc_id,
                                    "issue": f"Allows unrestricted ingress to port {from_port}-{to_port} from {cidr_ip}",
                                    "region": region,
                                    "ip_protocol": ip_protocol,
                                    "cidr_ip": cidr_ip,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                            break

        total_scanned = len(security_groups)
        affected = len(resources_affected)
        return {
            "id": "EC2.53",
            "check_name": "EC2 Security Group Admin Port Restrictions",
            "problem_statement": "EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports (22, 3389)",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "recommendation": "Restrict SSH/RDP access in security groups to specific IP ranges",
            "status": "passed" if affected == 0 else "failed",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to EC2 service in AWS Console",
                "2. Go to Security Groups",
                "3. Select the problematic security group",
                "4. Edit inbound rules",
                "5. Remove rules allowing 0.0.0.0/0 to ports 22/3389",
                "6. Add rules with restricted source IP ranges",
                "7. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking security groups: {e}")
        return None


def check_ec2_security_group_ipv6_admin_ports(session):
    # EC2.54
    print("Checking EC2 security groups for IPv6 unrestricted admin ports")

    ec2 = session.client("ec2")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        security_groups = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "N/A")
            vpc_id = sg.get("VpcId", "N/A")
            is_affected = False

            for permission in sg.get("IpPermissions", []):
                if is_affected:
                    break
                ip_protocol = permission.get("IpProtocol", "")
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                if (
                    from_port is None
                    or to_port is None
                    or ip_protocol not in ["tcp", "-1"]
                ):
                    continue

                if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                    for ipv6_range in permission.get("Ipv6Ranges", []):
                        cidr_ipv6 = ipv6_range.get("CidrIpv6", "")
                        if cidr_ipv6 == "::/0":
                            is_affected = True
                            resources_affected.append(
                                {
                                    "account_id": account_id,
                                    "resource_id": sg_id,
                                    "resource_name": sg_name,
                                    "vpc_id": vpc_id,
                                    "issue": f"Allows unrestricted IPv6 ingress to port {from_port}-{to_port} from {cidr_ipv6}",
                                    "region": region,
                                    "ip_protocol": ip_protocol,
                                    "cidr_ipv6": cidr_ipv6,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                            break

        total_scanned = len(security_groups)
        affected = len(resources_affected)
        return {
            "id": "EC2.54",
            "check_name": "EC2 Security Group IPv6 Admin Port Restrictions",
            "problem_statement": "EC2 security groups should not allow ingress from ::/0 to remote server administration ports (22, 3389)",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Restrict SSH/RDP IPv6 access in security groups to specific IP ranges",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to EC2 service in AWS Console",
                "2. Go to Security Groups",
                "3. Select the problematic security group",
                "4. Edit inbound rules",
                "5. Remove rules allowing ::/0 to ports 22/3389",
                "6. Add rules with restricted IPv6 source ranges",
                "7. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking security groups for IPv6 rules: {e}")
        return None
