import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_ebs_snapshot_public(session):
    # [EC2.1]
    print("Checking EBS snapshots for public access")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        snapshots = ec2.describe_snapshots(OwnerIds=[account_id]).get("Snapshots", [])

        for snap in snapshots:
            snap_id = snap["SnapshotId"]
            attrs = ec2.describe_snapshot_attribute(
                SnapshotId=snap_id, Attribute="createVolumePermission"
            )
            permissions = attrs.get("CreateVolumePermissions", [])
            if any("Group" in p and p["Group"] == "all" for p in permissions):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": snap_id,
                        "resource_id_type": "SnapshotId",
                        "issue": "EBS snapshot is publicly shared",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(snapshots)
        affected = len(resources_affected)
        return {
            "id": "EC2.1",
            "check_name": "EBS snapshot public access",
            "problem_statement": "EBS snapshots should not be publicly shared.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Modify snapshot permissions to restrict access to specific accounts only.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open EC2 console → Snapshots.",
                "2. Select the public snapshot.",
                "3. Choose 'Modify permissions'.",
                "4. Remove 'all' and restrict to specific accounts.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EBS snapshot public access: {e}")
        return None


def check_default_security_group_restricts_traffic(session):
    # [EC2.2]
    print("Checking default Security Groups for open traffic")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in sgs:
            if sg["GroupName"] == "default":
                open_ingress = [
                    r for r in sg.get("IpPermissions", []) if r.get("IpRanges")
                ]
                open_egress = [
                    r for r in sg.get("IpPermissionsEgress", []) if r.get("IpRanges")
                ]
                if open_ingress or open_egress:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": sg["GroupId"],
                            "resource_id_type": "SecurityGroupId",
                            "issue": "Default Security Group allows ingress or egress traffic",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(sgs)
        affected = len(resources_affected)
        return {
            "id": "EC2.2",
            "check_name": "Default Security Group restricts all traffic",
            "problem_statement": "Default Security Groups should not allow any inbound or outbound access.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove all rules from default Security Groups.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open EC2 console → Security Groups.",
                "2. Select default group in each VPC.",
                "3. Remove all inbound and outbound rules.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking default Security Group: {e}")
        return None


def check_ebs_volumes_encrypted(session):
    # [EC2.3, EC2.7]
    print("Checking EBS volumes encryption")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        volumes = ec2.describe_volumes().get("Volumes", [])

        for vol in volumes:
            if not vol.get("Encrypted"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": vol["VolumeId"],
                        "resource_id_type": "VolumeId",
                        "issue": "EBS volume not encrypted at rest",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(volumes)
        affected = len(resources_affected)
        return {
            "id": "EC2.3/7",
            "check_name": "EBS volumes encrypted at rest",
            "problem_statement": "All EBS volumes should be encrypted at rest using KMS keys.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable EBS encryption by default or create new encrypted volumes.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable 'EBS encryption by default' in EC2 console.",
                "2. Create encrypted volumes and migrate data if necessary.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EBS encryption: {e}")
        return None


def check_ec2_instances_active(session):
    # [EC2.4]
    print("Checking EC2 active instance status")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = ec2.describe_instances().get("Reservations", [])

        total_instances = sum(len(res.get("Instances", [])) for res in instances)
        inactive = [
            inst["InstanceId"]
            for res in instances
            for inst in res.get("Instances", [])
            if inst["State"]["Name"] not in ["running", "stopped"]
        ]

        for iid in inactive:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": iid,
                    "resource_id_type": "InstanceId",
                    "issue": "Instance not in running/stopped state",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        affected = len(resources_affected)
        return {
            "id": "EC2.4",
            "check_name": "EC2 instances in valid state",
            "problem_statement": "Instances should be either running or stopped to maintain valid states.",
            "severity_score": 20,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Check terminated or pending instances and validate lifecycle policies.",
            "additional_info": {"total_scanned": total_instances, "affected": affected},
            "remediation_steps": [
                "1. Review EC2 instance list.",
                "2. Ensure instances are in appropriate state.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EC2 instance states: {e}")
        return None


def check_asg_imdsv2_enabled(session):
    # [EC2.8]
    print("Checking EC2 Auto Scaling Group IMDSv2 enforcement")

    asg = session.client("autoscaling")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        groups = asg.describe_auto_scaling_groups().get("AutoScalingGroups", [])

        for group in groups:
            metadata_options = group.get("MetadataOptions", {})
            if metadata_options.get("HttpTokens") != "required":
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": group["AutoScalingGroupName"],
                        "resource_id_type": "AutoScalingGroupName",
                        "issue": "IMDSv2 not enforced in Auto Scaling Group launch configuration",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(groups)
        affected = len(resources_affected)
        return {
            "id": "EC2.8",
            "check_name": "IMDSv2 enforced in Auto Scaling Groups",
            "problem_statement": "IMDSv2 should be enforced to prevent metadata service exploitation.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Modify launch templates to require IMDSv2 (HttpTokens=required).",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Update launch template metadata options.",
                "2. Set HttpTokens=required.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IMDSv2 enforcement: {e}")
        return None


def check_ec2_instance_public_ip(session):
    # [EC2.9]
    print("Checking EC2 instances with public IPs")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        reservations = ec2.describe_instances().get("Reservations", [])
        for res in reservations:
            for inst in res.get("Instances", []):
                if inst.get("PublicIpAddress"):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": inst["InstanceId"],
                            "resource_id_type": "InstanceId",
                            "issue": f"Instance has public IP {inst['PublicIpAddress']}",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = sum(len(r["Instances"]) for r in reservations)
        affected = len(resources_affected)
        return {
            "id": "EC2.9",
            "check_name": "EC2 instances with public IPs",
            "problem_statement": "Instances should avoid public IPs unless explicitly required.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Use private subnets or remove public IPs.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Launch instances in private subnets.",
                "2. Remove public IPs from sensitive workloads.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EC2 public IPs: {e}")
        return None


def check_eip_not_in_use(session):
    # [EC2.12]
    print("Checking Elastic IPs not in use")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        eips = ec2.describe_addresses().get("Addresses", [])

        for eip in eips:
            if "InstanceId" not in eip:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": eip.get("PublicIp"),
                        "resource_id_type": "ElasticIP",
                        "issue": "Elastic IP allocated but not in use",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(eips)
        affected = len(resources_affected)
        return {
            "id": "EC2.12",
            "check_name": "Elastic IPs in use",
            "problem_statement": "Unused Elastic IPs should be released to avoid unnecessary costs.",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Release unused Elastic IPs.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open EC2 console → Elastic IPs.",
                "2. Identify unattached IPs.",
                "3. Release them.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking unused Elastic IPs: {e}")
        return None


def check_security_groups_sensitive_ports_open(session):
    # [EC2.13]
    print("Checking Security Groups with sensitive ports open to all")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    sensitive_ports = [22, 3389, 3306, 5432]

    try:
        account_id = sts.get_caller_identity()["Account"]
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                ip_ranges = [ip["CidrIp"] for ip in perm.get("IpRanges", [])]
                if any(ip == "0.0.0.0/0" for ip in ip_ranges):
                    if any(
                        p
                        for p in sensitive_ports
                        if from_port <= p <= (to_port or from_port)
                    ):
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": sg["GroupId"],
                                "resource_id_type": "SecurityGroupId",
                                "issue": f"Sensitive port {from_port}-{to_port} open to all",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )

        total_scanned = len(sgs)
        affected = len(resources_affected)
        return {
            "id": "EC2.13",
            "check_name": "Sensitive ports open to all",
            "problem_statement": "Sensitive ports (22, 3389, etc.) should not be open to the public.",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Restrict sensitive ports to specific IP ranges or VPNs.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Review Security Group rules.",
                "2. Restrict public access to sensitive ports.",
                "3. Use bastion hosts or VPN tunnels.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Security Group open ports: {e}")
        return None


def check_subnet_auto_assign_public_ip(session):
    # [EC2.15]
    print("Checking subnet auto-assign public IP setting")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        subnets = ec2.describe_subnets().get("Subnets", [])

        for subnet in subnets:
            if subnet.get("MapPublicIpOnLaunch"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": subnet["SubnetId"],
                        "resource_id_type": "SubnetId",
                        "issue": "Subnet auto-assigns public IPs on launch",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(subnets)
        affected = len(resources_affected)
        return {
            "id": "EC2.15",
            "check_name": "Subnets auto-assign public IP",
            "problem_statement": "Subnets should not auto-assign public IPs unless explicitly required.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Disable auto-assign public IP in subnet settings.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to VPC console.",
                "2. Select the subnet.",
                "3. Edit subnet settings and disable 'Auto-assign public IPv4'.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking subnet auto-assign public IP: {e}")
        return None
