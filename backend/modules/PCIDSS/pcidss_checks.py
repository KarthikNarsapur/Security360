from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


# ─────────────────────────────────────────────────────────────────────────────
# PCI-DSS v4.0 Checks
#
# Mandatory for any company storing, processing, or transmitting
# credit/debit card (Visa, Mastercard, Amex, Rupay) data.
#
# 12 Requirements → grouped as:
#   Req 1-2  → Network Security Controls
#   Req 3-4  → Protect Account Data
#   Req 5-6  → Vulnerability Management
#   Req 7-8  → Access Control
#   Req 9    → Physical Security (N/A for cloud)
#   Req 10   → Logging & Monitoring
#   Req 11   → Security Testing
#   Req 12   → Security Policies
# ─────────────────────────────────────────────────────────────────────────────


def pcidss_default_sg_allows_traffic(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 1.3.2 - Network Access Controls
    Default security groups must not allow any inbound or outbound traffic.
    Cardholder Data Environment (CDE) must be network-segmented.
    """
    print("pcidss_default_sg_allows_traffic")
    ec2 = session.client("ec2")
    non_compliant = []

    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            try:
                sgs = ec2.describe_security_groups(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "group-name", "Values": ["default"]},
                    ]
                ).get("SecurityGroups", [])

                for sg in sgs:
                    inbound = sg.get("IpPermissions", [])
                    outbound = sg.get("IpPermissionsEgress", [])
                    if inbound or outbound:
                        non_compliant.append(
                            {
                                "resource_name": sg["GroupId"],
                                "vpc_id": vpc_id,
                                "inbound_rules": len(inbound),
                                "outbound_rules": len(outbound),
                                "note": "Default SG has active rules — violates PCI-DSS network segmentation",
                            }
                        )
            except Exception as e:
                print(f"Error checking default SG for VPC {vpc_id}: {e}")
                continue

    except Exception as e:
        print(f"Error listing VPCs: {e}")

    total = len(vpcs) if "vpcs" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "VPC" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "PCI-DSS - Default Security Group Has Active Rules",
        "service": "VPC",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-1.3.2",
        "problem_statement": "Default security groups with active rules break network segmentation. The CDE must be isolated — default SGs must have zero inbound and outbound rules.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Remove all inbound and outbound rules from default security groups in every VPC. Create dedicated security groups per workload with least-privilege rules.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_ssh_rdp_open_to_internet(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 1.3.4 - Inbound Traffic Restriction
    SSH (22) and RDP (3389) must never be open to 0.0.0.0/0.
    These ports provide direct system access and must be restricted.
    """
    print("pcidss_ssh_rdp_open_to_internet")
    ec2 = session.client("ec2")
    non_compliant = []
    RESTRICTED_PORTS = {22, 3389}

    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            open_ports = []
            try:
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)

                    is_open_cidr = any(
                        r.get("CidrIp") in ("0.0.0.0/0", "::/0")
                        for r in rule.get("IpRanges", []) + rule.get("Ipv6Ranges", [])
                    )

                    if is_open_cidr:
                        for port in RESTRICTED_PORTS:
                            if from_port <= port <= to_port:
                                open_ports.append(port)

                if open_ports:
                    non_compliant.append(
                        {
                            "resource_name": sg["GroupId"],
                            "group_name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "open_ports": open_ports,
                            "note": "SSH/RDP open to internet — direct system access exposed",
                        }
                    )
            except Exception as e:
                print(f"Error checking SG {sg.get('GroupId')}: {e}")
                continue

    except Exception as e:
        print(f"Error listing security groups: {e}")

    total = len(sgs) if "sgs" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "PCI-DSS - SSH/RDP Open to Internet",
        "service": "EC2",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-1.3.4",
        "problem_statement": "Security groups allowing SSH (22) or RDP (3389) from 0.0.0.0/0 expose systems in the CDE to unauthorized remote access.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Remove 0.0.0.0/0 rules for port 22 and 3389. Use bastion hosts, AWS Systems Manager Session Manager, or VPN for all administrative access.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_s3_buckets_not_encrypted(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 3.5.1 - Protection of Stored Account Data
    All cardholder data at rest must be encrypted using strong cryptography.
    S3 buckets without server-side encryption may store CHD unprotected.
    """
    print("pcidss_s3_buckets_not_encrypted")
    s3 = session.client("s3")
    non_compliant = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except Exception as e:
                if (
                    hasattr(e, "response")
                    and e.response.get("Error", {}).get("Code")
                    == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    non_compliant.append(
                        {
                            "resource_name": bucket_name,
                            "creation_date": str(bucket.get("CreationDate")),
                            "note": "S3 bucket has no server-side encryption — CHD at risk if stored here",
                        }
                    )
                else:
                    print(f"Error checking encryption for {bucket_name}: {e}")
                continue

    except Exception as e:
        print(f"Error listing buckets: {e}")

    total = len(buckets) if "buckets" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "S3" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("S3")

    return {
        "check_name": "PCI-DSS - S3 Buckets Without Encryption",
        "service": "S3",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-3.5.1",
        "problem_statement": "S3 buckets without server-side encryption may expose cardholder data (CHD) at rest. PCI-DSS requires strong cryptography for all stored account data.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable SSE-S3 or SSE-KMS on all S3 buckets. Prefer SSE-KMS with customer-managed keys for CHD buckets. Enable S3 Block Public Access on all buckets.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_rds_not_encrypted(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 3.5.1 - Protection of Stored Account Data
    Databases storing cardholder data must be encrypted at rest.
    """
    print("pcidss_rds_not_encrypted")
    rds = session.client("rds")
    non_compliant = []

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        for db in instances:
            try:
                if not db.get("StorageEncrypted", False):
                    non_compliant.append(
                        {
                            "resource_name": db["DBInstanceIdentifier"],
                            "engine": db.get("Engine"),
                            "availability_zone": db.get("AvailabilityZone"),
                            "note": "RDS not encrypted — cardholder data unprotected at rest",
                        }
                    )
            except Exception as e:
                print(f"Error checking RDS {db.get('DBInstanceIdentifier')}: {e}")
                continue

    except Exception as e:
        print(f"Error listing RDS instances: {e}")

    total = len(instances) if "instances" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "PCI-DSS - Unencrypted RDS Instances",
        "service": "RDS",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-3.5.1",
        "problem_statement": "Unencrypted RDS instances storing cardholder data violate PCI-DSS Req 3 — all CHD must be protected using strong cryptography.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable encryption on all RDS instances. Existing unencrypted instances must be snapshotted and restored as an encrypted instance. Use AWS KMS CMK for key management.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_ssl_tls_on_load_balancers(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 4.2.1 - Strong Cryptography in Transit
    All transmission of CHD over open/public networks must use strong
    cryptography. Load balancers must not allow insecure HTTP or old TLS.
    """
    print("pcidss_ssl_tls_on_load_balancers")
    elbv2 = session.client("elbv2")
    non_compliant = []

    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb["LoadBalancerName"]
            try:
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get(
                    "Listeners", []
                )
                for listener in listeners:
                    port = listener.get("Port")
                    protocol = listener.get("Protocol", "")
                    ssl_pol = listener.get("SslPolicy", "")

                    # HTTP listener on internet-facing LB = plaintext CHD in transit
                    if protocol == "HTTP" and lb.get("Scheme") == "internet-facing":
                        non_compliant.append(
                            {
                                "resource_name": lb_name,
                                "listener_port": port,
                                "protocol": protocol,
                                "note": "HTTP listener on internet-facing LB — CHD transmitted in plaintext",
                            }
                        )

                    # Old/weak TLS policies
                    if ssl_pol and any(
                        weak in ssl_pol
                        for weak in ["TLS-1-0", "TLS-1-1", "2014", "2015", "2016"]
                    ):
                        non_compliant.append(
                            {
                                "resource_name": lb_name,
                                "listener_port": port,
                                "ssl_policy": ssl_pol,
                                "note": f"Weak TLS policy {ssl_pol} — TLS 1.2+ required by PCI-DSS v4.0",
                            }
                        )
            except Exception as e:
                print(f"Error checking listeners for LB {lb_name}: {e}")
                continue

    except Exception as e:
        print(f"Error listing load balancers: {e}")

    total = len(lbs) if "lbs" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "ELB" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ELB")

    return {
        "check_name": "PCI-DSS - Insecure Protocol on Load Balancers",
        "service": "ELB",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-4.2.1",
        "problem_statement": "Load balancers using HTTP or outdated TLS policies transmit cardholder data without strong encryption, violating PCI-DSS Req 4.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Redirect all HTTP to HTTPS. Set TLS policy to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer. Never use TLS 1.0 or 1.1 in the CDE.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_mfa_not_on_all_users(session, scan_meta_data, users, iam):
    """
    PCI-DSS v4.0 Req 8.4.2 - MFA for All Access into CDE
    PCI-DSS v4.0 expanded MFA requirement — now mandatory for ALL users
    accessing the CDE, not just administrators (upgraded from v3.2.1).
    """
    print("pcidss_mfa_not_on_all_users")
    non_compliant = []

    for user in users:
        user_name = user["UserName"]
        try:
            try:
                iam.get_login_profile(UserName=user_name)
                has_console = True
            except iam.exceptions.NoSuchEntityException:
                has_console = False

            if has_console:
                mfa_devices = iam.list_mfa_devices(UserName=user_name).get(
                    "MFADevices", []
                )
                if not mfa_devices:
                    non_compliant.append(
                        {
                            "resource_name": user_name,
                            "user_id": user.get("UserId"),
                            "password_last_used": str(
                                user.get("PasswordLastUsed", "Never")
                            ),
                            "note": "Console user without MFA — violates PCI-DSS v4.0 Req 8.4.2",
                        }
                    )
        except Exception as e:
            print(f"Error checking MFA for {user_name}: {e}")
            continue

    scan_meta_data["total_scanned"] += len(users)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "IAM" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("IAM")

    return {
        "check_name": "PCI-DSS - MFA Not Enabled for All IAM Users",
        "service": "IAM",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-8.4.2",
        "problem_statement": "PCI-DSS v4.0 mandates MFA for all accounts accessing the CDE. This is a strengthened requirement from v3.2.1 which only required MFA for admins.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable MFA for all IAM users with console access. Enforce via IAM policy condition 'aws:MultiFactorAuthPresent': 'true'. Consider hardware MFA for privileged accounts.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(non_compliant),
        },
    }


def pcidss_password_policy_weak(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 8.3.6 - Password Complexity
    Passwords must be min 12 chars (increased from 7 in v3.2.1),
    with complexity and 90-day rotation.
    """
    print("pcidss_password_policy_weak")
    iam = session.client("iam")
    non_compliant = []

    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        issues = []

        if policy.get("MinimumPasswordLength", 0) < 12:
            issues.append(
                f"Min length is {policy.get('MinimumPasswordLength')} — PCI-DSS v4.0 requires 12+"
            )
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("Uppercase not required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("Lowercase not required")
        if not policy.get("RequireNumbers"):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols"):
            issues.append("Symbols not required")
        if policy.get("MaxPasswordAge", 999) > 90:
            issues.append(
                f"Expiry is {policy.get('MaxPasswordAge')} days — must be 90 or less"
            )
        if policy.get("PasswordReusePrevention", 0) < 4:
            issues.append(
                f"Only {policy.get('PasswordReusePrevention')} passwords remembered — must be 4+"
            )

        if issues:
            non_compliant.append(
                {
                    "resource_name": "Account Password Policy",
                    "issues": issues,
                    "current_min_length": policy.get("MinimumPasswordLength"),
                }
            )

    except iam.exceptions.NoSuchEntityException:
        non_compliant.append(
            {
                "resource_name": "Account Password Policy",
                "issues": [
                    "No password policy configured — AWS defaults do not meet PCI-DSS requirements"
                ],
            }
        )
    except Exception as e:
        print(f"Error checking password policy: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "IAM" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("IAM")

    return {
        "check_name": "PCI-DSS - Weak IAM Password Policy",
        "service": "IAM",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-8.3.6",
        "problem_statement": "PCI-DSS v4.0 raised minimum password length to 12 characters and requires complexity. Weak password policy increases credential compromise risk in the CDE.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Set min length to 12, require uppercase/lowercase/numbers/symbols, 90-day expiry, remember last 4 passwords. Consider passphrase policy (15+ chars) as an alternative.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def pcidss_cloudtrail_disabled(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 10.2 / 10.3 - Audit Log Implementation
    All access to system components and CHD must be logged.
    Logs must be protected from modification and retained for 12 months
    (3 months immediately available, 9 months archived).
    """
    print("pcidss_cloudtrail_disabled")
    ct = session.client("cloudtrail")
    non_compliant = []

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            non_compliant.append(
                {
                    "resource_name": "CloudTrail",
                    "note": "No CloudTrail configured — zero audit logging of CDE access",
                }
            )
        else:
            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    issues = []

                    if not status.get("IsLogging"):
                        issues.append("Logging disabled")
                    if not trail.get("IsMultiRegionTrail"):
                        issues.append(
                            "Not multi-region — cross-region activity unlogged"
                        )
                    if not trail.get("LogFileValidationEnabled"):
                        issues.append("Log validation disabled — logs can be tampered")
                    if not trail.get("IncludeGlobalServiceEvents"):
                        issues.append("Global events (IAM/STS) not captured")

                    if issues:
                        non_compliant.append(
                            {
                                "resource_name": trail["Name"],
                                "s3_bucket": trail.get("S3BucketName"),
                                "issues": issues,
                            }
                        )
                except Exception as e:
                    print(f"Error checking trail {trail.get('Name')}: {e}")
                    continue

    except Exception as e:
        print(f"Error listing trails: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "CloudTrail" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudTrail")

    return {
        "check_name": "PCI-DSS - CloudTrail Audit Logging Incomplete",
        "service": "CloudTrail",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-10.2",
        "problem_statement": "Incomplete CloudTrail configuration leaves CDE access unaudited. PCI-DSS Req 10 mandates tamper-proof logs retained for 12 months.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable multi-region CloudTrail with log file validation. Store logs in a dedicated S3 bucket with MFA delete, versioning, and lifecycle policy for 12-month retention.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def pcidss_guardduty_disabled(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 10.7 / 11.5 - Detect & Alert on Failures
    PCI-DSS v4.0 requires continuous monitoring and alerting on
    security control failures. GuardDuty provides this for AWS.
    """
    print("pcidss_guardduty_disabled")
    gd = session.client("guardduty")
    non_compliant = []

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            non_compliant.append(
                {
                    "resource_name": "GuardDuty",
                    "region": session.region_name,
                    "note": "GuardDuty not enabled — no automated threat detection",
                }
            )
        else:
            for detector_id in detectors:
                try:
                    detector = gd.get_detector(DetectorId=detector_id)
                    if detector.get("Status") != "ENABLED":
                        non_compliant.append(
                            {
                                "resource_name": detector_id,
                                "status": detector.get("Status"),
                                "note": "GuardDuty detector is disabled",
                            }
                        )
                except Exception as e:
                    print(f"Error checking detector {detector_id}: {e}")
                    continue

    except Exception as e:
        print(f"Error checking GuardDuty: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "GuardDuty" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("GuardDuty")

    return {
        "check_name": "PCI-DSS - GuardDuty Not Enabled",
        "service": "GuardDuty",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-11.5",
        "problem_statement": "GuardDuty is not enabled. PCI-DSS v4.0 Req 11.5 requires change-detection mechanisms to alert on unauthorized modification of critical files and systems.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable GuardDuty in all regions. Configure SNS alerts for High/Critical findings. Integrate with your SIEM for continuous monitoring as required by PCI-DSS Req 10.7.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def pcidss_ebs_snapshots_public(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 3.3 - Sensitive Data Not Retained Beyond Need
    Public EBS snapshots may expose cardholder data to any AWS account.
    This is one of the most common CHD exposure vectors in AWS.
    """
    print("pcidss_ebs_snapshots_public")
    ec2 = session.client("ec2")
    non_compliant = []

    try:
        account_id = ec2._endpoint.host  # fallback
        try:
            sts = session.client("sts")
            account_id = sts.get_caller_identity()["Account"]
        except Exception:
            pass

        snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        for snap in snapshots:
            try:
                perms = ec2.describe_snapshot_attribute(
                    SnapshotId=snap["SnapshotId"],
                    Attribute="createVolumePermission",
                ).get("CreateVolumePermissions", [])

                if any(p.get("Group") == "all" for p in perms):
                    non_compliant.append(
                        {
                            "resource_name": snap["SnapshotId"],
                            "volume_id": snap.get("VolumeId"),
                            "size_gb": snap.get("VolumeSize"),
                            "start_time": str(snap.get("StartTime")),
                            "note": "EBS snapshot is public — any AWS account can access this data",
                        }
                    )
            except Exception as e:
                print(f"Error checking snapshot {snap.get('SnapshotId')}: {e}")
                continue

    except Exception as e:
        print(f"Error listing snapshots: {e}")

    total = len(snapshots) if "snapshots" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "PCI-DSS - Public EBS Snapshots",
        "service": "EC2",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-3.3",
        "problem_statement": "Public EBS snapshots expose disk images — potentially containing cardholder data — to any AWS account globally. This violates PCI-DSS Req 3 data protection requirements.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Make all EBS snapshots private immediately. Use AWS Config rule 'ebs-snapshot-public-restorable-check' to auto-detect future violations. Encrypt all snapshots containing CHD.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_secrets_in_env_variables(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 8.6.2 - No Hard-Coded Credentials
    Credentials must not be hard-coded. Lambda env vars are a common
    place where developers accidentally store secrets/keys in plaintext.
    """
    print("pcidss_secrets_in_env_variables")
    lmb = session.client("lambda")
    non_compliant = []

    SECRET_KEYWORDS = [
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "token",
        "private_key",
        "db_pass",
        "db_pwd",
        "auth_token",
        "connection_string",
    ]

    try:
        paginator = lmb.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        for fn in functions:
            fn_name = fn["FunctionName"]
            try:
                config = lmb.get_function_configuration(FunctionName=fn_name)
                env_vars = config.get("Environment", {}).get("Variables", {})

                risky_keys = [
                    k
                    for k in env_vars.keys()
                    if any(secret in k.lower() for secret in SECRET_KEYWORDS)
                ]

                if risky_keys:
                    non_compliant.append(
                        {
                            "resource_name": fn_name,
                            "runtime": fn.get("Runtime"),
                            "risky_env_keys": risky_keys,
                            "note": "Lambda has env vars that may contain plaintext credentials",
                        }
                    )
            except Exception as e:
                print(f"Error checking Lambda env vars for {fn_name}: {e}")
                continue

    except Exception as e:
        print(f"Error listing Lambda functions: {e}")

    total = len(functions) if "functions" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "Lambda" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Lambda")

    return {
        "check_name": "PCI-DSS - Potential Secrets in Lambda Environment Variables",
        "service": "Lambda",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-8.6.2",
        "problem_statement": "Lambda functions with password/key/token environment variable names may contain hardcoded credentials. PCI-DSS v4.0 explicitly prohibits hardcoded credentials.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Move all credentials to AWS Secrets Manager or SSM Parameter Store (SecureString). Reference secrets at runtime using IAM role permissions — never store in env vars.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def pcidss_vpc_flow_logs_disabled(session, scan_meta_data):
    """
    PCI-DSS v4.0 Req 10.2.1 / 1.3 - Network Traffic Logging & Segmentation Verification
    All inbound and outbound traffic in the CDE must be logged.
    VPC Flow Logs are the primary mechanism for this on AWS.
    """
    print("pcidss_vpc_flow_logs_disabled")
    ec2 = session.client("ec2")
    non_compliant = []

    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            try:
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                ).get("FlowLogs", [])

                active = [fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]
                if not active:
                    non_compliant.append(
                        {
                            "resource_name": vpc_id,
                            "cidr": vpc.get("CidrBlock"),
                            "is_default": vpc.get("IsDefault", False),
                            "note": "No active VPC flow logs — CDE network traffic not logged",
                        }
                    )
            except Exception as e:
                print(f"Error checking flow logs for VPC {vpc_id}: {e}")
                continue

    except Exception as e:
        print(f"Error listing VPCs: {e}")

    total = len(vpcs) if "vpcs" in dir() else 0
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "VPC" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "PCI-DSS - VPC Flow Logs Disabled",
        "service": "VPC",
        "framework": "PCI-DSS v4.0",
        "control_id": "PCI-DSS-10.2.1",
        "problem_statement": "VPCs without flow logs leave CDE network traffic unlogged. PCI-DSS requires all inbound and outbound traffic in the CDE to be captured and retained.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable VPC Flow Logs for ALL VPCs. Send to CloudWatch Logs or S3 with 12-month retention. Set up metric filters and alarms for suspicious traffic patterns.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }
