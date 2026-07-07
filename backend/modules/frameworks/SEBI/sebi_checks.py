from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


# ─────────────────────────────────────────────────────────────────────────────
# SEBI CSCRF 2024 - Checks for Bank / NBFC
#
# Framework: SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 (August 20, 2024)
# Functions: Governance → Identify → Protect → Detect → Respond → Recover
# ─────────────────────────────────────────────────────────────────────────────


def sebi_guardduty_not_enabled(session, scan_meta_data):
    """
    SEBI CSCRF - DE.CM-1 | Detect: Continuous Monitoring
    SEBI mandates all REs establish a SOC with real-time threat detection.
    GuardDuty is the AWS equivalent — its absence means no threat monitoring.
    """
    print("sebi_guardduty_not_enabled")
    gd = session.client("guardduty")
    non_compliant = []

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])

        if not detectors:
            non_compliant.append(
                {
                    "resource_name": "GuardDuty",
                    "region": session.region_name,
                    "note": "GuardDuty not enabled — no threat detection in this region",
                }
            )
        else:
            for detector_id in detectors:
                detector = gd.get_detector(DetectorId=detector_id)
                if detector.get("Status") != "ENABLED":
                    non_compliant.append(
                        {
                            "resource_name": detector_id,
                            "region": session.region_name,
                            "status": detector.get("Status"),
                            "note": "GuardDuty detector exists but is disabled",
                        }
                    )
    except Exception as e:
        print(f"Error checking GuardDuty: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "GuardDuty" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("GuardDuty")

    return {
        "check_name": "SEBI CSCRF - GuardDuty Threat Detection",
        "service": "GuardDuty",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-1",
        "problem_statement": "GuardDuty is not enabled. SEBI mandates continuous threat monitoring via a SOC for all regulated entities.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable GuardDuty in all regions. Integrate findings with your SOC or SIEM for real-time alerting as required by SEBI CSCRF.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def sebi_waf_not_enabled_on_albs(session, scan_meta_data):
    """
    SEBI CSCRF - PR.PT-1 | Protect: Internet-Facing Interface Security
    SEBI requires WAF, DDoS protection on all internet-facing interfaces.
    Checks ALBs (internet-facing load balancers) without WAF attached.
    """
    print("sebi_waf_not_enabled_on_albs")
    elbv2 = session.client("elbv2")
    wafv2 = session.client("wafv2")
    non_compliant = []

    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        internet_facing = [lb for lb in lbs if lb.get("Scheme") == "internet-facing"]

        # Get all WAF associations
        waf_associations = set()
        try:
            web_acls = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
            for acl in web_acls:
                resources = wafv2.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get(
                    "ResourceArns", []
                )
                waf_associations.update(resources)
        except Exception as e:
            print(f"Error fetching WAF ACLs: {e}")

        for lb in internet_facing:
            lb_arn = lb["LoadBalancerArn"]
            if lb_arn not in waf_associations:
                non_compliant.append(
                    {
                        "resource_name": lb["LoadBalancerName"],
                        "arn": lb_arn,
                        "dns_name": lb.get("DNSName"),
                        "note": "Internet-facing ALB has no WAF attached — violates SEBI CSCRF interface security",
                    }
                )

    except Exception as e:
        print(f"Error checking WAF on ALBs: {e}")

    scan_meta_data["total_scanned"] += (
        len(internet_facing) if "internet_facing" in dir() else 0
    )
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "WAF" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("WAF")

    return {
        "check_name": "SEBI CSCRF - WAF on Internet-Facing Load Balancers",
        "service": "WAF",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-PR.PT-1",
        "problem_statement": "Internet-facing ALBs without WAF expose financial applications to web attacks. SEBI mandates WAF and DDoS protection on all internet-facing interfaces.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Attach AWS WAF Web ACL to all internet-facing load balancers. Enable AWS Shield Standard (minimum) or Shield Advanced for DDoS protection.",
        "additional_info": {
            "total_scanned": scan_meta_data.get("total_scanned", 0),
            "affected": len(non_compliant),
        },
    }


def sebi_cloudtrail_not_multiregion(session, scan_meta_data):
    """
    SEBI CSCRF - DE.AE-1 | Detect: Audit & Event Logging
    SEBI requires comprehensive audit trails across all systems.
    CloudTrail must be enabled in all regions with log validation.
    """
    print("sebi_cloudtrail_not_multiregion")
    ct = session.client("cloudtrail")
    non_compliant = []

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            non_compliant.append(
                {
                    "resource_name": "CloudTrail",
                    "note": "No CloudTrail configured — zero audit logging",
                }
            )
        else:
            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    issues = []

                    if not status.get("IsLogging"):
                        issues.append("Logging is disabled")
                    if not trail.get("IsMultiRegionTrail"):
                        issues.append(
                            "Not multi-region — activity in other regions is not logged"
                        )
                    if not trail.get("LogFileValidationEnabled"):
                        issues.append("Log file validation off — logs can be tampered")
                    if not trail.get("IncludeGlobalServiceEvents"):
                        issues.append("Global service events (IAM, STS) not captured")

                    if issues:
                        non_compliant.append(
                            {
                                "resource_name": trail["Name"],
                                "s3_bucket": trail.get("S3BucketName"),
                                "issues": issues,
                            }
                        )
                except Exception as e:
                    print(f"Error getting trail status for {trail.get('Name')}: {e}")
                    continue

    except Exception as e:
        print(f"Error checking CloudTrail: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "CloudTrail" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudTrail")

    return {
        "check_name": "SEBI CSCRF - CloudTrail Multi-Region Audit Logging",
        "service": "CloudTrail",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-1",
        "problem_statement": "CloudTrail is not fully configured. SEBI mandates complete, tamper-proof audit logs across all regions for all regulated entities.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable multi-region CloudTrail with log file validation and global service events. Store logs in a dedicated S3 bucket with MFA delete enabled.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def sebi_mfa_not_enabled_on_iam_users(session, scan_meta_data, users, iam):
    """
    SEBI CSCRF - PR.AA-3 | Protect: Identity & Access Control
    SEBI mandates MFA for all users accessing critical systems.
    Especially mandatory for access from untrusted/external networks.
    """
    print("sebi_mfa_not_enabled_on_iam_users")
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
                            "note": "Console user without MFA — violates SEBI CSCRF identity controls",
                        }
                    )
        except Exception as e:
            print(f"Error checking MFA for {user_name}: {e}")
            continue

    scan_meta_data["total_scanned"] += len(users)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "IAM" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("IAM")

    return {
        "check_name": "SEBI CSCRF - MFA on IAM Console Users",
        "service": "IAM",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-PR.AA-3",
        "problem_statement": "IAM console users without MFA violate SEBI's mandate for multi-factor authentication on all systems accessed by regulated entity staff.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable MFA for all IAM users with console access. Enforce via IAM policy that denies all actions if MFA is not present.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(non_compliant),
        },
    }


def sebi_s3_logging_disabled(session, scan_meta_data):
    """
    SEBI CSCRF - DE.AE-2 | Detect: Data Access Logging
    SEBI requires logging of all access to critical data stores.
    S3 server access logs capture who accessed what data and when.
    """
    print("sebi_s3_logging_disabled")
    s3 = session.client("s3")
    non_compliant = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                if "LoggingEnabled" not in logging_config:
                    non_compliant.append(
                        {
                            "resource_name": bucket_name,
                            "creation_date": str(bucket.get("CreationDate")),
                            "note": "S3 access logging disabled — data access not audited",
                        }
                    )
            except Exception as e:
                print(f"Error checking logging for bucket {bucket_name}: {e}")
                continue

    except Exception as e:
        print(f"Error listing buckets: {e}")

    scan_meta_data["total_scanned"] += len(buckets) if "buckets" in dir() else 0
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "S3" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("S3")

    return {
        "check_name": "SEBI CSCRF - S3 Access Logging Disabled",
        "service": "S3",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-2",
        "problem_statement": "S3 buckets without access logging leave data access unaudited. SEBI requires detailed logging of all access to critical data for audit and incident investigation.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable S3 server access logging on all buckets. Send logs to a dedicated audit bucket. Retain for minimum 2 years per SEBI requirements.",
        "additional_info": {
            "total_scanned": len(non_compliant) + len([]),
            "affected": len(non_compliant),
        },
    }


def sebi_vpc_flow_logs_disabled(session, scan_meta_data):
    """
    SEBI CSCRF - DE.CM-3 | Detect: Network Traffic Monitoring
    SEBI mandates network activity monitoring as part of SOC requirements.
    VPC Flow Logs capture all network traffic for forensics and anomaly detection.
    """
    print("sebi_vpc_flow_logs_disabled")
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

                active_logs = [
                    fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"
                ]

                if not active_logs:
                    non_compliant.append(
                        {
                            "resource_name": vpc_id,
                            "is_default": vpc.get("IsDefault", False),
                            "cidr": vpc.get("CidrBlock"),
                            "note": "VPC has no active flow logs — network traffic not monitored",
                        }
                    )
            except Exception as e:
                print(f"Error checking flow logs for VPC {vpc_id}: {e}")
                continue

    except Exception as e:
        print(f"Error listing VPCs: {e}")

    scan_meta_data["total_scanned"] += len(vpcs) if "vpcs" in dir() else 0
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "VPC" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "SEBI CSCRF - VPC Flow Logs Disabled",
        "service": "VPC",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-3",
        "problem_statement": "VPCs without flow logs cannot detect lateral movement, data exfiltration, or suspicious network activity — violates SEBI CSCRF network monitoring requirements.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable VPC Flow Logs for all VPCs. Send logs to CloudWatch Logs or S3. Set up CloudWatch alarms for suspicious traffic patterns.",
        "additional_info": {
            "total_scanned": len(non_compliant),
            "affected": len(non_compliant),
        },
    }


def sebi_ebs_volumes_unencrypted(session, scan_meta_data):
    """
    SEBI CSCRF - PR.DS-1 | Protect: Data Security at Rest
    SEBI mandates encryption of all data at rest using strong cryptography.
    EBS volumes attached to EC2 instances storing financial data must be encrypted.
    """
    print("sebi_ebs_volumes_unencrypted")
    ec2 = session.client("ec2")
    non_compliant = []

    try:
        volumes = ec2.describe_volumes().get("Volumes", [])

        for vol in volumes:
            if not vol.get("Encrypted", False):
                attached_to = [a.get("InstanceId") for a in vol.get("Attachments", [])]
                non_compliant.append(
                    {
                        "resource_name": vol["VolumeId"],
                        "size_gb": vol.get("Size"),
                        "state": vol.get("State"),
                        "attached_to": attached_to,
                        "note": "EBS volume not encrypted — data at rest unprotected",
                    }
                )
    except Exception as e:
        print(f"Error checking EBS volumes: {e}")

    scan_meta_data["total_scanned"] += len(volumes) if "volumes" in dir() else 0
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "SEBI CSCRF - Unencrypted EBS Volumes",
        "service": "EC2",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-PR.DS-1",
        "problem_statement": "Unencrypted EBS volumes expose financial and customer data if the underlying hardware is compromised. SEBI mandates encryption of all data at rest.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable EBS encryption by default at the account level (EC2 > Settings > EBS Encryption). Existing unencrypted volumes must be snapshot and re-created as encrypted.",
        "additional_info": {
            "total_scanned": len(non_compliant),
            "affected": len(non_compliant),
        },
    }


def sebi_password_policy_weak(session, scan_meta_data):
    """
    SEBI CSCRF - PR.AA-1 | Protect: Credential Management
    SEBI requires strong password policies for all accounts.
    Weak password policy increases brute force and credential stuffing risk.
    """
    print("sebi_password_policy_weak")
    iam = session.client("iam")
    non_compliant = []

    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        issues = []

        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(
                f"Minimum length is {policy.get('MinimumPasswordLength')} — must be 14+"
            )
        if not policy.get("RequireUppercaseCharacters"):
            issues.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters"):
            issues.append("Lowercase characters not required")
        if not policy.get("RequireNumbers"):
            issues.append("Numbers not required")
        if not policy.get("RequireSymbols"):
            issues.append("Symbols not required")
        if policy.get("MaxPasswordAge", 999) > 90:
            issues.append(
                f"Password expiry is {policy.get('MaxPasswordAge')} days — must be 90 or less"
            )
        if policy.get("PasswordReusePrevention", 0) < 12:
            issues.append(
                f"Only {policy.get('PasswordReusePrevention')} passwords remembered — must be 12+"
            )

        if issues:
            non_compliant.append(
                {
                    "resource_name": "Account Password Policy",
                    "issues": issues,
                    "current_policy": policy,
                }
            )

    except iam.exceptions.NoSuchEntityException:
        non_compliant.append(
            {
                "resource_name": "Account Password Policy",
                "note": "No password policy set at all — using AWS defaults",
                "issues": ["No password policy configured"],
            }
        )
    except Exception as e:
        print(f"Error checking password policy: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "IAM" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("IAM")

    return {
        "check_name": "SEBI CSCRF - Weak IAM Password Policy",
        "service": "IAM",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-PR.AA-1",
        "problem_statement": "Weak or missing password policy increases risk of unauthorized access. SEBI mandates strong credential management for all regulated entities.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Set password policy: min length 14, require uppercase/lowercase/numbers/symbols, 90-day expiry, prevent reuse of last 12 passwords.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def sebi_rds_publicly_accessible(session, scan_meta_data):
    """
    SEBI CSCRF - PR.AC-5 | Protect: Network Integrity
    Databases must never be directly accessible from the internet.
    SEBI requires network segmentation between public and internal systems.
    """
    print("sebi_rds_publicly_accessible")
    rds = session.client("rds")
    non_compliant = []

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if db.get("PubliclyAccessible", False):
                non_compliant.append(
                    {
                        "resource_name": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine"),
                        "endpoint": db.get("Endpoint", {}).get("Address"),
                        "availability_zone": db.get("AvailabilityZone"),
                        "note": "RDS instance is publicly accessible — database exposed to internet",
                    }
                )
    except Exception as e:
        print(f"Error checking RDS public access: {e}")

    scan_meta_data["total_scanned"] += len(instances) if "instances" in dir() else 0
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "SEBI CSCRF - RDS Instances Publicly Accessible",
        "service": "RDS",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-PR.AC-5",
        "problem_statement": "Publicly accessible RDS instances expose financial databases directly to the internet, violating SEBI's network segmentation and data protection requirements.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Disable public accessibility on all RDS instances. Place databases in private subnets. Use bastion hosts or VPN for administrative access only.",
        "additional_info": {
            "total_scanned": len(non_compliant),
            "affected": len(non_compliant),
        },
    }


def sebi_untagged_critical_resources(session, scan_meta_data):
    """
    SEBI CSCRF - ID.AM-1 | Identify: Asset Management
    SEBI mandates a complete inventory of all IT assets with classification.
    Missing tags = unclassified assets = gaps in the asset inventory.
    Checks EC2 instances and RDS instances missing required tags.
    """
    print("sebi_untagged_critical_resources")
    ec2 = session.client("ec2")
    rds = session.client("rds")
    non_compliant = []

    REQUIRED_TAGS = {"Environment", "Owner", "DataClassification"}

    try:
        instances = ec2.describe_instances().get("Reservations", [])
        for res in instances:
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                tags = {t["Key"] for t in inst.get("Tags", [])}
                missing = REQUIRED_TAGS - tags
                if missing:
                    name = next(
                        (
                            t["Value"]
                            for t in inst.get("Tags", [])
                            if t["Key"] == "Name"
                        ),
                        inst["InstanceId"],
                    )
                    non_compliant.append(
                        {
                            "resource_name": name,
                            "resource_id": inst["InstanceId"],
                            "resource_type": "EC2",
                            "missing_tags": list(missing),
                            "note": "Resource missing classification tags — not in asset inventory",
                        }
                    )
    except Exception as e:
        print(f"Error checking EC2 tags: {e}")

    try:
        db_instances = rds.describe_db_instances().get("DBInstances", [])
        for db in db_instances:
            tags = {t["Key"] for t in db.get("TagList", [])}
            missing = REQUIRED_TAGS - tags
            if missing:
                non_compliant.append(
                    {
                        "resource_name": db["DBInstanceIdentifier"],
                        "resource_type": "RDS",
                        "missing_tags": list(missing),
                        "note": "RDS instance missing classification tags",
                    }
                )
    except Exception as e:
        print(f"Error checking RDS tags: {e}")

    total = (
        len(instances) + len(db_instances)
        if "instances" in dir() and "db_instances" in dir()
        else 0
    )
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "SEBI CSCRF - Untagged Critical Resources",
        "service": "EC2/RDS",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-1",
        "problem_statement": "Resources missing classification tags are absent from the asset inventory. SEBI mandates a complete, classified IT asset inventory for all regulated entities.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Tag all resources with Environment, Owner, and DataClassification (Public/Internal/Confidential/Restricted). Enforce via AWS Config rules or SCP.",
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def sebi_root_account_used_recently(session, scan_meta_data):
    """
    SEBI CSCRF - PR.AA-2 | Protect: Privileged Access
    Root account usage is a red flag — SEBI requires privileged access to be
    tightly controlled and restricted. Root should never be used for day-to-day ops.
    """
    print("sebi_root_account_used_recently")
    iam = session.client("iam")
    non_compliant = []

    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        credential_report = None

        try:
            iam.generate_credential_report()
        except Exception:
            pass

        import time

        time.sleep(2)

        try:
            report = iam.get_credential_report()
            import csv, io

            reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
            for row in reader:
                if row.get("user") == "<root_account>":
                    last_used = row.get("password_last_used", "N/A")
                    access_key_1_last = row.get("access_key_1_last_used_date", "N/A")
                    access_key_2_last = row.get("access_key_2_last_used_date", "N/A")

                    root_mfa = summary.get("AccountMFAEnabled", 0)

                    issues = []
                    if not root_mfa:
                        issues.append("Root account has NO MFA enabled")
                    if last_used != "N/A" and last_used != "no_information":
                        issues.append(f"Root account was used on {last_used}")
                    if access_key_1_last not in ("N/A", "no_information", ""):
                        issues.append(
                            f"Root access key 1 was used on {access_key_1_last}"
                        )

                    if issues:
                        non_compliant.append(
                            {
                                "resource_name": "Root Account",
                                "last_used": last_used,
                                "mfa_enabled": bool(root_mfa),
                                "issues": issues,
                            }
                        )
        except Exception as e:
            print(f"Error reading credential report: {e}")

    except Exception as e:
        print(f"Error checking root account: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "IAM" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("IAM")

    return {
        "check_name": "SEBI CSCRF - Root Account MFA and Usage",
        "service": "IAM",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-PR.AA-2",
        "problem_statement": "Root account usage or missing MFA on root violates SEBI's privileged access management requirements. Root should only be used for break-glass scenarios.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable MFA on root account immediately. Remove all root access keys. Use IAM roles with least privilege for all operational activities.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }
