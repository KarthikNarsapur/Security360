from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

INDIA_REGIONS = {"ap-south-1", "ap-south-2"}


def rbi_data_localization(session, scan_meta_data):
    print("rbi_data_localization")
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    non_compliant = []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            region = location.get("LocationConstraint") or "us-east-1"

            if region not in INDIA_REGIONS:
                non_compliant.append(
                    {
                        "resource_name": bucket_name,
                        "region": region,
                        "creation_date": str(bucket.get("CreationDate")),
                        "note": "Bucket not in India region — violates RBI data localization mandate",
                    }
                )
        except Exception as e:
            print(f"Error checking bucket location for {bucket_name}: {e}")
            continue

    scan_meta_data["total_scanned"] += len(buckets)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "S3" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("S3")

    return {
        "check_name": "RBI Data Localization - S3 Buckets",
        "service": "S3",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-4.1",
        "problem_statement": "RBI mandates all payment and financial data must reside within India (ap-south-1 or ap-south-2).",
        "severity_score": 90,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Move all S3 buckets containing financial data to ap-south-1 (Mumbai) or ap-south-2 (Hyderabad).",
        "additional_info": {
            "total_scanned": len(buckets),
            "affected": len(non_compliant),
        },
    }


def rbi_public_s3_buckets(session, scan_meta_data):
    print("rbi_public_s3_buckets")
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    public = []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})

            if not all(
                [
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]
            ):
                public.append(
                    {
                        "resource_name": bucket_name,
                        "creation_date": str(bucket.get("CreationDate")),
                        "public_access_block_configuration": config,
                    }
                )
        except Exception as e:
            if (
                hasattr(e, "response")
                and e.response.get("Error", {}).get("Code")
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                public.append(
                    {
                        "resource_name": bucket_name,
                        "creation_date": str(bucket.get("CreationDate")),
                        "public_access_block_configuration": "Not configured",
                    }
                )
            else:
                print(f"Error checking public access for {bucket_name}: {e}")
                continue

    scan_meta_data["total_scanned"] += len(buckets)
    scan_meta_data["affected"] += len(public)
    scan_meta_data["Critical"] += len(public)
    if "S3" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("S3")

    return {
        "check_name": "RBI Access Control - Public S3 Buckets",
        "service": "S3",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-6.3",
        "problem_statement": "Publicly accessible S3 buckets expose financial data to unauthorized access.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": public,
        "recommendation": "Enable all public access block settings on all S3 buckets containing financial data.",
        "additional_info": {"total_scanned": len(buckets), "affected": len(public)},
    }


def rbi_privileged_users_without_mfa(session, scan_meta_data, users, iam):
    print("rbi_privileged_users_without_mfa")
    non_compliant = []

    for user in users:
        user_name = user["UserName"]
        try:
            attached = iam.list_attached_user_policies(UserName=user_name).get(
                "AttachedPolicies", []
            )
            is_admin = any(p["PolicyName"] == "AdministratorAccess" for p in attached)

            if is_admin:
                mfa_devices = iam.list_mfa_devices(UserName=user_name).get(
                    "MFADevices", []
                )
                if not mfa_devices:
                    non_compliant.append(
                        {
                            "resource_name": user_name,
                            "user_id": user.get("UserId"),
                            "note": "Admin user without MFA — violates RBI privileged access controls",
                        }
                    )
        except Exception as e:
            print(f"Error checking privileged access for {user_name}: {e}")
            continue

    scan_meta_data["total_scanned"] += len(users)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "IAM" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("IAM")

    return {
        "check_name": "RBI Privileged Access - Admin Users Without MFA",
        "service": "IAM",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-6.2",
        "problem_statement": "Admin IAM users without MFA violate RBI Privileged Access Management requirements.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable MFA for all IAM users with AdministratorAccess policy attached.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(non_compliant),
        },
    }


def rbi_unencrypted_rds(session, scan_meta_data):
    print("rbi_unencrypted_rds")
    rds = session.client("rds")
    instances = rds.describe_db_instances().get("DBInstances", [])
    non_compliant = []

    for db in instances:
        try:
            if not db.get("StorageEncrypted", False):
                non_compliant.append(
                    {
                        "resource_name": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine"),
                        "region": db.get("AvailabilityZone"),
                        "note": "RDS instance not encrypted at rest — violates RBI cryptographic controls",
                    }
                )
        except Exception as e:
            print(
                f"Error checking RDS encryption for {db.get('DBInstanceIdentifier')}: {e}"
            )
            continue

    scan_meta_data["total_scanned"] += len(instances)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RBI Encryption at Rest - RDS Instances",
        "service": "RDS",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-9.1",
        "problem_statement": "Unencrypted RDS instances storing financial data violate RBI cryptographic control requirements.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable encryption on all RDS instances. Note: existing unencrypted instances must be recreated from an encrypted snapshot.",
        "additional_info": {
            "total_scanned": len(instances),
            "affected": len(non_compliant),
        },
    }


def rbi_cloudtrail_audit_logs(session, scan_meta_data):
    print("rbi_cloudtrail_audit_logs")
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    non_compliant = []

    if not trails:
        non_compliant.append(
            {
                "resource_name": "CloudTrail",
                "note": "No CloudTrail trail configured — audit logging completely missing",
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
                    issues.append("Not enabled for all regions")
                if not trail.get("LogFileValidationEnabled"):
                    issues.append("Log file validation disabled — logs may be tampered")

                if issues:
                    non_compliant.append(
                        {
                            "resource_name": trail["Name"],
                            "issues": issues,
                            "s3_bucket": trail.get("S3BucketName"),
                        }
                    )
            except Exception as e:
                print(f"Error checking CloudTrail {trail.get('Name')}: {e}")
                continue

    scan_meta_data["total_scanned"] += max(len(trails), 1)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "CloudTrail" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudTrail")

    return {
        "check_name": "RBI Audit Trail - CloudTrail Logging",
        "service": "CloudTrail",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-11.1",
        "problem_statement": "Missing or incomplete CloudTrail logging violates RBI's requirement for tamper-proof audit trails.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable CloudTrail in all regions with log file validation enabled. Retain logs for minimum 2 years per RBI mandate.",
        "additional_info": {
            "total_scanned": max(len(trails), 1),
            "affected": len(non_compliant),
        },
    }


def rbi_open_security_groups(session, scan_meta_data):
    print("rbi_open_security_groups")
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    non_compliant = []

    CRITICAL_PORTS = {22, 3306, 5432, 1433, 27017, 6379}

    for sg in sgs:
        open_ports = []
        try:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        if from_port is None:  # all traffic
                            open_ports.append("all")
                        elif from_port in CRITICAL_PORTS or to_port in CRITICAL_PORTS:
                            open_ports.append(f"{from_port}-{to_port}")

            if open_ports:
                non_compliant.append(
                    {
                        "resource_name": sg["GroupId"],
                        "group_name": sg.get("GroupName"),
                        "vpc_id": sg.get("VpcId"),
                        "open_ports": open_ports,
                        "note": "Security group allows public inbound on sensitive ports",
                    }
                )
        except Exception as e:
            print(f"Error checking security group {sg.get('GroupId')}: {e}")
            continue

    scan_meta_data["total_scanned"] += len(sgs)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "EC2" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EC2")

    return {
        "check_name": "RBI Network Security - Open Security Groups",
        "service": "EC2",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-7.1",
        "problem_statement": "Security groups allowing public inbound access on sensitive ports expose financial systems to unauthorized access.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Remove 0.0.0.0/0 rules from security groups. Restrict SSH (22), MySQL (3306), Postgres (5432), MSSQL (1433), Redis (6379) to specific IPs only.",
        "additional_info": {"total_scanned": len(sgs), "affected": len(non_compliant)},
    }


def rbi_rds_backup_disabled(session, scan_meta_data):
    print("rbi_rds_backup_disabled")
    rds = session.client("rds")
    instances = rds.describe_db_instances().get("DBInstances", [])
    non_compliant = []

    for db in instances:
        try:
            if db.get("BackupRetentionPeriod", 0) == 0:
                non_compliant.append(
                    {
                        "resource_name": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine"),
                        "region": db.get("AvailabilityZone"),
                        "note": "Automated backups disabled — violates RBI business continuity requirements",
                    }
                )
        except Exception as e:
            print(
                f"Error checking RDS backup for {db.get('DBInstanceIdentifier')}: {e}"
            )
            continue

    scan_meta_data["total_scanned"] += len(instances)
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RBI Business Continuity - RDS Backup Disabled",
        "service": "RDS",
        "framework": "RBI CSF",
        "control_id": "RBI-CSF-13.1",
        "problem_statement": "RDS instances without automated backups risk unrecoverable data loss, violating RBI Business Continuity Planning requirements.",
        "severity_score": 75,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable automated backups on all RDS instances with a minimum 7-day retention period.",
        "additional_info": {
            "total_scanned": len(instances),
            "affected": len(non_compliant),
        },
    }
