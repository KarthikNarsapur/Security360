from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def _update_meta(scan_meta_data, service, total, affected, severity_level):
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += affected
    scan_meta_data[severity_level] = scan_meta_data.get(severity_level, 0) + affected
    if service not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append(service)


# ============ RC: Recover ============

def sebi_rds_backup_enabled(session, scan_meta_data):
    print("sebi_rds_backup_enabled")
    service = "RDS"
    non_compliant = []
    instances = []
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])
    except Exception as e:
        instances = []

    for db in instances:
        if db.get("BackupRetentionPeriod", 0) == 0:
            non_compliant.append({
                "resource_id": db["DBInstanceIdentifier"],
                "resource_arn": db["DBInstanceArn"],
                "region": session.region_name,
                "reason": "BackupRetentionPeriod is 0 (backups disabled)"
            })

    _update_meta(scan_meta_data, service, len(instances), len(non_compliant), "High")
    return {
        "check_name": "RDS Automated Backup Enabled",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-1",
        "problem_statement": "RDS instances with BackupRetentionPeriod set to 0 have no automated backups, risking data loss.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable automated backups by setting BackupRetentionPeriod to at least 7 days.",
        "additional_info": f"Total RDS instances scanned: {len(instances)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_rds_multi_az(session, scan_meta_data):
    print("sebi_rds_multi_az")
    service = "RDS"
    non_compliant = []
    instances = []
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])
    except Exception as e:
        instances = []

    for db in instances:
        if not db.get("MultiAZ", False):
            non_compliant.append({
                "resource_id": db["DBInstanceIdentifier"],
                "resource_arn": db["DBInstanceArn"],
                "region": session.region_name,
                "reason": "Single-AZ deployment without Multi-AZ failover"
            })

    _update_meta(scan_meta_data, service, len(instances), len(non_compliant), "High")
    return {
        "check_name": "RDS Multi-AZ Deployment",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-2",
        "problem_statement": "RDS instances without Multi-AZ deployment lack automatic failover for high availability.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable Multi-AZ deployment for production RDS instances to ensure automatic failover.",
        "additional_info": f"Total RDS instances scanned: {len(instances)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_dynamodb_pitr(session, scan_meta_data):
    print("sebi_dynamodb_pitr")
    service = "DynamoDB"
    non_compliant = []
    tables = []
    try:
        dynamodb = session.client("dynamodb")
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            tables.extend(page["TableNames"])
    except Exception as e:
        tables = []

    for table_name in tables:
        try:
            resp = dynamodb.describe_continuous_backups(TableName=table_name)
            status = resp["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
            if status != "ENABLED":
                non_compliant.append({
                    "resource_id": table_name,
                    "resource_arn": f"arn:aws:dynamodb:{session.region_name}:{session.client('sts').get_caller_identity()['Account']}:table/{table_name}",
                    "region": session.region_name,
                    "reason": "Point-in-Time Recovery (PITR) is disabled"
                })
        except Exception:
            non_compliant.append({
                "resource_id": table_name,
                "resource_arn": "N/A",
                "region": session.region_name,
                "reason": "Unable to determine PITR status"
            })

    _update_meta(scan_meta_data, service, len(tables), len(non_compliant), "High")
    return {
        "check_name": "DynamoDB Point-in-Time Recovery",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-3",
        "problem_statement": "DynamoDB tables without PITR enabled cannot be restored to a specific point in time.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable Point-in-Time Recovery on all DynamoDB tables for continuous backup capability.",
        "additional_info": f"Total tables scanned: {len(tables)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_backup_vault_exists(session, scan_meta_data):
    print("sebi_backup_vault_exists")
    service = "Backup"
    non_compliant = []
    vaults = []
    try:
        backup = session.client("backup")
        resp = backup.list_backup_vaults()
        vaults = resp.get("BackupVaultList", [])
    except Exception as e:
        vaults = []

    total = 1  # account-level check
    if not vaults:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "No backup vaults exist in this region"
        })

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "AWS Backup Vault Exists",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-4",
        "problem_statement": "No AWS Backup vaults found, indicating no centralized backup strategy.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Create AWS Backup vaults and configure backup plans for critical resources.",
        "additional_info": f"Backup vaults found: {len(vaults)}"
    }


def sebi_backup_vault_lock(session, scan_meta_data):
    print("sebi_backup_vault_lock")
    service = "Backup"
    non_compliant = []
    vaults = []
    try:
        backup = session.client("backup")
        resp = backup.list_backup_vaults()
        vaults = resp.get("BackupVaultList", [])
    except Exception as e:
        vaults = []

    for vault in vaults:
        vault_name = vault["BackupVaultName"]
        try:
            backup.describe_backup_vault(BackupVaultName=vault_name)
            # Check if vault lock is configured
            try:
                lock_resp = backup.get_backup_vault_access_policy(BackupVaultName=vault_name)
            except Exception:
                pass
            # Vault lock check via locked property
            if not vault.get("Locked", False):
                non_compliant.append({
                    "resource_id": vault_name,
                    "resource_arn": vault.get("BackupVaultArn", "N/A"),
                    "region": session.region_name,
                    "reason": "Backup vault does not have vault lock enabled"
                })
        except Exception:
            non_compliant.append({
                "resource_id": vault_name,
                "resource_arn": vault.get("BackupVaultArn", "N/A"),
                "region": session.region_name,
                "reason": "Unable to determine vault lock status"
            })

    _update_meta(scan_meta_data, service, len(vaults) if vaults else 1, len(non_compliant), "Medium")
    return {
        "check_name": "AWS Backup Vault Lock",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-5",
        "problem_statement": "Backup vaults without vault lock can have backups deleted, compromising recovery capability.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable vault lock on backup vaults to prevent deletion of recovery points.",
        "additional_info": f"Total vaults scanned: {len(vaults)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_backup_cross_region(session, scan_meta_data):
    print("sebi_backup_cross_region")
    service = "Backup"
    non_compliant = []
    plans = []
    try:
        backup = session.client("backup")
        resp = backup.list_backup_plans()
        plans = resp.get("BackupPlansList", [])
    except Exception as e:
        plans = []

    for plan in plans:
        plan_id = plan["BackupPlanId"]
        try:
            detail = backup.get_backup_plan(BackupPlanId=plan_id)
            rules = detail["BackupPlan"].get("Rules", [])
            has_cross_region = any(
                rule.get("CopyActions", []) for rule in rules
            )
            if not has_cross_region:
                non_compliant.append({
                    "resource_id": plan.get("BackupPlanName", plan_id),
                    "resource_arn": plan.get("BackupPlanArn", "N/A"),
                    "region": session.region_name,
                    "reason": "No cross-region copy rules configured in backup plan"
                })
        except Exception:
            non_compliant.append({
                "resource_id": plan_id,
                "resource_arn": plan.get("BackupPlanArn", "N/A"),
                "region": session.region_name,
                "reason": "Unable to retrieve backup plan details"
            })

    total = len(plans) if plans else 1
    if not plans:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "No backup plans exist to configure cross-region copies"
        })

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "Backup Cross-Region Copy Rules",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-6",
        "problem_statement": "Backup plans without cross-region copy rules cannot survive regional disasters.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Add cross-region copy actions to backup plan rules for disaster recovery.",
        "additional_info": f"Total backup plans scanned: {len(plans)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_ec2_backup_coverage(session, scan_meta_data):
    print("sebi_ec2_backup_coverage")
    service = "Backup"
    non_compliant = []
    instances = []
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                instances.extend(res["Instances"])
    except Exception as e:
        instances = []

    protected_arns = set()
    try:
        backup = session.client("backup")
        paginator = backup.get_paginator("list_protected_resources")
        for page in paginator.paginate():
            for r in page["Results"]:
                if r["ResourceType"] == "EC2":
                    protected_arns.add(r["ResourceArn"])
    except Exception:
        pass

    for inst in instances:
        instance_id = inst["InstanceId"]
        arn = f"arn:aws:ec2:{session.region_name}:{inst.get('OwnerId', '')}:instance/{instance_id}"
        if arn not in protected_arns and f"instance/{instance_id}" not in str(protected_arns):
            non_compliant.append({
                "resource_id": instance_id,
                "resource_arn": arn,
                "region": session.region_name,
                "reason": "EC2 instance not covered by any AWS Backup plan"
            })

    _update_meta(scan_meta_data, service, len(instances) if instances else 1, len(non_compliant), "Medium")
    return {
        "check_name": "EC2 Backup Coverage",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-7",
        "problem_statement": "EC2 instances not covered by backup plans risk data loss in case of failure.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Include all EC2 instances in AWS Backup plans using resource tags or direct assignment.",
        "additional_info": f"Total EC2 instances: {len(instances)}, Not in backup: {len(non_compliant)}"
    }


def sebi_rds_backup_coverage(session, scan_meta_data):
    print("sebi_rds_backup_coverage")
    service = "Backup"
    non_compliant = []
    instances = []
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])
    except Exception as e:
        instances = []

    protected_arns = set()
    try:
        backup = session.client("backup")
        paginator = backup.get_paginator("list_protected_resources")
        for page in paginator.paginate():
            for r in page["Results"]:
                if r["ResourceType"] == "RDS":
                    protected_arns.add(r["ResourceArn"])
    except Exception:
        pass

    for db in instances:
        if db["DBInstanceArn"] not in protected_arns:
            non_compliant.append({
                "resource_id": db["DBInstanceIdentifier"],
                "resource_arn": db["DBInstanceArn"],
                "region": session.region_name,
                "reason": "RDS instance not covered by any AWS Backup plan"
            })

    _update_meta(scan_meta_data, service, len(instances) if instances else 1, len(non_compliant), "High")
    return {
        "check_name": "RDS Backup Coverage",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-8",
        "problem_statement": "RDS instances not covered by AWS Backup plans may lack centralized backup governance.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Include all RDS instances in AWS Backup plans for centralized backup management.",
        "additional_info": f"Total RDS instances: {len(instances)}, Not in backup: {len(non_compliant)}"
    }


def sebi_s3_versioning(session, scan_meta_data):
    print("sebi_s3_versioning")
    service = "S3"
    non_compliant = []
    buckets = []
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        buckets = []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket_name)
            status = resp.get("Status", "Disabled")
            if status != "Enabled":
                non_compliant.append({
                    "resource_id": bucket_name,
                    "resource_arn": f"arn:aws:s3:::{bucket_name}",
                    "region": session.region_name,
                    "reason": f"Versioning status: {status}"
                })
        except Exception:
            non_compliant.append({
                "resource_id": bucket_name,
                "resource_arn": f"arn:aws:s3:::{bucket_name}",
                "region": session.region_name,
                "reason": "Unable to determine versioning status"
            })

    _update_meta(scan_meta_data, service, len(buckets) if buckets else 1, len(non_compliant), "Medium")
    return {
        "check_name": "S3 Bucket Versioning",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-9",
        "problem_statement": "S3 buckets without versioning cannot recover from accidental deletions or overwrites.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable versioning on all S3 buckets to allow object recovery.",
        "additional_info": f"Total buckets scanned: {len(buckets)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_efs_backup(session, scan_meta_data):
    print("sebi_efs_backup")
    service = "EFS"
    non_compliant = []
    file_systems = []
    try:
        efs = session.client("efs")
        resp = efs.describe_file_systems()
        file_systems = resp.get("FileSystems", [])
    except Exception as e:
        file_systems = []

    for fs in file_systems:
        fs_id = fs["FileSystemId"]
        try:
            bp = efs.describe_backup_policy(FileSystemId=fs_id)
            status = bp.get("BackupPolicy", {}).get("Status", "DISABLED")
            if status != "ENABLED":
                non_compliant.append({
                    "resource_id": fs_id,
                    "resource_arn": fs.get("FileSystemArn", f"arn:aws:elasticfilesystem:{session.region_name}::file-system/{fs_id}"),
                    "region": session.region_name,
                    "reason": f"EFS backup policy status: {status}"
                })
        except Exception:
            non_compliant.append({
                "resource_id": fs_id,
                "resource_arn": fs.get("FileSystemArn", "N/A"),
                "region": session.region_name,
                "reason": "No backup policy configured for EFS file system"
            })

    _update_meta(scan_meta_data, service, len(file_systems) if file_systems else 1, len(non_compliant), "Medium")
    return {
        "check_name": "EFS Backup Policy",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.RP-10",
        "problem_statement": "EFS file systems without backup policies risk permanent data loss.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable automatic backups for all EFS file systems via backup policy.",
        "additional_info": f"Total EFS file systems: {len(file_systems)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_rds_snapshot_retention(session, scan_meta_data):
    print("sebi_rds_snapshot_retention")
    service = "RDS"
    non_compliant = []
    instances = []
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page["DBInstances"])
    except Exception as e:
        instances = []

    for db in instances:
        retention = db.get("BackupRetentionPeriod", 0)
        if retention < 35:
            non_compliant.append({
                "resource_id": db["DBInstanceIdentifier"],
                "resource_arn": db["DBInstanceArn"],
                "region": session.region_name,
                "reason": f"Backup retention period is {retention} days (required: >= 35)"
            })

    _update_meta(scan_meta_data, service, len(instances) if instances else 1, len(non_compliant), "Medium")
    return {
        "check_name": "RDS Snapshot Retention Period",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.IM-1",
        "problem_statement": "RDS instances with retention period less than 35 days may not meet SEBI recovery requirements.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Set RDS backup retention period to at least 35 days as per SEBI CSCRF guidelines.",
        "additional_info": f"Total RDS instances: {len(instances)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_aurora_global_db(session, scan_meta_data):
    print("sebi_aurora_global_db")
    service = "RDS"
    non_compliant = []
    clusters = []
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            clusters.extend(page["DBClusters"])
    except Exception as e:
        clusters = []

    aurora_clusters = [c for c in clusters if c.get("Engine", "").startswith("aurora")]

    for cluster in aurora_clusters:
        if not cluster.get("CrossAccountClone", False) and not cluster.get("GlobalWriteForwardingStatus"):
            # Check if part of a global database
            global_id = cluster.get("GlobalClusterIdentifier")
            if not global_id:
                non_compliant.append({
                    "resource_id": cluster["DBClusterIdentifier"],
                    "resource_arn": cluster["DBClusterArn"],
                    "region": session.region_name,
                    "reason": "Aurora cluster is not part of a global database for cross-region DR"
                })

    _update_meta(scan_meta_data, service, len(aurora_clusters) if aurora_clusters else 1, len(non_compliant), "Medium")
    return {
        "check_name": "Aurora Global Database",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RC.IM-2",
        "problem_statement": "Aurora clusters without global database configuration lack cross-region disaster recovery.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Configure Aurora Global Database for cross-region replication and failover.",
        "additional_info": f"Total Aurora clusters: {len(aurora_clusters)}, Non-compliant: {len(non_compliant)}"
    }


# ============ RS: Respond ============

def sebi_sns_security_topics(session, scan_meta_data):
    print("sebi_sns_security_topics")
    service = "SNS"
    non_compliant = []
    topics = []
    try:
        sns = session.client("sns")
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            topics.extend(page["Topics"])
    except Exception as e:
        topics = []

    security_keywords = ["security", "alert", "incident", "guardduty", "securityhub", "threat"]
    security_topics = [t for t in topics if any(kw in t["TopicArn"].lower() for kw in security_keywords)]

    total = 1  # account-level check
    if not security_topics:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "No security-related SNS topics found for incident notifications"
        })

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "SNS Security Topics",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.MA-1",
        "problem_statement": "No security-related SNS topics exist for incident alerting and response coordination.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Create SNS topics for security alerts and subscribe incident response team members.",
        "additional_info": f"Total SNS topics: {len(topics)}, Security topics found: {len(security_topics)}"
    }


def sebi_cloudwatch_alarm_actions(session, scan_meta_data):
    print("sebi_cloudwatch_alarm_actions")
    service = "CloudWatch"
    non_compliant = []
    alarms = []
    try:
        cw = session.client("cloudwatch")
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate():
            alarms.extend(page["MetricAlarms"])
    except Exception as e:
        alarms = []

    for alarm in alarms:
        actions = alarm.get("AlarmActions", [])
        has_sns = any("sns" in a.lower() for a in actions)
        if not has_sns:
            non_compliant.append({
                "resource_id": alarm["AlarmName"],
                "resource_arn": alarm["AlarmArn"],
                "region": session.region_name,
                "reason": "CloudWatch alarm has no SNS notification action configured"
            })

    _update_meta(scan_meta_data, service, len(alarms) if alarms else 1, len(non_compliant), "Medium")
    return {
        "check_name": "CloudWatch Alarm SNS Actions",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.MA-2",
        "problem_statement": "CloudWatch alarms without SNS actions cannot notify teams of critical events.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Configure SNS notification actions on all CloudWatch alarms for timely incident response.",
        "additional_info": f"Total alarms: {len(alarms)}, Without SNS actions: {len(non_compliant)}"
    }


def sebi_guardduty_export_config(session, scan_meta_data):
    print("sebi_guardduty_export_config")
    service = "GuardDuty"
    non_compliant = []
    detectors = []
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
    except Exception as e:
        detectors = []

    total = 1
    if not detectors:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "GuardDuty is not enabled; no publishing destination possible"
        })
    else:
        for det_id in detectors:
            try:
                destinations = gd.list_publishing_destinations(DetectorId=det_id).get("Destinations", [])
                if not destinations:
                    non_compliant.append({
                        "resource_id": det_id,
                        "resource_arn": f"arn:aws:guardduty:{session.region_name}::detector/{det_id}",
                        "region": session.region_name,
                        "reason": "GuardDuty detector has no publishing destination configured"
                    })
            except Exception:
                non_compliant.append({
                    "resource_id": det_id,
                    "resource_arn": f"arn:aws:guardduty:{session.region_name}::detector/{det_id}",
                    "region": session.region_name,
                    "reason": "Unable to check publishing destinations"
                })
        total = len(detectors)

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "GuardDuty Export Configuration",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.MA-3",
        "problem_statement": "GuardDuty findings not exported to S3 limits long-term analysis and compliance auditing.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Configure GuardDuty publishing destination to export findings to S3 for retention and analysis.",
        "additional_info": f"Detectors checked: {len(detectors)}, Non-compliant: {len(non_compliant)}"
    }


def sebi_eventbridge_securityhub(session, scan_meta_data):
    print("sebi_eventbridge_securityhub")
    service = "EventBridge"
    non_compliant = []
    rules = []
    try:
        eb = session.client("events")
        paginator = eb.get_paginator("list_rules")
        for page in paginator.paginate():
            rules.extend(page["Rules"])
    except Exception as e:
        rules = []

    securityhub_rules = []
    for rule in rules:
        pattern = rule.get("EventPattern", "")
        if "securityhub" in pattern.lower() or "Security Hub" in pattern:
            securityhub_rules.append(rule)

    total = 1  # account-level check
    if not securityhub_rules:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "No EventBridge rules configured for Security Hub events"
        })

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "EventBridge Security Hub Rules",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.CO-1",
        "problem_statement": "Without EventBridge rules for Security Hub, findings cannot trigger automated response workflows.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Create EventBridge rules to route Security Hub findings to SNS, Lambda, or Step Functions for automated response.",
        "additional_info": f"Total EventBridge rules: {len(rules)}, Security Hub rules found: {len(securityhub_rules)}"
    }


def sebi_lambda_dlq(session, scan_meta_data):
    print("sebi_lambda_dlq")
    service = "Lambda"
    non_compliant = []
    functions = []
    try:
        lam = session.client("lambda")
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            functions.extend(page["Functions"])
    except Exception as e:
        functions = []

    for func in functions:
        dlq = func.get("DeadLetterConfig", {}).get("TargetArn")
        if not dlq:
            non_compliant.append({
                "resource_id": func["FunctionName"],
                "resource_arn": func["FunctionArn"],
                "region": session.region_name,
                "reason": "Lambda function has no Dead Letter Queue (DLQ) configured"
            })

    _update_meta(scan_meta_data, service, len(functions) if functions else 1, len(non_compliant), "Medium")
    return {
        "check_name": "Lambda Dead Letter Queue",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.CO-2",
        "problem_statement": "Lambda functions without DLQ lose failed event data, impeding incident investigation.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Configure DLQ (SQS or SNS) on Lambda functions to capture failed invocations for analysis.",
        "additional_info": f"Total functions: {len(functions)}, Without DLQ: {len(non_compliant)}"
    }


def sebi_cloudtrail_insights(session, scan_meta_data):
    print("sebi_cloudtrail_insights")
    service = "CloudTrail"
    non_compliant = []
    trails = []
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
    except Exception as e:
        trails = []

    for trail in trails:
        trail_arn = trail.get("TrailARN", "")
        try:
            selectors = ct.get_insight_selectors(TrailName=trail_arn)
            insight_selectors = selectors.get("InsightSelectors", [])
            if not insight_selectors:
                non_compliant.append({
                    "resource_id": trail.get("Name", ""),
                    "resource_arn": trail_arn,
                    "region": session.region_name,
                    "reason": "CloudTrail insight events are not enabled"
                })
        except Exception:
            non_compliant.append({
                "resource_id": trail.get("Name", ""),
                "resource_arn": trail_arn,
                "region": session.region_name,
                "reason": "Insight selectors not configured or unable to retrieve"
            })

    _update_meta(scan_meta_data, service, len(trails) if trails else 1, len(non_compliant), "Medium")
    return {
        "check_name": "CloudTrail Insight Events",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.AN-1",
        "problem_statement": "CloudTrail without insight events cannot detect unusual API activity patterns automatically.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable CloudTrail Insights to detect anomalous API call volumes and error rates.",
        "additional_info": f"Total trails: {len(trails)}, Without insights: {len(non_compliant)}"
    }


def sebi_detective_enabled(session, scan_meta_data):
    print("sebi_detective_enabled")
    service = "Detective"
    non_compliant = []
    graphs = []
    try:
        detective = session.client("detective")
        graphs = detective.list_graphs().get("GraphList", [])
    except Exception as e:
        graphs = []

    total = 1  # account-level check
    if not graphs:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "Amazon Detective is not enabled in this region"
        })

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "Amazon Detective Enabled",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.AN-2",
        "problem_statement": "Without Amazon Detective, security investigation and root cause analysis is limited.",
        "severity_score": 6,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable Amazon Detective to facilitate security investigation and threat hunting.",
        "additional_info": f"Detective graphs found: {len(graphs)}"
    }


def sebi_cloudwatch_logs_insights(session, scan_meta_data):
    print("sebi_cloudwatch_logs_insights")
    service = "CloudWatch"
    non_compliant = []
    log_groups = []
    try:
        logs = session.client("logs")
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            log_groups.extend(page["logGroups"])
    except Exception as e:
        log_groups = []

    total = 1  # account-level check
    if not log_groups:
        non_compliant.append({
            "resource_id": "AWS Account",
            "resource_arn": "N/A",
            "region": session.region_name,
            "reason": "No CloudWatch Log Groups exist; CloudWatch Logs Insights cannot be used for analysis"
        })

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Low")
    return {
        "check_name": "CloudWatch Logs Insights Availability",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-RS.AN-3",
        "problem_statement": "Without CloudWatch Log Groups, Logs Insights cannot be used for security log analysis.",
        "severity_score": 4,
        "severity_level": "Low",
        "resources_affected": non_compliant,
        "recommendation": "Ensure application and infrastructure logs are sent to CloudWatch Logs for analysis via Logs Insights.",
        "additional_info": f"Log groups found: {len(log_groups)}"
    }
