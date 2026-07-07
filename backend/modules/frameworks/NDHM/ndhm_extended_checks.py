"""
NDHM/ABDM — Extended Checks
Additional service-specific deep-dive checks for enterprise-grade coverage.

Covers: S3 extended, IAM extended, Secrets, GuardDuty, Config, Backup,
        EventBridge, SNS, RDS extended, DynamoDB, EBS, CloudTrail.

All checks use READ-ONLY APIs compatible with arn:aws:iam::aws:policy/ReadOnlyAccess
"""

import json as _json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "NDHM"
INDIA_REGIONS = {"ap-south-1", "ap-south-2"}


def _result(check_name, service, control_id, problem, max_score, max_severity,
            non_compliant, recommendation, total, region="global"):
    has_issues = len(non_compliant) > 0
    return {
        "check_name": check_name,
        "service": service,
        "framework": FRAMEWORK,
        "control_id": control_id,
        "problem_statement": problem,
        "severity_score": max_score if has_issues else 0,
        "severity_level": max_severity if has_issues else "None",
        "resources_affected": non_compliant,
        "recommendation": recommendation,
        "region": region,
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def _meta(meta, service, total, non_compliant, severity_key):
    meta["total_scanned"] += total
    meta["affected"] += len(non_compliant)
    meta[severity_key] += len(non_compliant)
    if service not in meta["services_scanned"]:
        meta["services_scanned"].append(service)


# ═══════════════════════════════════════════════════════════════════════════════
# S3 EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_s3_public_access_block(session, meta):
    """NDHM.S3.2 — All 4 public access block flags TRUE."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                pa = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                issues = []
                if not pa.get("BlockPublicAcls"): issues.append("BlockPublicAcls")
                if not pa.get("IgnorePublicAcls"): issues.append("IgnorePublicAcls")
                if not pa.get("BlockPublicPolicy"): issues.append("BlockPublicPolicy")
                if not pa.get("RestrictPublicBuckets"): issues.append("RestrictPublicBuckets")
                if issues:
                    nc.append({"resource_name": b["Name"], "note": f"Missing: {', '.join(issues)}"})
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No public access block configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_ext_s3_public_access_block error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("NDHM — S3 Public Access Block (All Flags)", "S3", "NDHM.S3.2",
        "All 4 public access block settings must be TRUE to prevent health data exposure.",
        95, "Critical", nc,
        "Enable all 4 Block Public Access settings on every bucket.", total)


def ndhm_ext_s3_ssl_enforcement(session, meta):
    """NDHM.S3.4 — Bucket policies enforce SSL-only access."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                policy = _json.loads(s3.get_bucket_policy(Bucket=b["Name"])["Policy"])
                has_ssl_deny = False
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Deny":
                        cond = stmt.get("Condition", {})
                        bool_cond = cond.get("Bool", {})
                        if bool_cond.get("aws:SecureTransport") == "false":
                            has_ssl_deny = True
                            break
                if not has_ssl_deny:
                    nc.append({"resource_name": b["Name"], "note": "No SSL enforcement in policy"})
            except ClientError as e:
                if "NoSuchBucketPolicy" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No bucket policy (no SSL enforcement)"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_ext_s3_ssl_enforcement error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("NDHM — S3 SSL-Only Access", "S3", "NDHM.S3.4",
        "Health data must never be transmitted unencrypted. SSL enforcement prevents HTTP access.",
        80, "High", nc,
        "Add bucket policy with Deny for aws:SecureTransport=false.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# IAM EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_iam_access_analyzer(session, meta):
    """NDHM.IAM.1 — IAM Access Analyzer enabled."""
    nc, total = [], 0
    try:
        aa = session.client("accessanalyzer")
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
        total = 1
        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        if not active:
            nc.append({"resource_name": "Account", "note": "No active IAM Access Analyzer"})
    except Exception as e:
        print(f"ndhm_ext_iam_access_analyzer error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("NDHM — IAM Access Analyzer", "IAM", "NDHM.IAM.1",
        "Access Analyzer detects external access to health resources.",
        75, "High", nc, "Create an account-level IAM Access Analyzer.", total)


def ndhm_ext_iam_password_reuse(session, meta):
    """NDHM.IAM.7 — Password reuse prevention >= 24."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        total = 1
        try:
            pp = iam.get_account_password_policy()["PasswordPolicy"]
            reuse = pp.get("PasswordReusePrevention", 0)
            if reuse < 24:
                nc.append({"resource_name": "Password Policy",
                           "note": f"Reuse prevention: {reuse} (need 24)"})
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                nc.append({"resource_name": "Account", "note": "No password policy"})
    except Exception as e:
        print(f"ndhm_ext_iam_password_reuse error: {e}")
    _meta(meta, "IAM", total, nc, "Medium")
    return _result("NDHM — Password Reuse Prevention", "IAM", "NDHM.IAM.7",
        "Password reuse prevention must be >= 24 to prevent credential recycling.",
        65, "Medium", nc, "Set PasswordReusePrevention to 24 in password policy.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# SECRETS MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_secrets_rotation(session, meta):
    """NDHM.SEC.1 — Secret rotation enabled."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if not s.get("RotationEnabled"):
                nc.append({"resource_name": s.get("Name", "unknown"), "note": "Rotation not enabled"})
    except Exception as e:
        print(f"ndhm_ext_secrets_rotation error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "High")
    return _result("NDHM — Secret Rotation Enabled", "Secrets Manager", "NDHM.SEC.1",
        "All health system secrets must have automatic rotation configured.",
        75, "High", nc, "Enable rotation on all secrets with appropriate Lambda rotators.", total)


def ndhm_ext_secrets_age(session, meta):
    """NDHM.SEC.2 — Secrets rotated within 90 days."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        now = datetime.now(timezone.utc)
        for s in secrets:
            last_rotated = s.get("LastRotatedDate")
            if last_rotated and (now - last_rotated).days > 90:
                nc.append({"resource_name": s.get("Name", "unknown"),
                           "note": f"Last rotated {(now - last_rotated).days} days ago"})
            elif not last_rotated and s.get("CreatedDate"):
                if (now - s["CreatedDate"]).days > 90:
                    nc.append({"resource_name": s.get("Name", "unknown"),
                               "note": "Never rotated, created >90 days ago"})
    except Exception as e:
        print(f"ndhm_ext_secrets_age error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "Medium")
    return _result("NDHM — Secrets Rotated Within 90 Days", "Secrets Manager", "NDHM.SEC.2",
        "Stale secrets increase credential compromise risk for health systems.",
        70, "Medium", nc, "Configure 90-day rotation schedules for all secrets.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# GUARDDUTY EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_guardduty_s3_protection(session, meta):
    """NDHM.MON.1 — GuardDuty S3 Protection enabled."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            ds = det.get("DataSources", {})
            s3_logs = ds.get("S3Logs", {})
            if s3_logs.get("Status") != "ENABLED":
                features = det.get("Features", [])
                s3_feat = any(f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
                             for f in features)
                if not s3_feat:
                    nc.append({"resource_name": "GuardDuty", "note": "S3 Protection not enabled"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"ndhm_ext_guardduty_s3 error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("NDHM — GuardDuty S3 Protection", "GuardDuty", "NDHM.MON.1",
        "S3 protection detects anomalous access to health data buckets.",
        80, "High", nc, "Enable S3 data event monitoring in GuardDuty.", total)


def ndhm_ext_guardduty_rds_protection(session, meta):
    """NDHM.MON.3 — GuardDuty RDS Protection enabled."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            rds_feat = any(f.get("Name") == "RDS_LOGIN_EVENTS" and f.get("Status") == "ENABLED"
                         for f in features)
            if not rds_feat:
                nc.append({"resource_name": "GuardDuty", "note": "RDS Protection not enabled"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"ndhm_ext_guardduty_rds error: {e}")
    _meta(meta, "GuardDuty", total, nc, "Medium")
    return _result("NDHM — GuardDuty RDS Protection", "GuardDuty", "NDHM.MON.3",
        "RDS protection detects suspicious login attempts to health databases.",
        70, "Medium", nc, "Enable RDS login event monitoring in GuardDuty.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG & COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_config_delivery_channel(session, meta):
    """NDHM.CMP.2 — Config delivery channel healthy."""
    nc, total = [], 0
    try:
        config = session.client("config")
        total = 1
        channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        if not channels:
            nc.append({"resource_name": "Config", "note": "No delivery channel configured"})
        else:
            status = config.describe_delivery_channel_status().get("DeliveryChannelsStatus", [])
            for s in status:
                last_status = s.get("configHistoryDeliveryInfo", {}).get("lastStatus", "")
                if last_status == "FAILURE":
                    nc.append({"resource_name": s.get("name", "unknown"),
                               "note": "Delivery failing"})
    except Exception as e:
        print(f"ndhm_ext_config_delivery error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("NDHM — Config Delivery Channel", "Config", "NDHM.CMP.2",
        "Config delivery channel must be active for compliance evidence.",
        60, "Medium", nc, "Fix Config delivery channel issues.", total)


def ndhm_ext_config_conformance(session, meta):
    """NDHM.CMP.3 — Conformance packs deployed."""
    nc, total = [], 0
    try:
        config = session.client("config")
        total = 1
        packs = config.describe_conformance_packs().get("ConformancePackDetails", [])
        if not packs:
            nc.append({"resource_name": "Config", "note": "No conformance packs deployed"})
    except Exception as e:
        print(f"ndhm_ext_config_conformance error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("NDHM — Conformance Packs", "Config", "NDHM.CMP.3",
        "Conformance packs provide automated compliance assessment.",
        60, "Medium", nc, "Deploy health-specific conformance packs.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_backup_vault_lock(session, meta):
    """NDHM.BKP.3 — Backup Vault Lock enabled (WORM)."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            if not v.get("Locked"):
                nc.append({"resource_name": v.get("BackupVaultName", "unknown"),
                           "note": "Vault Lock not enabled"})
    except Exception as e:
        print(f"ndhm_ext_backup_vault_lock error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("NDHM — Backup Vault Lock (WORM)", "Backup", "NDHM.BKP.3",
        "Vault Lock prevents deletion of health data backups, ensuring immutability.",
        65, "Medium", nc, "Enable Vault Lock on backup vaults containing health data.", total)


def ndhm_ext_backup_recovery_points(session, meta):
    """NDHM.BKP.4 — Recovery points created recently."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults) if vaults else 1
        if not vaults:
            nc.append({"resource_name": "Account", "note": "No backup vaults"})
        else:
            now = datetime.now(timezone.utc)
            for v in vaults[:5]:
                try:
                    rps = backup.list_recovery_points_by_backup_vault(
                        BackupVaultName=v["BackupVaultName"], MaxResults=1
                    ).get("RecoveryPoints", [])
                    if rps:
                        last_created = rps[0].get("CreationDate")
                        if last_created and (now - last_created).days > 7:
                            nc.append({"resource_name": v["BackupVaultName"],
                                       "note": f"Last backup {(now - last_created).days} days ago"})
                    else:
                        nc.append({"resource_name": v["BackupVaultName"],
                                   "note": "No recovery points"})
                except Exception:
                    pass
    except Exception as e:
        print(f"ndhm_ext_backup_recovery_points error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("NDHM — Backup Recovery Points", "Backup", "NDHM.BKP.4",
        "Recent recovery points confirm backups are actually running.",
        60, "Medium", nc, "Verify backup plans are executing and creating recovery points.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT RESPONSE EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_eventbridge_guardduty(session, meta):
    """NDHM.IR.1 — EventBridge rule for GuardDuty findings."""
    nc, total = [], 0
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        total = 1
        gd_rule = any("guardduty" in r.get("Name", "").lower() or
                     "guard" in _json.dumps(r).lower() for r in rules)
        if not gd_rule:
            nc.append({"resource_name": "EventBridge",
                       "note": "No rule targeting GuardDuty findings"})
    except Exception as e:
        print(f"ndhm_ext_eventbridge_guardduty error: {e}")
    _meta(meta, "EventBridge", total, nc, "Medium")
    return _result("NDHM — EventBridge GuardDuty Rule", "EventBridge", "NDHM.IR.1",
        "EventBridge rules route GuardDuty findings to notification/response workflows.",
        65, "Medium", nc, "Create EventBridge rule matching GuardDuty finding events.", total)


def ndhm_ext_eventbridge_securityhub(session, meta):
    """NDHM.IR.2 — EventBridge rule for Security Hub findings."""
    nc, total = [], 0
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        total = 1
        sh_rule = any("security" in r.get("Name", "").lower() and "hub" in r.get("Name", "").lower()
                     for r in rules)
        if not sh_rule:
            nc.append({"resource_name": "EventBridge",
                       "note": "No rule targeting Security Hub findings"})
    except Exception as e:
        print(f"ndhm_ext_eventbridge_securityhub error: {e}")
    _meta(meta, "EventBridge", total, nc, "Medium")
    return _result("NDHM — EventBridge Security Hub Rule", "EventBridge", "NDHM.IR.2",
        "Security Hub findings should trigger automated notification workflows.",
        60, "Medium", nc, "Create EventBridge rule matching Security Hub IMPORTED findings.", total)


def ndhm_ext_sns_subscribers(session, meta):
    """NDHM.IR.4 — SNS topics have confirmed subscribers."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = len(topics)
        for t in topics[:20]:
            subs = sns.list_subscriptions_by_topic(TopicArn=t["TopicArn"]).get("Subscriptions", [])
            confirmed = [s for s in subs if s.get("SubscriptionArn") not in ("PendingConfirmation", "Deleted")]
            if not confirmed:
                topic_name = t["TopicArn"].split(":")[-1]
                nc.append({"resource_name": topic_name, "note": "No confirmed subscribers"})
    except Exception as e:
        print(f"ndhm_ext_sns_subscribers error: {e}")
    _meta(meta, "SNS", total, nc, "Medium")
    return _result("NDHM — SNS Topics With Subscribers", "SNS", "NDHM.IR.4",
        "Notification topics without subscribers cannot deliver breach alerts.",
        60, "Medium", nc, "Add and confirm subscribers on all security notification topics.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# RDS & DATABASE EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_rds_multi_az(session, meta):
    """NDHM.DB.5 — Multi-AZ for health databases."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("MultiAZ"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Single-AZ deployment"})
    except Exception as e:
        print(f"ndhm_ext_rds_multi_az error: {e}")
    _meta(meta, "RDS", total, nc, "Medium")
    return _result("NDHM — RDS Multi-AZ", "RDS", "NDHM.DB.5",
        "Multi-AZ ensures high availability for health databases.",
        65, "Medium", nc, "Enable Multi-AZ on production health databases.", total)


def ndhm_ext_rds_enhanced_monitoring(session, meta):
    """NDHM.RDSX.1 — Enhanced Monitoring enabled."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if db.get("MonitoringInterval", 0) == 0:
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": "Enhanced Monitoring not enabled"})
    except Exception as e:
        print(f"ndhm_ext_rds_enhanced_monitoring error: {e}")
    _meta(meta, "RDS", total, nc, "Low")
    return _result("NDHM — RDS Enhanced Monitoring", "RDS", "NDHM.RDSX.1",
        "Enhanced monitoring provides OS-level metrics for health database performance.",
        40, "Low", nc, "Enable Enhanced Monitoring with 60-second granularity.", total)


def ndhm_ext_dynamodb_pitr(session, meta):
    """NDHM.DB.8 — DynamoDB Point-in-Time Recovery enabled."""
    ddb = session.client("dynamodb")
    nc, total = [], 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for table in tables[:30]:
            try:
                pitr = ddb.describe_continuous_backups(TableName=table)
                status = pitr.get("ContinuousBackupsDescription", {}).get(
                    "PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
                if status != "ENABLED":
                    nc.append({"resource_name": table, "note": "PITR not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_ext_dynamodb_pitr error: {e}")
    _meta(meta, "DynamoDB", total, nc, "Medium")
    return _result("NDHM — DynamoDB Point-in-Time Recovery", "DynamoDB", "NDHM.DB.8",
        "PITR enables recovery of health data to any second within 35-day window.",
        65, "Medium", nc, "Enable PITR on all DynamoDB tables storing health data.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_ext_ebs_default_encryption(session, meta):
    """NDHM.ADV.1 — Account-level EBS default encryption."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        total = 1
        result = ec2.get_ebs_encryption_by_default()
        if not result.get("EbsEncryptionByDefault"):
            nc.append({"resource_name": "Account",
                       "note": "EBS default encryption not enabled"})
    except Exception as e:
        print(f"ndhm_ext_ebs_default_encryption error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("NDHM — EBS Default Encryption", "EC2", "NDHM.ADV.1",
        "Default EBS encryption ensures new volumes are automatically encrypted.",
        75, "High", nc, "Enable EBS encryption by default at the account level.", total)


def ndhm_ext_cloudtrail_kms(session, meta):
    """NDHM.LOG.3 — CloudTrail encrypted with customer-managed KMS."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        for t in trails:
            if not t.get("KmsKeyId"):
                nc.append({"resource_name": t.get("Name", "unknown"),
                           "note": "Not encrypted with KMS (using default SSE-S3)"})
    except Exception as e:
        print(f"ndhm_ext_cloudtrail_kms error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Medium")
    return _result("NDHM — CloudTrail KMS Encryption", "CloudTrail", "NDHM.LOG.3",
        "Customer-managed KMS encryption adds access control on audit trail logs.",
        65, "Medium", nc, "Set KmsKeyId on CloudTrail trails for enhanced log protection.", total)
