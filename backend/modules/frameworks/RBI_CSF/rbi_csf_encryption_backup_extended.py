"""
RBI CSF — Encryption, Secrets & Backup Extended Checks
Covers remaining ENC, SEC, BKP, and advanced hardening checks.

All checks use READ-ONLY APIs.
"""

import json as _json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "RBI CSF"
INDIA_REGIONS = {"ap-south-1", "ap-south-2"}


def _result(check_name, service, control_id, problem, max_score, max_severity,
            non_compliant, recommendation, total, region="global"):
    has_issues = len(non_compliant) > 0
    return {
        "check_name": check_name, "service": service, "framework": FRAMEWORK,
        "control_id": control_id, "problem_statement": problem,
        "severity_score": max_score if has_issues else 0,
        "severity_level": max_severity if has_issues else "None",
        "resources_affected": non_compliant, "recommendation": recommendation,
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
# KMS EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_enc_kms_cmk_usage(session, meta):
    """RBI.ENC.11 — Customer-managed keys actively used."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        total = 1
        cmk_count = 0
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER" and desc.get("KeyState") == "Enabled":
                    cmk_count += 1
            except Exception:
                pass
        if cmk_count == 0:
            nc.append({"resource_name": "Account", "note": "No active customer-managed KMS keys"})
    except Exception as e:
        print(f"rbi_enc_kms_cmk_usage error: {e}")
    _meta(meta, "KMS", total, nc, "Medium")
    return _result("RBI CSF — Customer-Managed Keys Active", "KMS", "RBI.ENC.11",
        "CMKs provide granular access control over financial data encryption.",
        65, "Medium", nc, "Create and use customer-managed KMS keys.", total)


def rbi_enc_dynamodb(session, meta):
    """RBI.ENC.7 — DynamoDB encryption with CMK."""
    ddb = session.client("dynamodb")
    nc, total = [], 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables[:30]:
            try:
                desc = ddb.describe_table(TableName=t)["Table"]
                sse = desc.get("SSEDescription", {})
                if sse.get("SSEType") != "KMS":
                    nc.append({"resource_name": t, "note": "Not using customer-managed KMS"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_enc_dynamodb error: {e}")
    _meta(meta, "DynamoDB", total, nc, "Medium")
    return _result("RBI CSF — DynamoDB CMK Encryption", "DynamoDB", "RBI.ENC.7",
        "Financial transaction tables should use customer-managed KMS.",
        65, "Medium", nc, "Enable SSE with customer-managed KMS on DynamoDB tables.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# SECRETS EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_sec_rotation_schedule(session, meta):
    """RBI.SEC.6 — Rotation schedule configured."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if s.get("RotationEnabled"):
                rules = s.get("RotationRules", {})
                if not rules.get("AutomaticallyAfterDays") and not rules.get("ScheduleExpression"):
                    nc.append({"resource_name": s.get("Name"), "note": "Rotation enabled but no schedule"})
            else:
                nc.append({"resource_name": s.get("Name"), "note": "Rotation not enabled"})
    except Exception as e:
        print(f"rbi_sec_rotation_schedule error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "Medium")
    return _result("RBI CSF — Secret Rotation Schedule", "Secrets Manager", "RBI.SEC.6",
        "All secrets must have defined rotation schedules.",
        60, "Medium", nc, "Configure AutomaticallyAfterDays or ScheduleExpression.", total)


def rbi_sec_pending_deletion(session, meta):
    """RBI.SEC.5 — Secrets not pending deletion."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if s.get("DeletedDate"):
                nc.append({"resource_name": s.get("Name"), "note": "Pending deletion"})
    except Exception as e:
        print(f"rbi_sec_pending_deletion error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "Medium")
    return _result("RBI CSF — Secrets Pending Deletion", "Secrets Manager", "RBI.SEC.5",
        "Secrets pending deletion may impact financial system connectivity.",
        55, "Medium", nc, "Review and cancel unintended secret deletions.", total)


def rbi_sec_resource_policy(session, meta):
    """RBI.SEC.4 — Secret resource policies no public access."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets[:20]:
            try:
                policy_resp = sm.get_resource_policy(SecretId=s["ARN"])
                policy_str = policy_resp.get("ResourcePolicy")
                if policy_str:
                    policy = _json.loads(policy_str)
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            p = stmt.get("Principal", {})
                            if p == "*" or (isinstance(p, dict) and p.get("AWS") == "*"):
                                if not stmt.get("Condition"):
                                    nc.append({"resource_name": s.get("Name"), "note": "Principal:* in policy"})
                                    break
            except ClientError:
                pass
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_sec_resource_policy error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "High")
    return _result("RBI CSF — Secret Resource Policy", "Secrets Manager", "RBI.SEC.4",
        "Secret policies must not allow wildcard principals.",
        75, "High", nc, "Remove Principal:* from secret resource policies.", total)


def rbi_sec_cmk_encryption(session, meta):
    """RBI.ENC.14 — Secrets encrypted with CMK."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets[:20]:
            try:
                detail = sm.describe_secret(SecretId=s["ARN"])
                kms_key = detail.get("KmsKeyId", "")
                if not kms_key or "aws/secretsmanager" in kms_key:
                    nc.append({"resource_name": s.get("Name"), "note": "Using default AWS-managed key"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_sec_cmk_encryption error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "Medium")
    return _result("RBI CSF — Secrets CMK Encryption", "Secrets Manager", "RBI.ENC.14",
        "Financial secrets should use customer-managed KMS for access control.",
        60, "Medium", nc, "Use customer-managed KMS key for secrets.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_bkp_plans_exist(session, meta):
    """RBI.BKP.1 — Backup plans configured."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = 1
        if not plans:
            nc.append({"resource_name": "Account", "note": "No AWS Backup plans configured"})
    except Exception as e:
        print(f"rbi_bkp_plans_exist error: {e}")
    _meta(meta, "Backup", total, nc, "High")
    return _result("RBI CSF — Backup Plans Exist", "Backup", "RBI.BKP.1",
        "AWS Backup plans required for financial data protection.",
        75, "High", nc, "Create backup plans covering all financial data stores.", total)


def rbi_bkp_vault_policy(session, meta):
    """RBI.BKP.3 — Backup vault access policy restricted."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            try:
                policy = backup.get_backup_vault_access_policy(
                    BackupVaultName=v["BackupVaultName"])
                policy_doc = _json.loads(policy.get("Policy", "{}"))
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        p = stmt.get("Principal", {})
                        if p == "*" or (isinstance(p, dict) and p.get("AWS") == "*"):
                            if not stmt.get("Condition"):
                                nc.append({"resource_name": v["BackupVaultName"],
                                           "note": "Wildcard principal in vault policy"})
                                break
            except ClientError as e:
                if "AccessDenied" not in str(e) and "ResourceNotFoundException" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_bkp_vault_policy error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("RBI CSF — Backup Vault Access Policy", "Backup", "RBI.BKP.3",
        "Vault policies must restrict access to authorized personnel.",
        65, "Medium", nc, "Remove wildcard principals from vault access policies.", total)


def rbi_bkp_vault_lock(session, meta):
    """RBI.BKP.4 — Backup Vault Lock (WORM)."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            if not v.get("Locked"):
                nc.append({"resource_name": v.get("BackupVaultName"), "note": "Vault Lock not enabled"})
    except Exception as e:
        print(f"rbi_bkp_vault_lock error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("RBI CSF — Backup Vault Lock (WORM)", "Backup", "RBI.BKP.4",
        "Vault Lock prevents deletion of financial backups (immutability).",
        60, "Medium", nc, "Enable Vault Lock for regulatory compliance.", total)


def rbi_bkp_recovery_points(session, meta):
    """RBI.BKP.5 — Recent recovery points exist."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults) if vaults else 1
        now = datetime.now(timezone.utc)
        if not vaults:
            nc.append({"resource_name": "Account", "note": "No backup vaults"})
        for v in vaults[:5]:
            try:
                rps = backup.list_recovery_points_by_backup_vault(
                    BackupVaultName=v["BackupVaultName"], MaxResults=1
                ).get("RecoveryPoints", [])
                if rps:
                    last = rps[0].get("CreationDate")
                    if last and (now - last).days > 7:
                        nc.append({"resource_name": v["BackupVaultName"],
                                   "note": f"Last backup {(now - last).days} days ago"})
                else:
                    nc.append({"resource_name": v["BackupVaultName"], "note": "No recovery points"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_bkp_recovery_points error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("RBI CSF — Recent Recovery Points", "Backup", "RBI.BKP.5",
        "Confirm backups are actually running by checking recent recovery points.",
        60, "Medium", nc, "Verify backup plans are executing successfully.", total)


def rbi_bkp_retention(session, meta):
    """RBI.BKP.6 — Backup retention meets requirements."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = len(plans)
        for p in plans[:10]:
            try:
                plan = backup.get_backup_plan(BackupPlanId=p["BackupPlanId"])["BackupPlan"]
                for rule in plan.get("Rules", []):
                    lifecycle = rule.get("Lifecycle", {})
                    delete_days = lifecycle.get("DeleteAfterDays", 0)
                    if delete_days and delete_days < 35:
                        nc.append({"resource_name": p.get("BackupPlanName", "unknown"),
                                   "note": f"Retention {delete_days} days (need 35+)"})
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_bkp_retention error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("RBI CSF — Backup Retention Period", "Backup", "RBI.BKP.6",
        "Financial data backup retention must meet RBI requirements (35+ days).",
        60, "Medium", nc, "Set backup retention to minimum 35 days.", total)


def rbi_bkp_cross_region_dr(session, meta):
    """RBI.BKP.7 — Cross-region backup for DR."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = len(plans) if plans else 1
        has_copy = False
        for p in plans[:10]:
            try:
                plan = backup.get_backup_plan(BackupPlanId=p["BackupPlanId"])["BackupPlan"]
                for rule in plan.get("Rules", []):
                    if rule.get("CopyActions"):
                        has_copy = True
                        break
            except Exception:
                pass
            if has_copy:
                break
        if not has_copy and plans:
            nc.append({"resource_name": "Backup Plans", "note": "No cross-region copy actions for DR"})
    except Exception as e:
        print(f"rbi_bkp_cross_region_dr error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("RBI CSF — Cross-Region Backup (DR)", "Backup", "RBI.BKP.7",
        "Cross-region copies enable disaster recovery per RBI BCP requirements.",
        55, "Medium", nc, "Add CopyActions to backup rules targeting DR region.", total)


def rbi_bkp_all_dbs_covered(session, meta):
    """RBI.BKP.8 — All financial databases in backup plans."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        rds = session.client("rds")
        protected = backup.list_protected_resources().get("Results", [])
        protected_arns = {r.get("ResourceArn", "") for r in protected}
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            arn = db.get("DBInstanceArn", "")
            if arn not in protected_arns:
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Not in backup plan"})
    except Exception as e:
        print(f"rbi_bkp_all_dbs_covered error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("RBI CSF — All Databases in Backup", "Backup", "RBI.BKP.8",
        "Every financial database must be included in AWS Backup plans.",
        65, "Medium", nc, "Add all RDS/DynamoDB resources to backup selections.", total)


def rbi_bkp_dynamodb_pitr(session, meta):
    """RBI.BKP.12 — DynamoDB Point-in-Time Recovery."""
    ddb = session.client("dynamodb")
    nc, total = [], 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables[:30]:
            try:
                pitr = ddb.describe_continuous_backups(TableName=t)
                status = pitr.get("ContinuousBackupsDescription", {}).get(
                    "PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
                if status != "ENABLED":
                    nc.append({"resource_name": t, "note": "PITR not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_bkp_dynamodb_pitr error: {e}")
    _meta(meta, "DynamoDB", total, nc, "Medium")
    return _result("RBI CSF — DynamoDB PITR", "DynamoDB", "RBI.BKP.12",
        "PITR enables financial data recovery to any second within 35 days.",
        65, "Medium", nc, "Enable PITR on all financial DynamoDB tables.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# GOVERNANCE EXTENDED
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_gov_audit_manager(session, meta):
    """RBI.GOV.6 — Audit Manager enabled."""
    nc, total = [], 0
    try:
        total = 1
        am = session.client("auditmanager")
        try:
            settings = am.get_settings(attribute="ALL")
            if not settings:
                nc.append({"resource_name": "Audit Manager", "note": "Not configured"})
        except ClientError:
            nc.append({"resource_name": "Audit Manager", "note": "Not enabled"})
    except Exception as e:
        print(f"rbi_gov_audit_manager error: {e}")
    _meta(meta, "Audit Manager", total, nc, "Low")
    return _result("RBI CSF — Audit Manager", "Audit Manager", "RBI.GOV.6",
        "Audit Manager provides automated compliance assessment evidence.",
        40, "Low", nc, "Enable Audit Manager with financial compliance frameworks.", total)


def rbi_gov_config_compliance(session, meta):
    """RBI.GOV.8 — Config rules compliance status."""
    nc, total = [], 0
    try:
        config = session.client("config")
        compliance = config.describe_compliance_by_config_rule().get("ComplianceByConfigRules", [])
        total = len(compliance)
        non_compliant_rules = [c.get("ConfigRuleName") for c in compliance
                              if c.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT"]
        if non_compliant_rules:
            nc.append({"resource_name": "Config Rules",
                       "note": f"{len(non_compliant_rules)} non-compliant: {', '.join(non_compliant_rules[:5])}"})
    except Exception as e:
        print(f"rbi_gov_config_compliance error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("RBI CSF — Config Rules Compliance", "Config", "RBI.GOV.8",
        "Non-compliant Config rules indicate configuration drift from RBI standards.",
        60, "Medium", nc, "Remediate non-compliant Config rules.", total)


def rbi_gov_config_delivery(session, meta):
    """RBI.GOV.10 — Config delivery channel healthy."""
    nc, total = [], 0
    try:
        config = session.client("config")
        total = 1
        channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        if not channels:
            nc.append({"resource_name": "Config", "note": "No delivery channel"})
        else:
            status = config.describe_delivery_channel_status().get("DeliveryChannelsStatus", [])
            for s in status:
                last = s.get("configHistoryDeliveryInfo", {}).get("lastStatus", "")
                if last == "FAILURE":
                    nc.append({"resource_name": s.get("name", "unknown"), "note": "Delivery failing"})
    except Exception as e:
        print(f"rbi_gov_config_delivery error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("RBI CSF — Config Delivery Channel", "Config", "RBI.GOV.10",
        "Config delivery must be healthy for compliance evidence collection.",
        55, "Medium", nc, "Fix Config delivery channel issues.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED HARDENING (ADV selections)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_adv_s3_inventory(session, meta):
    """RBI.ADV.1 — S3 Inventory enabled."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        has_inventory = False
        for b in buckets[:10]:
            try:
                inv = s3.list_bucket_inventory_configurations(Bucket=b["Name"])
                if inv.get("InventoryConfigurationList"):
                    has_inventory = True
                    break
            except Exception:
                pass
        if not has_inventory:
            nc.append({"resource_name": "Account", "note": "No S3 inventory configurations"})
    except Exception as e:
        print(f"rbi_adv_s3_inventory error: {e}")
    _meta(meta, "S3", total, nc, "Low")
    return _result("RBI CSF — S3 Inventory", "S3", "RBI.ADV.1",
        "S3 Inventory supports data discovery and audit for financial data.",
        35, "Low", nc, "Enable inventory on financial data buckets.", total)


def rbi_adv_cloudtrail_lake(session, meta):
    """RBI.ADV.6 — CloudTrail Lake for long-term audit."""
    nc, total = [], 0
    try:
        ct = session.client("cloudtrail")
        total = 1
        try:
            stores = ct.list_event_data_stores().get("EventDataStores", [])
            if not stores:
                nc.append({"resource_name": "CloudTrail", "note": "No event data stores (Lake)"})
        except Exception:
            nc.append({"resource_name": "CloudTrail Lake", "note": "Not configured"})
    except Exception as e:
        print(f"rbi_adv_cloudtrail_lake error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Low")
    return _result("RBI CSF — CloudTrail Lake", "CloudTrail", "RBI.ADV.6",
        "CloudTrail Lake enables long-term audit analytics for financial events.",
        30, "Low", nc, "Create event data store for long-term audit retention.", total)


def rbi_adv_route53_query_logging(session, meta):
    """RBI.ADV.7 — Route53 query logging."""
    nc, total = [], 0
    try:
        r53 = session.client("route53")
        total = 1
        try:
            configs = r53.list_query_logging_configs().get("QueryLoggingConfigs", [])
            if not configs:
                nc.append({"resource_name": "Route53", "note": "No DNS query logging configured"})
        except Exception:
            nc.append({"resource_name": "Route53", "note": "Query logging not available"})
    except Exception as e:
        print(f"rbi_adv_route53_query_logging error: {e}")
    _meta(meta, "Route53", total, nc, "Low")
    return _result("RBI CSF — Route53 Query Logging", "Route53", "RBI.ADV.7",
        "DNS query logging provides visibility into financial domain resolution.",
        30, "Low", nc, "Enable query logging on financial service hosted zones.", total)


def rbi_adv_route53_health_checks(session, meta):
    """RBI.ADV.8 — Route53 health checks."""
    nc, total = [], 0
    try:
        r53 = session.client("route53")
        total = 1
        checks = r53.list_health_checks().get("HealthChecks", [])
        if not checks:
            nc.append({"resource_name": "Route53", "note": "No health checks configured"})
    except Exception as e:
        print(f"rbi_adv_route53_health_checks error: {e}")
    _meta(meta, "Route53", total, nc, "Low")
    return _result("RBI CSF — Route53 Health Checks", "Route53", "RBI.ADV.8",
        "Health checks monitor financial endpoint availability.",
        30, "Low", nc, "Create health checks for critical financial endpoints.", total)
