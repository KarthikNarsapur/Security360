"""
DPDP Rules 2025 — Digital Personal Data Protection Rules (India)
AWS Security Checks mapped to DPDP Rules 2025 obligations.

Rules referenced:
  Rule 3/4  — Notice & Consent (data flow visibility)
  Rule 5    — Rights of Data Principal (erasure, access, correction)
  Rule 6    — Security Safeguards (encryption, tokenization, access control, 1-yr logs)
  Rule 7    — Data Breach Notification (72-hour readiness)
  Rule 8    — Data Retention & Erasure (purpose limitation, automated deletion)
  Rule 9    — Children's Data Protection
  Rule 10   — Significant Data Fiduciary (DPIA, annual audit, DPO)
  Rule 12   — Cross-Border Data Transfer (data localization)
  Rule 14   — Data Processor Obligations (vendor/third-party risk)

Notified: 13 November 2025 | Compliance Deadline: 13 May 2027
"""

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "DPDP Rules 2025"


def _result(check_name, service, control_id, problem, max_score, max_severity,
            non_compliant, recommendation, total, region="global"):
    """Build check result with dynamic severity based on actual findings."""
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


def _update_meta(meta, service, total, non_compliant, severity_key):
    """Update scan metadata consistently."""
    meta["total_scanned"] += total
    meta["affected"] += len(non_compliant)
    meta[severity_key] += len(non_compliant)
    if service not in meta["services_scanned"]:
        meta["services_scanned"].append(service)


# ═══════════════════════════════════════════════════════════════════════════════
# 📋 RULE 3/4 — NOTICE & CONSENT (Data Flow Visibility)
# Data Fiduciaries must provide clear notice specifying purpose, categories,
# retention periods, and mechanisms to withdraw consent.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r4_data_classification_tagging(session, meta):
    """Rule 3/4 — Resources must be tagged to identify personal data categories."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    REQUIRED_TAGS = ["DataClassification", "PersonalData", "data-classification", "personal-data"]
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                tags = s3.get_bucket_tagging(Bucket=b["Name"])
                tag_keys = [t["Key"].lower() for t in tags.get("TagSet", [])]
                has_classification = any(
                    req.lower() in tag_keys for req in REQUIRED_TAGS
                )
                if not has_classification:
                    non_compliant.append({
                        "resource_name": b["Name"],
                        "note": "No data classification tag — cannot identify personal data"
                    })
            except ClientError as e:
                if "NoSuchTagSet" in str(e):
                    non_compliant.append({
                        "resource_name": b["Name"],
                        "note": "No tags at all — data classification unknown"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r4_data_classification_tagging error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Data Classification Tagging (S3)", "S3", "DPDP-R4-CONSENT-01",
        "S3 buckets without data classification tags make it impossible to identify where personal data resides, "
        "violating Rule 3/4 notice requirements (purpose, categories, retention must be documented).",
        80, "High", non_compliant,
        "Tag all S3 buckets with 'DataClassification' (e.g., PersonalData, SensitivePersonalData, NonPersonal). "
        "This enables automated data flow mapping required for DPDP consent notices.", total)


def dpdp_r4_rds_data_classification(session, meta):
    """Rule 3/4 — RDS instances must be tagged to identify personal data."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    CLASSIFICATION_TAGS = ["dataclassification", "personaldata", "data-classification", "personal-data"]
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            tag_keys = [t["Key"].lower() for t in db.get("TagList", [])]
            has_classification = any(c in tag_keys for c in CLASSIFICATION_TAGS)
            if not has_classification:
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine"),
                    "note": "No data classification tag on database"
                })
    except Exception as e:
        print(f"dpdp_r4_rds_data_classification error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Data Classification Tagging (RDS)", "RDS", "DPDP-R4-CONSENT-02",
        "RDS instances without data classification tags cannot be mapped in data flow inventories, "
        "violating Rule 3/4 requirements for documenting personal data processing purposes.",
        80, "High", non_compliant,
        "Tag all RDS instances with 'DataClassification' to identify databases storing personal data. "
        "Required for consent notice generation and data flow mapping.", total)


def dpdp_r4_dynamodb_data_classification(session, meta):
    """Rule 3/4 — DynamoDB tables must be tagged to identify personal data."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    CLASSIFICATION_TAGS = ["dataclassification", "personaldata", "data-classification", "personal-data"]
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                arn = ddb.describe_table(TableName=t)["Table"]["TableArn"]
                tags = ddb.list_tags_of_resource(ResourceArn=arn).get("Tags", [])
                tag_keys = [tag["Key"].lower() for tag in tags]
                if not any(c in tag_keys for c in CLASSIFICATION_TAGS):
                    non_compliant.append({
                        "resource_name": t,
                        "note": "No data classification tag on DynamoDB table"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r4_dynamodb_data_classification error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Data Classification Tagging (DynamoDB)", "DynamoDB", "DPDP-R4-CONSENT-03",
        "DynamoDB tables without classification tags cannot be included in data flow inventories.",
        70, "Medium", non_compliant,
        "Tag all DynamoDB tables with 'DataClassification' to enable personal data discovery.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 RULE 6 — SECURITY SAFEGUARDS (Enhanced)
# Mandatory: encryption, masking/tokenization, access controls, activity logs,
# continuity measures (backups), 1-year log retention for breach detection.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r6_kms_key_rotation(session, meta):
    """Rule 6 — KMS keys must have automatic rotation enabled."""
    kms = session.client("kms")
    non_compliant = []
    total = 0
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    # Skip AWS-managed keys and disabled keys
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    if key_meta.get("KeyState") != "Enabled":
                        continue
                    total += 1
                    rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
                    if not rotation.get("KeyRotationEnabled"):
                        non_compliant.append({
                            "resource_name": key_meta.get("KeyId"),
                            "alias": key_meta.get("Description", "No description"),
                            "note": "Automatic key rotation not enabled"
                        })
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_r6_kms_key_rotation error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — KMS Key Rotation", "KMS", "DPDP-R6-CRYPTO-01",
        "KMS keys without automatic rotation increase risk of key compromise affecting personal data encryption.",
        80, "High", non_compliant,
        "Enable automatic annual rotation for all customer-managed KMS keys used to encrypt personal data.", total)


def dpdp_r6_rds_audit_logging(session, meta):
    """Rule 6 — RDS instances must have audit/activity logging enabled."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            logs = db.get("EnabledCloudwatchLogsExports", [])
            engine = db.get("Engine", "")
            # Check for audit logs based on engine type
            needs_audit = True
            if "mysql" in engine and "audit" not in logs:
                needs_audit = False
            elif "postgres" in engine and "postgresql" not in logs:
                needs_audit = False
            elif "oracle" in engine and "audit" not in logs:
                needs_audit = False
            elif "sqlserver" in engine and "audit" not in logs:
                needs_audit = False
            elif not logs:
                needs_audit = False
            if not needs_audit:
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "engine": engine,
                    "enabled_logs": logs,
                    "note": "Audit/activity logging not enabled or not exported to CloudWatch"
                })
    except Exception as e:
        print(f"dpdp_r6_rds_audit_logging error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — RDS Audit Logging", "RDS", "DPDP-R6-LOG-01",
        "Rule 6 mandates activity logs for all systems processing personal data. "
        "RDS instances without audit logging cannot demonstrate access accountability.",
        80, "High", non_compliant,
        "Enable audit logging and export to CloudWatch Logs for all RDS instances. "
        "Retain logs for minimum 1 year per Rule 6 requirements.", total)


def dpdp_r6_one_year_log_retention(session, meta):
    """Rule 6 — Logs must be retained for minimum 1 year for breach detection."""
    logs_client = session.client("logs")
    non_compliant = []
    total = 0
    MIN_RETENTION_DAYS = 365
    try:
        paginator = logs_client.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                total += 1
                retention = lg.get("retentionInDays")
                if retention and retention < MIN_RETENTION_DAYS:
                    non_compliant.append({
                        "resource_name": lg["logGroupName"],
                        "current_retention_days": retention,
                        "note": f"Retention {retention} days — Rule 6 requires minimum 365 days"
                    })
    except Exception as e:
        print(f"dpdp_r6_one_year_log_retention error: {e}")
    _update_meta(meta, "CloudWatch", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — 1-Year Log Retention", "CloudWatch", "DPDP-R6-LOG-02",
        "Rule 6 mandates retention of logs and personal data access records for at least 1 year "
        "to support breach detection and investigation.",
        80, "High", non_compliant,
        "Set CloudWatch log group retention to minimum 365 days for all groups containing "
        "access logs, audit trails, or personal data processing records.", total)


def dpdp_r6_s3_ssl_enforcement(session, meta):
    """Rule 6 — S3 buckets must enforce SSL/TLS for data in transit."""
    import json as _json
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            name = b["Name"]
            try:
                policy = s3.get_bucket_policy(Bucket=name)
                doc = _json.loads(policy["Policy"])
                has_ssl_deny = False
                for stmt in doc.get("Statement", []):
                    condition = stmt.get("Condition", {})
                    bool_cond = condition.get("Bool", {})
                    if (stmt.get("Effect") == "Deny" and
                            bool_cond.get("aws:SecureTransport") == "false"):
                        has_ssl_deny = True
                        break
                if not has_ssl_deny:
                    non_compliant.append({
                        "resource_name": name,
                        "note": "No policy denying non-SSL access"
                    })
            except ClientError as e:
                if "NoSuchBucketPolicy" in str(e):
                    non_compliant.append({
                        "resource_name": name,
                        "note": "No bucket policy — SSL not enforced"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r6_s3_ssl_enforcement error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 SSL/TLS Enforcement", "S3", "DPDP-R6-TRANSIT-01",
        "Rule 6 requires encryption of personal data in transit. S3 buckets without SSL enforcement "
        "allow unencrypted access to personal data.",
        85, "High", non_compliant,
        "Add bucket policy denying requests where aws:SecureTransport is false.", total)


def dpdp_r6_rds_ssl_enforcement(session, meta):
    """Rule 6 — RDS instances must enforce SSL connections for data in transit."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            # Check parameter groups for force_ssl or rds.force_ssl
            params_enforced = False
            for pg in db.get("DBParameterGroups", []):
                try:
                    pg_params = rds.describe_db_parameters(
                        DBParameterGroupName=pg["DBParameterGroupName"]
                    ).get("Parameters", [])
                    for p in pg_params:
                        if p.get("ParameterName") in ("rds.force_ssl", "require_secure_transport"):
                            if p.get("ParameterValue") == "1":
                                params_enforced = True
                                break
                except Exception:
                    pass
                if params_enforced:
                    break
            if not params_enforced:
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine"),
                    "note": "SSL/TLS not enforced via parameter group"
                })
    except Exception as e:
        print(f"dpdp_r6_rds_ssl_enforcement error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — RDS SSL/TLS Enforcement", "RDS", "DPDP-R6-TRANSIT-02",
        "Rule 6 requires encryption in transit. RDS instances without forced SSL allow "
        "unencrypted database connections exposing personal data.",
        85, "High", non_compliant,
        "Enable rds.force_ssl=1 or require_secure_transport=1 in parameter groups.", total)


def dpdp_r6_waf_protection(session, meta):
    """Rule 6 — Web applications processing personal data must have WAF protection."""
    waf = session.client("wafv2")
    elbv2 = session.client("elbv2")
    non_compliant = []
    total = 0
    try:
        # Check ALBs for WAF association
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        albs = [lb for lb in lbs if lb.get("Type") == "application"]
        total = len(albs)
        for alb in albs:
            try:
                waf_assoc = waf.get_web_acl_for_resource(ResourceArn=alb["LoadBalancerArn"])
                if not waf_assoc.get("WebACL"):
                    non_compliant.append({
                        "resource_name": alb["LoadBalancerName"],
                        "arn": alb["LoadBalancerArn"],
                        "note": "ALB has no WAF WebACL attached"
                    })
            except Exception:
                non_compliant.append({
                    "resource_name": alb["LoadBalancerName"],
                    "note": "Unable to verify WAF association"
                })
    except Exception as e:
        print(f"dpdp_r6_waf_protection error: {e}")
    _update_meta(meta, "WAF", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — WAF Protection for Web Apps", "WAF", "DPDP-R6-APP-01",
        "Rule 6 requires technical safeguards against unauthorized access. "
        "Application Load Balancers without WAF are vulnerable to web attacks targeting personal data.",
        80, "High", non_compliant,
        "Attach AWS WAF WebACL to all ALBs serving applications that process personal data. "
        "Configure rules for OWASP Top 10 protection.", total)


def dpdp_r6_iam_access_analyzer(session, meta):
    """Rule 6 — IAM Access Analyzer must be enabled for access control monitoring."""
    aa = session.client("accessanalyzer")
    non_compliant = []
    try:
        analyzers = aa.list_analyzers().get("analyzers", [])
        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        if not active:
            non_compliant.append({
                "resource_name": "IAM Access Analyzer",
                "note": "No active Access Analyzer — external access to personal data not monitored"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDeniedException":
            non_compliant.append({
                "resource_name": "IAM Access Analyzer",
                "note": "Access denied — cannot verify Access Analyzer status"
            })
        else:
            print(f"dpdp_r6_iam_access_analyzer error: {code}")
    except Exception as e:
        print(f"dpdp_r6_iam_access_analyzer error: {e}")
    _update_meta(meta, "IAM", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — IAM Access Analyzer", "IAM", "DPDP-R6-ACCESS-01",
        "Rule 6 mandates access controls and monitoring. Without IAM Access Analyzer, "
        "external or unintended access to resources storing personal data goes undetected.",
        80, "High", non_compliant,
        "Enable IAM Access Analyzer (ACCOUNT type) in all regions. "
        "Review and resolve findings for resources containing personal data.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🚨 RULE 7 — DATA BREACH NOTIFICATION (72-Hour Readiness)
# Must notify Data Protection Board AND affected Data Principals within 72 hours.
# Requires: automated detection, alerting pipeline, incident response readiness.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r7_eventbridge_rules(session, meta):
    """Rule 7 — EventBridge rules must exist for security event routing."""
    eb = session.client("events")
    non_compliant = []
    total = 0
    try:
        rules = eb.list_rules().get("Rules", [])
        total = len(rules)
        # Check if any rules target security-related sources
        security_sources = ["aws.guardduty", "aws.securityhub", "aws.config", "aws.macie"]
        has_security_rule = False
        for rule in rules:
            pattern = rule.get("EventPattern", "")
            if any(src in pattern for src in security_sources):
                has_security_rule = True
                break
        if not has_security_rule:
            non_compliant.append({
                "resource_name": "EventBridge",
                "note": "No EventBridge rules routing security events (GuardDuty/SecurityHub/Config/Macie)"
            })
    except Exception as e:
        print(f"dpdp_r7_eventbridge_rules error: {e}")
    _update_meta(meta, "EventBridge", max(total, 1), non_compliant, "High")
    return _result(
        "DPDP R2025 — Security Event Routing", "EventBridge", "DPDP-R7-BREACH-01",
        "Rule 7 requires breach notification within 72 hours. Without automated security event routing, "
        "breaches may not be detected in time to meet the notification deadline.",
        85, "High", non_compliant,
        "Create EventBridge rules to route GuardDuty, SecurityHub, and Config findings to SNS/Lambda "
        "for automated alerting. Build a 72-hour breach response playbook.", max(total, 1))


def dpdp_r7_securityhub_enabled(session, meta):
    """Rule 7 — Security Hub provides centralized breach detection dashboard."""
    sh = session.client("securityhub")
    non_compliant = []
    try:
        sh.get_enabled_standards()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "SubscriptionRequiredException"):
            non_compliant.append({
                "resource_name": "SecurityHub",
                "note": "Security Hub not enabled — no centralized security findings"
            })
        else:
            print(f"dpdp_r7_securityhub_enabled error: {code}")
    except Exception as e:
        print(f"dpdp_r7_securityhub_enabled error: {e}")
    _update_meta(meta, "SecurityHub", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Security Hub Enabled", "SecurityHub", "DPDP-R7-BREACH-02",
        "Rule 7 requires prompt breach detection. Security Hub aggregates findings from GuardDuty, "
        "Config, Inspector, and Macie into a single view for rapid incident response.",
        85, "High", non_compliant,
        "Enable AWS Security Hub with CIS and AWS Foundational Security Best Practices standards. "
        "Configure automated response actions for critical findings.", 1)


def dpdp_r7_cloudwatch_alarms(session, meta):
    """Rule 7 — CloudWatch alarms must exist for security-critical metrics."""
    cw = session.client("cloudwatch")
    non_compliant = []
    total = 0
    try:
        alarms = cw.describe_alarms(StateValue="OK").get("MetricAlarms", [])
        alarms += cw.describe_alarms(StateValue="ALARM").get("MetricAlarms", [])
        alarms += cw.describe_alarms(StateValue="INSUFFICIENT_DATA").get("MetricAlarms", [])
        total = len(alarms)
        if total == 0:
            non_compliant.append({
                "resource_name": "CloudWatch Alarms",
                "note": "No CloudWatch alarms configured — no automated breach alerting"
            })
        else:
            # Check if any alarms have SNS actions (notification capability)
            has_notification = any(
                a.get("AlarmActions") or a.get("OKActions") for a in alarms
            )
            if not has_notification:
                non_compliant.append({
                    "resource_name": "CloudWatch Alarms",
                    "note": "Alarms exist but none have notification actions configured"
                })
    except Exception as e:
        print(f"dpdp_r7_cloudwatch_alarms error: {e}")
    _update_meta(meta, "CloudWatch", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Security Alerting Pipeline", "CloudWatch", "DPDP-R7-BREACH-03",
        "Rule 7 requires organizations to detect and report breaches within 72 hours. "
        "Without CloudWatch alarms with notification actions, security events go unnoticed.",
        75, "Medium", non_compliant,
        "Create CloudWatch alarms for unauthorized API calls, root account usage, "
        "IAM policy changes, and security group modifications. Route to SNS for team notification.", max(total, 1))


def dpdp_r7_macie_enabled(session, meta):
    """Rule 7 — Amazon Macie for automated personal data discovery and breach detection."""
    macie = session.client("macie2")
    non_compliant = []
    try:
        status = macie.get_macie_session()
        if status.get("status") != "ENABLED":
            non_compliant.append({
                "resource_name": "Macie",
                "note": "Macie not enabled — no automated PII discovery"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ForbiddenException"):
            non_compliant.append({
                "resource_name": "Macie",
                "note": "Macie not enabled or access denied"
            })
        else:
            print(f"dpdp_r7_macie_enabled error: {code}")
    except Exception as e:
        print(f"dpdp_r7_macie_enabled error: {e}")
    _update_meta(meta, "Macie", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Macie PII Discovery", "Macie", "DPDP-R7-BREACH-04",
        "Rule 7 requires knowing where personal data resides to assess breach impact. "
        "Macie automatically discovers and classifies personal data in S3.",
        70, "Medium", non_compliant,
        "Enable Amazon Macie to automatically discover PII in S3 buckets. "
        "Configure automated alerts for sensitive data exposure.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🗑️ RULE 8 — DATA RETENTION & ERASURE
# Personal data must be erased once consent is withdrawn or purpose is fulfilled.
# Data must not be retained beyond the specified retention period.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r8_s3_object_lock(session, meta):
    """Rule 8 — S3 Object Lock can prevent premature deletion but must align with retention."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                lock = s3.get_object_lock_configuration(Bucket=b["Name"])
                config = lock.get("ObjectLockConfiguration", {})
                rule = config.get("Rule", {})
                retention = rule.get("DefaultRetention", {})
                # If COMPLIANCE mode with very long retention, flag it
                if retention.get("Mode") == "COMPLIANCE":
                    days = retention.get("Days", 0)
                    years = retention.get("Years", 0)
                    total_days = days + (years * 365)
                    if total_days > 1095:  # More than 3 years
                        non_compliant.append({
                            "resource_name": b["Name"],
                            "retention": f"{years}y {days}d",
                            "note": "COMPLIANCE lock >3 years may conflict with erasure obligations"
                        })
            except ClientError as e:
                if "ObjectLockConfigurationNotFoundError" in str(e):
                    pass  # No lock is fine — allows erasure
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r8_s3_object_lock error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — S3 Object Lock vs Erasure", "S3", "DPDP-R8-ERASURE-01",
        "Rule 8 requires erasure of personal data when consent is withdrawn. "
        "S3 COMPLIANCE mode locks with excessive retention may prevent timely erasure.",
        65, "Medium", non_compliant,
        "Review Object Lock configurations on buckets storing personal data. "
        "Ensure retention periods align with DPDP erasure obligations.", total)


def dpdp_r8_rds_deletion_protection(session, meta):
    """Rule 8 — RDS deletion protection must be balanced with erasure capability."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            # Flag instances WITHOUT deletion protection — they need it for data integrity
            # but also need documented erasure procedures
            if not db.get("DeletionProtection"):
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "note": "No deletion protection — accidental deletion could cause data loss"
                })
    except Exception as e:
        print(f"dpdp_r8_rds_deletion_protection error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — RDS Deletion Protection", "RDS", "DPDP-R8-ERASURE-02",
        "Rule 8 requires both data protection and erasure capability. "
        "RDS instances without deletion protection risk accidental loss of personal data.",
        65, "Medium", non_compliant,
        "Enable deletion protection on all RDS instances storing personal data. "
        "Document erasure procedures for when consent is withdrawn.", total)


def dpdp_r8_dynamodb_ttl(session, meta):
    """Rule 8 — DynamoDB tables should use TTL for automated data expiry."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                ttl = ddb.describe_time_to_live(TableName=t)
                status = ttl.get("TimeToLiveDescription", {}).get("TimeToLiveStatus")
                if status != "ENABLED":
                    non_compliant.append({
                        "resource_name": t,
                        "ttl_status": status or "DISABLED",
                        "note": "TTL not enabled — no automated data expiry"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r8_dynamodb_ttl error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — DynamoDB TTL for Data Expiry", "DynamoDB", "DPDP-R8-ERASURE-03",
        "Rule 8 requires deletion of personal data once purpose is fulfilled. "
        "DynamoDB tables without TTL retain data indefinitely.",
        65, "Medium", non_compliant,
        "Enable TTL on DynamoDB tables storing personal data with defined retention periods. "
        "Set TTL attribute aligned with your data processing purpose.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🌍 RULE 12 — CROSS-BORDER DATA TRANSFER
# Personal data can be transferred outside India unless restricted by government.
# Significant Data Fiduciaries must prevent transfer of specified data categories.
# Data localization checks for ap-south-1 (Mumbai) region.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r12_s3_replication_regions(session, meta):
    """Rule 12 — S3 cross-region replication must not transfer data to restricted regions."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    # India region
    INDIA_REGIONS = ["ap-south-1", "ap-south-2"]
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                repl = s3.get_bucket_replication(Bucket=b["Name"])
                rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
                for rule in rules:
                    dest = rule.get("Destination", {})
                    dest_bucket = dest.get("Bucket", "")
                    # Check if replication goes outside India
                    # We flag it for review — actual restriction depends on government notification
                    if rule.get("Status") == "Enabled":
                        non_compliant.append({
                            "resource_name": b["Name"],
                            "destination": dest_bucket,
                            "note": "Cross-region replication active — verify destination complies with Rule 12"
                        })
            except ClientError as e:
                if "ReplicationConfigurationNotFoundError" in str(e):
                    pass  # No replication is fine
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r12_s3_replication_regions error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — S3 Cross-Border Replication", "S3", "DPDP-R12-TRANSFER-01",
        "Rule 12 restricts transfer of personal data to countries not approved by the government. "
        "S3 cross-region replication may transfer personal data outside India.",
        70, "Medium", non_compliant,
        "Review S3 replication configurations. Ensure personal data is not replicated to "
        "regions/countries restricted under Rule 12. Document transfer justification.", total)


def dpdp_r12_rds_cross_region_replicas(session, meta):
    """Rule 12 — RDS read replicas in non-India regions may violate data transfer rules."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    INDIA_REGIONS = ["ap-south-1", "ap-south-2"]
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            replicas = db.get("ReadReplicaDBInstanceIdentifiers", [])
            source = db.get("ReadReplicaSourceDBInstanceIdentifier")
            # If this is a replica, check if it's in a non-India region
            current_region = session.region_name
            if source and current_region not in INDIA_REGIONS:
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "region": current_region,
                    "source": source,
                    "note": f"Read replica in {current_region} — personal data transferred outside India"
                })
    except Exception as e:
        print(f"dpdp_r12_rds_cross_region_replicas error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — RDS Cross-Region Replicas", "RDS", "DPDP-R12-TRANSFER-02",
        "Rule 12 restricts cross-border transfer. RDS read replicas outside India "
        "transfer personal data to potentially restricted jurisdictions.",
        80, "High", non_compliant,
        "Review RDS read replicas outside ap-south-1/ap-south-2. "
        "Ensure cross-border transfers comply with Rule 12 restrictions.", total)


def dpdp_r12_dynamodb_global_tables(session, meta):
    """Rule 12 — DynamoDB Global Tables replicate data across regions."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    INDIA_REGIONS = ["ap-south-1", "ap-south-2"]
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                desc = ddb.describe_table(TableName=t)["Table"]
                replicas = desc.get("Replicas", [])
                non_india_replicas = [
                    r["RegionName"] for r in replicas
                    if r.get("RegionName") not in INDIA_REGIONS
                    and r.get("ReplicaStatus") == "ACTIVE"
                ]
                if non_india_replicas:
                    non_compliant.append({
                        "resource_name": t,
                        "non_india_regions": non_india_replicas,
                        "note": f"Global table replicates to: {', '.join(non_india_replicas)}"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r12_dynamodb_global_tables error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — DynamoDB Global Table Regions", "DynamoDB", "DPDP-R12-TRANSFER-03",
        "Rule 12 restricts cross-border data transfer. DynamoDB Global Tables "
        "replicate personal data to regions outside India.",
        80, "High", non_compliant,
        "Review DynamoDB Global Table configurations. Remove replicas in restricted regions "
        "or ensure transfer is permitted under Rule 12.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🏢 RULE 10 — SIGNIFICANT DATA FIDUCIARY (SDF) OBLIGATIONS
# Annual DPIA, independent audit, DPO appointment, algorithmic transparency.
# These checks verify infrastructure readiness for SDF compliance.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r10_backup_cross_region(session, meta):
    """Rule 10 — SDF must ensure business continuity with proper backup strategy."""
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        if total == 0:
            non_compliant.append({
                "resource_name": "AWS Backup",
                "note": "No backup vaults — no centralized backup strategy for personal data"
            })
        else:
            # Check if any backup plans exist
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            if not plans:
                non_compliant.append({
                    "resource_name": "AWS Backup",
                    "note": "Backup vaults exist but no backup plans configured"
                })
    except Exception as e:
        print(f"dpdp_r10_backup_cross_region error: {e}")
    _update_meta(meta, "Backup", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Centralized Backup Strategy", "Backup", "DPDP-R10-SDF-01",
        "Rule 10 requires SDFs to maintain continuity measures. "
        "AWS Backup provides centralized backup management for personal data protection.",
        70, "Medium", non_compliant,
        "Configure AWS Backup with backup plans covering all resources storing personal data. "
        "Ensure backup retention aligns with DPDP requirements.", max(total, 1))


def dpdp_r10_inspector_enabled(session, meta):
    """Rule 10 — SDF must conduct periodic security assessments (DPIA readiness)."""
    inspector = session.client("inspector2")
    non_compliant = []
    try:
        status = inspector.batch_get_account_status(
            accountIds=[session.client("sts").get_caller_identity()["Account"]]
        )
        accounts = status.get("accounts", [])
        if accounts:
            state = accounts[0].get("state", {}).get("status", "")
            if state != "ENABLED":
                non_compliant.append({
                    "resource_name": "Inspector",
                    "status": state,
                    "note": "Inspector not fully enabled — vulnerability assessment incomplete"
                })
        else:
            non_compliant.append({
                "resource_name": "Inspector",
                "note": "Unable to determine Inspector status"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ValidationException"):
            non_compliant.append({
                "resource_name": "Inspector",
                "note": "Inspector not enabled or access denied"
            })
        else:
            print(f"dpdp_r10_inspector_enabled error: {code}")
    except Exception as e:
        print(f"dpdp_r10_inspector_enabled error: {e}")
    _update_meta(meta, "Inspector", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Vulnerability Assessment (Inspector)", "Inspector", "DPDP-R10-SDF-02",
        "Rule 10 requires SDFs to conduct annual DPIAs. AWS Inspector provides automated "
        "vulnerability assessment as part of security posture evaluation.",
        70, "Medium", non_compliant,
        "Enable Amazon Inspector for continuous vulnerability scanning of EC2, Lambda, and ECR. "
        "Use findings as input to annual DPIA process.", 1)


def dpdp_r10_multi_account_org(session, meta):
    """Rule 10 — SDF should use AWS Organizations for centralized governance."""
    org = session.client("organizations")
    non_compliant = []
    try:
        org.describe_organization()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            non_compliant.append({
                "resource_name": "AWS Organizations",
                "note": "Not using AWS Organizations — no centralized governance for personal data"
            })
        elif code == "AccessDeniedException":
            pass  # Can't check, skip
        else:
            print(f"dpdp_r10_multi_account_org error: {code}")
    except Exception as e:
        print(f"dpdp_r10_multi_account_org error: {e}")
    _update_meta(meta, "Organizations", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Centralized Governance (Organizations)", "Organizations", "DPDP-R10-SDF-03",
        "Rule 10 requires SDFs to demonstrate organizational accountability. "
        "AWS Organizations enables centralized policy enforcement across accounts.",
        65, "Medium", non_compliant,
        "Use AWS Organizations with SCPs to enforce data protection policies across all accounts. "
        "Enables centralized audit trail required for DPIA.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🤝 RULE 14 — DATA PROCESSOR OBLIGATIONS
# Data Fiduciary must ensure processors implement adequate safeguards.
# Contracts must mandate security measures. Third-party access must be controlled.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r14_cross_account_access(session, meta):
    """Rule 14 — IAM roles with cross-account trust represent data processor access."""
    iam = session.client("iam")
    import json as _json
    non_compliant = []
    total = 0
    try:
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        account_id = session.client("sts").get_caller_identity()["Account"]
        for role in roles:
            try:
                doc = role.get("AssumeRolePolicyDocument", {})
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        aws_principals = principal.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        for p in aws_principals:
                            if p == "*":
                                non_compliant.append({
                                    "resource_name": role["RoleName"],
                                    "note": "Role trusts ANY AWS account — unrestricted third-party access"
                                })
                                break
                            elif account_id not in p and "arn:aws:iam::" in p:
                                non_compliant.append({
                                    "resource_name": role["RoleName"],
                                    "trusted_account": p,
                                    "note": "Cross-account trust — data processor access"
                                })
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r14_cross_account_access error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Cross-Account Access (Data Processors)", "IAM", "DPDP-R14-PROCESSOR-01",
        "Rule 14 requires Data Fiduciaries to ensure processors implement adequate safeguards. "
        "Cross-account IAM roles represent third-party/processor access to personal data.",
        80, "High", non_compliant,
        "Review all cross-account IAM roles. Ensure each represents a documented data processor "
        "with contractual DPDP obligations. Remove wildcard (*) trust policies.", total)


def dpdp_r14_s3_cross_account_policies(session, meta):
    """Rule 14 — S3 bucket policies granting cross-account access = data processor sharing."""
    import json as _json
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                policy = s3.get_bucket_policy(Bucket=b["Name"])
                doc = _json.loads(policy["Policy"])
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*":
                            non_compliant.append({
                                "resource_name": b["Name"],
                                "note": "Bucket policy allows ANY principal — unrestricted data sharing"
                            })
                            break
                        aws_principals = principal.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        for p in aws_principals:
                            if account_id not in str(p) and p != "*":
                                non_compliant.append({
                                    "resource_name": b["Name"],
                                    "external_principal": p,
                                    "note": "Cross-account bucket policy — data shared with external entity"
                                })
                                break
            except ClientError as e:
                if "NoSuchBucketPolicy" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r14_s3_cross_account_policies error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 Cross-Account Sharing (Data Processors)", "S3", "DPDP-R14-PROCESSOR-02",
        "Rule 14 requires contractual safeguards with data processors. "
        "S3 bucket policies granting cross-account access share personal data with external entities.",
        80, "High", non_compliant,
        "Review S3 bucket policies with cross-account access. Ensure each external principal "
        "is a documented data processor with DPDP-compliant contract.", total)


def dpdp_r14_lambda_third_party_layers(session, meta):
    """Rule 14 — Lambda layers from external accounts represent third-party code processing data."""
    lam = session.client("lambda")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        functions = lam.list_functions().get("Functions", [])
        total = len(functions)
        for fn in functions:
            layers = fn.get("Layers", [])
            for layer in layers:
                layer_arn = layer.get("Arn", "")
                # Check if layer is from a different account
                if f":{account_id}:" not in layer_arn and ":aws:" not in layer_arn:
                    non_compliant.append({
                        "resource_name": fn["FunctionName"],
                        "external_layer": layer_arn,
                        "note": "Uses third-party Lambda layer — external code processes data"
                    })
                    break
    except Exception as e:
        print(f"dpdp_r14_lambda_third_party_layers error: {e}")
    _update_meta(meta, "Lambda", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Lambda Third-Party Layers", "Lambda", "DPDP-R14-PROCESSOR-03",
        "Rule 14 requires oversight of data processors. Lambda functions using third-party layers "
        "execute external code that may process personal data without contractual safeguards.",
        70, "Medium", non_compliant,
        "Audit Lambda functions using external layers. Ensure third-party layer providers "
        "are documented as data processors with appropriate DPDP contracts.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 👶 RULE 9 — CHILDREN'S DATA PROTECTION
# Verifiable parental consent required. Tracking/behavioral monitoring prohibited.
# Special safeguards for persons with disabilities.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r9_cognito_age_verification(session, meta):
    """Rule 9 — Cognito user pools should have age verification attributes."""
    cognito = session.client("cognito-idp")
    non_compliant = []
    total = 0
    try:
        pools = cognito.list_user_pools(MaxResults=60).get("UserPools", [])
        total = len(pools)
        AGE_ATTRIBUTES = ["birthdate", "custom:age", "custom:date_of_birth", "custom:dob"]
        for pool in pools:
            try:
                detail = cognito.describe_user_pool(UserPoolId=pool["Id"])["UserPool"]
                schema = detail.get("SchemaAttributes", [])
                attr_names = [a.get("Name", "").lower() for a in schema]
                has_age = any(age_attr in attr_names for age_attr in AGE_ATTRIBUTES)
                if not has_age:
                    non_compliant.append({
                        "resource_name": pool["Name"],
                        "pool_id": pool["Id"],
                        "note": "No age/birthdate attribute — cannot verify if user is a child"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r9_cognito_age_verification error: {e}")
    _update_meta(meta, "Cognito", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Age Verification (Cognito)", "Cognito", "DPDP-R9-CHILD-01",
        "Rule 9 requires verifiable parental consent for children's data. "
        "Cognito user pools without age/birthdate attributes cannot identify child users.",
        70, "Medium", non_compliant,
        "Add birthdate or custom:age attribute to Cognito user pools. "
        "Implement age gate logic to trigger parental consent flow for minors.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔒 RULE 5 — RIGHTS OF DATA PRINCIPAL
# Right to access, correction, erasure, grievance redressal, and nomination.
# Infrastructure must support these rights technically.
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_r5_s3_intelligent_tiering(session, meta):
    """Rule 5 — Data must be accessible for Data Principal requests (not archived inaccessibly)."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                lc = s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                rules = lc.get("Rules", [])
                for rule in rules:
                    transitions = rule.get("Transitions", [])
                    for t in transitions:
                        storage_class = t.get("StorageClass", "")
                        if storage_class in ("GLACIER", "DEEP_ARCHIVE"):
                            non_compliant.append({
                                "resource_name": b["Name"],
                                "storage_class": storage_class,
                                "note": f"Data transitions to {storage_class} — may delay access requests"
                            })
                            break
                    else:
                        continue
                    break
            except ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_r5_s3_intelligent_tiering error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Low")
    return _result(
        "DPDP R2025 — Data Accessibility for Principal Rights", "S3", "DPDP-R5-RIGHTS-01",
        "Rule 5 grants Data Principals the right to access their data. "
        "S3 buckets with Glacier/Deep Archive transitions may delay fulfilling access requests.",
        50, "Low", non_compliant,
        "Ensure personal data subject to access requests is not archived in Glacier/Deep Archive "
        "without a retrieval plan. Document SLA for fulfilling Data Principal requests.", total)
