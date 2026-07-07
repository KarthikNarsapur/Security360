"""
NDHM/ABDM — Regional Checks
Sections G-K (Audit, Breach, Interoperability, Anonymization, Governance)
+ Service-specific checks (S3, IAM, KMS, Network, API, Database, etc.)

These checks run per-region via the framework_scan hybrid runner.
Total: ~100 regional checks

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
# G — AUDIT TRAIL & LOGGING (10 checks — regional)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_g1_health_data_access_logging(session, meta):
    """NDHM.G.1 — Multi-region trail with data events."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            nc.append({"resource_name": "Account", "note": "No CloudTrail configured"})
        else:
            multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
            if not multi_region:
                nc.append({"resource_name": "CloudTrail", "note": "No multi-region trail"})
    except Exception as e:
        print(f"ndhm_g1 error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Critical")
    return _result("NDHM — Health Data Access Audit Logging", "CloudTrail", "NDHM.G.1",
        "Multi-region CloudTrail required for comprehensive health data access auditing.",
        90, "Critical", nc,
        "Enable multi-region CloudTrail with data events for S3 and DynamoDB.", total)


def ndhm_g2_log_integrity(session, meta):
    """NDHM.G.2 — Log file validation enabled."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        for t in trails:
            if not t.get("LogFileValidationEnabled"):
                nc.append({"resource_name": t.get("Name", "unknown"),
                           "note": "Log file validation disabled"})
    except Exception as e:
        print(f"ndhm_g2 error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("NDHM — Log File Integrity Validation", "CloudTrail", "NDHM.G.2",
        "Log validation ensures tamper detection for health data audit trails.",
        80, "High", nc,
        "Enable LogFileValidationEnabled on all trails.", total)


def ndhm_g3_centralized_log_management(session, meta):
    """NDHM.G.3 — CloudWatch log groups with retention."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups) if groups else 1
        if not groups:
            nc.append({"resource_name": "Account", "note": "No CloudWatch Log groups"})
        else:
            for g in groups:
                if not g.get("retentionInDays"):
                    nc.append({"resource_name": g["logGroupName"],
                               "note": "No retention policy (infinite retention)"})
    except Exception as e:
        print(f"ndhm_g3 error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result("NDHM — Centralized Log Management", "CloudWatch Logs", "NDHM.G.3",
        "Log groups must have defined retention periods for compliance and cost management.",
        65, "Medium", nc,
        "Set retention policies on all log groups (minimum 365 days for health data).", total)


def ndhm_g4_log_encryption(session, meta):
    """NDHM.G.4 — CloudWatch log groups encrypted with KMS."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups)
        for g in groups:
            if not g.get("kmsKeyId"):
                nc.append({"resource_name": g["logGroupName"], "note": "Not KMS encrypted"})
    except Exception as e:
        print(f"ndhm_g4 error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result("NDHM — Log Encryption (KMS)", "CloudWatch Logs", "NDHM.G.4",
        "Health system logs may contain PHI. KMS encryption protects log data at rest.",
        70, "Medium", nc,
        "Associate KMS keys with all CloudWatch log groups.", total)


def ndhm_g5_health_record_access_monitoring(session, meta):
    """NDHM.G.5 — CloudWatch alarms for anomalous access; GuardDuty active."""
    cw = session.client("cloudwatch")
    nc, total = [], 0
    try:
        alarms = cw.describe_alarms().get("MetricAlarms", [])
        total = 1
        if not alarms:
            nc.append({"resource_name": "Account", "note": "No CloudWatch alarms configured"})
    except Exception as e:
        print(f"ndhm_g5 error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("NDHM — Health Record Access Monitoring", "CloudWatch", "NDHM.G.5",
        "Alarms needed to detect anomalous health data access patterns.",
        65, "Medium", nc,
        "Create CloudWatch alarms for failed API calls, unusual S3 access, and auth failures.", total)


def ndhm_g6_admin_activity_logging(session, meta):
    """NDHM.G.6 — CloudTrail Insights for anomaly detection."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        for t in trails:
            try:
                insights = ct.get_insight_selectors(TrailName=t["TrailARN"])
                if not insights.get("InsightSelectors"):
                    nc.append({"resource_name": t.get("Name"), "note": "Insights not enabled"})
            except ClientError:
                nc.append({"resource_name": t.get("Name"), "note": "Insights not configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_g6 error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Medium")
    return _result("NDHM — Admin Activity Logging (Insights)", "CloudTrail", "NDHM.G.6",
        "CloudTrail Insights detects unusual API activity patterns.",
        60, "Medium", nc,
        "Enable CloudTrail Insights on trails covering health infrastructure.", total)


def ndhm_g7_consent_operation_logging(session, meta):
    """NDHM.G.7 — Metric filters for consent-related events."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = 1
        has_filters = False
        for g in groups[:10]:
            try:
                filters = logs.describe_metric_filters(logGroupName=g["logGroupName"]).get("metricFilters", [])
                if filters:
                    has_filters = True
                    break
            except Exception:
                pass
        if not has_filters:
            nc.append({"resource_name": "Account", "note": "No metric filters for security events"})
    except Exception as e:
        print(f"ndhm_g7 error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result("NDHM — Consent Operation Logging (Metric Filters)", "CloudWatch Logs", "NDHM.G.7",
        "Metric filters should capture consent operations and security events.",
        60, "Medium", nc,
        "Create metric filters for consent grant/revoke, IAM changes, and root login events.", total)


def ndhm_g8_log_retention_compliance(session, meta):
    """NDHM.G.8 — Log retention >= 365 days."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups)
        for g in groups:
            retention = g.get("retentionInDays")
            if retention and retention < 365:
                nc.append({"resource_name": g["logGroupName"],
                           "note": f"Retention {retention} days (need 365+)"})
    except Exception as e:
        print(f"ndhm_g8 error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result("NDHM — Log Retention Compliance (365 days)", "CloudWatch Logs", "NDHM.G.8",
        "NDHM requires minimum 365-day log retention for health data audit trails.",
        65, "Medium", nc,
        "Set retentionInDays >= 365 on all health-related log groups.", total)


def ndhm_g9_realtime_alerting(session, meta):
    """NDHM.G.9 — Alarms trigger SNS for unauthorized access."""
    cw = session.client("cloudwatch")
    nc, total = [], 0
    try:
        alarms = cw.describe_alarms().get("MetricAlarms", [])
        total = len(alarms) if alarms else 1
        alarms_with_actions = [a for a in alarms if a.get("AlarmActions")]
        if not alarms_with_actions:
            nc.append({"resource_name": "Account",
                       "note": "No alarms with notification actions configured"})
    except Exception as e:
        print(f"ndhm_g9 error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("NDHM — Real-Time Alerting", "CloudWatch", "NDHM.G.9",
        "Alarms must trigger notifications for unauthorized health data access attempts.",
        60, "Medium", nc,
        "Configure alarm actions (SNS) for security-related CloudWatch alarms.", total)


def ndhm_g10_data_sharing_audit(session, meta):
    """NDHM.G.10 — Data events capture sharing; metric filters flag cross-account access."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = 1
        data_events = False
        for t in trails:
            try:
                sel = ct.get_event_selectors(TrailName=t["TrailARN"])
                for es in sel.get("EventSelectors", []):
                    if es.get("DataResources"):
                        data_events = True
                        break
                if not data_events:
                    if sel.get("AdvancedEventSelectors"):
                        data_events = True
            except Exception:
                pass
            if data_events:
                break
        if not data_events:
            nc.append({"resource_name": "CloudTrail",
                       "note": "No data events for sharing/disclosure audit"})
    except Exception as e:
        print(f"ndhm_g10 error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("NDHM — Data Sharing/Disclosure Audit", "CloudTrail", "NDHM.G.10",
        "All health data sharing must be logged via CloudTrail data events.",
        75, "High", nc,
        "Enable S3 data events in CloudTrail for complete data access audit.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# H — BREACH NOTIFICATION & INCIDENT MANAGEMENT (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_h1_breach_detection(session, meta):
    """NDHM.H.1 — GuardDuty and Security Hub active."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if not detectors:
            nc.append({"resource_name": "GuardDuty", "note": "Not enabled"})
        try:
            sh = session.client("securityhub")
            sh.describe_hub()
        except ClientError:
            nc.append({"resource_name": "Security Hub", "note": "Not enabled"})
    except Exception as e:
        print(f"ndhm_h1 error: {e}")
    _meta(meta, "GuardDuty", total, nc, "Critical")
    return _result("NDHM — Breach Detection Mechanisms", "GuardDuty", "NDHM.H.1",
        "NDHM requires automated breach detection. GuardDuty + Security Hub provide this.",
        90, "Critical", nc,
        "Enable both GuardDuty and Security Hub for comprehensive breach detection.", total)


def ndhm_h2_breach_notification(session, meta):
    """NDHM.H.2 — EventBridge rules + SNS for 72-hour notification."""
    nc, total = [], 0
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = 1
        security_rules = [r for r in rules if any(
            x in r.get("Name", "").lower() for x in ["guard", "security", "breach", "finding"]
        )]
        if not security_rules:
            nc.append({"resource_name": "EventBridge",
                       "note": "No rules for security finding events"})
        if not topics:
            nc.append({"resource_name": "SNS", "note": "No notification topics"})
    except Exception as e:
        print(f"ndhm_h2 error: {e}")
    _meta(meta, "EventBridge", total, nc, "High")
    return _result("NDHM — Breach Notification Infrastructure", "EventBridge", "NDHM.H.2",
        "72-hour breach notification to NHA/CERT-In requires automated event routing.",
        80, "High", nc,
        "Create EventBridge rules for GuardDuty/SecurityHub findings → SNS notification.", total)


def ndhm_h3_incident_response_plans(session, meta):
    """NDHM.H.3 — Incident Manager response plans defined."""
    nc, total = [], 0
    try:
        total = 1
        ssm_inc = session.client("ssm-incidents")
        plans = ssm_inc.list_response_plans().get("responsePlanSummaries", [])
        if not plans:
            nc.append({"resource_name": "Account", "note": "No incident response plans defined"})
    except ClientError:
        nc.append({"resource_name": "SSM Incidents", "note": "Incident Manager not configured"})
    except Exception as e:
        print(f"ndhm_h3 error: {e}")
    _meta(meta, "SSM Incidents", total, nc, "High")
    return _result("NDHM — Incident Response Plans", "SSM Incidents", "NDHM.H.3",
        "Predefined response plans ensure rapid, coordinated breach response.",
        75, "High", nc,
        "Create Incident Manager response plans for health data breach scenarios.", total)


def ndhm_h4_security_event_correlation(session, meta):
    """NDHM.H.4 — Security Hub with standards enabled."""
    nc, total = [], 0
    try:
        sh = session.client("securityhub")
        total = 1
        try:
            standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
            if not standards:
                nc.append({"resource_name": "Security Hub", "note": "No standards enabled"})
        except ClientError:
            nc.append({"resource_name": "Security Hub", "note": "Not enabled"})
    except Exception as e:
        print(f"ndhm_h4 error: {e}")
    _meta(meta, "Security Hub", total, nc, "Medium")
    return _result("NDHM — Security Event Correlation", "Security Hub", "NDHM.H.4",
        "Security Hub with standards provides centralized, correlated security findings.",
        65, "Medium", nc,
        "Enable AWS FSBP and CIS standards in Security Hub.", total)


def ndhm_h5_automated_escalation(session, meta):
    """NDHM.H.5 — EventBridge + Lambda for incident escalation."""
    nc, total = [], 0
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        total = 1
        lambda_targets = False
        for r in rules[:20]:
            try:
                targets = eb.list_targets_by_rule(Rule=r["Name"]).get("Targets", [])
                if any("lambda" in t.get("Arn", "").lower() for t in targets):
                    lambda_targets = True
                    break
            except Exception:
                pass
        if not lambda_targets:
            nc.append({"resource_name": "Account",
                       "note": "No EventBridge→Lambda escalation workflows detected"})
    except Exception as e:
        print(f"ndhm_h5 error: {e}")
    _meta(meta, "EventBridge", total, nc, "Medium")
    return _result("NDHM — Automated Incident Escalation", "EventBridge", "NDHM.H.5",
        "Automated escalation via EventBridge→Lambda ensures rapid incident response.",
        60, "Medium", nc,
        "Configure EventBridge rules with Lambda targets for incident escalation.", total)


def ndhm_h6_evidence_preservation(session, meta):
    """NDHM.H.6 — CloudTrail data events + Object Lock for evidence."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails) if trails else 1
        for t in trails:
            if not t.get("LogFileValidationEnabled"):
                nc.append({"resource_name": t.get("Name"),
                           "note": "Log validation disabled — evidence can be tampered"})
                break
    except Exception as e:
        print(f"ndhm_h6 error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("NDHM — Evidence Preservation", "CloudTrail", "NDHM.H.6",
        "Incident evidence must be preserved with integrity. Log validation prevents tampering.",
        75, "High", nc,
        "Enable log file validation and store logs in Object Lock-protected buckets.", total)


def ndhm_h7_regulatory_notification(session, meta):
    """NDHM.H.7 — Notification channels for NHA/CERT-In."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = 1
        has_confirmed = False
        for t in topics[:10]:
            subs = sns.list_subscriptions_by_topic(TopicArn=t["TopicArn"]).get("Subscriptions", [])
            if any(s.get("SubscriptionArn") not in ("PendingConfirmation", "Deleted") for s in subs):
                has_confirmed = True
                break
        if not has_confirmed:
            nc.append({"resource_name": "Account",
                       "note": "No confirmed notification subscribers for regulatory reporting"})
    except Exception as e:
        print(f"ndhm_h7 error: {e}")
    _meta(meta, "SNS", total, nc, "High")
    return _result("NDHM — NHA/CERT-In Notification Readiness", "SNS", "NDHM.H.7",
        "6-hour CERT-In and 72-hour NHA notification requires confirmed subscribers.",
        75, "High", nc,
        "Ensure SNS topics have confirmed subscribers for regulatory breach notification.", total)


def ndhm_h8_post_incident_review(session, meta):
    """NDHM.H.8 — Audit Manager assessments for post-incident reviews."""
    nc, total = [], 0
    try:
        total = 1
        am = session.client("auditmanager")
        try:
            assessments = am.list_assessments().get("assessmentMetadata", [])
            if not assessments:
                nc.append({"resource_name": "Audit Manager", "note": "No assessments active"})
        except ClientError:
            nc.append({"resource_name": "Audit Manager", "note": "Not enabled"})
    except Exception as e:
        print(f"ndhm_h8 error: {e}")
    _meta(meta, "Audit Manager", total, nc, "Low")
    return _result("NDHM — Post-Incident Review Mechanisms", "Audit Manager", "NDHM.H.8",
        "Post-incident assessments capture lessons learned and remediation evidence.",
        40, "Low", nc,
        "Enable Audit Manager with health-specific assessment frameworks.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL SERVICE CHECKS — KMS, Network, RDS, API, Monitoring, Backup
# ═══════════════════════════════════════════════════════════════════════════════


# --- KMS (7 checks) ---

def ndhm_kms_rotation(session, meta):
    """NDHM.KMS.1 — Key rotation enabled."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER" and desc.get("KeyState") == "Enabled":
                    total += 1
                    rot = kms.get_key_rotation_status(KeyId=k["KeyId"])
                    if not rot.get("KeyRotationEnabled"):
                        nc.append({"resource_name": k["KeyId"][:8] + "...",
                                   "note": "Key rotation not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_kms_rotation error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("NDHM — KMS Key Rotation", "KMS", "NDHM.KMS.1",
        "Annual key rotation required for health data encryption keys.",
        80, "High", nc, "Enable automatic key rotation on all customer-managed keys.", total)


def ndhm_kms_disabled(session, meta):
    """NDHM.KMS.2 — No disabled keys protecting active data."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER":
                    total += 1
                    if desc.get("KeyState") == "Disabled":
                        nc.append({"resource_name": k["KeyId"][:8] + "...", "note": "Key disabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_kms_disabled error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("NDHM — Disabled KMS Keys", "KMS", "NDHM.KMS.2",
        "Disabled keys may protect active health data, causing access failures.",
        75, "High", nc, "Re-enable or schedule rotation for disabled keys.", total)


def ndhm_kms_pending_deletion(session, meta):
    """NDHM.KMS.3 — No keys pending deletion."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER":
                    total += 1
                    if desc.get("KeyState") == "PendingDeletion":
                        nc.append({"resource_name": k["KeyId"][:8] + "...",
                                   "note": "Key pending deletion"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_kms_pending_deletion error: {e}")
    _meta(meta, "KMS", total, nc, "Critical")
    return _result("NDHM — Pending Deletion KMS Keys", "KMS", "NDHM.KMS.3",
        "Keys pending deletion will render encrypted health data permanently inaccessible.",
        90, "Critical", nc, "Cancel key deletion or migrate data to new keys.", total)


def ndhm_kms_key_policy(session, meta):
    """NDHM.KMS.4 — Key policies restrict access to authorized roles."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:30]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") != "CUSTOMER":
                    continue
                total += 1
                policy = _json.loads(kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"])
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            if not stmt.get("Condition"):
                                nc.append({"resource_name": k["KeyId"][:8] + "...",
                                           "note": "Key policy allows Principal:* without Condition"})
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_kms_key_policy error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("NDHM — KMS Key Policy Validation", "KMS", "NDHM.KMS.4",
        "Key policies must restrict access to authorized health system roles only.",
        80, "High", nc, "Remove wildcard principals from KMS key policies.", total)


def ndhm_kms_cmk_usage(session, meta):
    """NDHM.KMS.5 — Customer-managed keys in use."""
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
            nc.append({"resource_name": "Account", "note": "No customer-managed KMS keys active"})
    except Exception as e:
        print(f"ndhm_kms_cmk_usage error: {e}")
    _meta(meta, "KMS", total, nc, "Medium")
    return _result("NDHM — Customer-Managed Key Usage", "KMS", "NDHM.KMS.5",
        "Customer-managed keys provide granular access control for health data.",
        65, "Medium", nc, "Create and use customer-managed KMS keys for health data encryption.", total)


# --- Network (10 checks) ---

def ndhm_net_db_sg_exposed(session, meta):
    """NDHM.NET.1 — Database SGs not exposed to 0.0.0.0/0."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        db_ports = {3306, 5432, 1433, 5439, 27017, 6379}
        total = len(sgs)
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                if from_port in db_ports or to_port in db_ports:
                    for ip in perm.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            nc.append({"resource_name": sg["GroupId"],
                                       "note": f"DB port {from_port} open to 0.0.0.0/0"})
                            break
    except Exception as e:
        print(f"ndhm_net_db_sg error: {e}")
    _meta(meta, "EC2", total, nc, "Critical")
    return _result("NDHM — Database Security Groups Exposed", "EC2", "NDHM.NET.1",
        "Database ports open to the internet expose health data to unauthorized access.",
        95, "Critical", nc, "Restrict database SG inbound to specific private CIDR ranges.", total)


def ndhm_net_vpc_flow_logs(session, meta):
    """NDHM.NET.9 — VPC Flow Logs enabled."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = len(vpcs)
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        logged_vpcs = {fl.get("ResourceId") for fl in flow_logs}
        for vpc in vpcs:
            if vpc["VpcId"] not in logged_vpcs:
                nc.append({"resource_name": vpc["VpcId"], "note": "No VPC flow logs"})
    except Exception as e:
        print(f"ndhm_net_vpc_flow_logs error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("NDHM — VPC Flow Logs", "EC2", "NDHM.NET.9",
        "Flow logs required for network forensics and anomaly detection in health VPCs.",
        80, "High", nc, "Enable VPC flow logs on all VPCs hosting health infrastructure.", total)


def ndhm_net_vpc_endpoint_s3(session, meta):
    """NDHM.NET.3 — VPC endpoint for S3."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        total = 1
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        s3_ep = any("s3" in ep.get("ServiceName", "") for ep in endpoints)
        if not s3_ep:
            nc.append({"resource_name": "VPC", "note": "No VPC endpoint for S3"})
    except Exception as e:
        print(f"ndhm_net_vpc_endpoint_s3 error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("NDHM — VPC Endpoint for S3", "EC2", "NDHM.NET.3",
        "VPC endpoints keep health data traffic off the public internet.",
        65, "Medium", nc, "Create a gateway VPC endpoint for S3 in each health VPC.", total)


def ndhm_net_waf_alb(session, meta):
    """NDHM.NET.7 — WAF on public-facing health ALBs."""
    nc, total = [], 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        public_albs = [lb for lb in lbs if lb.get("Scheme") == "internet-facing"
                       and lb.get("Type") == "application"]
        total = len(public_albs)
        if public_albs:
            try:
                wafv2 = session.client("wafv2")
                acls = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
                protected_arns = set()
                for acl in acls:
                    try:
                        resources = wafv2.list_resources_for_web_acl(
                            WebACLArn=acl["ARN"]).get("ResourceArns", [])
                        protected_arns.update(resources)
                    except Exception:
                        pass
                for lb in public_albs:
                    if lb["LoadBalancerArn"] not in protected_arns:
                        nc.append({"resource_name": lb["LoadBalancerName"],
                                   "note": "Public ALB without WAF"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_net_waf_alb error: {e}")
    _meta(meta, "WAF", total, nc, "High")
    return _result("NDHM — WAF on Public Health ALBs", "WAF", "NDHM.NET.7",
        "Public-facing health APIs must be protected by WAF against OWASP attacks.",
        80, "High", nc, "Associate WAF web ACL with all internet-facing ALBs.", total)


# --- RDS / Database (9 checks) ---

def ndhm_db_encryption(session, meta):
    """NDHM.DB.1 — RDS encryption at rest."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("StorageEncrypted"):
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": "Storage not encrypted"})
    except Exception as e:
        print(f"ndhm_db_encryption error: {e}")
    _meta(meta, "RDS", total, nc, "Critical")
    return _result("NDHM — RDS Encryption at Rest", "RDS", "NDHM.DB.1",
        "Health databases must be encrypted at rest per NDHM security requirements.",
        95, "Critical", nc, "Enable encryption on all RDS instances. Migrate unencrypted instances.", total)


def ndhm_db_not_public(session, meta):
    """NDHM.DB.2 — RDS not publicly accessible."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if db.get("PubliclyAccessible"):
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": "Publicly accessible"})
    except Exception as e:
        print(f"ndhm_db_not_public error: {e}")
    _meta(meta, "RDS", total, nc, "Critical")
    return _result("NDHM — RDS Not Publicly Accessible", "RDS", "NDHM.DB.2",
        "Health databases must never be publicly accessible.",
        100, "Critical", nc, "Disable PubliclyAccessible on all health RDS instances.", total)


def ndhm_db_deletion_protection(session, meta):
    """NDHM.DB.3 — Deletion protection enabled."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("DeletionProtection"):
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": "Deletion protection disabled"})
    except Exception as e:
        print(f"ndhm_db_deletion_protection error: {e}")
    _meta(meta, "RDS", total, nc, "High")
    return _result("NDHM — RDS Deletion Protection", "RDS", "NDHM.DB.3",
        "Prevents accidental health data loss from database deletion.",
        80, "High", nc, "Enable DeletionProtection on all health databases.", total)


def ndhm_db_backup_retention(session, meta):
    """NDHM.DB.4 — Backup retention >= 35 days."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            retention = db.get("BackupRetentionPeriod", 0)
            if retention < 35:
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": f"Retention: {retention} days (need 35+)"})
    except Exception as e:
        print(f"ndhm_db_backup_retention error: {e}")
    _meta(meta, "RDS", total, nc, "Medium")
    return _result("NDHM — RDS Backup Retention", "RDS", "NDHM.DB.4",
        "Health databases need extended backup retention for data recovery.",
        65, "Medium", nc, "Set BackupRetentionPeriod to at least 35 days.", total)


def ndhm_db_india_region(session, meta):
    """NDHM.DB.6 — RDS instances in India regions only."""
    rds = session.client("rds")
    region = session.region_name
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        if region not in INDIA_REGIONS:
            for db in instances:
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": f"Located in {region} — outside India"})
    except Exception as e:
        print(f"ndhm_db_india_region error: {e}")
    _meta(meta, "RDS", total, nc, "Critical")
    return _result("NDHM — RDS Data Residency (India Only)", "RDS", "NDHM.DB.6",
        "Health databases MUST be in ap-south-1 or ap-south-2.",
        100, "Critical", nc, "Migrate RDS instances to Indian regions.", total)


# --- API Security (6 checks) ---

def ndhm_api_authorization(session, meta):
    """NDHM.API.1 — All API endpoints have authorization."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            resources = apigw.get_resources(restApiId=api["id"]).get("items", [])
            for res in resources:
                methods = res.get("resourceMethods", {})
                for method_name in methods:
                    if method_name == "OPTIONS":
                        continue
                    total += 1
                    try:
                        method = apigw.get_method(restApiId=api["id"],
                                                  resourceId=res["id"], httpMethod=method_name)
                        if method.get("authorizationType") == "NONE":
                            nc.append({"resource_name": f"{api['name']}{res.get('path', '')}",
                                       "note": f"{method_name} has no authorization"})
                    except Exception:
                        pass
    except Exception as e:
        print(f"ndhm_api_authorization error: {e}")
    _meta(meta, "API Gateway", total, nc, "Critical")
    return _result("NDHM — API Authorization", "API Gateway", "NDHM.API.1",
        "All health API endpoints must have authorization. NONE type exposes PHI.",
        90, "Critical", nc, "Add Cognito, IAM, or Lambda authorizers to all API methods.", total)


def ndhm_api_access_logging(session, meta):
    """NDHM.API.2 — Access logging enabled on API stages."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            stages = apigw.get_stages(restApiId=api["id"]).get("item", [])
            for stage in stages:
                total += 1
                if not stage.get("accessLogSettings"):
                    nc.append({"resource_name": f"{api['name']}/{stage['stageName']}",
                               "note": "Access logging not enabled"})
    except Exception as e:
        print(f"ndhm_api_access_logging error: {e}")
    _meta(meta, "API Gateway", total, nc, "High")
    return _result("NDHM — API Access Logging", "API Gateway", "NDHM.API.2",
        "Access logging provides audit trail for all health API requests.",
        75, "High", nc, "Enable access logging on all API Gateway stages.", total)


def ndhm_api_tls_version(session, meta):
    """NDHM.API.4 — TLS 1.2 minimum enforced."""
    nc, total = [], 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            listeners = elbv2.describe_listeners(
                LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
            for l in listeners:
                if l.get("Protocol") == "HTTPS":
                    total += 1
                    ssl_policy = l.get("SslPolicy", "")
                    if "TLS-1-0" in ssl_policy or "TLS-1-1" in ssl_policy:
                        nc.append({"resource_name": lb["LoadBalancerName"],
                                   "note": f"SSL policy {ssl_policy} allows TLS < 1.2"})
    except Exception as e:
        print(f"ndhm_api_tls_version error: {e}")
    _meta(meta, "ELB", total, nc, "High")
    return _result("NDHM — TLS 1.2 Minimum Enforcement", "ELB", "NDHM.API.4",
        "Health data in transit must use TLS 1.2+. Older versions have known vulnerabilities.",
        80, "High", nc, "Use ELBSecurityPolicy-TLS13 or TLS-1-2 policies.", total)


def ndhm_api_acm_expiry(session, meta):
    """NDHM.API.6 — No expired/expiring certificates."""
    nc, total = [], 0
    try:
        acm = session.client("acm")
        certs = acm.list_certificates().get("CertificateSummaryList", [])
        total = len(certs)
        now = datetime.now(timezone.utc)
        for c in certs:
            not_after = c.get("NotAfter")
            if not_after:
                days_left = (not_after - now).days
                if days_left < 0:
                    nc.append({"resource_name": c.get("DomainName", "unknown"),
                               "note": "Certificate EXPIRED"})
                elif days_left < 30:
                    nc.append({"resource_name": c.get("DomainName", "unknown"),
                               "note": f"Expires in {days_left} days"})
    except Exception as e:
        print(f"ndhm_api_acm_expiry error: {e}")
    _meta(meta, "ACM", total, nc, "High")
    return _result("NDHM — ACM Certificate Validity", "ACM", "NDHM.API.6",
        "Expired certificates cause outages and security warnings on health endpoints.",
        80, "High", nc, "Renew or replace certificates expiring within 30 days.", total)
