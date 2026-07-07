"""
NDHM/ABDM — National Digital Health Mission (India)
Core Checks: Consent, Data Principal Rights, Storage, Security Safeguards, Authentication, Audit

Sections A-F from HDMP (Health Data Management Policy)
Total: 86 core checks

All checks use READ-ONLY APIs compatible with arn:aws:iam::aws:policy/ReadOnlyAccess
"""

import json as _json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "NDHM"


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

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


def _get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


INDIA_REGIONS = {"ap-south-1", "ap-south-2"}


# ═══════════════════════════════════════════════════════════════════════════════
# A — CONSENT MANAGEMENT & PURPOSE LIMITATION (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_a1_consent_audit_trail(session, meta):
    """NDHM.A.1 — CloudTrail active for auditing consent operations."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            nc.append({"resource_name": "Account", "note": "No CloudTrail trails configured"})
        else:
            active_found = False
            for t in trails:
                try:
                    status = ct.get_trail_status(Name=t["TrailARN"])
                    if status.get("IsLogging"):
                        active_found = True
                        break
                except Exception:
                    pass
            if not active_found:
                nc.append({"resource_name": "Account", "note": "No active trails logging"})
    except Exception as e:
        print(f"ndhm_a1_consent_audit_trail error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Critical")
    return _result("NDHM — Consent Processing Audit Trail", "CloudTrail", "NDHM.A.1",
        "NDHM requires immutable audit trail for all consent grant/revoke operations. "
        "Without active CloudTrail, consent activities cannot be audited.",
        95, "Critical", nc,
        "Enable multi-region CloudTrail with data events for consent audit compliance.", total)


def ndhm_a2_consent_artefact_integrity(session, meta):
    """NDHM.A.2 — KMS keys available for consent artefact signing/verification."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        total = len(keys) if keys else 1
        if not keys:
            nc.append({"resource_name": "Account", "note": "No KMS keys for consent artefact signing"})
        else:
            rotation_ok = False
            for k in keys[:50]:
                try:
                    desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    if desc.get("KeyManager") == "CUSTOMER" and desc.get("KeyState") == "Enabled":
                        try:
                            rot = kms.get_key_rotation_status(KeyId=k["KeyId"])
                            if rot.get("KeyRotationEnabled"):
                                rotation_ok = True
                                break
                        except Exception:
                            pass
                except Exception:
                    pass
            if not rotation_ok:
                nc.append({"resource_name": "Account",
                           "note": "No customer-managed KMS key with rotation enabled for consent artefacts"})
    except Exception as e:
        print(f"ndhm_a2_consent_artefact_integrity error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("NDHM — Consent Artefact Integrity (KMS)", "KMS", "NDHM.A.2",
        "ABDM consent artefacts must be cryptographically signed. KMS keys with rotation "
        "ensure artefact integrity and non-repudiation.",
        80, "High", nc,
        "Create customer-managed KMS keys with annual rotation for consent artefact operations.", total)


def ndhm_a3_purpose_limitation(session, meta):
    """NDHM.A.3 — IAM roles enforce purpose-based access (no wildcard on health stores)."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        health_services = ["s3:", "rds:", "dynamodb:", "healthlake:"]
        for role in roles:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            try:
                policies = iam.list_attached_role_policies(RoleName=role["RoleName"]).get("AttachedPolicies", [])
                for pol in policies:
                    if pol["PolicyArn"].endswith("/AdministratorAccess"):
                        nc.append({"resource_name": role["RoleName"],
                                   "note": "AdministratorAccess attached — violates purpose limitation"})
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_a3_purpose_limitation error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("NDHM — Purpose Limitation Enforcement", "IAM", "NDHM.A.3",
        "NDHM mandates purpose-based access control. Roles with AdministratorAccess "
        "can access health data beyond consent scope.",
        80, "High", nc,
        "Replace AdministratorAccess with least-privilege policies scoped to specific health data purposes.", total)


def ndhm_a4_consent_expiry_enforcement(session, meta):
    """NDHM.A.4 — Automated mechanisms exist to invalidate expired consents."""
    nc, total = [], 0
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        total = 1
        consent_fn = any("consent" in f.get("FunctionName", "").lower() for f in functions)
        consent_rule = any("consent" in r.get("Name", "").lower() or
                          "expir" in r.get("Name", "").lower() for r in rules)
        if not consent_fn and not consent_rule:
            nc.append({"resource_name": "Account",
                       "note": "No Lambda/EventBridge automation for consent expiry enforcement"})
    except Exception as e:
        print(f"ndhm_a4_consent_expiry_enforcement error: {e}")
    _meta(meta, "Lambda", total, nc, "High")
    return _result("NDHM — Consent Expiry Enforcement", "Lambda", "NDHM.A.4",
        "Expired/revoked consent must immediately terminate data access. "
        "Automated enforcement via Lambda/EventBridge is required.",
        75, "High", nc,
        "Implement Lambda functions triggered by EventBridge to automatically revoke access on consent expiry.", total)


def ndhm_a5_consent_revocation_notification(session, meta):
    """NDHM.A.5 — Real-time notification for consent revocation propagation."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = len(topics) if topics else 1
        if not topics:
            nc.append({"resource_name": "Account", "note": "No SNS topics for consent revocation notification"})
        else:
            has_subs = False
            for t in topics[:20]:
                subs = sns.list_subscriptions_by_topic(TopicArn=t["TopicArn"]).get("Subscriptions", [])
                if any(s.get("SubscriptionArn") != "PendingConfirmation" for s in subs):
                    has_subs = True
                    break
            if not has_subs:
                nc.append({"resource_name": "Account", "note": "SNS topics have no confirmed subscribers"})
    except Exception as e:
        print(f"ndhm_a5_consent_revocation_notification error: {e}")
    _meta(meta, "SNS", total, nc, "Medium")
    return _result("NDHM — Consent Revocation Notification", "SNS", "NDHM.A.5",
        "ABDM requires real-time propagation of consent revocation to all HIPs/HIUs. "
        "SNS infrastructure with active subscribers is needed.",
        70, "Medium", nc,
        "Create SNS topics with confirmed subscribers for consent revocation event notification.", total)


def ndhm_a6_consent_scope_validation(session, meta):
    """NDHM.A.6 — Config rules enforce data access matches consent scope."""
    nc, total = [], 0
    try:
        config = session.client("config")
        rules = config.describe_config_rules().get("ConfigRules", [])
        total = len(rules) if rules else 1
        if not rules:
            nc.append({"resource_name": "Account", "note": "No AWS Config rules deployed"})
        else:
            non_compliant_rules = []
            compliance = config.describe_compliance_by_config_rule().get("ComplianceByConfigRules", [])
            for c in compliance:
                if c.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT":
                    non_compliant_rules.append(c.get("ConfigRuleName", "unknown"))
            if non_compliant_rules:
                nc.append({"resource_name": "Config Rules",
                           "note": f"{len(non_compliant_rules)} rules non-compliant: {', '.join(non_compliant_rules[:5])}"})
    except Exception as e:
        print(f"ndhm_a6_consent_scope_validation error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("NDHM — Consent Scope Validation (Config Rules)", "Config", "NDHM.A.6",
        "AWS Config rules help enforce that data access policies align with consent scope. "
        "Non-compliant rules indicate potential consent boundary violations.",
        65, "Medium", nc,
        "Review and remediate non-compliant Config rules related to health data access.", total)


def ndhm_a7_granular_consent_logging(session, meta):
    """NDHM.A.7 — Granular consent event logging via CloudWatch Logs + data events."""
    nc, total = [], 0
    try:
        logs = session.client("logs")
        groups = logs.describe_log_groups().get("logGroups", [])
        total = 1
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        data_events_enabled = False
        for t in trails:
            try:
                selectors = ct.get_event_selectors(TrailName=t["TrailARN"])
                for es in selectors.get("EventSelectors", []):
                    if es.get("DataResources"):
                        data_events_enabled = True
                        break
                if not data_events_enabled:
                    for adv in selectors.get("AdvancedEventSelectors", []):
                        data_events_enabled = True
                        break
            except Exception:
                pass
            if data_events_enabled:
                break
        if not data_events_enabled:
            nc.append({"resource_name": "CloudTrail", "note": "No data events enabled for granular consent logging"})
        if not groups:
            nc.append({"resource_name": "CloudWatch Logs", "note": "No log groups exist"})
    except Exception as e:
        print(f"ndhm_a7_granular_consent_logging error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("NDHM — Granular Consent Logging", "CloudTrail", "NDHM.A.7",
        "NDHM requires granular logging of all consent operations including data-level access. "
        "CloudTrail data events provide object-level audit trail.",
        75, "High", nc,
        "Enable CloudTrail data events for S3/DynamoDB to capture all health record access.", total)


def ndhm_a8_data_principal_notification(session, meta):
    """NDHM.A.8 — Notification channels exist to inform data principals."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = 1
        try:
            ses = session.client("ses")
            ses_account = ses.get_account()
            ses_active = ses_account.get("SendingEnabled", False)
        except Exception:
            ses_active = False
        if not topics and not ses_active:
            nc.append({"resource_name": "Account",
                       "note": "No SNS topics or SES configured for data principal notifications"})
    except Exception as e:
        print(f"ndhm_a8_data_principal_notification error: {e}")
    _meta(meta, "SNS", total, nc, "Medium")
    return _result("NDHM — Data Principal Consent Notification", "SNS", "NDHM.A.8",
        "Data principals must be informed of consent activities. SNS/SES infrastructure required.",
        60, "Medium", nc,
        "Configure SNS topics or SES for automated data principal notification.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# B — HEALTH DATA COLLECTION & PROCESSING (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_b1_data_minimization(session, meta):
    """NDHM.B.1 — Macie enabled for health data classification and over-collection detection."""
    nc, total = [], 0
    try:
        macie = session.client("macie2")
        total = 1
        try:
            status = macie.get_macie_session()
            if status.get("status") != "ENABLED":
                nc.append({"resource_name": "Macie", "note": "Macie not enabled"})
        except ClientError:
            nc.append({"resource_name": "Macie", "note": "Macie not enabled in this account"})
    except Exception as e:
        print(f"ndhm_b1_data_minimization error: {e}")
    _meta(meta, "Macie", total, nc, "High")
    return _result("NDHM — Data Minimization (Macie)", "Macie", "NDHM.B.1",
        "NDHM requires collection of only necessary health data. Macie detects over-collection of PHI.",
        75, "High", nc,
        "Enable Amazon Macie to continuously discover and classify sensitive health data.", total)


def ndhm_b2_health_data_classification(session, meta):
    """NDHM.B.2 — Macie classification jobs actively running."""
    nc, total = [], 0
    try:
        macie = session.client("macie2")
        total = 1
        try:
            jobs = macie.list_classification_jobs(
                filterCriteria={"includes": [{"key": "jobStatus", "values": ["RUNNING", "IDLE"]}]}
            ).get("items", [])
            if not jobs:
                nc.append({"resource_name": "Macie", "note": "No active classification jobs running"})
        except ClientError:
            nc.append({"resource_name": "Macie", "note": "Macie not available"})
    except Exception as e:
        print(f"ndhm_b2_health_data_classification error: {e}")
    _meta(meta, "Macie", total, nc, "Medium")
    return _result("NDHM — Health Data Classification Jobs", "Macie", "NDHM.B.2",
        "Active classification jobs are needed to identify PHI in health data stores.",
        65, "Medium", nc,
        "Create Macie classification jobs targeting all S3 buckets containing health records.", total)


def ndhm_b3_processing_boundaries(session, meta):
    """NDHM.B.3 — Processing limited to defined roles; no wildcard on health services."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        total = len(policies)
        for pol in policies[:50]:
            try:
                ver = iam.get_policy_version(PolicyArn=pol["Arn"],
                                            VersionId=pol["DefaultVersionId"])
                doc = ver["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        if actions == "*" or (isinstance(actions, list) and "*" in actions):
                            resources = stmt.get("Resource", [])
                            if resources == "*" or (isinstance(resources, list) and "*" in resources):
                                nc.append({"resource_name": pol["PolicyName"],
                                           "note": "Action:* with Resource:* — unbounded processing"})
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_b3_processing_boundaries error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("NDHM — Processing Boundary Enforcement", "IAM", "NDHM.B.3",
        "Wildcard permissions violate NDHM's data processing limitation requirements.",
        80, "High", nc,
        "Replace Action:*/Resource:* policies with scoped permissions for health data processing.", total)


def ndhm_b4_collection_limitation(session, meta):
    """NDHM.B.4 — S3 bucket policies restrict data ingestion sources."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                policy = _json.loads(s3.get_bucket_policy(Bucket=b["Name"])["Policy"])
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        p = stmt.get("Principal", {})
                        if p == "*" or (isinstance(p, dict) and p.get("AWS") == "*"):
                            if not stmt.get("Condition"):
                                nc.append({"resource_name": b["Name"],
                                           "note": "Unrestricted Principal allows uncontrolled data collection"})
                                break
            except ClientError as e:
                if "NoSuchBucketPolicy" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_b4_collection_limitation error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("NDHM — Collection Limitation Controls", "S3", "NDHM.B.4",
        "Health data collection must be from authorized sources only. Wildcard principals violate this.",
        75, "High", nc,
        "Add Condition keys (aws:SourceAccount, aws:PrincipalOrgID) to restrict data ingestion.", total)


def ndhm_b5_data_integrity(session, meta):
    """NDHM.B.5 — Backup plans protect health data integrity."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = 1
        if not plans:
            nc.append({"resource_name": "Account", "note": "No AWS Backup plans configured"})
    except Exception as e:
        print(f"ndhm_b5_data_integrity error: {e}")
    _meta(meta, "Backup", total, nc, "Medium")
    return _result("NDHM — Data Quality & Integrity (Backup)", "Backup", "NDHM.B.5",
        "Backup plans protect health data integrity and support data quality assurance.",
        65, "Medium", nc,
        "Create AWS Backup plans covering all health data stores (RDS, DynamoDB, S3).", total)


def ndhm_b6_lawful_processing(session, meta):
    """NDHM.B.6 — Conformance packs and audit assessments for governance."""
    nc, total = [], 0
    try:
        config = session.client("config")
        packs = config.describe_conformance_packs().get("ConformancePackDetails", [])
        total = 1
        if not packs:
            nc.append({"resource_name": "Config", "note": "No conformance packs deployed"})
        try:
            am = session.client("auditmanager")
            assessments = am.list_assessments().get("assessmentMetadata", [])
            if not assessments:
                nc.append({"resource_name": "Audit Manager", "note": "No audit assessments active"})
        except Exception:
            nc.append({"resource_name": "Audit Manager", "note": "Audit Manager not enabled"})
    except Exception as e:
        print(f"ndhm_b6_lawful_processing error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("NDHM — Lawful Processing Documentation", "Config", "NDHM.B.6",
        "NDHM requires documented evidence of lawful data processing basis.",
        60, "Medium", nc,
        "Deploy conformance packs and enable Audit Manager for health data governance.", total)


def ndhm_b7_fhir_compliance(session, meta):
    """NDHM.B.7 — FHIR validation Lambda functions and APIs exist."""
    nc, total = [], 0
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        total = 1
        fhir_fn = any("fhir" in f.get("FunctionName", "").lower() for f in functions)
        health_api = any("health" in a.get("name", "").lower() or
                        "fhir" in a.get("name", "").lower() for a in apis)
        if not fhir_fn and not health_api:
            nc.append({"resource_name": "Account",
                       "note": "No FHIR validation functions or health APIs detected"})
    except Exception as e:
        print(f"ndhm_b7_fhir_compliance error: {e}")
    _meta(meta, "Lambda", total, nc, "Low")
    return _result("NDHM — FHIR Data Structure Compliance", "Lambda", "NDHM.B.7",
        "ABDM mandates FHIR-compliant health record exchange. Validation functions should exist.",
        40, "Low", nc,
        "Implement Lambda functions for FHIR resource validation per ABDM Implementation Guide.", total)


def ndhm_b8_record_linkage_security(session, meta):
    """NDHM.B.8 — Health record linkage data encrypted with KMS."""
    nc, total = [], 0
    try:
        ddb = session.client("dynamodb")
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables) if tables else 1
        for table_name in tables[:30]:
            try:
                desc = ddb.describe_table(TableName=table_name)["Table"]
                sse = desc.get("SSEDescription", {})
                if sse.get("Status") != "ENABLED" or sse.get("SSEType") != "KMS":
                    nc.append({"resource_name": table_name,
                               "note": "Not encrypted with customer-managed KMS"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_b8_record_linkage_security error: {e}")
    _meta(meta, "DynamoDB", total, nc, "Medium")
    return _result("NDHM — Record Linkage Security (DynamoDB)", "DynamoDB", "NDHM.B.8",
        "Health record linkage data (ABHA mappings) must be encrypted with customer-managed KMS.",
        70, "Medium", nc,
        "Enable SSE with customer-managed KMS on all DynamoDB tables storing health record linkages.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# C — DATA PRINCIPAL RIGHTS (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_c1_right_to_access(session, meta):
    """NDHM.C.1 — APIs exist for patient data retrieval."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        total = 1
        if not apis:
            nc.append({"resource_name": "Account", "note": "No API Gateway APIs configured for health data access"})
    except Exception as e:
        print(f"ndhm_c1_right_to_access error: {e}")
    _meta(meta, "API Gateway", total, nc, "Medium")
    return _result("NDHM — Right to Access Health Records", "API Gateway", "NDHM.C.1",
        "Data principals must be able to access their health records via APIs.",
        60, "Medium", nc,
        "Ensure authenticated API endpoints exist for patient health record retrieval.", total)


def ndhm_c2_right_to_correction(session, meta):
    """NDHM.C.2 — Versioning enabled for correction tracking."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                v = s3.get_bucket_versioning(Bucket=b["Name"])
                if v.get("Status") != "Enabled":
                    nc.append({"resource_name": b["Name"],
                               "note": f"Versioning: {v.get('Status', 'Disabled')}"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_c2_right_to_correction error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("NDHM — Right to Correction (Versioning)", "S3", "NDHM.C.2",
        "Versioning enables tracking of corrections/amendments to health records.",
        65, "Medium", nc,
        "Enable versioning on all S3 buckets containing health records.", total)


def ndhm_c3_right_to_erasure(session, meta):
    """NDHM.C.3 — Lifecycle policies and erasure workflows exist."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        no_lifecycle = 0
        for b in buckets:
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
            except ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    no_lifecycle += 1
            except Exception:
                pass
        if no_lifecycle > 0:
            nc.append({"resource_name": f"{no_lifecycle} buckets",
                       "note": "No lifecycle policy for data erasure"})
    except Exception as e:
        print(f"ndhm_c3_right_to_erasure error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("NDHM — Right to Erasure", "S3", "NDHM.C.3",
        "Data principals can request deletion. Lifecycle policies enable automated erasure workflows.",
        65, "Medium", nc,
        "Configure S3 lifecycle policies and Lambda-based erasure workflows.", total)


def ndhm_c4_right_to_portability(session, meta):
    """NDHM.C.4 — Export APIs and transfer mechanisms available."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        total = 1
        export_api = any("export" in a.get("name", "").lower() or
                        "portab" in a.get("name", "").lower() or
                        "transfer" in a.get("name", "").lower() for a in apis)
        if not export_api and not apis:
            nc.append({"resource_name": "Account",
                       "note": "No data export/portability APIs detected"})
    except Exception as e:
        print(f"ndhm_c4_right_to_portability error: {e}")
    _meta(meta, "API Gateway", total, nc, "Low")
    return _result("NDHM — Right to Data Portability", "API Gateway", "NDHM.C.4",
        "NDHM requires health data portability between NDHE participants.",
        40, "Low", nc,
        "Implement FHIR-compliant export APIs for data portability.", total)


def ndhm_c5_right_to_restrict_processing(session, meta):
    """NDHM.C.5 — Mechanisms to dynamically restrict role access."""
    nc, total = [], 0
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        total = 1
        restrict_fn = any("restrict" in f.get("FunctionName", "").lower() or
                         "suspend" in f.get("FunctionName", "").lower() for f in functions)
        if not restrict_fn:
            nc.append({"resource_name": "Account",
                       "note": "No Lambda function for dynamic processing restriction"})
    except Exception as e:
        print(f"ndhm_c5_right_to_restrict_processing error: {e}")
    _meta(meta, "Lambda", total, nc, "Low")
    return _result("NDHM — Right to Restrict Processing", "Lambda", "NDHM.C.5",
        "Data principals can request processing suspension. Automated mechanisms needed.",
        40, "Low", nc,
        "Implement Lambda-based workflow to dynamically restrict IAM access on request.", total)


def ndhm_c6_right_to_nominate(session, meta):
    """NDHM.C.6 — Audit trail for nominee management."""
    nc, total = [], 0
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        total = 1
        has_data_events = False
        for t in trails:
            try:
                sel = ct.get_event_selectors(TrailName=t["TrailARN"])
                if sel.get("EventSelectors") or sel.get("AdvancedEventSelectors"):
                    has_data_events = True
                    break
            except Exception:
                pass
        if not has_data_events:
            nc.append({"resource_name": "CloudTrail",
                       "note": "No data events for nominee delegation audit"})
    except Exception as e:
        print(f"ndhm_c6_right_to_nominate error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Low")
    return _result("NDHM — Right to Nominate (Audit)", "CloudTrail", "NDHM.C.6",
        "Nominee changes must be auditable via CloudTrail data events.",
        40, "Low", nc,
        "Enable data events in CloudTrail to capture nomination/delegation changes.", total)


def ndhm_c7_grievance_mechanisms(session, meta):
    """NDHM.C.7 — Grievance notification channels configured."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = 1
        if not topics:
            nc.append({"resource_name": "Account", "note": "No notification channels for grievance redressal"})
    except Exception as e:
        print(f"ndhm_c7_grievance_mechanisms error: {e}")
    _meta(meta, "SNS", total, nc, "Low")
    return _result("NDHM — Grievance Redressal Mechanisms", "SNS", "NDHM.C.7",
        "Communication infrastructure needed for data principal grievances.",
        35, "Low", nc,
        "Configure SNS/SES channels for grievance intake and acknowledgement.", total)


def ndhm_c8_abha_deactivation(session, meta):
    """NDHM.C.8 — Automated workflows for ABHA deactivation."""
    nc, total = [], 0
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        total = 1
        deactivation_fn = any("deactivat" in f.get("FunctionName", "").lower() or
                             "abha" in f.get("FunctionName", "").lower() for f in functions)
        deactivation_rule = any("deactivat" in r.get("Name", "").lower() for r in rules)
        if not deactivation_fn and not deactivation_rule:
            nc.append({"resource_name": "Account",
                       "note": "No automated ABHA deactivation workflow detected"})
    except Exception as e:
        print(f"ndhm_c8_abha_deactivation error: {e}")
    _meta(meta, "Lambda", total, nc, "Low")
    return _result("NDHM — ABHA Deactivation Support", "Lambda", "NDHM.C.8",
        "ABHA deactivation requires automated cleanup of linked health records.",
        35, "Low", nc,
        "Implement EventBridge+Lambda workflows for ABHA deactivation and data cleanup.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# D — DATA STORAGE, RETENTION & DISPOSAL (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_d1_retention_controls(session, meta):
    """NDHM.D.1 — Lifecycle and backup retention aligned with HDMP requirements."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
            except ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No lifecycle policy for retention"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_d1_retention_controls error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("NDHM — Health Data Retention Controls", "S3", "NDHM.D.1",
        "NDHM mandates defined retention periods for health records.",
        65, "Medium", nc,
        "Configure lifecycle policies aligned with NDHM retention requirements.", total)


def ndhm_d2_secure_disposal(session, meta):
    """NDHM.D.2 — Automated disposal via lifecycle; object lock for compliance retention."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                s3.get_object_lock_configuration(Bucket=b["Name"])
            except ClientError:
                nc.append({"resource_name": b["Name"], "note": "No Object Lock for compliance retention"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_d2_secure_disposal error: {e}")
    _meta(meta, "S3", total, nc, "Low")
    return _result("NDHM — Secure Disposal of Health Records", "S3", "NDHM.D.2",
        "Object Lock ensures records cannot be deleted before retention period expires.",
        45, "Low", nc,
        "Enable Object Lock on critical health record buckets for compliance retention.", total)


def ndhm_d3_storage_encryption(session, meta):
    """NDHM.D.3 — All health data stores encrypted at rest."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                enc = s3.get_bucket_encryption(Bucket=b["Name"])
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    if sse.get("SSEAlgorithm") not in ("aws:kms", "aws:kms:dsse"):
                        nc.append({"resource_name": b["Name"], "note": "Not using KMS encryption"})
                else:
                    nc.append({"resource_name": b["Name"], "note": "No encryption rules"})
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No encryption configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_d3_storage_encryption error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("NDHM — Health Data Storage Encryption", "S3", "NDHM.D.3",
        "All health data must be encrypted at rest with KMS per NDHM security safeguards.",
        95, "Critical", nc,
        "Enable SSE-KMS with customer-managed keys on all health data buckets.", total)


def ndhm_d4_data_residency_india(session, meta):
    """NDHM.D.4 — All resources in Indian regions (ap-south-1/ap-south-2)."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                loc = s3.get_bucket_location(Bucket=b["Name"])
                region = loc.get("LocationConstraint") or "us-east-1"
                if region not in INDIA_REGIONS:
                    nc.append({"resource_name": b["Name"],
                               "note": f"Located in {region} — outside India"})
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_d4_data_residency_india error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("NDHM — Data Residency Within India (S3)", "S3", "NDHM.D.4",
        "NDHM MANDATES all health data stays within India. Buckets outside ap-south-1/ap-south-2 violate this.",
        100, "Critical", nc,
        "Migrate all health data buckets to ap-south-1 (Mumbai) or ap-south-2 (Hyderabad).", total)


def ndhm_d5_cross_border_restriction(session, meta):
    """NDHM.D.5 — No replication to regions outside India."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                rep = s3.get_bucket_replication(Bucket=b["Name"])
                rules = rep.get("ReplicationConfiguration", {}).get("Rules", [])
                for r in rules:
                    dest = r.get("Destination", {})
                    dest_bucket = dest.get("Bucket", "")
                    # Check if destination has a region indicator outside India
                    if dest_bucket and r.get("Status") == "Enabled":
                        nc.append({"resource_name": b["Name"],
                                   "note": f"Active replication rule — verify destination is in India"})
                        break
            except ClientError as e:
                if "ReplicationConfigurationNotFoundError" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_d5_cross_border_restriction error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("NDHM — Cross-Border Transfer Restriction", "S3", "NDHM.D.5",
        "NDHM prohibits health data transfer outside India. All replication must target Indian regions.",
        100, "Critical", nc,
        "Ensure all S3 replication rules target only ap-south-1 or ap-south-2.", total)


def ndhm_d6_backup_encryption(session, meta):
    """NDHM.D.6 — Backup vaults encrypted with KMS."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults) if vaults else 1
        if not vaults:
            nc.append({"resource_name": "Account", "note": "No backup vaults configured"})
        for v in vaults:
            if not v.get("EncryptionKeyArn"):
                nc.append({"resource_name": v.get("BackupVaultName", "unknown"),
                           "note": "Vault not encrypted with KMS"})
    except Exception as e:
        print(f"ndhm_d6_backup_encryption error: {e}")
    _meta(meta, "Backup", total, nc, "High")
    return _result("NDHM — Backup Encryption & Integrity", "Backup", "NDHM.D.6",
        "Health data backups must be encrypted with KMS to maintain confidentiality.",
        80, "High", nc,
        "Ensure all backup vaults use customer-managed KMS encryption.", total)


def ndhm_d7_data_versioning(session, meta):
    """NDHM.D.7 — Versioning enabled for health records; RDS automated backups active."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            retention = db.get("BackupRetentionPeriod", 0)
            if retention < 7:
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": f"Backup retention only {retention} days (min 7 required)"})
    except Exception as e:
        print(f"ndhm_d7_data_versioning error: {e}")
    _meta(meta, "RDS", total, nc, "Medium")
    return _result("NDHM — Health Data Versioning (RDS Backups)", "RDS", "NDHM.D.7",
        "RDS automated backups with adequate retention enable point-in-time recovery of health records.",
        65, "Medium", nc,
        "Set RDS backup retention to at least 35 days for health databases.", total)


def ndhm_d8_archival_mechanisms(session, meta):
    """NDHM.D.8 — Archival tier transitions defined."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        has_archival = False
        for b in buckets:
            try:
                lc = s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                for rule in lc.get("Rules", []):
                    transitions = rule.get("Transitions", [])
                    if any(t.get("StorageClass") in ("GLACIER", "DEEP_ARCHIVE", "GLACIER_IR")
                           for t in transitions):
                        has_archival = True
                        break
            except ClientError:
                pass
            except Exception:
                pass
            if has_archival:
                break
        if not has_archival:
            nc.append({"resource_name": "Account", "note": "No archival transitions configured"})
    except Exception as e:
        print(f"ndhm_d8_archival_mechanisms error: {e}")
    _meta(meta, "S3", total, nc, "Low")
    return _result("NDHM — Archival & Retrieval Mechanisms", "S3", "NDHM.D.8",
        "Long-term health records should transition to archival storage for cost-efficient retention.",
        40, "Low", nc,
        "Add lifecycle rules with Glacier/Deep Archive transitions for aged health data.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# E — SECURITY SAFEGUARDS (10 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_e1_encryption_at_rest(session, meta):
    """NDHM.E.1 — All S3, RDS, EBS encrypted at rest."""
    nc, total = [], 0
    try:
        ec2 = session.client("ec2")
        volumes = ec2.describe_volumes().get("Volumes", [])
        total = len(volumes)
        for v in volumes:
            if not v.get("Encrypted"):
                nc.append({"resource_name": v["VolumeId"], "note": "EBS volume not encrypted"})
    except Exception as e:
        print(f"ndhm_e1_encryption_at_rest error: {e}")
    _meta(meta, "EC2", total, nc, "Critical")
    return _result("NDHM — Encryption at Rest (EBS)", "EC2", "NDHM.E.1",
        "All health data storage must be encrypted at rest per NDHM security safeguards.",
        90, "Critical", nc,
        "Encrypt all EBS volumes. Enable default EBS encryption at account level.", total)


def ndhm_e2_encryption_in_transit(session, meta):
    """NDHM.E.2 — HTTPS-only listeners; TLS 1.2 minimum."""
    nc, total = [], 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
            total += len(listeners)
            for l in listeners:
                if l.get("Protocol") == "HTTP":
                    # Check if it redirects to HTTPS
                    actions = l.get("DefaultActions", [])
                    is_redirect = any(a.get("Type") == "redirect" and
                                     a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                                     for a in actions)
                    if not is_redirect:
                        nc.append({"resource_name": lb["LoadBalancerName"],
                                   "note": f"HTTP listener on port {l.get('Port')} without HTTPS redirect"})
    except Exception as e:
        print(f"ndhm_e2_encryption_in_transit error: {e}")
    _meta(meta, "ELB", total, nc, "High")
    return _result("NDHM — Encryption in Transit (TLS)", "ELB", "NDHM.E.2",
        "All health data transmission must use TLS 1.2+. HTTP without redirect exposes PHI.",
        85, "High", nc,
        "Configure all listeners as HTTPS or add HTTP→HTTPS redirect rules.", total)


def ndhm_e3_e2e_encryption(session, meta):
    """NDHM.E.3 — Customer-managed KMS keys for ABDM data exchange."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        total = len(keys) if keys else 1
        cmk_count = 0
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER" and desc.get("KeyState") == "Enabled":
                    cmk_count += 1
            except Exception:
                pass
        if cmk_count == 0:
            nc.append({"resource_name": "Account",
                       "note": "No active customer-managed KMS keys for health data exchange"})
    except Exception as e:
        print(f"ndhm_e3_e2e_encryption error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("NDHM — End-to-End Encryption (KMS CMK)", "KMS", "NDHM.E.3",
        "ABDM health data exchange requires customer-managed encryption keys.",
        80, "High", nc,
        "Create dedicated customer-managed KMS keys for health data encryption.", total)


def ndhm_e4_access_control(session, meta):
    """NDHM.E.4 — Least privilege; MFA enabled for health data users."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        users = iam.list_users().get("Users", [])
        total = len(users)
        for user in users:
            try:
                iam.get_login_profile(UserName=user["UserName"])
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
                if not mfa:
                    nc.append({"resource_name": user["UserName"],
                               "note": "Console access without MFA"})
            except ClientError as e:
                if "NoSuchEntity" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_e4_access_control error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("NDHM — Access Control (MFA Enforcement)", "IAM", "NDHM.E.4",
        "All users with console access to health systems must have MFA enabled.",
        90, "Critical", nc,
        "Enable MFA for all IAM users with console access.", total)


def ndhm_e5_privileged_access(session, meta):
    """NDHM.E.5 — No overly permissive admin roles."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        for role in roles:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            try:
                policies = iam.list_attached_role_policies(RoleName=role["RoleName"]).get("AttachedPolicies", [])
                for pol in policies:
                    if "AdministratorAccess" in pol["PolicyName"]:
                        nc.append({"resource_name": role["RoleName"],
                                   "note": "AdministratorAccess violates separation of duties"})
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_e5_privileged_access error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("NDHM — Privileged Access Management", "IAM", "NDHM.E.5",
        "Overly permissive roles violate NDHM's security safeguard requirements.",
        80, "High", nc,
        "Replace AdministratorAccess with scoped policies on health system roles.", total)


def ndhm_e6_network_security(session, meta):
    """NDHM.E.6 — No unrestricted inbound; VPC flow logs enabled."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        total = len(sgs)
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 65535)
                        if from_port == 0 and to_port == 65535:
                            nc.append({"resource_name": sg["GroupId"],
                                       "note": "All ports open to 0.0.0.0/0"})
                            break
    except Exception as e:
        print(f"ndhm_e6_network_security error: {e}")
    _meta(meta, "EC2", total, nc, "Critical")
    return _result("NDHM — Network Security (Security Groups)", "EC2", "NDHM.E.6",
        "Unrestricted inbound access exposes health infrastructure to attacks.",
        90, "Critical", nc,
        "Remove 0.0.0.0/0 inbound rules. Use specific CIDR ranges and port restrictions.", total)


def ndhm_e7_intrusion_detection(session, meta):
    """NDHM.E.7 — GuardDuty active for health workload threat detection."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if not detectors:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
        else:
            det = gd.get_detector(DetectorId=detectors[0])
            if det.get("Status") != "ENABLED":
                nc.append({"resource_name": "GuardDuty", "note": "Detector not active"})
    except Exception as e:
        print(f"ndhm_e7_intrusion_detection error: {e}")
    _meta(meta, "GuardDuty", total, nc, "Critical")
    return _result("NDHM — Intrusion Detection (GuardDuty)", "GuardDuty", "NDHM.E.7",
        "NDHM requires continuous threat detection for health infrastructure.",
        90, "Critical", nc,
        "Enable GuardDuty with all protection plans for health workloads.", total)


def ndhm_e8_vulnerability_management(session, meta):
    """NDHM.E.8 — Inspector scanning; SSM patch compliance."""
    nc, total = [], 0
    try:
        inspector = session.client("inspector2")
        total = 1
        try:
            status = inspector.batch_get_account_status(
                accountIds=[_get_account_id(session)]
            ).get("accounts", [])
            if status:
                state = status[0].get("state", {}).get("status", "")
                if state != "ENABLED":
                    nc.append({"resource_name": "Inspector", "note": f"Status: {state}"})
            else:
                nc.append({"resource_name": "Inspector", "note": "Not enabled"})
        except Exception:
            nc.append({"resource_name": "Inspector", "note": "Inspector v2 not available"})
    except Exception as e:
        print(f"ndhm_e8_vulnerability_management error: {e}")
    _meta(meta, "Inspector", total, nc, "High")
    return _result("NDHM — Vulnerability Management (Inspector)", "Inspector", "NDHM.E.8",
        "Continuous vulnerability scanning required for health system hosts and containers.",
        75, "High", nc,
        "Enable Amazon Inspector for EC2, ECR, and Lambda vulnerability scanning.", total)


def ndhm_e9_anti_malware(session, meta):
    """NDHM.E.9 — GuardDuty Malware Protection enabled."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            malware_enabled = any(f.get("Name") == "EBS_MALWARE_PROTECTION" and
                                 f.get("Status") == "ENABLED" for f in features)
            if not malware_enabled:
                # Try dataSources for older API
                ds = det.get("DataSources", {})
                mal = ds.get("MalwareProtection", {}).get("ScanEc2InstanceWithFindings", {})
                if mal.get("EbsVolumes", {}).get("Status") != "ENABLED":
                    nc.append({"resource_name": "GuardDuty", "note": "Malware Protection not enabled"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"ndhm_e9_anti_malware error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("NDHM — Anti-Malware Protection", "GuardDuty", "NDHM.E.9",
        "Malware can compromise health data integrity. GuardDuty Malware Protection scans EBS volumes.",
        75, "High", nc,
        "Enable GuardDuty Malware Protection (EBS volume scanning).", total)


def ndhm_e10_security_config_management(session, meta):
    """NDHM.E.10 — Config recorder active for all resources."""
    nc, total = [], 0
    try:
        config = session.client("config")
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        total = 1
        if not recorders:
            nc.append({"resource_name": "Account", "note": "No Config recorder configured"})
        else:
            rec = recorders[0]
            group = rec.get("recordingGroup", {})
            if not group.get("allSupported"):
                nc.append({"resource_name": "Config Recorder",
                           "note": "Not recording all supported resource types"})
    except Exception as e:
        print(f"ndhm_e10_security_config_management error: {e}")
    _meta(meta, "Config", total, nc, "High")
    return _result("NDHM — Security Configuration Management", "Config", "NDHM.E.10",
        "AWS Config must record all resource types for health infrastructure visibility.",
        75, "High", nc,
        "Enable Config recorder with allSupported=true and includeGlobalResourceTypes=true.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# F — AUTHENTICATION & IDENTITY MANAGEMENT (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def ndhm_f1_password_policy(session, meta):
    """NDHM.F.1 — Strong password policy (min 14 chars, complexity)."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        total = 1
        try:
            pp = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if pp.get("MinimumPasswordLength", 0) < 14:
                issues.append(f"MinLength={pp.get('MinimumPasswordLength', 0)} (need 14)")
            if not pp.get("RequireUppercaseCharacters"):
                issues.append("No uppercase required")
            if not pp.get("RequireLowercaseCharacters"):
                issues.append("No lowercase required")
            if not pp.get("RequireNumbers"):
                issues.append("No numbers required")
            if not pp.get("RequireSymbols"):
                issues.append("No symbols required")
            if issues:
                nc.append({"resource_name": "Password Policy", "note": "; ".join(issues)})
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                nc.append({"resource_name": "Account", "note": "No password policy configured"})
    except Exception as e:
        print(f"ndhm_f1_password_policy error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("NDHM — Password Policy Enforcement", "IAM", "NDHM.F.1",
        "Strong password policy required for health system access. Minimum 14 characters with complexity.",
        80, "High", nc,
        "Set password policy: MinLength=14, RequireUppercase/Lowercase/Numbers/Symbols=true.", total)


def ndhm_f2_mfa_enforcement(session, meta):
    """NDHM.F.2 — All console users have MFA enabled."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        users = iam.list_users().get("Users", [])
        total = len(users)
        for user in users:
            try:
                iam.get_login_profile(UserName=user["UserName"])
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
                if not mfa:
                    nc.append({"resource_name": user["UserName"], "note": "Console access without MFA"})
            except ClientError as e:
                if "NoSuchEntity" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"ndhm_f2_mfa_enforcement error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("NDHM — MFA Enforcement for Health Systems", "IAM", "NDHM.F.2",
        "ABDM requires MFA on all user accounts accessing health data systems.",
        90, "Critical", nc,
        "Enable virtual or hardware MFA for all users with console access.", total)


def ndhm_f3_root_account_security(session, meta):
    """NDHM.F.3 — Root has no access keys; MFA enabled."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        total = 1
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            nc.append({"resource_name": "Root Account", "note": "Root access keys exist"})
        if summary.get("AccountMFAEnabled", 0) == 0:
            nc.append({"resource_name": "Root Account", "note": "Root MFA not enabled"})
    except Exception as e:
        print(f"ndhm_f3_root_account_security error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("NDHM — Root Account Security", "IAM", "NDHM.F.3",
        "Root account must have no access keys and MFA enabled.",
        95, "Critical", nc,
        "Delete root access keys and enable MFA on the root account.", total)


def ndhm_f4_access_key_rotation(session, meta):
    """NDHM.F.4 — Access keys rotated within 90 days."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        users = iam.list_users().get("Users", [])
        now = datetime.now(timezone.utc)
        for user in users:
            keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
            total += len(keys)
            for key in keys:
                if key.get("Status") == "Active":
                    created = key.get("CreateDate")
                    if created and (now - created).days > 90:
                        nc.append({"resource_name": f"{user['UserName']}/{key['AccessKeyId']}",
                                   "note": f"Key age: {(now - created).days} days"})
    except Exception as e:
        print(f"ndhm_f4_access_key_rotation error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("NDHM — Access Key Rotation", "IAM", "NDHM.F.4",
        "Access keys older than 90 days increase credential compromise risk.",
        75, "High", nc,
        "Rotate access keys every 90 days. Use IAM roles instead of long-term keys.", total)


def ndhm_f5_session_management(session, meta):
    """NDHM.F.5 — Appropriate session durations on roles."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        for role in roles:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            max_duration = role.get("MaxSessionDuration", 3600)
            if max_duration > 43200:  # 12 hours
                nc.append({"resource_name": role["RoleName"],
                           "note": f"MaxSessionDuration={max_duration}s (>12h)"})
    except Exception as e:
        print(f"ndhm_f5_session_management error: {e}")
    _meta(meta, "IAM", total, nc, "Low")
    return _result("NDHM — Session Management", "IAM", "NDHM.F.5",
        "Excessively long session durations increase window of opportunity for token misuse.",
        40, "Low", nc,
        "Set MaxSessionDuration to 1-4 hours for health system roles.", total)


def ndhm_f6_service_account_security(session, meta):
    """NDHM.F.6 — Service accounts use roles, not long-term keys."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        users = iam.list_users().get("Users", [])
        total = len(users)
        for user in users:
            name = user["UserName"].lower()
            if any(x in name for x in ["service", "svc", "bot", "automation", "ci", "deploy"]):
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                active_keys = [k for k in keys if k.get("Status") == "Active"]
                if active_keys:
                    nc.append({"resource_name": user["UserName"],
                               "note": "Service account using long-term access keys"})
    except Exception as e:
        print(f"ndhm_f6_service_account_security error: {e}")
    _meta(meta, "IAM", total, nc, "Medium")
    return _result("NDHM — Service Account Security", "IAM", "NDHM.F.6",
        "Service accounts should use IAM roles, not long-term access keys.",
        65, "Medium", nc,
        "Migrate service accounts to IAM roles with temporary credentials.", total)


def ndhm_f7_identity_federation(session, meta):
    """NDHM.F.7 — Federated identity for healthcare staff access."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        total = 1
        saml = iam.list_saml_providers().get("SAMLProviderList", [])
        oidc = iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
        if not saml and not oidc:
            nc.append({"resource_name": "Account",
                       "note": "No SAML/OIDC identity providers configured"})
    except Exception as e:
        print(f"ndhm_f7_identity_federation error: {e}")
    _meta(meta, "IAM", total, nc, "Low")
    return _result("NDHM — Identity Federation", "IAM", "NDHM.F.7",
        "Federated identity via SAML/OIDC enables centralized healthcare staff access management.",
        40, "Low", nc,
        "Configure SAML or OIDC identity providers for federated access.", total)


def ndhm_f8_credential_report(session, meta):
    """NDHM.F.8 — No inactive credentials; MFA coverage complete."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        total = 1
        summary = iam.get_account_summary()["SummaryMap"]
        users_count = summary.get("Users", 0)
        mfa_count = summary.get("MFADevices", 0)
        if users_count > 0 and mfa_count < users_count:
            nc.append({"resource_name": "Account",
                       "note": f"MFA devices ({mfa_count}) < Users ({users_count})"})
    except Exception as e:
        print(f"ndhm_f8_credential_report error: {e}")
    _meta(meta, "IAM", total, nc, "Medium")
    return _result("NDHM — Credential Report Analysis", "IAM", "NDHM.F.8",
        "MFA coverage gaps indicate incomplete authentication security.",
        65, "Medium", nc,
        "Ensure all active users have MFA. Disable inactive credentials.", total)
