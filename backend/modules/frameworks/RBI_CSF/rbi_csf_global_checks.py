"""
RBI CSF — Global Checks (run once per account)
Covers: IAM, S3, CloudTrail, Organizations, Data Residency, KMS, Secrets, DLP

All checks use READ-ONLY APIs compatible with arn:aws:iam::aws:policy/ReadOnlyAccess
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


# ═══════════════════════════════════════════════════════════════════════════════
# IAM & ACCESS CONTROL (beyond existing MFA check)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_iam_root_secured(session, meta):
    """RBI.IAM.2 — Root account no access keys + MFA enabled."""
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
        print(f"rbi_iam_root_secured error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("RBI CSF — Root Account Security", "IAM", "RBI.IAM.2",
        "Root account must have no access keys and MFA enabled per RBI privileged access controls.",
        95, "Critical", nc, "Delete root access keys and enable MFA on root account.", total)


def rbi_iam_password_policy(session, meta):
    """RBI.IAM.3 — Strong password policy (14 chars, complexity)."""
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
        print(f"rbi_iam_password_policy error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("RBI CSF — Password Policy", "IAM", "RBI.IAM.3",
        "Strong password policy required: minimum 14 characters with complexity.",
        80, "High", nc, "Set MinLength=14, RequireUppercase/Lowercase/Numbers/Symbols=true.", total)


def rbi_iam_password_reuse(session, meta):
    """RBI.IAM.4 — Password reuse prevention >= 24."""
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
        print(f"rbi_iam_password_reuse error: {e}")
    _meta(meta, "IAM", total, nc, "Medium")
    return _result("RBI CSF — Password Reuse Prevention", "IAM", "RBI.IAM.4",
        "Password reuse must be prevented for at least 24 previous passwords.",
        65, "Medium", nc, "Set PasswordReusePrevention=24.", total)


def rbi_iam_access_key_rotation(session, meta):
    """RBI.IAM.5 — Access keys rotated within 90 days."""
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
        print(f"rbi_iam_access_key_rotation error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("RBI CSF — Access Key Rotation (90 days)", "IAM", "RBI.IAM.5",
        "Access keys older than 90 days increase credential compromise risk.",
        75, "High", nc, "Rotate keys every 90 days. Prefer IAM roles over long-term keys.", total)


def rbi_iam_wildcard_permissions(session, meta):
    """RBI.IAM.6 — No Action:*/Resource:* policies."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        total = len(policies)
        for pol in policies[:50]:
            try:
                ver = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
                doc = ver["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if (actions == "*" or (isinstance(actions, list) and "*" in actions)):
                            if (resources == "*" or (isinstance(resources, list) and "*" in resources)):
                                nc.append({"resource_name": pol["PolicyName"],
                                           "note": "Action:* with Resource:*"})
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_iam_wildcard_permissions error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("RBI CSF — Wildcard IAM Permissions", "IAM", "RBI.IAM.6",
        "Wildcard permissions violate principle of least privilege for financial systems.",
        80, "High", nc, "Replace with scoped policies for specific financial services.", total)


def rbi_iam_admin_minimized(session, meta):
    """RBI.IAM.7 — Minimal entities with AdministratorAccess."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        total = 1
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        entities = iam.list_entities_for_policy(PolicyArn=admin_arn)
        users = entities.get("PolicyUsers", [])
        roles = entities.get("PolicyRoles", [])
        groups = entities.get("PolicyGroups", [])
        count = len(users) + len(roles) + len(groups)
        if count > 3:
            nc.append({"resource_name": "Account",
                       "note": f"{count} entities with AdministratorAccess (users:{len(users)}, roles:{len(roles)}, groups:{len(groups)})"})
    except Exception as e:
        print(f"rbi_iam_admin_minimized error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("RBI CSF — AdministratorAccess Minimized", "IAM", "RBI.IAM.7",
        "Excessive admin access violates RBI separation of duties requirements.",
        75, "High", nc, "Limit AdministratorAccess to max 2-3 break-glass roles.", total)


def rbi_iam_access_analyzer(session, meta):
    """RBI.IAM.9 — IAM Access Analyzer enabled."""
    nc, total = [], 0
    try:
        aa = session.client("accessanalyzer")
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
        total = 1
        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        if not active:
            nc.append({"resource_name": "Account", "note": "No active IAM Access Analyzer"})
    except Exception as e:
        print(f"rbi_iam_access_analyzer error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("RBI CSF — IAM Access Analyzer", "IAM", "RBI.IAM.9",
        "Access Analyzer detects external access to financial resources.",
        75, "High", nc, "Create an account-level IAM Access Analyzer.", total)


def rbi_iam_cross_account_trust(session, meta):
    """RBI.IAM.10 — Cross-account trust policies reviewed."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        account_id = _get_account_id(session)
        for role in roles:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                trust = _json.loads(trust)
            for stmt in trust.get("Statement", []):
                principal = stmt.get("Principal", {})
                if isinstance(principal, dict):
                    aws_principals = principal.get("AWS", [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if "arn:aws" in p and account_id not in p:
                            nc.append({"resource_name": role["RoleName"],
                                       "note": f"Cross-account trust: {p[:50]}..."})
                            break
    except Exception as e:
        print(f"rbi_iam_cross_account_trust error: {e}")
    _meta(meta, "IAM", total, nc, "Medium")
    return _result("RBI CSF — Cross-Account Trust Review", "IAM", "RBI.IAM.10",
        "Cross-account trust policies must be limited to known banking group accounts.",
        65, "Medium", nc, "Review and restrict trust policies to authorized accounts only.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# S3 / DLP EXTENDED (beyond existing public access + localization)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_s3_ssl_enforcement(session, meta):
    """RBI.ENC.3 — S3 bucket policies enforce SSL-only."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                policy = _json.loads(s3.get_bucket_policy(Bucket=b["Name"])["Policy"])
                has_ssl_deny = any(
                    stmt.get("Effect") == "Deny" and
                    stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false"
                    for stmt in policy.get("Statement", [])
                )
                if not has_ssl_deny:
                    nc.append({"resource_name": b["Name"], "note": "No SSL enforcement in policy"})
            except ClientError as e:
                if "NoSuchBucketPolicy" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No bucket policy (no SSL enforcement)"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_s3_ssl_enforcement error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("RBI CSF — S3 SSL-Only Enforcement", "S3", "RBI.ENC.3",
        "Financial data must never be transmitted unencrypted. SSL enforcement required.",
        80, "High", nc, "Add Deny statement for aws:SecureTransport=false.", total)


def rbi_s3_bucket_policy_wildcard(session, meta):
    """RBI.DLP.2 — No wildcard principals in bucket policies."""
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
                                           "note": "Principal:* without Condition"})
                                break
            except ClientError:
                pass
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_s3_bucket_policy_wildcard error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("RBI CSF — S3 Wildcard Principal", "S3", "RBI.DLP.2",
        "Wildcard principals allow anyone to access financial data buckets.",
        85, "High", nc, "Remove Principal:* or add restrictive Conditions.", total)


def rbi_s3_versioning(session, meta):
    """RBI.DLP.4 — S3 versioning enabled for data integrity."""
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
        print(f"rbi_s3_versioning error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("RBI CSF — S3 Versioning", "S3", "RBI.DLP.4",
        "Versioning protects financial data integrity and enables recovery from accidental deletion.",
        65, "Medium", nc, "Enable versioning on all financial data buckets.", total)


def rbi_s3_logging(session, meta):
    """RBI.LOG.11 — S3 server access logging."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                log = s3.get_bucket_logging(Bucket=b["Name"])
                if not log.get("LoggingEnabled"):
                    nc.append({"resource_name": b["Name"], "note": "Access logging not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_s3_logging error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("RBI CSF — S3 Access Logging", "S3", "RBI.LOG.11",
        "Access logging required for financial data bucket audit trail.",
        60, "Medium", nc, "Enable server access logging on all financial buckets.", total)


def rbi_s3_encryption_kms(session, meta):
    """RBI.ENC.1 — S3 encrypted with KMS (not just SSE-S3)."""
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
                        nc.append({"resource_name": b["Name"], "note": "Using SSE-S3, not KMS"})
                else:
                    nc.append({"resource_name": b["Name"], "note": "No encryption rules"})
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No encryption"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_s3_encryption_kms error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("RBI CSF — S3 KMS Encryption", "S3", "RBI.ENC.1",
        "Financial data requires KMS encryption for granular access control over encryption keys.",
        80, "High", nc, "Enable SSE-KMS with customer-managed keys on all buckets.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# CLOUDTRAIL EXTENDED (beyond existing basic check)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_ct_kms_encryption(session, meta):
    """RBI.LOG.4 — CloudTrail KMS encryption."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        for t in trails:
            if not t.get("KmsKeyId"):
                nc.append({"resource_name": t.get("Name"), "note": "Not KMS encrypted"})
    except Exception as e:
        print(f"rbi_ct_kms_encryption error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Medium")
    return _result("RBI CSF — CloudTrail KMS Encryption", "CloudTrail", "RBI.LOG.4",
        "Customer-managed KMS adds access control on financial audit trail logs.",
        65, "Medium", nc, "Set KmsKeyId on CloudTrail for enhanced log protection.", total)


def rbi_ct_data_events(session, meta):
    """RBI.LOG.5 — CloudTrail S3 data events enabled."""
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
                if not data_events and sel.get("AdvancedEventSelectors"):
                    data_events = True
            except Exception:
                pass
            if data_events:
                break
        if not data_events:
            nc.append({"resource_name": "CloudTrail", "note": "No data events enabled"})
    except Exception as e:
        print(f"rbi_ct_data_events error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("RBI CSF — CloudTrail Data Events", "CloudTrail", "RBI.LOG.5",
        "S3 data events required for object-level audit of financial data access.",
        75, "High", nc, "Enable data events for S3 and DynamoDB on CloudTrail.", total)


def rbi_ct_insights(session, meta):
    """RBI.LOG.7 — CloudTrail Insights enabled."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        for t in trails:
            try:
                ins = ct.get_insight_selectors(TrailName=t["TrailARN"])
                if not ins.get("InsightSelectors"):
                    nc.append({"resource_name": t.get("Name"), "note": "Insights not enabled"})
            except ClientError:
                nc.append({"resource_name": t.get("Name"), "note": "Insights not configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_ct_insights error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Medium")
    return _result("RBI CSF — CloudTrail Insights", "CloudTrail", "RBI.LOG.7",
        "Insights detects unusual API patterns indicating potential security incidents.",
        60, "Medium", nc, "Enable Insights on trails covering financial infrastructure.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# DATA RESIDENCY EXTENDED (beyond existing S3 localization)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_dr_s3_replication(session, meta):
    """RBI.DR.3 — No S3 replication outside India."""
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
                    if r.get("Status") == "Enabled":
                        nc.append({"resource_name": b["Name"],
                                   "note": "Active replication — verify destination is in India"})
                        break
            except ClientError as e:
                if "ReplicationConfigurationNotFoundError" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_dr_s3_replication error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("RBI CSF — S3 Cross-Border Replication", "S3", "RBI.DR.3",
        "RBI mandates financial data stays in India. Verify all replication targets Indian regions.",
        90, "Critical", nc, "Ensure replication rules target only ap-south-1/ap-south-2.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# ORGANIZATIONS & GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_gov_conformance_packs(session, meta):
    """RBI.GOV.7 — Conformance packs deployed."""
    nc, total = [], 0
    try:
        config = session.client("config")
        total = 1
        packs = config.describe_conformance_packs().get("ConformancePackDetails", [])
        if not packs:
            nc.append({"resource_name": "Config", "note": "No conformance packs deployed"})
    except Exception as e:
        print(f"rbi_gov_conformance_packs error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("RBI CSF — Conformance Packs", "Config", "RBI.GOV.7",
        "Conformance packs provide automated compliance assessment for RBI governance.",
        60, "Medium", nc, "Deploy RBI-aligned conformance packs.", total)


def rbi_gov_config_recorder(session, meta):
    """RBI.GOV.9 — Config recorder active for all resources."""
    nc, total = [], 0
    try:
        config = session.client("config")
        total = 1
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            nc.append({"resource_name": "Account", "note": "No Config recorder"})
        else:
            rec = recorders[0]
            group = rec.get("recordingGroup", {})
            if not group.get("allSupported"):
                nc.append({"resource_name": "Config", "note": "Not recording all resource types"})
    except Exception as e:
        print(f"rbi_gov_config_recorder error: {e}")
    _meta(meta, "Config", total, nc, "High")
    return _result("RBI CSF — Config Recorder (All Resources)", "Config", "RBI.GOV.9",
        "Full resource visibility required for RBI IT governance.",
        75, "High", nc, "Enable Config recorder with allSupported=true.", total)
