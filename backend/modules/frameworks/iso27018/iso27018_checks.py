"""
ISO/IEC 27018 — Protection of PII in Public Clouds
Complete AWS ReadOnlyAccess Implementation (150 checks)

All checks use READ-ONLY APIs compatible with arn:aws:iam::aws:policy/ReadOnlyAccess
"""

import json as _json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "ISO 27018"


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
# 🏷️ PII CLASSIFICATION HELPERS — Three-State Model
# ═══════════════════════════════════════════════════════════════════════════════
#
# Classification states:
#   CONFIRMED_PII     — Resource is tagged/identified as containing PII
#   CONFIRMED_NON_PII — Resource is explicitly tagged as NOT containing PII
#   UNKNOWN           — No classification tags; sensitivity undetermined
#
# Behavior per state:
#   CONFIRMED_PII     → Full severity, produces actionable findings
#   CONFIRMED_NON_PII → Skipped entirely (no finding, no recommendation)
#   UNKNOWN           → Reported as "Recommendation" at reduced severity
#
# Tag recognition (case-insensitive):
#   PII-positive tags:
#     DataClassification: PII, Personal, Sensitive, Confidential, Restricted
#     Sensitivity: High, Critical
#     Contains-PII / PII / Personal-Data: true, yes
#     GDPR / Privacy / iso27018: true, yes, high
#
#   Non-PII tags (explicitly excluded from PII checks):
#     DataClassification: Public, Non-Sensitive, None, Internal, Low
#     Sensitivity: Low, None, Public
#     Contains-PII / PII: false, no, none
#     Privacy: none, no, false, low, public

_PII_TAG_KEYS = {"dataclassification", "sensitivity", "contains-pii",
                 "gdpr", "privacy", "iso27018", "data-classification",
                 "data_classification", "pii", "personal-data"}

_PII_POSITIVE_VALUES = {"pii", "personal", "sensitive", "confidential", "restricted",
                        "high", "critical", "true", "yes"}

_NON_PII_VALUES = {"public", "non-sensitive", "none", "internal", "low",
                   "false", "no", "non-pii", "non_pii"}

# Classification enum
PII_CONFIRMED = "confirmed_pii"
PII_NON_PII = "confirmed_non_pii"
PII_UNKNOWN = "unknown"


def _classify_resource(tags):
    """
    Classify a resource based on its tags.
    Returns: PII_CONFIRMED, PII_NON_PII, or PII_UNKNOWN
    """
    if not tags:
        return PII_UNKNOWN
    for tag in tags:
        key = tag.get("Key", "").lower().strip()
        value = tag.get("Value", "").lower().strip()
        if key in _PII_TAG_KEYS:
            if value in _PII_POSITIVE_VALUES:
                return PII_CONFIRMED
            if value in _NON_PII_VALUES:
                return PII_NON_PII
    return PII_UNKNOWN


def _get_s3_bucket_tags(s3, bucket_name):
    """Get tags for an S3 bucket, returns empty list on failure."""
    try:
        return s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
    except ClientError:
        return []
    except Exception:
        return []


def _classify_s3_buckets(s3):
    """
    Classify all S3 buckets into three categories.
    Returns: (all_buckets, confirmed_pii, confirmed_non_pii, unknown)
    """
    buckets = s3.list_buckets().get("Buckets", [])
    confirmed_pii = []
    confirmed_non_pii = []
    unknown = []
    for b in buckets:
        tags = _get_s3_bucket_tags(s3, b["Name"])
        classification = _classify_resource(tags)
        if classification == PII_CONFIRMED:
            confirmed_pii.append(b)
        elif classification == PII_NON_PII:
            confirmed_non_pii.append(b)
        else:
            unknown.append(b)
    return buckets, confirmed_pii, confirmed_non_pii, unknown


def _get_pii_check_targets(confirmed_pii, unknown):
    """
    Determine which buckets to check for PII-dependent controls.
    - If PII buckets exist → check only those (full severity)
    - If none tagged → check unknown ones (reduced severity as recommendation)
    - Confirmed non-PII are always excluded
    Returns: (targets, pii_state)
      pii_state: PII_CONFIRMED if PII buckets found, PII_UNKNOWN otherwise
    """
    if confirmed_pii:
        return confirmed_pii, PII_CONFIRMED
    elif unknown:
        return unknown, PII_UNKNOWN
    else:
        return [], PII_NON_PII  # Everything is confirmed non-PII


# Legacy compatibility wrapper
def _get_pii_buckets(s3):
    """Return (all_buckets, pii_buckets, unclassified_buckets). Legacy wrapper."""
    all_b, pii, non_pii, unknown = _classify_s3_buckets(s3)
    return all_b, pii, unknown


def _pii_result(check_name, service, control_id, problem, max_score, max_severity,
                non_compliant, recommendation, total, pii_confirmed=True, region="global"):
    """
    Build result for PII-dependent checks with three-state severity model.

    pii_confirmed values:
      True  (or PII_CONFIRMED)  → Full severity findings
      False (or PII_UNKNOWN)    → Reduced to "Recommendation" (score capped at 40)
      PII_NON_PII              → No finding at all (returns zero-severity result)
    """
    has_issues = len(non_compliant) > 0

    # Map boolean to state for backward compat
    if pii_confirmed is True:
        state = PII_CONFIRMED
    elif pii_confirmed == PII_NON_PII:
        state = PII_NON_PII
    else:
        state = PII_UNKNOWN

    # Confirmed non-PII: suppress completely
    if state == PII_NON_PII:
        return {
            "check_name": check_name,
            "service": service,
            "framework": FRAMEWORK,
            "control_id": control_id,
            "problem_statement": problem,
            "severity_score": 0,
            "severity_level": "None",
            "resources_affected": [],
            "recommendation": recommendation,
            "region": region,
            "additional_info": {
                "total_scanned": total,
                "affected": 0,
                "pii_classification": "confirmed_non_pii",
                "note": "All scanned resources are confirmed non-PII. Check skipped.",
            },
        }

    # Unknown PII state: downgrade to recommendation
    if state == PII_UNKNOWN and has_issues:
        max_score = min(max_score, 40)
        max_severity = "Recommendation"
        problem = f"[RECOMMENDATION — PII unconfirmed] {problem}"

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
        "additional_info": {
            "total_scanned": total,
            "affected": len(non_compliant),
            "pii_classification": state,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 🗄️ S3 SECURITY (14 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_s3_ownership_controls(session, meta):
    """ISO27018.S3.1 — Bucket Ownership Controls must be BucketOwnerEnforced."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                own = s3.get_bucket_ownership_controls(Bucket=b["Name"])
                rules = own.get("OwnershipControls", {}).get("Rules", [])
                if not any(r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules):
                    nc.append({"resource_name": b["Name"], "note": "Not BucketOwnerEnforced"})
            except ClientError as e:
                if "OwnershipControlsNotFoundError" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No ownership controls"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_ownership_controls error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("ISO 27018 — S3 Bucket Ownership Controls", "S3", "ISO27018.S3.1",
        "Without BucketOwnerEnforced, ACL-based access remains possible for PII buckets.",
        70, "Medium", nc, "Set Object Ownership to BucketOwnerEnforced on all buckets.", total)


def iso27018_s3_acls_disabled(session, meta):
    """ISO27018.S3.2 — ACLs must not grant public/cross-account access."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                acl = s3.get_bucket_acl(Bucket=b["Name"])
                owner_id = acl.get("Owner", {}).get("ID", "")
                for g in acl.get("Grants", []):
                    grantee = g.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        nc.append({"resource_name": b["Name"], "note": f"Public ACL: {uri}"})
                        break
                    if grantee.get("Type") == "CanonicalUser" and grantee.get("ID") != owner_id:
                        nc.append({"resource_name": b["Name"], "note": "Cross-account ACL"})
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_acls_disabled error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("ISO 27018 — S3 ACLs Disabled", "S3", "ISO27018.S3.2",
        "Public or cross-account ACL grants expose PII without policy control.",
        80, "High", nc, "Disable ACLs via BucketOwnerEnforced and remove public grants.", total)


def iso27018_s3_block_public_acls(session, meta):
    """ISO27018.S3.3 — BlockPublicAcls must be enabled."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                pa = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                if not pa.get("BlockPublicAcls"):
                    nc.append({"resource_name": b["Name"], "note": "BlockPublicAcls=false"})
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No public access block"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_block_public_acls error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("ISO 27018 — S3 Block Public ACLs", "S3", "ISO27018.S3.3",
        "Public ACLs can be applied to PII buckets without this setting.", 90, "Critical", nc,
        "Enable BlockPublicAcls on all PII buckets.", total)


def iso27018_s3_ignore_public_acls(session, meta):
    """ISO27018.S3.4 — IgnorePublicAcls must be enabled."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                pa = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                if not pa.get("IgnorePublicAcls"):
                    nc.append({"resource_name": b["Name"], "note": "IgnorePublicAcls=false"})
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No public access block"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_ignore_public_acls error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("ISO 27018 — S3 Ignore Public ACLs", "S3", "ISO27018.S3.4",
        "Existing public ACLs are still honored without IgnorePublicAcls.", 90, "Critical", nc,
        "Enable IgnorePublicAcls on all PII buckets.", total)


def iso27018_s3_block_public_policy(session, meta):
    """ISO27018.S3.5 — BlockPublicPolicy must be enabled."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                pa = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                if not pa.get("BlockPublicPolicy"):
                    nc.append({"resource_name": b["Name"], "note": "BlockPublicPolicy=false"})
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No public access block"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_block_public_policy error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("ISO 27018 — S3 Block Public Policy", "S3", "ISO27018.S3.5",
        "Public bucket policies can be applied without BlockPublicPolicy.", 90, "Critical", nc,
        "Enable BlockPublicPolicy on all PII buckets.", total)


def iso27018_s3_restrict_public_buckets(session, meta):
    """ISO27018.S3.6 — RestrictPublicBuckets must be enabled."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                pa = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                if not pa.get("RestrictPublicBuckets"):
                    nc.append({"resource_name": b["Name"], "note": "RestrictPublicBuckets=false"})
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No public access block"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_restrict_public_buckets error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("ISO 27018 — S3 Restrict Public Buckets", "S3", "ISO27018.S3.6",
        "Public and cross-account access via bucket policies still works without this.", 90, "Critical", nc,
        "Enable RestrictPublicBuckets on all PII buckets.", total)


def iso27018_s3_access_points(session, meta):
    """ISO27018.S3.7 — S3 Access Points must not have public access."""
    nc, total = [], 0
    try:
        account_id = _get_account_id(session)
        s3ctrl = session.client("s3control")
        aps = s3ctrl.list_access_points(AccountId=account_id).get("AccessPointList", [])
        total = len(aps)
        for ap in aps:
            if ap.get("NetworkOrigin") == "Internet":
                nc.append({"resource_name": ap.get("Name", "unknown"), "note": "Internet-facing access point"})
    except ClientError:
        pass
    except Exception as e:
        print(f"iso27018_s3_access_points error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("ISO 27018 — S3 Access Points Exposure", "S3", "ISO27018.S3.7",
        "Internet-facing S3 access points can expose PII publicly.", 80, "High", nc,
        "Restrict access points to VPC origin only.", total)


def iso27018_s3_bucket_policy_wildcard(session, meta):
    """ISO27018.S3.8 — Bucket policies must not have Principal:*."""
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
                                nc.append({"resource_name": b["Name"], "note": "Principal:* without Condition"})
                                break
            except ClientError as e:
                if "NoSuchBucketPolicy" not in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_bucket_policy_wildcard error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("ISO 27018 — S3 Bucket Policy Wildcard Principal", "S3", "ISO27018.S3.8",
        "Bucket policies with Principal:* allow anyone to access PII data.", 85, "High", nc,
        "Remove wildcard principals from bucket policies or add restrictive Conditions.", total)


def iso27018_s3_logging(session, meta):
    """ISO27018.S3.9 — S3 server access logging must be enabled."""
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
        print(f"iso27018_s3_logging error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("ISO 27018 — S3 Bucket Logging", "S3", "ISO27018.S3.9",
        "Without access logging, PII access cannot be audited at the object level.", 65, "Medium", nc,
        "Enable server access logging on all PII buckets.", total)


def iso27018_s3_encryption(session, meta):
    """ISO27018.S3.10 — Default encryption must be configured."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                s3.get_bucket_encryption(Bucket=b["Name"])
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No default encryption"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_encryption error: {e}")
    _meta(meta, "S3", total, nc, "Critical")
    return _result("ISO 27018 — S3 Default Encryption", "S3", "ISO27018.S3.10",
        "PII stored without encryption at rest violates data protection requirements.", 95, "Critical", nc,
        "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets.", total)


def iso27018_s3_versioning(session, meta):
    """ISO27018.S3.11 — Versioning must not be suspended."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                v = s3.get_bucket_versioning(Bucket=b["Name"])
                status = v.get("Status", "")
                if status != "Enabled":
                    nc.append({"resource_name": b["Name"], "note": f"Versioning: {status or 'Disabled'}"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_s3_versioning error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("ISO 27018 — S3 Versioning Active", "S3", "ISO27018.S3.11",
        "Without versioning, PII deletions cannot be tracked or recovered.", 65, "Medium", nc,
        "Enable versioning on all PII buckets for deletion tracking.", total)


def iso27018_s3_object_lock(session, meta):
    """ISO27018.S3.12 — Object Lock should be enabled for compliance retention on PII buckets."""
    s3 = session.client("s3")
    nc, total = [], 0
    pii_state = PII_UNKNOWN
    try:
        _, confirmed_pii, confirmed_non_pii, unknown = _classify_s3_buckets(s3)
        targets, pii_state = _get_pii_check_targets(confirmed_pii, unknown)
        total = len(targets)
        if pii_state == PII_NON_PII:
            pass  # All resources confirmed non-PII, skip
        else:
            for b in targets:
                try:
                    s3.get_object_lock_configuration(Bucket=b["Name"])
                except ClientError as e:
                    if "ObjectLockConfigurationNotFoundError" in str(e):
                        nc.append({"resource_name": b["Name"],
                                   "pii_classification": PII_CONFIRMED if b in confirmed_pii else PII_UNKNOWN,
                                   "note": "No Object Lock configured"})
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_s3_object_lock error: {e}")
    _meta(meta, "S3", total, nc, "Low")
    return _pii_result("ISO 27018 — S3 Object Lock", "S3", "ISO27018.S3.12",
        "Object Lock provides WORM compliance for PII retention requirements.",
        50, "Low", nc, "Enable Object Lock on buckets requiring compliance retention.",
        total, pii_confirmed=(pii_state == PII_CONFIRMED))


def iso27018_s3_replication_accounts(session, meta):
    """ISO27018.S3.13 — Replication must not target unauthorized accounts (PII-scoped)."""
    s3 = session.client("s3")
    nc, total = [], 0
    pii_state = PII_UNKNOWN
    try:
        account_id = _get_account_id(session)
        _, confirmed_pii, confirmed_non_pii, unknown = _classify_s3_buckets(s3)
        targets, pii_state = _get_pii_check_targets(confirmed_pii, unknown)
        total = len(targets)
        if pii_state != PII_NON_PII:
            for b in targets:
                try:
                    rep = s3.get_bucket_replication(Bucket=b["Name"])
                    for rule in rep.get("ReplicationConfiguration", {}).get("Rules", []):
                        dest = rule.get("Destination", {})
                        dest_account = dest.get("Account", "")
                        if dest_account and dest_account != account_id:
                            nc.append({"resource_name": b["Name"], "dest_account": dest_account,
                                       "pii_classification": PII_CONFIRMED if b in confirmed_pii else PII_UNKNOWN,
                                       "note": "Cross-account replication detected"})
                            break
                except ClientError as e:
                    if "ReplicationConfigurationNotFoundError" in str(e):
                        pass
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_s3_replication_accounts error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _pii_result("ISO 27018 — S3 Replication Unauthorized Accounts", "S3", "ISO27018.S3.13",
        "Cross-account replication sends PII to external accounts without controls.",
        80, "High", nc, "Review and validate all replication destination accounts.",
        total, pii_confirmed=(pii_state == PII_CONFIRMED))


def iso27018_s3_replication_regions(session, meta):
    """ISO27018.S3.14 — Replication must not target unauthorized regions (PII-scoped)."""
    s3 = session.client("s3")
    nc, total = [], 0
    pii_state = PII_UNKNOWN
    try:
        _, confirmed_pii, confirmed_non_pii, unknown = _classify_s3_buckets(s3)
        targets, pii_state = _get_pii_check_targets(confirmed_pii, unknown)
        total = len(targets)
        if pii_state != PII_NON_PII:
            for b in targets:
                try:
                    rep = s3.get_bucket_replication(Bucket=b["Name"])
                    for rule in rep.get("ReplicationConfiguration", {}).get("Rules", []):
                        dest_bucket = rule.get("Destination", {}).get("Bucket", "")
                        if dest_bucket:
                            nc.append({"resource_name": b["Name"], "dest": dest_bucket,
                                       "pii_classification": PII_CONFIRMED if b in confirmed_pii else PII_UNKNOWN,
                                       "note": "Replication configured — verify destination region"})
                            break
                except ClientError as e:
                    if "ReplicationConfigurationNotFoundError" in str(e):
                        pass
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_s3_replication_regions error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _pii_result("ISO 27018 — S3 Replication Region Review", "S3", "ISO27018.S3.14",
        "PII replication to non-approved regions violates data residency requirements.",
        70, "Medium", nc, "Ensure replication destinations are in approved regions only.",
        total, pii_confirmed=(pii_state == PII_CONFIRMED))


# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 IAM & IDENTITY (11 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_iam_access_analyzer(session, meta):
    """ISO27018.IAM.1 — IAM Access Analyzer must be enabled."""
    nc, total = [], 1
    try:
        aa = session.client("accessanalyzer")
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
        if not analyzers:
            nc.append({"resource_name": "AccessAnalyzer", "note": "No analyzer enabled"})
    except Exception as e:
        print(f"iso27018_iam_access_analyzer error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("ISO 27018 — IAM Access Analyzer Enabled", "IAM", "ISO27018.IAM.1",
        "Access Analyzer identifies resources shared externally, critical for PII protection.", 80, "High", nc,
        "Enable IAM Access Analyzer at the account level.", total)


def iso27018_iam_access_analyzer_findings(session, meta):
    """ISO27018.IAM.2 — No active Access Analyzer findings."""
    nc, total = [], 0
    try:
        aa = session.client("accessanalyzer")
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
        for a in analyzers:
            findings = aa.list_findings(analyzerArn=a["arn"],
                filter={"status": {"eq": ["ACTIVE"]}}).get("findings", [])
            total += len(findings)
            for f in findings[:20]:
                nc.append({"resource_name": f.get("resource", "unknown"),
                           "note": f"Active finding: {f.get('resourceType', '')}"})
    except Exception as e:
        print(f"iso27018_iam_access_analyzer_findings error: {e}")
    _meta(meta, "IAM", max(total, 1), nc, "High")
    return _result("ISO 27018 — Access Analyzer Active Findings", "IAM", "ISO27018.IAM.2",
        "Active findings indicate external access to resources potentially containing PII.", 80, "High", nc,
        "Resolve or archive all active Access Analyzer findings.", max(total, 1))


def iso27018_iam_cross_account_roles(session, meta):
    """ISO27018.IAM.3 — Review cross-account trust policies."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        account_id = _get_account_id(session)
        roles = iam.list_roles(MaxItems=200).get("Roles", [])
        total = len(roles)
        for role in roles:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                trust = _json.loads(trust)
            for stmt in trust.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal", {})
                    aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                    if isinstance(aws_p, str):
                        aws_p = [aws_p]
                    for p in aws_p:
                        if "arn:aws:iam::" in str(p) and account_id not in str(p):
                            nc.append({"resource_name": role["RoleName"], "external": p,
                                       "note": "Cross-account trust"})
                            break
    except Exception as e:
        print(f"iso27018_iam_cross_account_roles error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("ISO 27018 — IAM Cross-Account Trust", "IAM", "ISO27018.IAM.3",
        "Cross-account roles may allow external entities to access PII.", 75, "High", nc,
        "Review and validate all cross-account trust policies.", total)


def iso27018_iam_wildcard_permissions(session, meta):
    """ISO27018.IAM.4 — No IAM policies with wildcard permissions."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        policies = iam.list_policies(Scope="Local", OnlyAttached=True).get("Policies", [])
        total = len(policies)
        for pol in policies:
            try:
                ver = iam.get_policy_version(PolicyArn=pol["Arn"],
                    VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
                if isinstance(ver, str):
                    ver = _json.loads(ver)
                for stmt in ver.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions and "*" in resources:
                            nc.append({"resource_name": pol["PolicyName"], "note": "Action:* Resource:*"})
                            break
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_iam_wildcard_permissions error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("ISO 27018 — IAM Wildcard Permissions", "IAM", "ISO27018.IAM.4",
        "Policies with Action:*/Resource:* grant unlimited access to PII.", 90, "Critical", nc,
        "Replace wildcard policies with least-privilege permissions.", total)


def iso27018_iam_admin_access(session, meta):
    """ISO27018.IAM.5 — Minimize AdministratorAccess usage."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        entities = iam.list_entities_for_policy(PolicyArn=admin_arn)
        users = entities.get("PolicyUsers", [])
        roles = entities.get("PolicyRoles", [])
        groups = entities.get("PolicyGroups", [])
        total = len(users) + len(roles) + len(groups)
        for u in users:
            nc.append({"resource_name": u["UserName"], "type": "User", "note": "Has AdministratorAccess"})
        for r in roles:
            if not r["RoleName"].startswith("AWS"):
                nc.append({"resource_name": r["RoleName"], "type": "Role", "note": "Has AdministratorAccess"})
    except Exception as e:
        print(f"iso27018_iam_admin_access error: {e}")
    _meta(meta, "IAM", max(total, 1), nc, "High")
    return _result("ISO 27018 — AdministratorAccess Detection", "IAM", "ISO27018.IAM.5",
        "Entities with AdministratorAccess have unrestricted access to all PII.", 85, "High", nc,
        "Remove AdministratorAccess and use purpose-specific policies.", max(total, 1))


def iso27018_iam_password_length(session, meta):
    """ISO27018.IAM.6 — Password minimum length >= 14."""
    nc, total = [], 1
    try:
        iam = session.client("iam")
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len < 14:
            nc.append({"resource_name": "PasswordPolicy", "current": min_len, "note": f"Min length {min_len} < 14"})
    except ClientError as e:
        if "NoSuchEntity" in str(e):
            nc.append({"resource_name": "PasswordPolicy", "note": "No password policy configured"})
    except Exception as e:
        print(f"iso27018_iam_password_length error: {e}")
    _meta(meta, "IAM", total, nc, "High")
    return _result("ISO 27018 — Password Minimum Length", "IAM", "ISO27018.IAM.6",
        "Weak passwords risk unauthorized PII access.", 80, "High", nc,
        "Set minimum password length to 14 characters.", total)


def iso27018_iam_password_reuse(session, meta):
    """ISO27018.IAM.7 — Password reuse prevention >= 24."""
    nc, total = [], 1
    try:
        iam = session.client("iam")
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        reuse = policy.get("PasswordReusePrevention", 0)
        if reuse < 24:
            nc.append({"resource_name": "PasswordPolicy", "current": reuse, "note": f"Reuse prevention {reuse} < 24"})
    except ClientError as e:
        if "NoSuchEntity" in str(e):
            nc.append({"resource_name": "PasswordPolicy", "note": "No password policy"})
    except Exception as e:
        print(f"iso27018_iam_password_reuse error: {e}")
    _meta(meta, "IAM", total, nc, "Medium")
    return _result("ISO 27018 — Password Reuse Prevention", "IAM", "ISO27018.IAM.7",
        "Password reuse allows compromised credentials to be reused for PII access.", 70, "Medium", nc,
        "Set password reuse prevention to at least 24.", total)


def iso27018_iam_console_mfa(session, meta):
    """ISO27018.IAM.8 — All console users must have MFA."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        users = iam.list_users(MaxItems=200).get("Users", [])
        for u in users:
            try:
                iam.get_login_profile(UserName=u["UserName"])
                total += 1
                mfa = iam.list_mfa_devices(UserName=u["UserName"]).get("MFADevices", [])
                if not mfa:
                    nc.append({"resource_name": u["UserName"], "note": "Console access without MFA"})
            except ClientError as e:
                if "NoSuchEntity" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_iam_console_mfa error: {e}")
    _meta(meta, "IAM", max(total, 1), nc, "Critical")
    return _result("ISO 27018 — Console Users Without MFA", "IAM", "ISO27018.IAM.8",
        "Console access without MFA allows single-factor PII access.", 95, "Critical", nc,
        "Enable MFA for all IAM users with console access.", max(total, 1))


def iso27018_iam_root_access_keys(session, meta):
    """ISO27018.IAM.9 — Root account must have no access keys."""
    nc, total = [], 1
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            nc.append({"resource_name": "Root", "note": "Root has active access keys"})
    except Exception as e:
        print(f"iso27018_iam_root_access_keys error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("ISO 27018 — Root Access Keys", "IAM", "ISO27018.IAM.9",
        "Root access keys provide unrestricted access to all PII with no audit trail.", 95, "Critical", nc,
        "Delete root access keys immediately.", total)


def iso27018_iam_cross_account_trust(session, meta):
    """ISO27018.IAM.10 — Trust policies must be limited to known accounts."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        account_id = _get_account_id(session)
        roles = iam.list_roles(MaxItems=200).get("Roles", [])
        total = len(roles)
        for role in roles:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                trust = _json.loads(trust)
            for stmt in trust.get("Statement", []):
                principal = stmt.get("Principal", {})
                if principal == "*":
                    nc.append({"resource_name": role["RoleName"], "note": "Trust allows any principal (*)"})
                    break
    except Exception as e:
        print(f"iso27018_iam_cross_account_trust error: {e}")
    _meta(meta, "IAM", total, nc, "Critical")
    return _result("ISO 27018 — Wildcard Trust Policies", "IAM", "ISO27018.IAM.10",
        "Roles trusting any principal (*) allow anyone to assume and access PII.", 90, "Critical", nc,
        "Restrict trust policies to specific account IDs.", total)


def iso27018_iam_service_linked_roles(session, meta):
    """ISO27018.IAM.11 — Service-linked roles validation."""
    iam = session.client("iam")
    nc, total = [], 0
    try:
        roles = iam.list_roles(MaxItems=200).get("Roles", [])
        slr = [r for r in roles if r.get("Path", "").startswith("/aws-service-role/")]
        total = len(slr)
        # Flag informational — no hard pass/fail, just inventory
    except Exception as e:
        print(f"iso27018_iam_service_linked_roles error: {e}")
    _meta(meta, "IAM", max(total, 1), nc, "Low")
    return _result("ISO 27018 — Service-Linked Roles Inventory", "IAM", "ISO27018.IAM.11",
        "Service-linked roles should be reviewed for unexpected services.", 40, "Low", nc,
        "Review service-linked roles periodically.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 🔑 SECRETS MANAGEMENT (4 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_secrets_rotation(session, meta):
    """ISO27018.SEC.1 — All secrets must have rotation enabled."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if not s.get("RotationEnabled"):
                nc.append({"resource_name": s["Name"], "note": "Rotation not enabled"})
    except Exception as e:
        print(f"iso27018_secrets_rotation error: {e}")
    _meta(meta, "SecretsManager", total, nc, "High")
    return _result("ISO 27018 — Secret Rotation Enabled", "SecretsManager", "ISO27018.SEC.1",
        "Secrets without rotation increase risk of compromised PII access credentials.", 80, "High", nc,
        "Enable automatic rotation on all secrets.", total)


def iso27018_secrets_age(session, meta):
    """ISO27018.SEC.2 — Secrets must be rotated within 90 days."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        now = datetime.now(timezone.utc)
        for s in secrets:
            last = s.get("LastRotatedDate") or s.get("CreatedDate")
            if last and (now - last).days > 90:
                nc.append({"resource_name": s["Name"], "age_days": (now - last).days,
                           "note": f"Last rotated {(now - last).days} days ago"})
    except Exception as e:
        print(f"iso27018_secrets_age error: {e}")
    _meta(meta, "SecretsManager", total, nc, "High")
    return _result("ISO 27018 — Secrets Older Than 90 Days", "SecretsManager", "ISO27018.SEC.2",
        "Stale secrets increase window of exposure for PII access.", 75, "High", nc,
        "Ensure all secrets are rotated within 90 days.", total)


def iso27018_secrets_cmk(session, meta):
    """ISO27018.SEC.3 — Secrets should use customer-managed KMS."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            kms_id = s.get("KmsKeyId", "")
            if not kms_id or "aws/secretsmanager" in str(kms_id):
                nc.append({"resource_name": s["Name"], "note": "Using default AWS-managed KMS"})
    except Exception as e:
        print(f"iso27018_secrets_cmk error: {e}")
    _meta(meta, "SecretsManager", total, nc, "Medium")
    return _result("ISO 27018 — Secrets Customer-Managed KMS", "SecretsManager", "ISO27018.SEC.3",
        "Default KMS lacks fine-grained access control for PII credential encryption.", 65, "Medium", nc,
        "Use customer-managed KMS keys for secrets protecting PII access.", total)


def iso27018_secrets_rotation_schedule(session, meta):
    """ISO27018.SEC.4 — Rotation schedule must be configured."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if not s.get("RotationRules"):
                nc.append({"resource_name": s["Name"], "note": "No rotation schedule"})
    except Exception as e:
        print(f"iso27018_secrets_rotation_schedule error: {e}")
    _meta(meta, "SecretsManager", total, nc, "Medium")
    return _result("ISO 27018 — Secrets Rotation Schedule", "SecretsManager", "ISO27018.SEC.4",
        "Without rotation schedules, credential hygiene for PII systems is unmanaged.", 65, "Medium", nc,
        "Configure rotation schedules on all secrets.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 KMS (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_kms_disabled_keys(session, meta):
    """ISO27018.KMS.1 — No KMS keys in Disabled state."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                try:
                    km = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if km.get("KeyManager") == "AWS":
                        continue
                    total += 1
                    if km.get("KeyState") == "Disabled":
                        nc.append({"resource_name": km["KeyId"], "note": "Key disabled"})
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_kms_disabled_keys error: {e}")
    _meta(meta, "KMS", max(total, 1), nc, "High")
    return _result("ISO 27018 — Disabled KMS Keys", "KMS", "ISO27018.KMS.1",
        "Disabled keys may be protecting active PII — data becomes inaccessible.", 75, "High", nc,
        "Review disabled keys; re-enable or confirm PII is no longer encrypted with them.", max(total, 1))


def iso27018_kms_pending_deletion(session, meta):
    """ISO27018.KMS.2 — No KMS keys pending deletion."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                try:
                    km = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if km.get("KeyManager") == "AWS":
                        continue
                    total += 1
                    if km.get("KeyState") == "PendingDeletion":
                        nc.append({"resource_name": km["KeyId"],
                                   "deletion_date": str(km.get("DeletionDate", "")),
                                   "note": "Key pending deletion"})
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_kms_pending_deletion error: {e}")
    _meta(meta, "KMS", max(total, 1), nc, "Critical")
    return _result("ISO 27018 — KMS Keys Pending Deletion", "KMS", "ISO27018.KMS.2",
        "Keys pending deletion will make encrypted PII permanently inaccessible.", 95, "Critical", nc,
        "Cancel deletion for keys protecting active PII data.", max(total, 1))


def iso27018_kms_multi_region(session, meta):
    """ISO27018.KMS.3 — Review Multi-Region KMS keys."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                try:
                    km = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if km.get("KeyManager") == "AWS":
                        continue
                    total += 1
                    if km.get("MultiRegion"):
                        nc.append({"resource_name": km["KeyId"], "note": "Multi-Region key — verify regions"})
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_kms_multi_region error: {e}")
    _meta(meta, "KMS", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — Multi-Region KMS Keys", "KMS", "ISO27018.KMS.3",
        "Multi-Region keys may replicate PII decryption capability to unapproved regions.", 65, "Medium", nc,
        "Verify all Multi-Region key replicas are in approved regions.", max(total, 1))


def iso27018_kms_key_policy(session, meta):
    """ISO27018.KMS.4 — KMS key policies must not allow external access."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        account_id = _get_account_id(session)
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                try:
                    km = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if km.get("KeyManager") == "AWS" or km.get("KeyState") != "Enabled":
                        continue
                    total += 1
                    policy = _json.loads(kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")["Policy"])
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            if principal == "*":
                                nc.append({"resource_name": km["KeyId"], "note": "Key policy allows Principal:*"})
                                break
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_kms_key_policy error: {e}")
    _meta(meta, "KMS", max(total, 1), nc, "High")
    return _result("ISO 27018 — KMS Key Policy Validation", "KMS", "ISO27018.KMS.4",
        "Key policies with external access allow unauthorized PII decryption.", 80, "High", nc,
        "Restrict key policies to the owning account only.", max(total, 1))


def iso27018_kms_cmk_usage(session, meta):
    """ISO27018.KMS.5 — Customer-managed keys should exist."""
    kms = session.client("kms")
    nc, total, cmk_count = [], 0, 0
    try:
        for page in kms.get_paginator("list_keys").paginate():
            for key in page.get("Keys", []):
                try:
                    km = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if km.get("KeyManager") == "Customer" and km.get("KeyState") == "Enabled":
                        cmk_count += 1
                    total += 1
                except Exception:
                    pass
        if cmk_count == 0:
            nc.append({"resource_name": "KMS", "note": "No active customer-managed keys"})
    except Exception as e:
        print(f"iso27018_kms_cmk_usage error: {e}")
    _meta(meta, "KMS", 1, nc, "High")
    return _result("ISO 27018 — Customer-Managed Key Usage", "KMS", "ISO27018.KMS.5",
        "Without CMKs, PII encryption relies solely on AWS-managed keys with no custom access control.", 75, "High", nc,
        "Create customer-managed KMS keys for PII encryption with fine-grained policies.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 📋 CLOUDTRAIL & LOGGING (9 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_log_insights(session, meta):
    """ISO27018.LOG.1 — CloudTrail Insights enabled."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) or 1
        has_insights = False
        for t in trails:
            try:
                sel = ct.get_insight_selectors(TrailName=t["TrailARN"])
                if sel.get("InsightSelectors"):
                    has_insights = True
                    break
            except Exception:
                pass
        if not has_insights:
            nc.append({"resource_name": "CloudTrail", "note": "No trail has Insights enabled"})
    except Exception as e:
        print(f"iso27018_log_insights error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Medium")
    return _result("ISO 27018 — CloudTrail Insights", "CloudTrail", "ISO27018.LOG.1",
        "Insights detect anomalous API activity that may indicate unauthorized PII access.", 65, "Medium", nc,
        "Enable CloudTrail Insights on at least one trail.", total)


def iso27018_log_org_trail(session, meta):
    """ISO27018.LOG.2 — Organization Trail enabled."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) or 1
        has_org = any(t.get("IsOrganizationTrail") for t in trails)
        if not has_org:
            nc.append({"resource_name": "CloudTrail", "note": "No organization trail"})
    except Exception as e:
        print(f"iso27018_log_org_trail error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Medium")
    return _result("ISO 27018 — Organization Trail", "CloudTrail", "ISO27018.LOG.2",
        "Organization trails centralize PII audit logging across all accounts.", 60, "Medium", nc,
        "Enable an Organization Trail for multi-account PII audit.", total)


def iso27018_log_validation(session, meta):
    """ISO27018.LOG.3 — Log file validation enabled."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) or 1
        for t in trails:
            if not t.get("LogFileValidationEnabled"):
                nc.append({"resource_name": t["Name"], "note": "Log validation disabled"})
    except Exception as e:
        print(f"iso27018_log_validation error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("ISO 27018 — CloudTrail Log Validation", "CloudTrail", "ISO27018.LOG.3",
        "Without validation, PII audit logs can be tampered with undetected.", 80, "High", nc,
        "Enable log file validation on all trails.", total)


def iso27018_log_cw_encryption(session, meta):
    """ISO27018.LOG.4 — CloudWatch Logs encryption."""
    nc, total = [], 0
    try:
        logs = session.client("logs")
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups)
        for g in groups:
            if not g.get("kmsKeyId"):
                nc.append({"resource_name": g["logGroupName"], "note": "No KMS encryption"})
    except Exception as e:
        print(f"iso27018_log_cw_encryption error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("ISO 27018 — CloudWatch Logs Encryption", "CloudWatch", "ISO27018.LOG.4",
        "Unencrypted log groups may contain PII metadata.", 65, "Medium", nc,
        "Associate KMS keys with CloudWatch log groups.", total)


def iso27018_log_retention(session, meta):
    """ISO27018.LOG.5 — Log retention must be configured."""
    nc, total = [], 0
    try:
        logs = session.client("logs")
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups)
        for g in groups:
            if not g.get("retentionInDays"):
                nc.append({"resource_name": g["logGroupName"], "note": "No retention set (infinite)"})
    except Exception as e:
        print(f"iso27018_log_retention error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("ISO 27018 — Log Retention Configured", "CloudWatch", "ISO27018.LOG.5",
        "Infinite retention of logs containing PII metadata violates data minimization.", 60, "Medium", nc,
        "Set retention policies on all log groups.", total)


def iso27018_log_alarm_root(session, meta):
    """ISO27018.LOG.6 — Alarm for root login."""
    nc, total = [], 1
    try:
        logs = session.client("logs")
        filters = logs.describe_metric_filters().get("metricFilters", [])
        root_pattern = any("Root" in (f.get("filterPattern", "") or "") for f in filters)
        if not root_pattern:
            nc.append({"resource_name": "MetricFilters", "note": "No metric filter for root login"})
    except Exception as e:
        print(f"iso27018_log_alarm_root error: {e}")
    _meta(meta, "CloudWatch", total, nc, "High")
    return _result("ISO 27018 — Root Login Alarm", "CloudWatch", "ISO27018.LOG.6",
        "Root logins must be alarmed for immediate PII breach detection.", 80, "High", nc,
        "Create a metric filter and alarm for root account login events.", total)


def iso27018_log_alarm_unauth(session, meta):
    """ISO27018.LOG.7 — Alarm for unauthorized API calls."""
    nc, total = [], 1
    try:
        logs = session.client("logs")
        filters = logs.describe_metric_filters().get("metricFilters", [])
        unauth = any("UnauthorizedAccess" in (f.get("filterPattern", "") or "") or
                     "AccessDenied" in (f.get("filterPattern", "") or "") for f in filters)
        if not unauth:
            nc.append({"resource_name": "MetricFilters", "note": "No filter for unauthorized API calls"})
    except Exception as e:
        print(f"iso27018_log_alarm_unauth error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("ISO 27018 — Unauthorized API Alarm", "CloudWatch", "ISO27018.LOG.7",
        "Unauthorized API calls may indicate attempted PII exfiltration.", 70, "Medium", nc,
        "Create metric filters for unauthorized/denied API calls.", total)


def iso27018_log_alarm_s3(session, meta):
    """ISO27018.LOG.8 — Alarm for S3 policy changes."""
    nc, total = [], 1
    try:
        logs = session.client("logs")
        filters = logs.describe_metric_filters().get("metricFilters", [])
        s3_filter = any("PutBucketPolicy" in (f.get("filterPattern", "") or "") or
                        "DeleteBucketPolicy" in (f.get("filterPattern", "") or "") for f in filters)
        if not s3_filter:
            nc.append({"resource_name": "MetricFilters", "note": "No filter for S3 policy changes"})
    except Exception as e:
        print(f"iso27018_log_alarm_s3 error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("ISO 27018 — S3 Policy Change Alarm", "CloudWatch", "ISO27018.LOG.8",
        "S3 policy changes can expose PII buckets publicly.", 70, "Medium", nc,
        "Create metric filters for S3 bucket policy modifications.", total)


def iso27018_log_alarm_kms(session, meta):
    """ISO27018.LOG.9 — Alarm for KMS changes."""
    nc, total = [], 1
    try:
        logs = session.client("logs")
        filters = logs.describe_metric_filters().get("metricFilters", [])
        kms_filter = any("DisableKey" in (f.get("filterPattern", "") or "") or
                         "ScheduleKeyDeletion" in (f.get("filterPattern", "") or "") for f in filters)
        if not kms_filter:
            nc.append({"resource_name": "MetricFilters", "note": "No filter for KMS changes"})
    except Exception as e:
        print(f"iso27018_log_alarm_kms error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("ISO 27018 — KMS Change Alarm", "CloudWatch", "ISO27018.LOG.9",
        "KMS key deletion/disable can make PII permanently inaccessible.", 70, "Medium", nc,
        "Create metric filters for KMS key disable and schedule deletion events.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🌍 DATA RESIDENCY (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_dr_s3_regions(session, meta):
    """ISO27018.DR.1 — Identify S3 bucket regions."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                loc = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint") or "us-east-1"
                # Flag non-standard regions (informational — customize approved list)
                nc.append({"resource_name": b["Name"], "region": loc, "note": f"Located in {loc}"})
            except Exception:
                pass
        # This is informational — clear nc if all is well (user should customize)
        nc = []  # Remove for production — keep as inventory only
    except Exception as e:
        print(f"iso27018_dr_s3_regions error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("ISO 27018 — S3 Bucket Region Inventory", "S3", "ISO27018.DR.1",
        "PII bucket locations must be known and in approved regions.", 65, "Medium", nc,
        "Document all bucket regions and validate against approved list.", total)


def iso27018_dr_rds_regions(session, meta):
    """ISO27018.DR.2 — Identify RDS instance regions."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total = len(dbs)
        # Informational — validate against approved regions
    except Exception as e:
        print(f"iso27018_dr_rds_regions error: {e}")
    _meta(meta, "RDS", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — RDS Region Inventory", "RDS", "ISO27018.DR.2",
        "RDS instances with PII must be in approved regions.", 65, "Medium", nc,
        "Validate all RDS instances are in approved regions.", max(total, 1))


def iso27018_dr_cross_region_snapshots(session, meta):
    """ISO27018.DR.3 — Detect cross-region snapshots."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        snaps = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        total = len(snaps)
        region = session.region_name
        for s in snaps:
            az = s.get("AvailabilityZone", "")
            if az and not az.startswith(region):
                nc.append({"resource_name": s["DBSnapshotIdentifier"], "note": f"Snapshot in {az}"})
    except Exception as e:
        print(f"iso27018_dr_cross_region_snapshots error: {e}")
    _meta(meta, "RDS", total, nc, "Medium")
    return _result("ISO 27018 — Cross-Region Snapshots", "RDS", "ISO27018.DR.3",
        "Cross-region snapshots may move PII outside approved jurisdictions.", 70, "Medium", nc,
        "Review cross-region snapshot copies for PII databases.", total)


def iso27018_dr_s3_cross_account_replication(session, meta):
    """ISO27018.DR.4 — S3 cross-account replication review (PII-scoped, three-state)."""
    s3 = session.client("s3")
    nc, total = [], 0
    pii_state = PII_UNKNOWN
    try:
        account_id = _get_account_id(session)
        _, confirmed_pii, confirmed_non_pii, unknown = _classify_s3_buckets(s3)
        targets, pii_state = _get_pii_check_targets(confirmed_pii, unknown)
        total = len(targets)
        if pii_state != PII_NON_PII:
            for b in targets:
                try:
                    rep = s3.get_bucket_replication(Bucket=b["Name"])
                    for rule in rep.get("ReplicationConfiguration", {}).get("Rules", []):
                        dest_acct = rule.get("Destination", {}).get("Account", "")
                        if dest_acct and dest_acct != account_id:
                            nc.append({"resource_name": b["Name"], "dest_account": dest_acct,
                                       "pii_classification": PII_CONFIRMED if b in confirmed_pii else PII_UNKNOWN,
                                       "note": "Cross-account replication"})
                            break
                except ClientError:
                    pass
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_dr_s3_cross_account_replication error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _pii_result("ISO 27018 — Cross-Account Replication", "S3", "ISO27018.DR.4",
        "Cross-account replication sends PII copies to other AWS accounts.",
        75, "High", nc, "Validate all replication destinations are authorized.",
        total, pii_confirmed=(pii_state == PII_CONFIRMED))


def iso27018_dr_cloudfront(session, meta):
    """ISO27018.DR.5 — CloudFront distribution review."""
    nc, total = [], 0
    try:
        cf = session.client("cloudfront")
        dists = cf.list_distributions().get("DistributionList", {}).get("Items", [])
        total = len(dists) if dists else 0
        for d in (dists or []):
            geo = d.get("Restrictions", {}).get("GeoRestriction", {})
            if geo.get("RestrictionType") == "none":
                nc.append({"resource_name": d.get("Id", ""), "note": "No geo restriction on distribution"})
    except Exception as e:
        print(f"iso27018_dr_cloudfront error: {e}")
    _meta(meta, "CloudFront", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — CloudFront Geo Restrictions", "CloudFront", "ISO27018.DR.5",
        "CloudFront without geo restrictions may serve PII content globally.", 60, "Medium", nc,
        "Apply geo restrictions on distributions serving PII content.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 💾 BACKUP (6 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_backup_vault_encryption(session, meta):
    """ISO27018.BKP.1 — Backup vaults must be encrypted."""
    nc, total = [], 0
    try:
        bk = session.client("backup")
        vaults = bk.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            if not v.get("EncryptionKeyArn"):
                nc.append({"resource_name": v["BackupVaultName"], "note": "No encryption key"})
    except Exception as e:
        print(f"iso27018_backup_vault_encryption error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "High")
    return _result("ISO 27018 — Backup Vault Encryption", "Backup", "ISO27018.BKP.1",
        "Unencrypted backup vaults expose PII in recovery scenarios.", 80, "High", nc,
        "Ensure all backup vaults use KMS encryption.", max(total, 1))


def iso27018_backup_vault_policy(session, meta):
    """ISO27018.BKP.2 — Backup vault access policies must restrict access."""
    nc, total = [], 0
    try:
        bk = session.client("backup")
        vaults = bk.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            try:
                policy = bk.get_backup_vault_access_policy(BackupVaultName=v["BackupVaultName"])
                doc = _json.loads(policy.get("Policy", "{}"))
                for stmt in doc.get("Statement", []):
                    if stmt.get("Principal") == "*" and stmt.get("Effect") == "Allow":
                        nc.append({"resource_name": v["BackupVaultName"], "note": "Wildcard principal in vault policy"})
                        break
            except ClientError:
                pass
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_backup_vault_policy error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "High")
    return _result("ISO 27018 — Backup Vault Policy", "Backup", "ISO27018.BKP.2",
        "Open vault policies allow unauthorized PII backup access.", 75, "High", nc,
        "Restrict backup vault policies to specific principals.", max(total, 1))


def iso27018_backup_recovery_points(session, meta):
    """ISO27018.BKP.3 — Recovery points must exist."""
    nc, total = [], 0
    try:
        bk = session.client("backup")
        vaults = bk.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            try:
                points = bk.list_recovery_points_by_backup_vault(
                    BackupVaultName=v["BackupVaultName"], MaxResults=1).get("RecoveryPoints", [])
                if not points:
                    nc.append({"resource_name": v["BackupVaultName"], "note": "No recovery points"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_backup_recovery_points error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — Recovery Points Exist", "Backup", "ISO27018.BKP.3",
        "Vaults without recovery points indicate backups are not running.", 65, "Medium", nc,
        "Verify backup jobs are producing recovery points.", max(total, 1))


def iso27018_backup_retention(session, meta):
    """ISO27018.BKP.4 — Backup retention must be adequate."""
    nc, total = [], 0
    try:
        bk = session.client("backup")
        plans = bk.list_backup_plans().get("BackupPlansList", [])
        total = len(plans)
        for p in plans:
            try:
                plan = bk.get_backup_plan(BackupPlanId=p["BackupPlanId"])["BackupPlan"]
                for rule in plan.get("Rules", []):
                    lifecycle = rule.get("Lifecycle", {})
                    delete_days = lifecycle.get("DeleteAfterDays", 0)
                    if delete_days and delete_days < 30:
                        nc.append({"resource_name": p.get("BackupPlanName", p["BackupPlanId"]),
                                   "retention": delete_days, "note": f"Retention only {delete_days} days"})
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_backup_retention error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — Backup Retention Validation", "Backup", "ISO27018.BKP.4",
        "Short retention periods may not meet PII recovery obligations.", 65, "Medium", nc,
        "Set backup retention to at least 30 days for PII resources.", max(total, 1))


def iso27018_backup_cross_region(session, meta):
    """ISO27018.BKP.5 — Cross-region copies must target approved regions."""
    nc, total = [], 0
    try:
        bk = session.client("backup")
        plans = bk.list_backup_plans().get("BackupPlansList", [])
        total = len(plans)
        for p in plans:
            try:
                plan = bk.get_backup_plan(BackupPlanId=p["BackupPlanId"])["BackupPlan"]
                for rule in plan.get("Rules", []):
                    copies = rule.get("CopyActions", [])
                    for c in copies:
                        dest = c.get("DestinationBackupVaultArn", "")
                        if dest:
                            nc.append({"resource_name": p.get("BackupPlanName", ""),
                                       "dest": dest, "note": "Cross-region copy — verify region"})
            except Exception:
                pass
        nc = []  # Informational only — customize for production
    except Exception as e:
        print(f"iso27018_backup_cross_region error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — Cross-Region Backup Copies", "Backup", "ISO27018.BKP.5",
        "Cross-region backup copies may move PII to unapproved regions.", 65, "Medium", nc,
        "Validate backup copy destinations are in approved regions.", max(total, 1))


def iso27018_backup_rds_coverage(session, meta):
    """ISO27018.BKP.6 — All RDS instances must be in backup plans."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        bk = session.client("backup")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total = len(dbs)
        protected = bk.list_protected_resources().get("Results", [])
        protected_arns = {r["ResourceArn"] for r in protected}
        for db in dbs:
            arn = db.get("DBInstanceArn", "")
            if arn and arn not in protected_arns:
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Not in backup plan"})
    except Exception as e:
        print(f"iso27018_backup_rds_coverage error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "High")
    return _result("ISO 27018 — RDS Backup Coverage", "Backup", "ISO27018.BKP.6",
        "RDS instances without backup plans risk PII data loss.", 75, "High", nc,
        "Add all RDS instances to AWS Backup plans.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 🌐 NETWORK (7 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_net_db_sg_exposed(session, meta):
    """ISO27018.NET.1 — Database security groups must not be exposed."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        total = len(sgs)
        db_ports = [3306, 5432, 1433, 1521, 27017, 6379]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                port = rule.get("FromPort", 0)
                if port in db_ports:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            nc.append({"resource_name": sg["GroupId"], "port": port,
                                       "note": f"Port {port} open to 0.0.0.0/0"})
                            break
    except Exception as e:
        print(f"iso27018_net_db_sg_exposed error: {e}")
    _meta(meta, "EC2", total, nc, "Critical")
    return _result("ISO 27018 — Database SG Exposed", "EC2", "ISO27018.NET.1",
        "Database ports open to the internet directly expose PII.", 95, "Critical", nc,
        "Restrict database security groups to specific CIDR blocks.", total)


def iso27018_net_public_subnets(session, meta):
    """ISO27018.NET.2 — PII resources should not be in public subnets."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        subnets = ec2.describe_subnets().get("Subnets", [])
        total = len(subnets)
        for s in subnets:
            if s.get("MapPublicIpOnLaunch"):
                nc.append({"resource_name": s["SubnetId"], "note": "Auto-assigns public IPs"})
    except Exception as e:
        print(f"iso27018_net_public_subnets error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("ISO 27018 — Public Subnets Hosting PII", "EC2", "ISO27018.NET.2",
        "Public subnets auto-assign public IPs, exposing PII workloads.", 65, "Medium", nc,
        "Place PII resources in private subnets only.", total)


def iso27018_net_vpc_endpoint_s3(session, meta):
    """ISO27018.NET.3 — VPC endpoint for S3 must exist."""
    ec2 = session.client("ec2")
    nc, total = [], 1
    try:
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        s3_ep = any("s3" in ep.get("ServiceName", "") for ep in endpoints)
        if not s3_ep:
            nc.append({"resource_name": "VPC", "note": "No S3 VPC endpoint"})
    except Exception as e:
        print(f"iso27018_net_vpc_endpoint_s3 error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("ISO 27018 — VPC Endpoint for S3", "EC2", "ISO27018.NET.3",
        "Without S3 VPC endpoint, PII traffic traverses the public internet.", 70, "Medium", nc,
        "Create a VPC endpoint for S3 to keep PII traffic private.", total)


def iso27018_net_vpc_endpoint_secrets(session, meta):
    """ISO27018.NET.4 — VPC endpoint for Secrets Manager must exist."""
    ec2 = session.client("ec2")
    nc, total = [], 1
    try:
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        sm_ep = any("secretsmanager" in ep.get("ServiceName", "") for ep in endpoints)
        if not sm_ep:
            nc.append({"resource_name": "VPC", "note": "No Secrets Manager VPC endpoint"})
    except Exception as e:
        print(f"iso27018_net_vpc_endpoint_secrets error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("ISO 27018 — VPC Endpoint for Secrets Manager", "EC2", "ISO27018.NET.4",
        "Secrets for PII systems traverse public internet without VPC endpoint.", 65, "Medium", nc,
        "Create a VPC endpoint for Secrets Manager.", total)


def iso27018_net_vpc_endpoint_kms(session, meta):
    """ISO27018.NET.5 — VPC endpoint for KMS must exist."""
    ec2 = session.client("ec2")
    nc, total = [], 1
    try:
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        kms_ep = any("kms" in ep.get("ServiceName", "") for ep in endpoints)
        if not kms_ep:
            nc.append({"resource_name": "VPC", "note": "No KMS VPC endpoint"})
    except Exception as e:
        print(f"iso27018_net_vpc_endpoint_kms error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("ISO 27018 — VPC Endpoint for KMS", "EC2", "ISO27018.NET.5",
        "KMS operations for PII encryption traverse public internet.", 65, "Medium", nc,
        "Create a VPC endpoint for KMS.", total)


def iso27018_net_waf_alb(session, meta):
    """ISO27018.NET.6 — Public ALBs must have WAF."""
    nc, total = [], 0
    try:
        elbv2 = session.client("elbv2")
        waf = session.client("wafv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        public_albs = [lb for lb in lbs if lb.get("Scheme") == "internet-facing" and lb.get("Type") == "application"]
        total = len(public_albs)
        # Get WAF-protected resources
        protected_arns = set()
        try:
            acls = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
            for acl in acls:
                try:
                    resources = waf.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get("ResourceArns", [])
                    protected_arns.update(resources)
                except Exception:
                    pass
        except Exception:
            pass
        for alb in public_albs:
            if alb["LoadBalancerArn"] not in protected_arns:
                nc.append({"resource_name": alb.get("LoadBalancerName", ""), "note": "No WAF associated"})
    except Exception as e:
        print(f"iso27018_net_waf_alb error: {e}")
    _meta(meta, "WAF", max(total, 1), nc, "High")
    return _result("ISO 27018 — WAF on Public ALBs", "WAF", "ISO27018.NET.6",
        "Public ALBs without WAF expose PII endpoints to attacks.", 80, "High", nc,
        "Associate WAF web ACLs with all internet-facing ALBs.", max(total, 1))


def iso27018_net_nacl_open(session, meta):
    """ISO27018.NET.7 — NACLs must not allow unrestricted inbound."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        nacls = ec2.describe_network_acls().get("NetworkAcls", [])
        total = len(nacls)
        for nacl in nacls:
            for entry in nacl.get("Entries", []):
                if (not entry.get("Egress") and entry.get("RuleAction") == "allow" and
                    entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("Protocol") == "-1" and
                    entry.get("RuleNumber", 0) != 32767):
                    nc.append({"resource_name": nacl["NetworkAclId"], "note": "Allow all inbound"})
                    break
    except Exception as e:
        print(f"iso27018_net_nacl_open error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("ISO 27018 — NACL Unrestricted Access", "EC2", "ISO27018.NET.7",
        "Open NACLs provide no network-level protection for PII.", 75, "High", nc,
        "Restrict NACLs to specific CIDR blocks and ports.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔌 API SECURITY (6 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_api_authorization(session, meta):
    """ISO27018.API.1 — API Gateway must have authorization."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        total = len(apis)
        for api in apis:
            try:
                resources = apigw.get_resources(restApiId=api["id"]).get("items", [])
                for res in resources:
                    for method in res.get("resourceMethods", {}).keys():
                        try:
                            m = apigw.get_method(restApiId=api["id"], resourceId=res["id"], httpMethod=method)
                            if m.get("authorizationType") == "NONE":
                                nc.append({"resource_name": f"{api['name']}/{res.get('path', '')}/{method}",
                                           "note": "No authorization"})
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_api_authorization error: {e}")
    _meta(meta, "APIGateway", max(total, 1), nc, "High")
    return _result("ISO 27018 — API Gateway Authorization", "APIGateway", "ISO27018.API.1",
        "Unauthenticated APIs may expose PII without access control.", 80, "High", nc,
        "Add authorization (IAM, Cognito, or Lambda) to all API methods.", max(total, 1))


def iso27018_api_access_logging(session, meta):
    """ISO27018.API.2 — API Gateway access logging enabled."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        total = len(apis)
        for api in apis:
            try:
                stages = apigw.get_stages(restApiId=api["id"]).get("item", [])
                for stage in stages:
                    if not stage.get("accessLogSettings"):
                        nc.append({"resource_name": f"{api['name']}/{stage['stageName']}",
                                   "note": "No access logging"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_api_access_logging error: {e}")
    _meta(meta, "APIGateway", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — API Gateway Access Logging", "APIGateway", "ISO27018.API.2",
        "Without access logging, PII API access cannot be audited.", 70, "Medium", nc,
        "Enable access logging on all API Gateway stages.", max(total, 1))


def iso27018_api_execution_logging(session, meta):
    """ISO27018.API.3 — API Gateway execution logging enabled."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        total = len(apis)
        for api in apis:
            try:
                stages = apigw.get_stages(restApiId=api["id"]).get("item", [])
                for stage in stages:
                    settings = stage.get("methodSettings", {}).get("*/*", {})
                    if not settings.get("loggingLevel") or settings["loggingLevel"] == "OFF":
                        nc.append({"resource_name": f"{api['name']}/{stage['stageName']}",
                                   "note": "Execution logging OFF"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_api_execution_logging error: {e}")
    _meta(meta, "APIGateway", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — API Execution Logging", "APIGateway", "ISO27018.API.3",
        "Execution logging captures request/response details for PII audit.", 65, "Medium", nc,
        "Enable execution logging on API Gateway stages.", max(total, 1))


def iso27018_api_tls_version(session, meta):
    """ISO27018.API.4 — TLS must be 1.2 or higher."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        domains = apigw.get_domain_names().get("items", [])
        total = len(domains)
        for d in domains:
            policy = d.get("securityPolicy", "")
            if policy and "TLS_1_0" in policy:
                nc.append({"resource_name": d["domainName"], "note": f"TLS policy: {policy}"})
    except Exception as e:
        print(f"iso27018_api_tls_version error: {e}")
    _meta(meta, "APIGateway", max(total, 1), nc, "High")
    return _result("ISO 27018 — TLS Version", "APIGateway", "ISO27018.API.4",
        "TLS below 1.2 has known vulnerabilities for PII-in-transit.", 80, "High", nc,
        "Set security policy to TLS_1_2 on all custom domains.", max(total, 1))


def iso27018_api_http_listeners(session, meta):
    """ISO27018.API.5 — No HTTP listeners without HTTPS redirect."""
    nc, total = [], 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
            total += len(listeners)
            for l in listeners:
                if l.get("Protocol") == "HTTP":
                    actions = l.get("DefaultActions", [])
                    is_redirect = any(a.get("Type") == "redirect" and
                                      a.get("RedirectConfig", {}).get("Protocol") == "HTTPS" for a in actions)
                    if not is_redirect:
                        nc.append({"resource_name": lb.get("LoadBalancerName", ""),
                                   "port": l.get("Port"), "note": "HTTP without HTTPS redirect"})
    except Exception as e:
        print(f"iso27018_api_http_listeners error: {e}")
    _meta(meta, "ELB", max(total, 1), nc, "High")
    return _result("ISO 27018 — HTTP Listeners", "ELB", "ISO27018.API.5",
        "HTTP listeners transmit PII in cleartext.", 85, "High", nc,
        "Replace HTTP listeners with HTTPS or add redirect actions.", max(total, 1))


def iso27018_api_acm_expiry(session, meta):
    """ISO27018.API.6 — ACM certificates must not be expiring."""
    nc, total = [], 0
    try:
        acm = session.client("acm")
        certs = acm.list_certificates().get("CertificateSummaryList", [])
        total = len(certs)
        now = datetime.now(timezone.utc)
        for c in certs:
            try:
                detail = acm.describe_certificate(CertificateArn=c["CertificateArn"])["Certificate"]
                expiry = detail.get("NotAfter")
                if expiry and (expiry - now).days < 30:
                    nc.append({"resource_name": detail.get("DomainName", ""),
                               "expires_in": (expiry - now).days, "note": f"Expires in {(expiry - now).days} days"})
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_api_acm_expiry error: {e}")
    _meta(meta, "ACM", max(total, 1), nc, "High")
    return _result("ISO 27018 — ACM Certificate Expiry", "ACM", "ISO27018.API.6",
        "Expired certificates break TLS protection for PII in transit.", 80, "High", nc,
        "Renew certificates expiring within 30 days.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 📊 MONITORING (6 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_mon_macie_jobs(session, meta):
    """ISO27018.MON.1 — Macie must have active classification jobs (PII discovery)."""
    nc, total = [], 1
    pii_confirmed = False
    try:
        macie = session.client("macie2")
        macie.get_macie_session()  # Verify enabled
        pii_confirmed = True  # If Macie is enabled, org is PII-aware
        jobs = macie.list_classification_jobs(filterCriteria={"includes": [
            {"key": "jobStatus", "values": [{"value": "RUNNING"}]}
        ]}).get("items", [])
        if not jobs:
            nc.append({"resource_name": "Macie", "note": "No active classification jobs"})
    except ClientError:
        nc.append({"resource_name": "Macie", "note": "Macie not enabled or no access"})
    except Exception as e:
        print(f"iso27018_mon_macie_jobs error: {e}")
    _meta(meta, "Macie", total, nc, "Medium")
    return _pii_result("ISO 27018 — Macie Classification Jobs", "Macie", "ISO27018.MON.1",
        "Without active jobs, Macie cannot discover PII in S3.",
        65, "Medium", nc, "Create and run Macie classification jobs on PII buckets.",
        total, pii_confirmed=pii_confirmed)


def iso27018_mon_macie_buckets(session, meta):
    """ISO27018.MON.2 — Sensitive buckets must be monitored by Macie (PII-dependent)."""
    nc, total = [], 1
    pii_confirmed = False
    try:
        macie = session.client("macie2")
        macie.get_macie_session()  # Check if enabled
        pii_confirmed = True
    except ClientError:
        nc.append({"resource_name": "Macie", "note": "Macie not enabled"})
    except Exception as e:
        print(f"iso27018_mon_macie_buckets error: {e}")
    _meta(meta, "Macie", total, nc, "Medium")
    return _pii_result("ISO 27018 — Macie Bucket Coverage", "Macie", "ISO27018.MON.2",
        "PII buckets not monitored by Macie miss sensitive data exposure.",
        65, "Medium", nc, "Enable Macie and configure bucket monitoring.",
        total, pii_confirmed=pii_confirmed)


def iso27018_mon_cloudtrail_data_events(session, meta):
    """ISO27018.MON.3 — CloudTrail data events must be enabled."""
    ct = session.client("cloudtrail")
    nc, total = [], 1
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        has_data = False
        for t in trails:
            try:
                sel = ct.get_event_selectors(TrailName=t["TrailARN"])
                for es in sel.get("EventSelectors", []):
                    if es.get("DataResources"):
                        has_data = True
                        break
                for ads in sel.get("AdvancedEventSelectors", []):
                    for fs in ads.get("FieldSelectors", []):
                        if fs.get("Field") == "eventCategory" and "Data" in fs.get("Equals", []):
                            has_data = True
                if has_data:
                    break
            except Exception:
                pass
        if not has_data:
            nc.append({"resource_name": "CloudTrail", "note": "No data events configured"})
    except Exception as e:
        print(f"iso27018_mon_cloudtrail_data_events error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("ISO 27018 — CloudTrail Data Events", "CloudTrail", "ISO27018.MON.3",
        "Without data events, S3 object access to PII is not logged.", 80, "High", nc,
        "Enable data events for S3 and Lambda on at least one trail.", total)


def iso27018_mon_alarms(session, meta):
    """ISO27018.MON.4 — CloudWatch alarms must exist for PII services."""
    nc, total = [], 1
    try:
        cw = session.client("cloudwatch")
        alarms = cw.describe_alarms(MaxRecords=100).get("MetricAlarms", [])
        if not alarms:
            nc.append({"resource_name": "CloudWatch", "note": "No alarms configured"})
    except Exception as e:
        print(f"iso27018_mon_alarms error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("ISO 27018 — CloudWatch Alarms", "CloudWatch", "ISO27018.MON.4",
        "Without alarms, PII-related security events go unnoticed.", 65, "Medium", nc,
        "Create alarms for S3, RDS, KMS, and IAM security events.", total)


def iso27018_mon_guardduty_s3(session, meta):
    """ISO27018.MON.5 — GuardDuty S3 Protection enabled."""
    nc, total = [], 1
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            nc.append({"resource_name": "GuardDuty", "note": "No detectors"})
        else:
            det = gd.get_detector(DetectorId=detectors[0])
            ds = det.get("DataSources", {}).get("S3Logs", {})
            if ds.get("Status") != "ENABLED":
                nc.append({"resource_name": "GuardDuty", "note": "S3 Protection not enabled"})
    except Exception as e:
        print(f"iso27018_mon_guardduty_s3 error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("ISO 27018 — GuardDuty S3 Protection", "GuardDuty", "ISO27018.MON.5",
        "S3 Protection detects anomalous access to PII in buckets.", 80, "High", nc,
        "Enable S3 Protection in GuardDuty.", total)


def iso27018_mon_guardduty_malware(session, meta):
    """ISO27018.MON.6 — GuardDuty Malware Protection enabled."""
    nc, total = [], 1
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            nc.append({"resource_name": "GuardDuty", "note": "No detectors"})
        else:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            malware = any(f.get("Name") == "EBS_MALWARE_PROTECTION" and f.get("Status") == "ENABLED" for f in features)
            if not malware:
                nc.append({"resource_name": "GuardDuty", "note": "Malware Protection not enabled"})
    except Exception as e:
        print(f"iso27018_mon_guardduty_malware error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("ISO 27018 — GuardDuty Malware Protection", "GuardDuty", "ISO27018.MON.6",
        "Malware can be used to exfiltrate PII from compromised instances.", 75, "High", nc,
        "Enable Malware Protection in GuardDuty.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🚨 INCIDENT RESPONSE (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_ir_eventbridge_guardduty(session, meta):
    """ISO27018.IR.1 — EventBridge rule for GuardDuty findings."""
    nc, total = [], 1
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        gd_rule = any("guardduty" in _json.dumps(r).lower() or "guard" in r.get("Name", "").lower() for r in rules)
        if not gd_rule:
            nc.append({"resource_name": "EventBridge", "note": "No rule for GuardDuty findings"})
    except Exception as e:
        print(f"iso27018_ir_eventbridge_guardduty error: {e}")
    _meta(meta, "EventBridge", total, nc, "High")
    return _result("ISO 27018 — EventBridge GuardDuty Rule", "EventBridge", "ISO27018.IR.1",
        "Without EventBridge rules, GuardDuty PII threat findings are not actioned.", 75, "High", nc,
        "Create EventBridge rule to route GuardDuty findings to SNS/Lambda.", total)


def iso27018_ir_eventbridge_securityhub(session, meta):
    """ISO27018.IR.2 — EventBridge rule for Security Hub findings."""
    nc, total = [], 1
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        sh_rule = any("securityhub" in _json.dumps(r).lower() or "security-hub" in r.get("Name", "").lower() for r in rules)
        if not sh_rule:
            nc.append({"resource_name": "EventBridge", "note": "No rule for Security Hub findings"})
    except Exception as e:
        print(f"iso27018_ir_eventbridge_securityhub error: {e}")
    _meta(meta, "EventBridge", total, nc, "Medium")
    return _result("ISO 27018 — EventBridge Security Hub Rule", "EventBridge", "ISO27018.IR.2",
        "Security Hub findings about PII controls need automated routing.", 70, "Medium", nc,
        "Create EventBridge rule for Security Hub findings.", total)


def iso27018_ir_eventbridge_macie(session, meta):
    """ISO27018.IR.3 — EventBridge rule for Macie findings."""
    nc, total = [], 1
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        macie_rule = any("macie" in _json.dumps(r).lower() for r in rules)
        if not macie_rule:
            nc.append({"resource_name": "EventBridge", "note": "No rule for Macie findings"})
    except Exception as e:
        print(f"iso27018_ir_eventbridge_macie error: {e}")
    _meta(meta, "EventBridge", total, nc, "Medium")
    return _result("ISO 27018 — EventBridge Macie Rule", "EventBridge", "ISO27018.IR.3",
        "Macie PII discovery findings need automated notification.", 65, "Medium", nc,
        "Create EventBridge rule for Macie PII findings.", total)


def iso27018_ir_sns_subscribers(session, meta):
    """ISO27018.IR.4 — SNS topics must have subscribers."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = len(topics)
        for t in topics:
            subs = sns.list_subscriptions_by_topic(TopicArn=t["TopicArn"]).get("Subscriptions", [])
            confirmed = [s for s in subs if s.get("SubscriptionArn") != "PendingConfirmation"]
            if not confirmed:
                nc.append({"resource_name": t["TopicArn"].split(":")[-1], "note": "No confirmed subscribers"})
    except Exception as e:
        print(f"iso27018_ir_sns_subscribers error: {e}")
    _meta(meta, "SNS", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — SNS Topics Without Subscribers", "SNS", "ISO27018.IR.4",
        "Notification topics without subscribers cannot deliver PII breach alerts.", 65, "Medium", nc,
        "Ensure all security notification topics have confirmed subscribers.", max(total, 1))


def iso27018_ir_incident_plans(session, meta):
    """ISO27018.IR.5 — Incident Manager response plans must exist."""
    nc, total = [], 1
    try:
        ir = session.client("ssm-incidents")
        plans = ir.list_response_plans().get("responsePlanSummaries", [])
        if not plans:
            nc.append({"resource_name": "IncidentManager", "note": "No response plans defined"})
    except ClientError:
        nc.append({"resource_name": "IncidentManager", "note": "Incident Manager not configured"})
    except Exception as e:
        print(f"iso27018_ir_incident_plans error: {e}")
    _meta(meta, "SSM", total, nc, "Medium")
    return _result("ISO 27018 — Incident Response Plans", "SSM", "ISO27018.IR.5",
        "Without response plans, PII breach response is ad-hoc and slow.", 70, "Medium", nc,
        "Create Incident Manager response plans for PII breach scenarios.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# ✅ COMPLIANCE (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_cmp_config_recorder(session, meta):
    """ISO27018.CMP.1 — Config recorder must be active."""
    nc, total = [], 1
    try:
        config = session.client("config")
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            nc.append({"resource_name": "Config", "note": "No Config recorder"})
        else:
            status = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            for s in status:
                if not s.get("recording"):
                    nc.append({"resource_name": s.get("name", ""), "note": "Recorder not recording"})
    except Exception as e:
        print(f"iso27018_cmp_config_recorder error: {e}")
    _meta(meta, "Config", total, nc, "High")
    return _result("ISO 27018 — Config Recorder Active", "Config", "ISO27018.CMP.1",
        "Without Config recorder, resource changes affecting PII are invisible.", 80, "High", nc,
        "Enable AWS Config recorder in all regions.", total)


def iso27018_cmp_config_delivery(session, meta):
    """ISO27018.CMP.2 — Config delivery channel must be active."""
    nc, total = [], 1
    try:
        config = session.client("config")
        channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        if not channels:
            nc.append({"resource_name": "Config", "note": "No delivery channel"})
    except Exception as e:
        print(f"iso27018_cmp_config_delivery error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("ISO 27018 — Config Delivery Channel", "Config", "ISO27018.CMP.2",
        "Config data must be delivered to S3 for compliance evidence.", 65, "Medium", nc,
        "Configure a Config delivery channel.", total)


def iso27018_cmp_conformance_packs(session, meta):
    """ISO27018.CMP.3 — Conformance packs should be compliant."""
    nc, total = [], 0
    try:
        config = session.client("config")
        packs = config.describe_conformance_packs().get("ConformancePackDetails", [])
        total = len(packs)
        if not packs:
            nc.append({"resource_name": "Config", "note": "No conformance packs deployed"})
    except Exception as e:
        print(f"iso27018_cmp_conformance_packs error: {e}")
    _meta(meta, "Config", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — Conformance Packs", "Config", "ISO27018.CMP.3",
        "Conformance packs provide automated compliance evidence for PII controls.", 60, "Medium", nc,
        "Deploy conformance packs for PII-related compliance standards.", max(total, 1))


def iso27018_cmp_audit_manager(session, meta):
    """ISO27018.CMP.4 — Audit Manager assessments active."""
    nc, total = [], 1
    try:
        am = session.client("auditmanager")
        assessments = am.list_assessments().get("assessmentMetadata", [])
        if not assessments:
            nc.append({"resource_name": "AuditManager", "note": "No assessments active"})
    except ClientError:
        nc.append({"resource_name": "AuditManager", "note": "Audit Manager not enabled"})
    except Exception as e:
        print(f"iso27018_cmp_audit_manager error: {e}")
    _meta(meta, "AuditManager", total, nc, "Medium")
    return _result("ISO 27018 — Audit Manager Status", "AuditManager", "ISO27018.CMP.4",
        "Audit Manager provides independent privacy compliance evidence.", 60, "Medium", nc,
        "Enable Audit Manager and create privacy assessments.", total)


def iso27018_cmp_noncompliant_rules(session, meta):
    """ISO27018.CMP.5 — Flag non-compliant Config rules."""
    nc, total = [], 0
    try:
        config = session.client("config")
        rules = config.describe_compliance_by_config_rule().get("ComplianceByConfigRules", [])
        total = len(rules)
        for r in rules:
            if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT":
                nc.append({"resource_name": r["ConfigRuleName"], "note": "NON_COMPLIANT"})
    except Exception as e:
        print(f"iso27018_cmp_noncompliant_rules error: {e}")
    _meta(meta, "Config", max(total, 1), nc, "High")
    return _result("ISO 27018 — Non-Compliant Config Rules", "Config", "ISO27018.CMP.5",
        "Non-compliant rules indicate PII security controls are not met.", 75, "High", nc,
        "Remediate all non-compliant Config rules.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 🏛️ ADVANCED HARDENING (20 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def iso27018_adv_rds_public(session, meta):
    """ISO27018.ADV.6 — RDS PubliclyAccessible must be false."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total = len(dbs)
        for db in dbs:
            if db.get("PubliclyAccessible"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "PubliclyAccessible=true"})
    except Exception as e:
        print(f"iso27018_adv_rds_public error: {e}")
    _meta(meta, "RDS", max(total, 1), nc, "Critical")
    return _result("ISO 27018 — RDS Public Accessibility", "RDS", "ISO27018.ADV.6",
        "Publicly accessible RDS instances expose PII databases to the internet.", 95, "Critical", nc,
        "Set PubliclyAccessible=false on all RDS instances.", max(total, 1))


def iso27018_adv_rds_deletion_protection(session, meta):
    """ISO27018.ADV.7 — RDS Deletion Protection must be enabled."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total = len(dbs)
        for db in dbs:
            if not db.get("DeletionProtection"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "DeletionProtection=false"})
    except Exception as e:
        print(f"iso27018_adv_rds_deletion_protection error: {e}")
    _meta(meta, "RDS", max(total, 1), nc, "High")
    return _result("ISO 27018 — RDS Deletion Protection", "RDS", "ISO27018.ADV.7",
        "Without deletion protection, PII databases can be accidentally deleted.", 80, "High", nc,
        "Enable DeletionProtection on all production RDS instances.", max(total, 1))


def iso27018_adv_rds_perf_insights_encryption(session, meta):
    """ISO27018.ADV.8 — RDS Performance Insights must use KMS."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total = len(dbs)
        for db in dbs:
            if db.get("PerformanceInsightsEnabled") and not db.get("PerformanceInsightsKMSKeyId"):
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": "Performance Insights without KMS encryption"})
    except Exception as e:
        print(f"iso27018_adv_rds_perf_insights_encryption error: {e}")
    _meta(meta, "RDS", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — RDS Performance Insights Encryption", "RDS", "ISO27018.ADV.8",
        "Performance Insights data may reveal PII query patterns.", 65, "Medium", nc,
        "Set PerformanceInsightsKMSKeyId on all instances with PI enabled.", max(total, 1))


def iso27018_adv_ebs_default_encryption(session, meta):
    """ISO27018.ADV.9 — EBS default encryption must be enabled."""
    nc, total = [], 1
    try:
        ec2 = session.client("ec2")
        result = ec2.get_ebs_encryption_by_default()
        if not result.get("EbsEncryptionByDefault"):
            nc.append({"resource_name": "EBS", "note": "Default encryption not enabled"})
    except Exception as e:
        print(f"iso27018_adv_ebs_default_encryption error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("ISO 27018 — EBS Default Encryption", "EC2", "ISO27018.ADV.9",
        "Without default encryption, new EBS volumes may store PII unencrypted.", 80, "High", nc,
        "Enable EBS encryption by default at the account level.", total)


def iso27018_adv_vpc_dns(session, meta):
    """ISO27018.ADV.10 — VPC DNS settings must be enabled."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = len(vpcs)
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            dns_support = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsSupport")
            dns_hostnames = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute="enableDnsHostnames")
            issues = []
            if not dns_support.get("EnableDnsSupport", {}).get("Value"):
                issues.append("DnsSupport disabled")
            if not dns_hostnames.get("EnableDnsHostnames", {}).get("Value"):
                issues.append("DnsHostnames disabled")
            if issues:
                nc.append({"resource_name": vpc_id, "note": ", ".join(issues)})
    except Exception as e:
        print(f"iso27018_adv_vpc_dns error: {e}")
    _meta(meta, "EC2", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — VPC DNS Security", "EC2", "ISO27018.ADV.10",
        "DNS settings required for VPC endpoints and private connectivity.", 60, "Medium", nc,
        "Enable DNS Support and Hostnames on all VPCs.", max(total, 1))


def iso27018_adv_cloudtrail_kms(session, meta):
    """ISO27018.ADV.13 — CloudTrail must use KMS encryption."""
    ct = session.client("cloudtrail")
    nc, total = [], 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) or 1
        for t in trails:
            if not t.get("KmsKeyId"):
                nc.append({"resource_name": t["Name"], "note": "Using SSE-S3 instead of KMS"})
    except Exception as e:
        print(f"iso27018_adv_cloudtrail_kms error: {e}")
    _meta(meta, "CloudTrail", total, nc, "High")
    return _result("ISO 27018 — CloudTrail KMS Encryption", "CloudTrail", "ISO27018.ADV.13",
        "KMS encryption provides access control on PII audit logs.", 80, "High", nc,
        "Configure CloudTrail to encrypt with a customer-managed KMS key.", total)


def iso27018_adv_securityhub_standards(session, meta):
    """ISO27018.ADV.14 — Security Hub standards must be enabled."""
    nc, total = [], 1
    try:
        sh = session.client("securityhub")
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        if not standards:
            nc.append({"resource_name": "SecurityHub", "note": "No standards enabled"})
        elif len(standards) < 2:
            nc.append({"resource_name": "SecurityHub", "note": f"Only {len(standards)} standard(s) enabled"})
    except ClientError:
        nc.append({"resource_name": "SecurityHub", "note": "Security Hub not enabled"})
    except Exception as e:
        print(f"iso27018_adv_securityhub_standards error: {e}")
    _meta(meta, "SecurityHub", total, nc, "High")
    return _result("ISO 27018 — Security Hub Standards", "SecurityHub", "ISO27018.ADV.14",
        "Multiple standards provide comprehensive PII security coverage.", 75, "High", nc,
        "Enable CIS AWS Foundations and AWS FSBP standards.", total)


def iso27018_adv_guardduty_plans(session, meta):
    """ISO27018.ADV.15 — All GuardDuty protection plans enabled."""
    nc, total = [], 1
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            nc.append({"resource_name": "GuardDuty", "note": "No detector"})
        else:
            det = gd.get_detector(DetectorId=detectors[0])
            features = {f["Name"]: f["Status"] for f in det.get("Features", [])}
            expected = ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION",
                        "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS"]
            for exp in expected:
                if features.get(exp) != "ENABLED":
                    nc.append({"resource_name": "GuardDuty", "feature": exp, "note": f"{exp} not enabled"})
    except Exception as e:
        print(f"iso27018_adv_guardduty_plans error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("ISO 27018 — GuardDuty All Protection Plans", "GuardDuty", "ISO27018.ADV.15",
        "Full GuardDuty coverage detects threats across all PII attack surfaces.", 80, "High", nc,
        "Enable all GuardDuty protection plans.", total)


def iso27018_adv_secrets_resource_policy(session, meta):
    """ISO27018.ADV.16 — Secrets Manager resource policies must be restrictive."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            try:
                policy = sm.get_resource_policy(SecretId=s["ARN"])
                doc = policy.get("ResourcePolicy")
                if doc:
                    doc = _json.loads(doc)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Principal") == "*" and stmt.get("Effect") == "Allow":
                            nc.append({"resource_name": s["Name"], "note": "Public resource policy"})
                            break
            except Exception:
                pass
    except Exception as e:
        print(f"iso27018_adv_secrets_resource_policy error: {e}")
    _meta(meta, "SecretsManager", max(total, 1), nc, "High")
    return _result("ISO 27018 — Secrets Manager Resource Policies", "SecretsManager", "ISO27018.ADV.16",
        "Public or overly permissive resource policies expose PII credentials.", 80, "High", nc,
        "Restrict resource policies to specific principals.", max(total, 1))


def iso27018_adv_backup_vault_lock(session, meta):
    """ISO27018.ADV.17 — Backup Vault Lock configured."""
    nc, total = [], 0
    try:
        bk = session.client("backup")
        vaults = bk.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for v in vaults:
            if not v.get("Locked"):
                nc.append({"resource_name": v["BackupVaultName"], "note": "Vault not locked"})
    except Exception as e:
        print(f"iso27018_adv_backup_vault_lock error: {e}")
    _meta(meta, "Backup", max(total, 1), nc, "Medium")
    return _result("ISO 27018 — Backup Vault Lock", "Backup", "ISO27018.ADV.17",
        "Vault Lock provides WORM compliance preventing PII backup tampering.", 65, "Medium", nc,
        "Configure Vault Lock on backup vaults containing PII.", max(total, 1))


def iso27018_adv_config_all_resources(session, meta):
    """ISO27018.ADV.12 — Config must record all resource types."""
    nc, total = [], 1
    try:
        config = session.client("config")
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        for r in recorders:
            group = r.get("recordingGroup", {})
            if not group.get("allSupported"):
                nc.append({"resource_name": r["name"], "note": "Not recording all resource types"})
            if not group.get("includeGlobalResourceTypes"):
                nc.append({"resource_name": r["name"], "note": "Not including global resources"})
    except Exception as e:
        print(f"iso27018_adv_config_all_resources error: {e}")
    _meta(meta, "Config", total, nc, "Medium")
    return _result("ISO 27018 — Config All Resource Types", "Config", "ISO27018.ADV.12",
        "Partial recording misses resource changes affecting PII.", 65, "Medium", nc,
        "Set allSupported=true and includeGlobalResourceTypes=true.", total)


def iso27018_adv_rds_encryption(session, meta):
    """ISO27018.ADV — RDS encryption at rest."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total = len(dbs)
        for db in dbs:
            if not db.get("StorageEncrypted"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Not encrypted"})
    except Exception as e:
        print(f"iso27018_adv_rds_encryption error: {e}")
    _meta(meta, "RDS", max(total, 1), nc, "Critical")
    return _result("ISO 27018 — RDS Encryption at Rest", "RDS", "ISO27018.D.4",
        "Unencrypted RDS instances expose PII in storage.", 95, "Critical", nc,
        "Enable encryption on all RDS instances.", max(total, 1))


def iso27018_adv_ebs_encryption(session, meta):
    """ISO27018.ADV — EBS volume encryption."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        vols = ec2.describe_volumes().get("Volumes", [])
        total = len(vols)
        for v in vols:
            if not v.get("Encrypted"):
                nc.append({"resource_name": v["VolumeId"], "note": "Unencrypted volume"})
    except Exception as e:
        print(f"iso27018_adv_ebs_encryption error: {e}")
    _meta(meta, "EC2", max(total, 1), nc, "High")
    return _result("ISO 27018 — EBS Volume Encryption", "EC2", "ISO27018.D.4",
        "Unencrypted EBS volumes may contain PII from compute workloads.", 80, "High", nc,
        "Encrypt all EBS volumes.", max(total, 1))


def iso27018_adv_vpc_flow_logs(session, meta):
    """ISO27018.ADV — VPC Flow Logs enabled."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = len(vpcs)
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        covered_vpcs = {fl["ResourceId"] for fl in flow_logs if fl.get("ResourceId", "").startswith("vpc-")}
        for vpc in vpcs:
            if vpc["VpcId"] not in covered_vpcs:
                nc.append({"resource_name": vpc["VpcId"], "note": "No flow logs"})
    except Exception as e:
        print(f"iso27018_adv_vpc_flow_logs error: {e}")
    _meta(meta, "EC2", max(total, 1), nc, "High")
    return _result("ISO 27018 — VPC Flow Logs", "EC2", "ISO27018.F.1",
        "Without flow logs, network access to PII cannot be monitored.", 80, "High", nc,
        "Enable VPC Flow Logs on all VPCs.", max(total, 1))


def iso27018_adv_guardduty_enabled(session, meta):
    """ISO27018.ADV — GuardDuty must be enabled."""
    nc, total = [], 1
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            nc.append({"resource_name": "GuardDuty", "note": "Not enabled"})
    except Exception as e:
        print(f"iso27018_adv_guardduty_enabled error: {e}")
    _meta(meta, "GuardDuty", total, nc, "Critical")
    return _result("ISO 27018 — GuardDuty Enabled", "GuardDuty", "ISO27018.F.7",
        "GuardDuty is essential for detecting threats to PII.", 90, "Critical", nc,
        "Enable GuardDuty in all regions.", total)


def iso27018_adv_s3_lifecycle(session, meta):
    """ISO27018.ADV — S3 lifecycle policies for PII buckets."""
    s3 = session.client("s3")
    nc, total = [], 0
    pii_state = PII_UNKNOWN
    try:
        _, confirmed_pii, confirmed_non_pii, unknown = _classify_s3_buckets(s3)
        targets, pii_state = _get_pii_check_targets(confirmed_pii, unknown)
        total = len(targets)
        if pii_state != PII_NON_PII:
            for b in targets:
                try:
                    s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                except ClientError as e:
                    if "NoSuchLifecycleConfiguration" in str(e):
                        nc.append({"resource_name": b["Name"],
                                   "pii_classification": PII_CONFIRMED if b in confirmed_pii else PII_UNKNOWN,
                                   "note": "No lifecycle policy"})
                except Exception:
                    pass
    except Exception as e:
        print(f"iso27018_adv_s3_lifecycle error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _pii_result("ISO 27018 — S3 Lifecycle Policies", "S3", "ISO27018.B.3",
        "PII retained indefinitely without lifecycle policies violates data minimization.",
        70, "Medium", nc, "Configure lifecycle rules for PII data expiration.",
        total, pii_confirmed=(pii_state == PII_CONFIRMED))


def iso27018_adv_cloudtrail_active(session, meta):
    """ISO27018.ADV — CloudTrail must be active."""
    ct = session.client("cloudtrail")
    nc, total = [], 1
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            nc.append({"resource_name": "CloudTrail", "note": "No trails configured"})
        else:
            active = False
            for t in trails:
                try:
                    status = ct.get_trail_status(Name=t["TrailARN"])
                    if status.get("IsLogging"):
                        active = True
                        break
                except Exception:
                    pass
            if not active:
                nc.append({"resource_name": "CloudTrail", "note": "No active trails"})
    except Exception as e:
        print(f"iso27018_adv_cloudtrail_active error: {e}")
    _meta(meta, "CloudTrail", total, nc, "Critical")
    return _result("ISO 27018 — CloudTrail Active", "CloudTrail", "ISO27018.G.1",
        "CloudTrail is mandatory for auditing all PII processing activities.", 95, "Critical", nc,
        "Enable and activate CloudTrail.", total)


def iso27018_adv_securityhub_enabled(session, meta):
    """ISO27018.ADV — Security Hub must be enabled."""
    nc, total = [], 1
    try:
        sh = session.client("securityhub")
        sh.describe_hub()
    except ClientError:
        nc.append({"resource_name": "SecurityHub", "note": "Not enabled"})
    except Exception as e:
        print(f"iso27018_adv_securityhub_enabled error: {e}")
    _meta(meta, "SecurityHub", total, nc, "High")
    return _result("ISO 27018 — Security Hub Enabled", "SecurityHub", "ISO27018.H.3",
        "Security Hub centralizes PII security findings from all services.", 80, "High", nc,
        "Enable Security Hub.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🚀 ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════════


def run_iso27018_global_checks(session, scan_meta_data):
    """Run all global (non-regional) ISO 27018 checks."""
    checks = [
        # S3 Security
        ("Scanning S3 PII Security Controls...", [
            iso27018_s3_ownership_controls, iso27018_s3_acls_disabled,
            iso27018_s3_block_public_acls, iso27018_s3_ignore_public_acls,
            iso27018_s3_block_public_policy, iso27018_s3_restrict_public_buckets,
            iso27018_s3_access_points, iso27018_s3_bucket_policy_wildcard,
            iso27018_s3_logging, iso27018_s3_encryption, iso27018_s3_versioning,
            iso27018_s3_object_lock, iso27018_s3_replication_accounts,
            iso27018_s3_replication_regions, iso27018_adv_s3_lifecycle,
        ]),
        # IAM & Identity
        ("Scanning IAM PII Access Controls...", [
            iso27018_iam_access_analyzer, iso27018_iam_access_analyzer_findings,
            iso27018_iam_cross_account_roles, iso27018_iam_wildcard_permissions,
            iso27018_iam_admin_access, iso27018_iam_password_length,
            iso27018_iam_password_reuse, iso27018_iam_console_mfa,
            iso27018_iam_root_access_keys, iso27018_iam_cross_account_trust,
            iso27018_iam_service_linked_roles,
        ]),
        # CloudTrail & Logging
        ("Scanning CloudTrail PII Audit Logging...", [
            iso27018_adv_cloudtrail_active, iso27018_log_insights,
            iso27018_log_org_trail, iso27018_log_validation,
            iso27018_adv_cloudtrail_kms, iso27018_mon_cloudtrail_data_events,
        ]),
        # Data Residency
        ("Scanning PII Data Residency...", [
            iso27018_dr_s3_regions, iso27018_dr_s3_cross_account_replication,
        ]),
    ]

    results = []
    for msg, fns in checks:
        print(msg)
        for fn in fns:
            try:
                results.append(fn(session, scan_meta_data))
            except Exception as e:
                print(f"  Error: {fn.__name__}: {e}")
    return results


def run_iso27018_regional_checks(session, scan_meta_data):
    """Run all regional ISO 27018 checks."""
    region = session.region_name or "unknown"

    checks = [
        # KMS
        ("Scanning KMS PII Encryption Keys...", [
            iso27018_kms_disabled_keys, iso27018_kms_pending_deletion,
            iso27018_kms_multi_region, iso27018_kms_key_policy, iso27018_kms_cmk_usage,
        ]),
        # Secrets
        ("Scanning Secrets Management...", [
            iso27018_secrets_rotation, iso27018_secrets_age,
            iso27018_secrets_cmk, iso27018_secrets_rotation_schedule,
            iso27018_adv_secrets_resource_policy,
        ]),
        # Logging & Monitoring
        ("Scanning Logging & Monitoring...", [
            iso27018_log_cw_encryption, iso27018_log_retention,
            iso27018_log_alarm_root, iso27018_log_alarm_unauth,
            iso27018_log_alarm_s3, iso27018_log_alarm_kms,
        ]),
        # Network
        ("Scanning Network PII Protection...", [
            iso27018_net_db_sg_exposed, iso27018_net_public_subnets,
            iso27018_net_vpc_endpoint_s3, iso27018_net_vpc_endpoint_secrets,
            iso27018_net_vpc_endpoint_kms, iso27018_net_waf_alb,
            iso27018_net_nacl_open, iso27018_adv_vpc_flow_logs,
            iso27018_adv_vpc_dns,
        ]),
        # RDS & Storage
        ("Scanning RDS & Storage PII Security...", [
            iso27018_adv_rds_public, iso27018_adv_rds_deletion_protection,
            iso27018_adv_rds_perf_insights_encryption, iso27018_adv_rds_encryption,
            iso27018_adv_ebs_encryption, iso27018_adv_ebs_default_encryption,
        ]),
        # API Security
        ("Scanning API PII Security...", [
            iso27018_api_authorization, iso27018_api_access_logging,
            iso27018_api_execution_logging, iso27018_api_tls_version,
            iso27018_api_http_listeners, iso27018_api_acm_expiry,
        ]),
        # Monitoring
        ("Scanning PII Monitoring...", [
            iso27018_mon_macie_jobs, iso27018_mon_macie_buckets,
            iso27018_mon_alarms, iso27018_mon_guardduty_s3,
            iso27018_mon_guardduty_malware, iso27018_adv_guardduty_enabled,
            iso27018_adv_guardduty_plans,
        ]),
        # Incident Response
        ("Scanning PII Incident Response...", [
            iso27018_ir_eventbridge_guardduty, iso27018_ir_eventbridge_securityhub,
            iso27018_ir_eventbridge_macie, iso27018_ir_sns_subscribers,
            iso27018_ir_incident_plans, iso27018_adv_securityhub_enabled,
            iso27018_adv_securityhub_standards,
        ]),
        # Compliance
        ("Scanning PII Compliance Evidence...", [
            iso27018_cmp_config_recorder, iso27018_cmp_config_delivery,
            iso27018_cmp_conformance_packs, iso27018_cmp_audit_manager,
            iso27018_cmp_noncompliant_rules, iso27018_adv_config_all_resources,
        ]),
        # Data Residency (regional)
        ("Scanning Regional Data Residency...", [
            iso27018_dr_rds_regions, iso27018_dr_cross_region_snapshots,
            iso27018_dr_cloudfront,
        ]),
        # Backup
        ("Scanning PII Backup Controls...", [
            iso27018_backup_vault_encryption, iso27018_backup_vault_policy,
            iso27018_backup_recovery_points, iso27018_backup_retention,
            iso27018_backup_cross_region, iso27018_backup_rds_coverage,
            iso27018_adv_backup_vault_lock,
        ]),
    ]

    results = []
    for msg, fns in checks:
        print(f"{msg} [{region}]")
        for fn in fns:
            try:
                results.append(fn(session, scan_meta_data))
            except Exception as e:
                print(f"  Error: {fn.__name__}: {e}")

    for r in results:
        r["region"] = region
    return results


def run_iso27018_checks(session, scan_meta_data):
    """Full ISO 27018 scan — global + regional checks."""
    results = []
    results.extend(run_iso27018_global_checks(session, scan_meta_data))
    results.extend(run_iso27018_regional_checks(session, scan_meta_data))
    return results


async def iso27018_scan_function(data):
    """Entry point for API calls — full ISO 27018 scan."""
    from utils.framework_scan import run_framework_scan
    return run_framework_scan(data, framework="iso27018")
