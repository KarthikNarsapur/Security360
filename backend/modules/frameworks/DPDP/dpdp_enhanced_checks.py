"""
DPDP Enhanced Checks — Additional AWS Security Checks
Digital Personal Data Protection Act & Rules (India)

These checks complement the existing dpdp_checks.py and dpdp_rules_2025_checks.py
with deeper, more granular validations across all critical AWS services.

All checks are ReadOnly compatible (no write/modify API calls).

Categories:
  - S3 Enhanced (7 checks)
  - CloudTrail Enhanced (6 checks)
  - KMS Enhanced (4 checks)
  - IAM Enhanced (8 checks)
  - EC2 Enhanced (6 checks)
  - RDS Enhanced (5 checks)
  - DynamoDB Enhanced (3 checks)
  - AWS Config Enhanced (3 checks)
  - GuardDuty Enhanced (5 checks)
  - Security Hub Enhanced (3 checks)
  - Backup Enhanced (4 checks)
  - Network Security (5 checks)
  - Secrets Manager Enhanced (3 checks)
  - Data Residency / Cross-Border (5 checks)
  - Organizations Enhanced (3 checks)
  - Inspector Enhanced (4 checks)
"""

import json as _json
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
# 🗄️ S3 ENHANCED CHECKS (7 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_s3_account_level_bpa(session, meta):
    """DPDP-R6-S3-01 — Account-level S3 Block Public Access must be enabled."""
    s3control = session.client("s3control")
    non_compliant = []
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        pa = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        issues = []
        if not pa.get("BlockPublicAcls"):
            issues.append("BlockPublicAcls disabled")
        if not pa.get("IgnorePublicAcls"):
            issues.append("IgnorePublicAcls disabled")
        if not pa.get("BlockPublicPolicy"):
            issues.append("BlockPublicPolicy disabled")
        if not pa.get("RestrictPublicBuckets"):
            issues.append("RestrictPublicBuckets disabled")
        if issues:
            non_compliant.append({
                "resource_name": f"Account {account_id}",
                "issues": issues,
                "note": "Account-level Block Public Access not fully enabled"
            })
    except ClientError as e:
        if "NoSuchPublicAccessBlockConfiguration" in str(e):
            non_compliant.append({
                "resource_name": "Account-Level BPA",
                "note": "No account-level Block Public Access configured"
            })
        else:
            print(f"dpdp_s3_account_level_bpa error: {e}")
    except Exception as e:
        print(f"dpdp_s3_account_level_bpa error: {e}")
    _update_meta(meta, "S3", 1, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — S3 Account-Level Block Public Access", "S3", "DPDP-R6-S3-01",
        "Account-level Block Public Access is the first line of defense preventing personal data exposure. "
        "Without it, any bucket can be made public accidentally.",
        95, "Critical", non_compliant,
        "Enable all four Block Public Access settings at the account level via S3 console or CLI.", 1)


def dpdp_s3_bucket_policy_wildcard(session, meta):
    """DPDP-R6-S3-02 — S3 bucket policies must not use wildcard principals."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                policy = s3.get_bucket_policy(Bucket=b["Name"])
                doc = _json.loads(policy["Policy"])
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            non_compliant.append({
                                "resource_name": b["Name"],
                                "note": "Bucket policy has Principal: * — allows anyone access"
                            })
                            break
            except ClientError as e:
                if "NoSuchBucketPolicy" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_bucket_policy_wildcard error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 Bucket Policy Wildcard Principal", "S3", "DPDP-R6-S3-02",
        "Bucket policies with Principal:* grant access to anyone on the internet, "
        "exposing personal data in violation of Rule 6 security safeguards.",
        85, "High", non_compliant,
        "Remove wildcard Principal from S3 bucket policies. Use specific account ARNs or conditions.", total)


def dpdp_s3_bucket_policy_cross_account(session, meta):
    """DPDP-R6-S3-03 — Detect cross-account access in S3 bucket policies."""
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
                        aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        for p in aws_principals:
                            if "arn:aws:iam::" in str(p) and account_id not in str(p):
                                non_compliant.append({
                                    "resource_name": b["Name"],
                                    "external_principal": p,
                                    "note": "Cross-account access detected in bucket policy"
                                })
                                break
            except ClientError as e:
                if "NoSuchBucketPolicy" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_bucket_policy_cross_account error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 Bucket Policy Cross-Account Access", "S3", "DPDP-R6-S3-03",
        "S3 bucket policies granting cross-account access share personal data with external entities "
        "without documented data processor agreements required by Rule 14.",
        80, "High", non_compliant,
        "Review all cross-account principals in bucket policies. Ensure each is a documented "
        "data processor with DPDP-compliant contractual obligations.", total)


def dpdp_s3_lifecycle_configured(session, meta):
    """DPDP-R8-S3-04 — S3 buckets must have lifecycle policies for data retention."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
            except ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    non_compliant.append({
                        "resource_name": b["Name"],
                        "note": "No lifecycle policy — data retained indefinitely"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_lifecycle_configured error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — S3 Lifecycle Policy Configured", "S3", "DPDP-R8-S3-04",
        "Rule 8 requires erasure of personal data once purpose is fulfilled. "
        "Buckets without lifecycle policies retain data indefinitely.",
        65, "Medium", non_compliant,
        "Configure lifecycle rules on all S3 buckets storing personal data. "
        "Align expiration with documented retention periods.", total)


def dpdp_s3_cmk_encryption(session, meta):
    """DPDP-R6-S3-05 — Sensitive S3 buckets should use KMS CMK, not AES256."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                enc = s3.get_bucket_encryption(Bucket=b["Name"])
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                for r in rules:
                    algo = r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                    if algo == "AES256":
                        non_compliant.append({
                            "resource_name": b["Name"],
                            "encryption": "AES256 (SSE-S3)",
                            "note": "Using SSE-S3 instead of KMS CMK — less control over key management"
                        })
                        break
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    pass  # Caught by other check
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_cmk_encryption error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — S3 Buckets Not Using CMK Encryption", "S3", "DPDP-R6-S3-05",
        "SSE-S3 (AES256) does not provide key management controls. KMS CMK allows key rotation, "
        "access policies, and audit trails required by Rule 6.",
        70, "Medium", non_compliant,
        "Migrate sensitive buckets from SSE-S3 to SSE-KMS with customer-managed keys. "
        "This enables key rotation and CloudTrail logging of key usage.", total)


def dpdp_s3_ownership_controls(session, meta):
    """DPDP-R6-S3-06 — S3 bucket ownership controls must be configured."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                ownership = s3.get_bucket_ownership_controls(Bucket=b["Name"])
                rules = ownership.get("OwnershipControls", {}).get("Rules", [])
                for rule in rules:
                    if rule.get("ObjectOwnership") == "BucketOwnerEnforced":
                        break
                else:
                    non_compliant.append({
                        "resource_name": b["Name"],
                        "note": "Ownership not set to BucketOwnerEnforced — ACLs still active"
                    })
            except ClientError as e:
                if "OwnershipControlsNotFoundError" in str(e):
                    non_compliant.append({
                        "resource_name": b["Name"],
                        "note": "No ownership controls — ACL-based access still possible"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_ownership_controls error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — S3 Bucket Ownership Controls Missing", "S3", "DPDP-R6-S3-06",
        "Without BucketOwnerEnforced ownership, objects uploaded by other accounts retain their ACLs, "
        "creating uncontrolled access paths to personal data.",
        65, "Medium", non_compliant,
        "Set Object Ownership to BucketOwnerEnforced to disable ACLs and ensure "
        "bucket policies are the sole access control mechanism.", total)


def dpdp_s3_inventory_disabled(session, meta):
    """DPDP-R6-S3-07 — S3 inventory should be enabled for breach investigations."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                inv = s3.list_bucket_inventory_configurations(Bucket=b["Name"])
                configs = inv.get("InventoryConfigurationList", [])
                if not configs:
                    non_compliant.append({
                        "resource_name": b["Name"],
                        "note": "No S3 inventory configured — limits breach investigation"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_inventory_disabled error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — S3 Inventory Disabled", "S3", "DPDP-R6-S3-07",
        "S3 inventory provides a complete manifest of objects, essential for breach impact assessment "
        "and fulfilling Rule 7 notification requirements.",
        60, "Medium", non_compliant,
        "Enable S3 Inventory on buckets storing personal data. Configure daily frequency "
        "with encryption status and last modified date included.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 📋 CLOUDTRAIL ENHANCED CHECKS (6 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_ct_multi_region(session, meta):
    """DPDP-R7-CT-01 — CloudTrail must be multi-region for complete audit."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No CloudTrail trails configured"})
        else:
            has_multi = any(t.get("IsMultiRegionTrail") for t in trails)
            if not has_multi:
                non_compliant.append({
                    "resource_name": "CloudTrail",
                    "note": "No multi-region trail — activities in other regions are not logged"
                })
    except Exception as e:
        print(f"dpdp_ct_multi_region error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — CloudTrail Multi-Region Trail", "CloudTrail", "DPDP-R7-CT-01",
        "Rule 7 requires comprehensive audit logging. Without a multi-region trail, "
        "API activities affecting personal data in non-primary regions go unlogged.",
        95, "Critical", non_compliant,
        "Enable at least one multi-region CloudTrail trail to capture all API activity across all regions.", total)


def dpdp_ct_log_validation(session, meta):
    """DPDP-R7-CT-02 — CloudTrail log file validation must be enabled."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No trails configured"})
        else:
            for trail in trails:
                if not trail.get("LogFileValidationEnabled"):
                    non_compliant.append({
                        "resource_name": trail["Name"],
                        "note": "Log file validation not enabled — logs can be tampered"
                    })
    except Exception as e:
        print(f"dpdp_ct_log_validation error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — CloudTrail Log File Validation", "CloudTrail", "DPDP-R7-CT-02",
        "Without log file validation, CloudTrail logs can be modified or deleted without detection, "
        "undermining breach investigation integrity required by Rule 7.",
        90, "Critical", non_compliant,
        "Enable log file validation on all CloudTrail trails to ensure log integrity.", total)


def dpdp_ct_kms_encryption(session, meta):
    """DPDP-R7-CT-03 — CloudTrail logs must be encrypted with KMS."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No trails configured"})
        else:
            for trail in trails:
                if not trail.get("KmsKeyId"):
                    non_compliant.append({
                        "resource_name": trail["Name"],
                        "note": "Not encrypted with KMS — using default S3 encryption only"
                    })
    except Exception as e:
        print(f"dpdp_ct_kms_encryption error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — CloudTrail KMS Encryption", "CloudTrail", "DPDP-R7-CT-03",
        "CloudTrail logs without KMS encryption rely on default S3 encryption, "
        "lacking the access control and audit trail that KMS provides.",
        80, "High", non_compliant,
        "Configure CloudTrail to use a KMS CMK for log encryption. "
        "This adds an additional layer of access control to audit logs.", total)


def dpdp_ct_all_regions(session, meta):
    """DPDP-R7-CT-04 — CloudTrail must cover all regions."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No trails configured"})
        else:
            active_multi_region = False
            for trail in trails:
                if trail.get("IsMultiRegionTrail"):
                    try:
                        status = ct.get_trail_status(Name=trail["TrailARN"])
                        if status.get("IsLogging"):
                            active_multi_region = True
                            break
                    except Exception:
                        pass
            if not active_multi_region:
                non_compliant.append({
                    "resource_name": "CloudTrail",
                    "note": "No active multi-region trail — some regions are not covered"
                })
    except Exception as e:
        print(f"dpdp_ct_all_regions error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — CloudTrail Covers All Regions", "CloudTrail", "DPDP-R7-CT-04",
        "Without active multi-region coverage, personal data access in uncovered regions "
        "cannot be audited for breach detection.",
        80, "High", non_compliant,
        "Ensure at least one multi-region trail is actively logging across all regions.", total)


def dpdp_ct_management_events(session, meta):
    """DPDP-R7-CT-05 — CloudTrail must have management events enabled."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No trails configured"})
        else:
            for trail in trails:
                try:
                    selectors = ct.get_event_selectors(TrailName=trail["TrailARN"])
                    event_selectors = selectors.get("EventSelectors", [])
                    adv_selectors = selectors.get("AdvancedEventSelectors", [])
                    has_mgmt = False
                    if event_selectors:
                        has_mgmt = any(
                            es.get("IncludeManagementEvents", True) for es in event_selectors
                        )
                    elif adv_selectors:
                        has_mgmt = True  # Advanced selectors include mgmt by default
                    else:
                        has_mgmt = True  # Default includes management events
                    if not has_mgmt:
                        non_compliant.append({
                            "resource_name": trail["Name"],
                            "note": "Management events disabled"
                        })
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_ct_management_events error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — CloudTrail Management Events Enabled", "CloudTrail", "DPDP-R7-CT-05",
        "Management events capture IAM, S3, and resource changes. Without them, "
        "security-relevant actions affecting personal data are invisible.",
        80, "High", non_compliant,
        "Ensure management events are enabled on at least one active trail.", total)


def dpdp_ct_data_events(session, meta):
    """DPDP-R7-CT-06 — CloudTrail should have data events for S3/Lambda."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No trails configured"})
        else:
            has_data_events = False
            for trail in trails:
                try:
                    selectors = ct.get_event_selectors(TrailName=trail["TrailARN"])
                    event_selectors = selectors.get("EventSelectors", [])
                    adv_selectors = selectors.get("AdvancedEventSelectors", [])
                    for es in event_selectors:
                        if es.get("DataResources"):
                            has_data_events = True
                            break
                    if adv_selectors:
                        for ads in adv_selectors:
                            for fs in ads.get("FieldSelectors", []):
                                if fs.get("Field") == "eventCategory" and "Data" in fs.get("Equals", []):
                                    has_data_events = True
                                    break
                    if has_data_events:
                        break
                except Exception:
                    pass
            if not has_data_events:
                non_compliant.append({
                    "resource_name": "CloudTrail",
                    "note": "No data events configured — S3 object-level and Lambda invocation activity not tracked"
                })
    except Exception as e:
        print(f"dpdp_ct_data_events error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — CloudTrail Data Events (S3/Lambda)", "CloudTrail", "DPDP-R7-CT-06",
        "Data events track S3 object access and Lambda invocations. Without them, "
        "actual access to personal data files cannot be audited.",
        70, "Medium", non_compliant,
        "Enable CloudTrail data events for S3 buckets storing personal data and Lambda functions "
        "processing personal data.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🔑 KMS ENHANCED CHECKS (4 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_kms_scheduled_deletion(session, meta):
    """DPDP-R6-KMS-02 — Detect CMKs scheduled for deletion."""
    kms = session.client("kms")
    non_compliant = []
    total = 0
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    total += 1
                    if key_meta.get("KeyState") == "PendingDeletion":
                        non_compliant.append({
                            "resource_name": key_meta["KeyId"],
                            "deletion_date": str(key_meta.get("DeletionDate", "Unknown")),
                            "note": "CMK scheduled for deletion — encrypted data will become inaccessible"
                        })
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_kms_scheduled_deletion error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — KMS Keys Scheduled For Deletion", "KMS", "DPDP-R6-KMS-02",
        "CMKs pending deletion will make all encrypted personal data permanently inaccessible, "
        "violating Rule 5 (right to access) and Rule 8 (data integrity).",
        95, "Critical", non_compliant,
        "Review all CMKs pending deletion. Cancel deletion if the key protects personal data "
        "that must remain accessible for data principal requests.", total)


def dpdp_kms_no_rotation(session, meta):
    """DPDP-R6-KMS-03 — Deep validation of KMS key rotation status."""
    kms = session.client("kms")
    non_compliant = []
    total = 0
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    if key_meta.get("KeyState") != "Enabled":
                        continue
                    if key_meta.get("KeySpec") not in ("SYMMETRIC_DEFAULT", None):
                        continue  # Asymmetric keys don't support auto-rotation
                    total += 1
                    rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
                    if not rotation.get("KeyRotationEnabled"):
                        non_compliant.append({
                            "resource_name": key_meta["KeyId"],
                            "description": key_meta.get("Description", ""),
                            "note": "Symmetric CMK without automatic rotation"
                        })
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_kms_no_rotation error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — KMS Keys Without Rotation (Deep Check)", "KMS", "DPDP-R6-KMS-03",
        "Rule 6 mandates cryptographic safeguards. Symmetric CMKs without rotation increase "
        "the blast radius of a key compromise affecting personal data.",
        80, "High", non_compliant,
        "Enable automatic annual rotation for all symmetric customer-managed KMS keys.", total)


def dpdp_kms_external_principals(session, meta):
    """DPDP-R6-KMS-04 — KMS key policies must not allow external principals."""
    kms = session.client("kms")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    if key_meta.get("KeyState") != "Enabled":
                        continue
                    total += 1
                    policy = kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")
                    doc = _json.loads(policy["Policy"])
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                            if isinstance(aws_p, str):
                                aws_p = [aws_p]
                            for p in aws_p:
                                if p == "*":
                                    non_compliant.append({
                                        "resource_name": key_meta["KeyId"],
                                        "note": "KMS key policy allows Principal: *"
                                    })
                                    break
                                elif "arn:aws:iam::" in p and account_id not in p:
                                    non_compliant.append({
                                        "resource_name": key_meta["KeyId"],
                                        "external_principal": p,
                                        "note": "KMS key policy allows external account access"
                                    })
                                    break
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_kms_external_principals error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — KMS Key Policies Allow External Principals", "KMS", "DPDP-R6-KMS-04",
        "KMS key policies granting access to external accounts allow third parties to decrypt personal data "
        "without documented data processor agreements.",
        80, "High", non_compliant,
        "Review KMS key policies for external principals. Ensure each external account "
        "is a documented data processor with DPDP contractual obligations.", total)


def dpdp_kms_unused_keys(session, meta):
    """DPDP-R6-KMS-05 — Detect unused KMS keys (enabled but not used recently)."""
    kms = session.client("kms")
    cw = session.client("cloudwatch")
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    if key_meta.get("KeyState") != "Enabled":
                        continue
                    total += 1
                    # Check CloudWatch metrics for key usage in last 30 days
                    resp = cw.get_metric_statistics(
                        Namespace="AWS/KMS",
                        MetricName="SecondsUntilKeyMaterialExpires",
                        Dimensions=[{"Name": "KeyId", "Value": key["KeyId"]}],
                        StartTime=now - timedelta(days=30),
                        EndTime=now,
                        Period=86400 * 30,
                        Statistics=["Sum"]
                    )
                    # Alternative: check creation date — if key > 90 days old and no aliases
                    creation_date = key_meta.get("CreationDate")
                    if creation_date:
                        age_days = (now - creation_date).days
                        if age_days > 90:
                            aliases = kms.list_aliases(KeyId=key["KeyId"]).get("Aliases", [])
                            if not aliases:
                                non_compliant.append({
                                    "resource_name": key_meta["KeyId"],
                                    "age_days": age_days,
                                    "note": f"Key is {age_days} days old with no aliases — likely unused"
                                })
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_kms_unused_keys error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Unused KMS Keys", "KMS", "DPDP-R6-KMS-05",
        "Unused KMS keys represent unnecessary attack surface and cost. "
        "They should be reviewed and disabled if not protecting personal data.",
        65, "Medium", non_compliant,
        "Review unused KMS keys. Disable or schedule deletion for keys that are confirmed "
        "no longer protecting personal data.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 IAM ENHANCED CHECKS (8 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_iam_root_access_keys(session, meta):
    """DPDP-R6-IAM-02 — Root account must not have access keys."""
    iam = session.client("iam")
    non_compliant = []
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            non_compliant.append({
                "resource_name": "Root Account",
                "note": "Root account has active access keys — highest privilege risk"
            })
    except Exception as e:
        print(f"dpdp_iam_root_access_keys error: {e}")
    _update_meta(meta, "IAM", 1, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — Root Access Keys Present", "IAM", "DPDP-R6-IAM-02",
        "Root access keys provide unrestricted programmatic access to all resources including personal data. "
        "This is the highest-risk credential in any AWS account.",
        95, "Critical", non_compliant,
        "Delete root account access keys immediately. Use IAM users or roles with least privilege.", 1)


def dpdp_iam_inactive_users(session, meta):
    """DPDP-R6-IAM-03 — Detect IAM users inactive for >90 days."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    try:
        users = iam.list_users().get("Users", [])
        total = len(users)
        for user in users:
            last_used = user.get("PasswordLastUsed")
            if last_used:
                days_inactive = (now - last_used).days
                if days_inactive > 90:
                    non_compliant.append({
                        "resource_name": user["UserName"],
                        "days_inactive": days_inactive,
                        "note": f"User inactive for {days_inactive} days"
                    })
            else:
                # Check if user has access keys that were used
                create_date = user.get("CreateDate")
                if create_date and (now - create_date).days > 90:
                    try:
                        keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                        has_active_key = any(k.get("Status") == "Active" for k in keys)
                        if not has_active_key:
                            non_compliant.append({
                                "resource_name": user["UserName"],
                                "note": "No console login and no active keys — likely inactive"
                            })
                    except Exception:
                        pass
    except Exception as e:
        print(f"dpdp_iam_inactive_users error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Inactive IAM Users", "IAM", "DPDP-R6-IAM-03",
        "Inactive IAM users are dormant credentials that attackers can compromise "
        "to gain access to personal data without detection.",
        80, "High", non_compliant,
        "Disable or delete IAM users inactive for more than 90 days. "
        "Implement an automated user access review process.", total)


def dpdp_iam_unused_access_keys(session, meta):
    """DPDP-R6-IAM-04 — Detect access keys not used in >90 days."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    try:
        users = iam.list_users().get("Users", [])
        for user in users:
            try:
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for key in keys:
                    if key.get("Status") == "Active":
                        total += 1
                        try:
                            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                            last_used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                            if last_used_date:
                                days_unused = (now - last_used_date).days
                                if days_unused > 90:
                                    non_compliant.append({
                                        "resource_name": f"{user['UserName']}/{key['AccessKeyId']}",
                                        "days_unused": days_unused,
                                        "note": f"Key unused for {days_unused} days"
                                    })
                            else:
                                # Key never used
                                age = (now - key["CreateDate"]).days
                                if age > 30:
                                    non_compliant.append({
                                        "resource_name": f"{user['UserName']}/{key['AccessKeyId']}",
                                        "age_days": age,
                                        "note": f"Key created {age} days ago but never used"
                                    })
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_iam_unused_access_keys error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Unused Access Keys", "IAM", "DPDP-R6-IAM-04",
        "Unused access keys are dormant credentials that can be compromised. "
        "They violate the principle of least privilege under Rule 6.",
        80, "High", non_compliant,
        "Deactivate or delete access keys not used in 90+ days. "
        "Implement automated key lifecycle management.", total)


def dpdp_iam_admin_access_users(session, meta):
    """DPDP-R6-IAM-05 — Detect IAM users with AdministratorAccess policy."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    try:
        users = iam.list_users().get("Users", [])
        total = len(users)
        for user in users:
            try:
                # Check attached policies
                attached = iam.list_attached_user_policies(UserName=user["UserName"]).get("AttachedPolicies", [])
                for pol in attached:
                    if "AdministratorAccess" in pol.get("PolicyName", ""):
                        non_compliant.append({
                            "resource_name": user["UserName"],
                            "policy": pol["PolicyName"],
                            "note": "User has AdministratorAccess — unrestricted access to personal data"
                        })
                        break
                else:
                    # Check group policies
                    groups = iam.list_groups_for_user(UserName=user["UserName"]).get("Groups", [])
                    for grp in groups:
                        grp_policies = iam.list_attached_group_policies(GroupName=grp["GroupName"]).get("AttachedPolicies", [])
                        for pol in grp_policies:
                            if "AdministratorAccess" in pol.get("PolicyName", ""):
                                non_compliant.append({
                                    "resource_name": user["UserName"],
                                    "via_group": grp["GroupName"],
                                    "note": "User has AdministratorAccess via group"
                                })
                                break
                        else:
                            continue
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_iam_admin_access_users error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — IAM Users With AdministratorAccess", "IAM", "DPDP-R6-IAM-05",
        "Users with AdministratorAccess have unrestricted access to all resources including personal data, "
        "violating Rule 6 least-privilege requirements.",
        85, "High", non_compliant,
        "Replace AdministratorAccess with task-specific policies. "
        "Use AWS Access Analyzer to generate least-privilege policies.", total)


def dpdp_iam_cross_account_trust(session, meta):
    """DPDP-R14-IAM-06 — Detect roles with cross-account trust relationships."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        for role in roles:
            try:
                doc = role.get("AssumeRolePolicyDocument", {})
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            if "arn:aws:iam::" in str(p) and account_id not in str(p):
                                non_compliant.append({
                                    "resource_name": role["RoleName"],
                                    "trusted_account": p,
                                    "note": "Cross-account trust — external entity can assume this role"
                                })
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_iam_cross_account_trust error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Cross-Account Trust Relationships", "IAM", "DPDP-R14-IAM-06",
        "Roles with cross-account trust allow external entities to access personal data. "
        "Rule 14 requires documented data processor agreements for all such access.",
        80, "High", non_compliant,
        "Review all cross-account trust relationships. Ensure each external account "
        "is a documented data processor with contractual DPDP obligations.", total)


def dpdp_iam_anonymous_federated(session, meta):
    """DPDP-R14-IAM-07 — Detect roles allowing anonymous/federated access."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    try:
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        for role in roles:
            try:
                doc = role.get("AssumeRolePolicyDocument", {})
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*":
                            non_compliant.append({
                                "resource_name": role["RoleName"],
                                "note": "Role allows ANY principal to assume — anonymous access"
                            })
                            break
                        federated = principal.get("Federated", []) if isinstance(principal, dict) else []
                        if isinstance(federated, str):
                            federated = [federated]
                        if "*" in federated:
                            non_compliant.append({
                                "resource_name": role["RoleName"],
                                "note": "Role allows anonymous federated access"
                            })
                            break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_iam_anonymous_federated error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Anonymous Federated Access", "IAM", "DPDP-R14-IAM-07",
        "Roles allowing anonymous or wildcard federated access can be assumed by anyone, "
        "providing unrestricted access to personal data.",
        85, "High", non_compliant,
        "Remove wildcard trust policies. Specify exact federated identity providers "
        "with conditions restricting access.", total)


def dpdp_iam_password_rotation(session, meta):
    """DPDP-R6-IAM-08 — Password rotation/expiry must be configured."""
    iam = session.client("iam")
    non_compliant = []
    try:
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            max_age = policy.get("MaxPasswordAge", 0)
            if max_age == 0 or max_age > 90:
                non_compliant.append({
                    "resource_name": "Password Policy",
                    "max_age": max_age,
                    "note": f"Password expiry is {max_age} days (should be ≤ 90) or disabled"
                })
        except iam.exceptions.NoSuchEntityException:
            non_compliant.append({
                "resource_name": "Password Policy",
                "note": "No password policy — rotation not enforced"
            })
    except Exception as e:
        print(f"dpdp_iam_password_rotation error: {e}")
    _update_meta(meta, "IAM", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Password Rotation Disabled", "IAM", "DPDP-R6-IAM-08",
        "Without password rotation, compromised credentials remain valid indefinitely, "
        "allowing prolonged unauthorized access to personal data.",
        70, "Medium", non_compliant,
        "Set MaxPasswordAge to 90 days or less in the account password policy.", 1)


def dpdp_iam_console_without_mfa(session, meta):
    """DPDP-R6-IAM-09 — All console users must have MFA enabled."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    try:
        users = iam.list_users().get("Users", [])
        for user in users:
            try:
                iam.get_login_profile(UserName=user["UserName"])
                total += 1
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
                if not mfa:
                    non_compliant.append({
                        "resource_name": user["UserName"],
                        "note": "Console access enabled without MFA"
                    })
            except iam.exceptions.NoSuchEntityException:
                pass  # No console access
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_iam_console_without_mfa error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Console Access Without MFA", "IAM", "DPDP-R6-IAM-09",
        "IAM users with console access but no MFA can be compromised with just a password, "
        "providing access to personal data management interfaces.",
        75, "Medium", non_compliant,
        "Enable MFA for all IAM users with console access. Consider enforcing MFA via SCP.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🖥️ EC2 ENHANCED CHECKS (6 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_ec2_imdsv2(session, meta):
    """DPDP-R6-EC2-01 — EC2 instances must enforce IMDSv2."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    total += 1
                    http_tokens = inst.get("MetadataOptions", {}).get("HttpTokens", "optional")
                    if http_tokens != "required":
                        name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                        non_compliant.append({
                            "resource_name": name,
                            "instance_id": inst["InstanceId"],
                            "note": "IMDSv2 not enforced (HttpTokens=optional)"
                        })
    except Exception as e:
        print(f"dpdp_ec2_imdsv2 error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — EC2 IMDSv2 Not Enforced", "EC2", "DPDP-R6-EC2-01",
        "Without IMDSv2 enforcement, SSRF attacks can steal instance credentials "
        "and access personal data in connected services.",
        80, "High", non_compliant,
        "Set HttpTokens=required on all EC2 instances to enforce IMDSv2.", total)


def dpdp_ec2_instance_profile_overprivileged(session, meta):
    """DPDP-R6-EC2-02 — Detect instances with overly permissive IAM roles."""
    ec2 = session.client("ec2")
    iam = session.client("iam")
    non_compliant = []
    total = 0
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    profile = inst.get("IamInstanceProfile", {})
                    if profile:
                        total += 1
                        profile_arn = profile.get("Arn", "")
                        profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else ""
                        if profile_name:
                            try:
                                ip = iam.get_instance_profile(InstanceProfileName=profile_name)
                                roles = ip.get("InstanceProfile", {}).get("Roles", [])
                                for role in roles:
                                    attached = iam.list_attached_role_policies(RoleName=role["RoleName"]).get("AttachedPolicies", [])
                                    for pol in attached:
                                        if pol.get("PolicyName") in ("AdministratorAccess", "PowerUserAccess"):
                                            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                                            non_compliant.append({
                                                "resource_name": name,
                                                "instance_id": inst["InstanceId"],
                                                "role": role["RoleName"],
                                                "policy": pol["PolicyName"],
                                                "note": f"Instance has {pol['PolicyName']} — over-privileged"
                                            })
                                            break
                            except Exception:
                                pass
    except Exception as e:
        print(f"dpdp_ec2_instance_profile_overprivileged error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — EC2 Instance Profile Over-Privileged", "EC2", "DPDP-R6-EC2-02",
        "EC2 instances with AdministratorAccess or PowerUserAccess can access all personal data. "
        "If compromised, the blast radius is the entire account.",
        85, "High", non_compliant,
        "Replace broad policies with task-specific roles. Use IAM Access Analyzer "
        "to generate least-privilege policies based on actual usage.", total)


def dpdp_ec2_unused_security_groups(session, meta):
    """DPDP-R6-EC2-03 — Detect unused security groups."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        total = len(sgs)
        # Get all SGs in use by network interfaces
        used_sgs = set()
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for ni in page.get("NetworkInterfaces", []):
                for grp in ni.get("Groups", []):
                    used_sgs.add(grp["GroupId"])
        for sg in sgs:
            if sg["GroupName"] == "default":
                continue  # Default SG can't be deleted
            if sg["GroupId"] not in used_sgs:
                non_compliant.append({
                    "resource_name": sg["GroupId"],
                    "group_name": sg.get("GroupName"),
                    "note": "Security group not attached to any network interface"
                })
    except Exception as e:
        print(f"dpdp_ec2_unused_security_groups error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Unused Security Groups", "EC2", "DPDP-R6-EC2-03",
        "Unused security groups create management overhead and may have permissive rules "
        "that could be accidentally attached to instances processing personal data.",
        65, "Medium", non_compliant,
        "Delete unused security groups or restrict their rules to prevent accidental misuse.", total)


def dpdp_ec2_default_sg_open(session, meta):
    """DPDP-R6-EC2-04 — Default security group must not have permissive rules."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        ).get("SecurityGroups", [])
        total = len(sgs)
        for sg in sgs:
            has_ingress = len(sg.get("IpPermissions", [])) > 0
            if has_ingress:
                non_compliant.append({
                    "resource_name": sg["GroupId"],
                    "vpc_id": sg.get("VpcId"),
                    "note": "Default security group has ingress rules — should be empty"
                })
    except Exception as e:
        print(f"dpdp_ec2_default_sg_open error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Default Security Group Open", "EC2", "DPDP-R6-EC2-04",
        "Default security groups with ingress rules can inadvertently allow network access "
        "to instances processing personal data when no custom SG is specified.",
        70, "Medium", non_compliant,
        "Remove all ingress/egress rules from default security groups. "
        "Always use custom security groups with explicit least-privilege rules.", total)


def dpdp_ec2_public_amis(session, meta):
    """DPDP-R6-EC2-05 — Detect AMIs shared publicly."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        images = ec2.describe_images(Owners=[account_id]).get("Images", [])
        total = len(images)
        for img in images:
            if img.get("Public", False):
                non_compliant.append({
                    "resource_name": img["ImageId"],
                    "name": img.get("Name", ""),
                    "note": "AMI is publicly shared — may contain personal data or secrets"
                })
    except Exception as e:
        print(f"dpdp_ec2_public_amis error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Public AMIs", "EC2", "DPDP-R6-EC2-05",
        "Public AMIs may contain embedded credentials, configuration data, or personal data "
        "from the source instance.",
        70, "Medium", non_compliant,
        "Make AMIs private unless intentionally shared. Review public AMIs for embedded secrets.", total)


def dpdp_ec2_public_snapshots(session, meta):
    """DPDP-R6-EC2-06 — Detect EBS snapshots shared publicly."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        snapshots = ec2.describe_snapshots(OwnerIds=[account_id]).get("Snapshots", [])
        total = len(snapshots)
        for snap in snapshots:
            try:
                attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=snap["SnapshotId"],
                    Attribute="createVolumePermission"
                )
                perms = attrs.get("CreateVolumePermissions", [])
                if any(p.get("Group") == "all" for p in perms):
                    non_compliant.append({
                        "resource_name": snap["SnapshotId"],
                        "size_gb": snap.get("VolumeSize"),
                        "note": "EBS snapshot is publicly shared"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_ec2_public_snapshots error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Public EBS Snapshots", "EC2", "DPDP-R6-EC2-06",
        "Public EBS snapshots expose volume data including potentially personal data "
        "to anyone who knows the snapshot ID.",
        70, "Medium", non_compliant,
        "Remove public sharing from all EBS snapshots. Use AWS RAM for controlled sharing.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🗄️ RDS ENHANCED CHECKS (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_rds_enhanced_monitoring(session, meta):
    """DPDP-R6-RDS-01 — RDS enhanced monitoring must be enabled."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            interval = db.get("MonitoringInterval", 0)
            if interval == 0:
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "note": "Enhanced Monitoring disabled — no OS-level metrics"
                })
    except Exception as e:
        print(f"dpdp_rds_enhanced_monitoring error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — RDS Enhanced Monitoring Disabled", "RDS", "DPDP-R6-RDS-01",
        "Without Enhanced Monitoring, OS-level anomalies on database instances processing "
        "personal data cannot be detected.",
        75, "High", non_compliant,
        "Enable Enhanced Monitoring with 60-second interval on all RDS instances.", total)


def dpdp_rds_performance_insights(session, meta):
    """DPDP-R6-RDS-02 — RDS Performance Insights for query-level visibility."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("PerformanceInsightsEnabled"):
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "note": "Performance Insights disabled — no query-level visibility"
                })
    except Exception as e:
        print(f"dpdp_rds_performance_insights error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — RDS Performance Insights Disabled", "RDS", "DPDP-R6-RDS-02",
        "Performance Insights provides query-level monitoring to detect unusual data access patterns "
        "that may indicate unauthorized access to personal data.",
        75, "High", non_compliant,
        "Enable Performance Insights on all RDS instances with 7-day retention minimum.", total)


def dpdp_rds_multi_az(session, meta):
    """DPDP-R8-RDS-03 — RDS instances should be Multi-AZ for data availability."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("MultiAZ"):
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "note": "Single-AZ deployment — no failover capability"
                })
    except Exception as e:
        print(f"dpdp_rds_multi_az error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — RDS Multi-AZ Disabled", "RDS", "DPDP-R8-RDS-03",
        "Single-AZ RDS instances have no automatic failover, risking personal data availability "
        "during infrastructure failures.",
        65, "Medium", non_compliant,
        "Enable Multi-AZ for all RDS instances storing personal data to ensure availability.", total)


def dpdp_rds_public_snapshots(session, meta):
    """DPDP-R6-RDS-04 — RDS snapshots must not be public."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        snapshots = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        total = len(snapshots)
        for snap in snapshots:
            try:
                attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap["DBSnapshotIdentifier"])
                results = attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
                for attr in results:
                    if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                        non_compliant.append({
                            "resource_name": snap["DBSnapshotIdentifier"],
                            "note": "RDS snapshot is publicly restorable"
                        })
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_rds_public_snapshots error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — RDS Public Snapshots", "RDS", "DPDP-R6-RDS-04",
        "Public RDS snapshots expose entire database contents including personal data "
        "to anyone with an AWS account.",
        75, "Medium", non_compliant,
        "Remove public access from all RDS snapshots. Use AWS RAM for controlled sharing.", total)


def dpdp_rds_cross_account_snapshots(session, meta):
    """DPDP-R12-RDS-05 — Detect RDS snapshots shared cross-account."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        snapshots = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        total = len(snapshots)
        for snap in snapshots:
            try:
                attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap["DBSnapshotIdentifier"])
                results = attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
                for attr in results:
                    if attr.get("AttributeName") == "restore":
                        values = attr.get("AttributeValues", [])
                        external = [v for v in values if v != "all" and v != account_id]
                        if external:
                            non_compliant.append({
                                "resource_name": snap["DBSnapshotIdentifier"],
                                "shared_with": external,
                                "note": f"Snapshot shared with external accounts: {external}"
                            })
                            break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_rds_cross_account_snapshots error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — RDS Cross-Account Snapshot Sharing", "RDS", "DPDP-R12-RDS-05",
        "RDS snapshots shared with external accounts transfer personal data "
        "to entities that may not comply with DPDP requirements.",
        70, "Medium", non_compliant,
        "Review cross-account snapshot sharing. Ensure recipients are documented "
        "data processors with DPDP-compliant agreements.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 📊 DYNAMODB ENHANCED CHECKS (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_dynamodb_cmk(session, meta):
    """DPDP-R6-DDB-01 — DynamoDB tables should use customer-managed KMS keys."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                desc = ddb.describe_table(TableName=t)["Table"]
                sse = desc.get("SSEDescription", {})
                sse_type = sse.get("SSEType", "")
                if sse_type != "KMS":
                    non_compliant.append({
                        "resource_name": t,
                        "encryption": sse_type or "DEFAULT (AWS owned)",
                        "note": "Not using customer-managed KMS key"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_dynamodb_cmk error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — DynamoDB Customer Managed KMS", "DynamoDB", "DPDP-R6-DDB-01",
        "DynamoDB tables without CMK use AWS-owned keys, providing no control over key management, "
        "rotation, or access audit trails for personal data encryption.",
        80, "High", non_compliant,
        "Enable SSE with customer-managed KMS keys on all DynamoDB tables storing personal data.", total)


def dpdp_dynamodb_streams_disabled(session, meta):
    """DPDP-R6-DDB-02 — DynamoDB Streams should be enabled for change tracking."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                desc = ddb.describe_table(TableName=t)["Table"]
                stream_spec = desc.get("StreamSpecification", {})
                if not stream_spec.get("StreamEnabled"):
                    non_compliant.append({
                        "resource_name": t,
                        "note": "DynamoDB Streams not enabled — no change data capture"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_dynamodb_streams_disabled error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — DynamoDB Streams Disabled", "DynamoDB", "DPDP-R6-DDB-02",
        "Without DynamoDB Streams, changes to personal data cannot be tracked or audited, "
        "limiting breach detection and data principal request fulfillment.",
        65, "Medium", non_compliant,
        "Enable DynamoDB Streams with NEW_AND_OLD_IMAGES to capture all changes to personal data.", total)


def dpdp_dynamodb_cross_account_access(session, meta):
    """DPDP-R14-DDB-03 — Detect DynamoDB tables with cross-account resource policies."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                policy = ddb.get_resource_policy(ResourceArn=f"arn:aws:dynamodb:{session.region_name}:{account_id}:table/{t}")
                doc = _json.loads(policy.get("Policy", "{}"))
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            if "arn:aws:iam::" in str(p) and account_id not in str(p):
                                non_compliant.append({
                                    "resource_name": t,
                                    "external_principal": p,
                                    "note": "Cross-account access via resource policy"
                                })
                                break
            except ClientError as e:
                if "ResourceNotFoundException" in str(e) or "PolicyNotFoundException" in str(e):
                    pass  # No resource policy is fine
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_dynamodb_cross_account_access error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — DynamoDB Cross-Account Access Policies", "DynamoDB", "DPDP-R14-DDB-03",
        "DynamoDB tables with cross-account resource policies share personal data "
        "with external entities requiring documented processor agreements.",
        70, "Medium", non_compliant,
        "Review DynamoDB resource policies. Ensure external principals are documented "
        "data processors under DPDP.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# ⚙️ AWS CONFIG ENHANCED CHECKS (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_config_all_resources(session, meta):
    """DPDP-R7-CFG-01 — AWS Config must record all resource types."""
    cfg = session.client("config")
    non_compliant = []
    try:
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            non_compliant.append({
                "resource_name": "AWS Config",
                "note": "No configuration recorder — nothing is being tracked"
            })
        else:
            for rec in recorders:
                group = rec.get("recordingGroup", {})
                if not group.get("allSupported"):
                    non_compliant.append({
                        "resource_name": rec["name"],
                        "note": "Not recording all supported resource types"
                    })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "AWS Config", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_config_all_resources error: {e}")
    _update_meta(meta, "Config", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Config Records All Resource Types", "Config", "DPDP-R7-CFG-01",
        "If AWS Config doesn't record all resource types, configuration changes to resources "
        "storing personal data go untracked, undermining breach detection.",
        80, "High", non_compliant,
        "Configure the recorder to track all supported resource types including global resources.", 1)


def dpdp_config_delivery_channel(session, meta):
    """DPDP-R7-CFG-02 — AWS Config delivery channel must be properly configured."""
    cfg = session.client("config")
    non_compliant = []
    try:
        channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
        if not channels:
            non_compliant.append({
                "resource_name": "AWS Config",
                "note": "No delivery channel — config data not being stored"
            })
        else:
            for ch in channels:
                if not ch.get("s3BucketName"):
                    non_compliant.append({
                        "resource_name": ch.get("name", "default"),
                        "note": "No S3 bucket configured for config delivery"
                    })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "AWS Config", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_config_delivery_channel error: {e}")
    _update_meta(meta, "Config", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Config Delivery Channel Present", "Config", "DPDP-R7-CFG-02",
        "Without a delivery channel, AWS Config data is not stored persistently, "
        "preventing historical analysis needed for breach investigations.",
        80, "High", non_compliant,
        "Configure a delivery channel with an S3 bucket and optional SNS topic for notifications.", 1)


def dpdp_config_aggregator(session, meta):
    """DPDP-R7-CFG-03 — Config aggregator should be configured for centralized view."""
    cfg = session.client("config")
    non_compliant = []
    try:
        aggregators = cfg.describe_configuration_aggregators().get("ConfigurationAggregators", [])
        if not aggregators:
            non_compliant.append({
                "resource_name": "AWS Config",
                "note": "No Config aggregator — no centralized compliance view"
            })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "AWS Config", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_config_aggregator error: {e}")
    _update_meta(meta, "Config", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Config Aggregator Configured", "Config", "DPDP-R7-CFG-03",
        "Without a Config aggregator, multi-account/multi-region compliance cannot be assessed "
        "from a single view, complicating DPDP audit readiness.",
        65, "Medium", non_compliant,
        "Create a Config aggregator to collect compliance data across all accounts and regions.", 1)



# ═══════════════════════════════════════════════════════════════════════════════
# 🛡️ GUARDDUTY ENHANCED CHECKS (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_guardduty_malware_protection(session, meta):
    """DPDP-R7-GD-01 — GuardDuty Malware Protection must be enabled."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            non_compliant.append({"resource_name": "GuardDuty", "note": "GuardDuty not enabled"})
        else:
            for did in detectors:
                det = gd.get_detector(DetectorId=did)
                features = det.get("Features", [])
                malware = next((f for f in features if f.get("Name") == "EBS_MALWARE_PROTECTION"), None)
                if not malware or malware.get("Status") != "ENABLED":
                    non_compliant.append({
                        "resource_name": did,
                        "note": "Malware Protection not enabled"
                    })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "GuardDuty", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_guardduty_malware_protection error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — GuardDuty Malware Protection", "GuardDuty", "DPDP-R7-GD-01",
        "Malware on instances processing personal data can exfiltrate or corrupt data. "
        "GuardDuty Malware Protection scans EBS volumes for threats.",
        80, "High", non_compliant,
        "Enable GuardDuty Malware Protection to detect malicious software on instances.", 1)


def dpdp_guardduty_s3_protection(session, meta):
    """DPDP-R7-GD-02 — GuardDuty S3 Protection must be enabled."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            non_compliant.append({"resource_name": "GuardDuty", "note": "GuardDuty not enabled"})
        else:
            for did in detectors:
                det = gd.get_detector(DetectorId=did)
                features = det.get("Features", [])
                s3_prot = next((f for f in features if f.get("Name") == "S3_DATA_EVENTS"), None)
                if not s3_prot or s3_prot.get("Status") != "ENABLED":
                    # Also check legacy data sources
                    ds = det.get("DataSources", {})
                    s3_logs = ds.get("S3Logs", {})
                    if s3_logs.get("Status") != "ENABLED":
                        non_compliant.append({
                            "resource_name": did,
                            "note": "S3 Protection not enabled — cannot detect data exfiltration"
                        })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "GuardDuty", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_guardduty_s3_protection error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — GuardDuty S3 Protection", "GuardDuty", "DPDP-R7-GD-02",
        "GuardDuty S3 Protection detects anomalous access patterns to S3 buckets storing personal data, "
        "essential for Rule 7 breach detection.",
        80, "High", non_compliant,
        "Enable GuardDuty S3 Protection to detect data exfiltration and unauthorized access.", 1)


def dpdp_guardduty_eks_protection(session, meta):
    """DPDP-R7-GD-03 — GuardDuty EKS Protection must be enabled."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            non_compliant.append({"resource_name": "GuardDuty", "note": "GuardDuty not enabled"})
        else:
            for did in detectors:
                det = gd.get_detector(DetectorId=did)
                features = det.get("Features", [])
                eks_prot = next((f for f in features if f.get("Name") == "EKS_AUDIT_LOGS"), None)
                if not eks_prot or eks_prot.get("Status") != "ENABLED":
                    ds = det.get("DataSources", {})
                    eks_ds = ds.get("Kubernetes", {}).get("AuditLogs", {})
                    if eks_ds.get("Status") != "ENABLED":
                        non_compliant.append({
                            "resource_name": did,
                            "note": "EKS Protection not enabled"
                        })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "GuardDuty", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_guardduty_eks_protection error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — GuardDuty EKS Protection", "GuardDuty", "DPDP-R7-GD-03",
        "EKS clusters processing personal data need threat detection. "
        "GuardDuty EKS Protection monitors Kubernetes audit logs for suspicious activity.",
        80, "High", non_compliant,
        "Enable GuardDuty EKS Audit Log Monitoring for all EKS clusters.", 1)


def dpdp_guardduty_high_findings(session, meta):
    """DPDP-R7-GD-04 — Detect unresolved HIGH severity GuardDuty findings."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        for did in detectors:
            try:
                findings = gd.list_findings(
                    DetectorId=did,
                    FindingCriteria={
                        "Criterion": {
                            "severity": {"Gte": 7, "Lt": 9},
                            "service.archived": {"Eq": ["false"]}
                        }
                    },
                    MaxResults=50
                ).get("FindingIds", [])
                if findings:
                    non_compliant.append({
                        "resource_name": f"GuardDuty ({did})",
                        "count": len(findings),
                        "note": f"{len(findings)} unresolved HIGH severity findings"
                    })
            except Exception:
                pass
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            pass  # Handled by enabled check
    except Exception as e:
        print(f"dpdp_guardduty_high_findings error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — GuardDuty Unresolved High Findings", "GuardDuty", "DPDP-R7-GD-04",
        "Unresolved high-severity GuardDuty findings indicate active threats that may be "
        "compromising personal data protection.",
        75, "Medium", non_compliant,
        "Investigate and remediate all HIGH severity GuardDuty findings immediately. "
        "Set up automated response with EventBridge and Lambda.", 1)


def dpdp_guardduty_critical_findings(session, meta):
    """DPDP-R7-GD-05 — Detect unresolved CRITICAL severity GuardDuty findings."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        for did in detectors:
            try:
                findings = gd.list_findings(
                    DetectorId=did,
                    FindingCriteria={
                        "Criterion": {
                            "severity": {"Gte": 9},
                            "service.archived": {"Eq": ["false"]}
                        }
                    },
                    MaxResults=50
                ).get("FindingIds", [])
                if findings:
                    non_compliant.append({
                        "resource_name": f"GuardDuty ({did})",
                        "count": len(findings),
                        "note": f"{len(findings)} unresolved CRITICAL severity findings"
                    })
            except Exception:
                pass
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            pass
    except Exception as e:
        print(f"dpdp_guardduty_critical_findings error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — GuardDuty Unresolved Critical Findings", "GuardDuty", "DPDP-R7-GD-05",
        "Critical GuardDuty findings indicate active compromise. "
        "This may constitute a data breach requiring notification under Rule 7.",
        95, "Critical", non_compliant,
        "IMMEDIATE ACTION: Investigate critical findings. Initiate breach notification process "
        "if personal data is affected. Isolate compromised resources.", 1)



# ═══════════════════════════════════════════════════════════════════════════════
# 🔒 SECURITY HUB ENHANCED CHECKS (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_securityhub_critical_findings(session, meta):
    """DPDP-R7-SH-01 — Detect open critical findings in Security Hub."""
    sh = session.client("securityhub")
    non_compliant = []
    try:
        findings = sh.get_findings(
            Filters={
                "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            },
            MaxResults=100
        ).get("Findings", [])
        if findings:
            non_compliant.append({
                "resource_name": "Security Hub",
                "count": len(findings),
                "note": f"{len(findings)} open CRITICAL findings requiring immediate action"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "SubscriptionRequiredException"):
            pass  # Handled by enabled check
        else:
            print(f"dpdp_securityhub_critical_findings error: {code}")
    except Exception as e:
        print(f"dpdp_securityhub_critical_findings error: {e}")
    _update_meta(meta, "SecurityHub", 1, non_compliant, "Critical")
    return _result(
        "DPDP R2025 — Security Hub Critical Findings Open", "SecurityHub", "DPDP-R7-SH-01",
        "Open critical Security Hub findings indicate severe security gaps "
        "that may already be compromising personal data.",
        95, "Critical", non_compliant,
        "Investigate and remediate all CRITICAL Security Hub findings. "
        "These represent the highest-risk issues in your environment.", 1)


def dpdp_securityhub_high_findings(session, meta):
    """DPDP-R7-SH-02 — Detect open high findings in Security Hub."""
    sh = session.client("securityhub")
    non_compliant = []
    try:
        findings = sh.get_findings(
            Filters={
                "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            },
            MaxResults=100
        ).get("Findings", [])
        if findings:
            non_compliant.append({
                "resource_name": "Security Hub",
                "count": len(findings),
                "note": f"{len(findings)} open HIGH findings"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "SubscriptionRequiredException"):
            pass
        else:
            print(f"dpdp_securityhub_high_findings error: {code}")
    except Exception as e:
        print(f"dpdp_securityhub_high_findings error: {e}")
    _update_meta(meta, "SecurityHub", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Security Hub High Findings Open", "SecurityHub", "DPDP-R7-SH-02",
        "Open HIGH severity Security Hub findings represent significant security gaps "
        "that could lead to personal data breaches.",
        80, "High", non_compliant,
        "Prioritize and remediate HIGH findings within 7 days. "
        "Configure automated notifications for new high-severity findings.", 1)


def dpdp_securityhub_standards(session, meta):
    """DPDP-R7-SH-03 — Security Hub standards must be enabled."""
    sh = session.client("securityhub")
    non_compliant = []
    try:
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        if not standards:
            non_compliant.append({
                "resource_name": "Security Hub",
                "note": "No security standards enabled — no automated compliance checks"
            })
        else:
            # Check if key standards are enabled
            enabled_arns = [s.get("StandardsArn", "") for s in standards]
            has_foundational = any("aws-foundational-security-best-practices" in a for a in enabled_arns)
            has_cis = any("cis-aws-foundations-benchmark" in a for a in enabled_arns)
            if not has_foundational and not has_cis:
                non_compliant.append({
                    "resource_name": "Security Hub",
                    "enabled_standards": [s.get("StandardsArn", "").split("/")[-2] for s in standards],
                    "note": "Neither AWS Foundational nor CIS Benchmark standards enabled"
                })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "SubscriptionRequiredException"):
            non_compliant.append({"resource_name": "Security Hub", "note": "Security Hub not enabled"})
    except Exception as e:
        print(f"dpdp_securityhub_standards error: {e}")
    _update_meta(meta, "SecurityHub", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Security Hub Standards Not Enabled", "SecurityHub", "DPDP-R7-SH-03",
        "Without security standards enabled, Security Hub cannot provide automated "
        "compliance checks against established best practices.",
        70, "Medium", non_compliant,
        "Enable AWS Foundational Security Best Practices and CIS AWS Foundations Benchmark standards.", 1)



# ═══════════════════════════════════════════════════════════════════════════════
# 💾 BACKUP ENHANCED CHECKS (4 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_backup_vault_encryption(session, meta):
    """DPDP-R10-BKP-01 — Backup vaults must be encrypted with KMS."""
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for vault in vaults:
            enc_key = vault.get("EncryptionKeyArn", "")
            if not enc_key:
                non_compliant.append({
                    "resource_name": vault["BackupVaultName"],
                    "note": "Backup vault not encrypted with KMS"
                })
            elif "aws/backup" in enc_key:
                # AWS-managed key — less control
                non_compliant.append({
                    "resource_name": vault["BackupVaultName"],
                    "encryption": "AWS-managed key",
                    "note": "Using AWS-managed key — limited control over encryption"
                })
    except Exception as e:
        print(f"dpdp_backup_vault_encryption error: {e}")
    _update_meta(meta, "Backup", max(total, 1), non_compliant, "High")
    return _result(
        "DPDP R2025 — Backup Vault Encryption", "Backup", "DPDP-R10-BKP-01",
        "Backup vaults without proper KMS encryption leave backup copies of personal data "
        "vulnerable to unauthorized access.",
        80, "High", non_compliant,
        "Configure backup vaults with customer-managed KMS keys for full control over "
        "encryption key lifecycle and access.", max(total, 1))


def dpdp_backup_cross_region_missing(session, meta):
    """DPDP-R10-BKP-02 — Cross-region backup should be configured for DR."""
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = len(plans) if plans else 1
        if not plans:
            non_compliant.append({
                "resource_name": "AWS Backup",
                "note": "No backup plans — no cross-region DR capability"
            })
        else:
            has_cross_region = False
            for plan in plans:
                try:
                    detail = backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"])
                    rules = detail.get("BackupPlan", {}).get("Rules", [])
                    for rule in rules:
                        copy_actions = rule.get("CopyActions", [])
                        if copy_actions:
                            has_cross_region = True
                            break
                    if has_cross_region:
                        break
                except Exception:
                    pass
            if not has_cross_region:
                non_compliant.append({
                    "resource_name": "AWS Backup",
                    "note": "No cross-region copy configured in any backup plan"
                })
    except Exception as e:
        print(f"dpdp_backup_cross_region_missing error: {e}")
    _update_meta(meta, "Backup", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Cross-Region Backup Missing", "Backup", "DPDP-R10-BKP-02",
        "Without cross-region backup copies, a regional disaster could permanently destroy "
        "personal data, violating continuity requirements under Rule 10.",
        80, "High", non_compliant,
        "Add cross-region copy actions to backup plans for personal data resources. "
        "Ensure destination region is also DPDP-approved.", total)


def dpdp_backup_vault_lock(session, meta):
    """DPDP-R10-BKP-03 — Backup Vault Lock should be enabled for immutability."""
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults)
        for vault in vaults:
            if not vault.get("Locked"):
                non_compliant.append({
                    "resource_name": vault["BackupVaultName"],
                    "note": "Vault Lock not enabled — backups can be deleted"
                })
    except Exception as e:
        print(f"dpdp_backup_vault_lock error: {e}")
    _update_meta(meta, "Backup", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Backup Vault Lock Missing", "Backup", "DPDP-R10-BKP-03",
        "Without Vault Lock, backup recovery points can be deleted by compromised credentials, "
        "allowing attackers to destroy personal data backups.",
        70, "Medium", non_compliant,
        "Enable Backup Vault Lock in governance or compliance mode to prevent "
        "accidental or malicious deletion of recovery points.", max(total, 1))


def dpdp_backup_recovery_retention(session, meta):
    """DPDP-R10-BKP-04 — Backup recovery points must have adequate retention."""
    backup = session.client("backup")
    non_compliant = []
    total = 0
    MIN_RETENTION_DAYS = 30
    try:
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = len(plans) if plans else 1
        for plan in plans:
            try:
                detail = backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"])
                rules = detail.get("BackupPlan", {}).get("Rules", [])
                for rule in rules:
                    lifecycle = rule.get("Lifecycle", {})
                    delete_days = lifecycle.get("DeleteAfterDays", 0)
                    if 0 < delete_days < MIN_RETENTION_DAYS:
                        non_compliant.append({
                            "resource_name": plan.get("BackupPlanName", plan["BackupPlanId"]),
                            "rule": rule.get("RuleName"),
                            "retention_days": delete_days,
                            "note": f"Retention {delete_days} days — should be {MIN_RETENTION_DAYS}+"
                        })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_backup_recovery_retention error: {e}")
    _update_meta(meta, "Backup", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Backup Recovery Point Retention Too Low", "Backup", "DPDP-R10-BKP-04",
        "Backup plans with retention below 30 days may not provide adequate recovery capability "
        "for personal data in case of breach or accidental deletion.",
        65, "Medium", non_compliant,
        "Set backup retention to at least 30 days for resources storing personal data. "
        "Align with your organization's data recovery objectives.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🌐 NETWORK SECURITY CHECKS (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_net_internet_facing_lb(session, meta):
    """DPDP-R6-NET-01 — Detect internet-facing load balancers."""
    elbv2 = session.client("elbv2")
    non_compliant = []
    total = 0
    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        total = len(lbs)
        for lb in lbs:
            if lb.get("Scheme") == "internet-facing":
                non_compliant.append({
                    "resource_name": lb["LoadBalancerName"],
                    "type": lb.get("Type"),
                    "dns": lb.get("DNSName"),
                    "note": "Internet-facing load balancer — publicly accessible"
                })
    except Exception as e:
        print(f"dpdp_net_internet_facing_lb error: {e}")
    _update_meta(meta, "ELB", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Internet-Facing Load Balancers", "ELB", "DPDP-R6-NET-01",
        "Internet-facing load balancers expose backend services processing personal data "
        "to the public internet without additional controls.",
        80, "High", non_compliant,
        "Review all internet-facing load balancers. Ensure WAF, TLS, and authentication "
        "are configured for those serving applications with personal data.", total)


def dpdp_net_internet_facing_opensearch(session, meta):
    """DPDP-R6-NET-02 — Detect internet-facing OpenSearch domains."""
    es = session.client("opensearch")
    non_compliant = []
    total = 0
    try:
        domains = es.list_domain_names().get("DomainNames", [])
        total = len(domains)
        for d in domains:
            try:
                config = es.describe_domain(DomainName=d["DomainName"])["DomainStatus"]
                # Check if domain is in VPC
                vpc_config = config.get("VPCOptions", {})
                if not vpc_config.get("VPCId"):
                    # Public domain — check access policy
                    non_compliant.append({
                        "resource_name": d["DomainName"],
                        "note": "OpenSearch domain not in VPC — publicly accessible"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_net_internet_facing_opensearch error: {e}")
    _update_meta(meta, "OpenSearch", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Internet-Facing OpenSearch", "OpenSearch", "DPDP-R6-NET-02",
        "OpenSearch domains not in a VPC are publicly accessible, "
        "exposing indexed personal data to the internet.",
        85, "High", non_compliant,
        "Place OpenSearch domains in a VPC with private subnets. "
        "Use VPC endpoints for access from other services.", total)


def dpdp_net_internet_facing_redshift(session, meta):
    """DPDP-R6-NET-03 — Detect internet-facing Redshift clusters."""
    rs = session.client("redshift")
    non_compliant = []
    total = 0
    try:
        clusters = rs.describe_clusters().get("Clusters", [])
        total = len(clusters)
        for c in clusters:
            if c.get("PubliclyAccessible"):
                non_compliant.append({
                    "resource_name": c["ClusterIdentifier"],
                    "endpoint": c.get("Endpoint", {}).get("Address", ""),
                    "note": "Redshift cluster is publicly accessible"
                })
    except Exception as e:
        print(f"dpdp_net_internet_facing_redshift error: {e}")
    _update_meta(meta, "Redshift", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Internet-Facing Redshift", "Redshift", "DPDP-R6-NET-03",
        "Publicly accessible Redshift clusters expose data warehouse contents "
        "including aggregated personal data to the internet.",
        85, "High", non_compliant,
        "Disable public accessibility on Redshift clusters. Place in private subnets "
        "and access via VPC endpoints or VPN.", total)


def dpdp_net_default_nacl_permissive(session, meta):
    """DPDP-R6-NET-04 — Default NACL must not be overly permissive."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        nacls = ec2.describe_network_acls(
            Filters=[{"Name": "default", "Values": ["true"]}]
        ).get("NetworkAcls", [])
        total = len(nacls)
        for nacl in nacls:
            # Check if default NACL has allow-all inbound
            for entry in nacl.get("Entries", []):
                if (not entry.get("Egress") and
                    entry.get("RuleAction") == "allow" and
                    entry.get("CidrBlock") == "0.0.0.0/0" and
                    entry.get("RuleNumber", 0) != 32767):  # Not the default deny
                    # Check if subnets are associated
                    associations = nacl.get("Associations", [])
                    if associations:
                        non_compliant.append({
                            "resource_name": nacl["NetworkAclId"],
                            "vpc_id": nacl.get("VpcId"),
                            "subnets": len(associations),
                            "note": "Default NACL allows all inbound — used by subnets"
                        })
                    break
    except Exception as e:
        print(f"dpdp_net_default_nacl_permissive error: {e}")
    _update_meta(meta, "VPC", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Default NACL Permissive", "VPC", "DPDP-R6-NET-04",
        "Default NACLs with allow-all rules provide no network-level protection for subnets "
        "hosting resources that process personal data.",
        65, "Medium", non_compliant,
        "Create custom NACLs with restrictive rules for subnets containing personal data. "
        "Associate them instead of using the default NACL.", total)


def dpdp_net_route_tables_igw(session, meta):
    """DPDP-R6-NET-05 — Detect route tables exposing private subnets via IGW."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        route_tables = ec2.describe_route_tables().get("RouteTables", [])
        total = len(route_tables)
        for rt in route_tables:
            has_igw = False
            for route in rt.get("Routes", []):
                gw = route.get("GatewayId", "")
                if gw.startswith("igw-") and route.get("State") == "active":
                    has_igw = True
                    break
            if has_igw:
                # Check if this route table is associated with subnets tagged as private
                for assoc in rt.get("Associations", []):
                    subnet_id = assoc.get("SubnetId")
                    if subnet_id:
                        try:
                            subnet = ec2.describe_subnets(SubnetIds=[subnet_id]).get("Subnets", [{}])[0]
                            tags = {t["Key"].lower(): t["Value"].lower() for t in subnet.get("Tags", [])}
                            if "private" in tags.get("name", "") or "private" in tags.get("tier", ""):
                                non_compliant.append({
                                    "resource_name": rt["RouteTableId"],
                                    "subnet": subnet_id,
                                    "note": "Route table with IGW route associated with private subnet"
                                })
                                break
                        except Exception:
                            pass
    except Exception as e:
        print(f"dpdp_net_route_tables_igw error: {e}")
    _update_meta(meta, "VPC", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Route Tables Exposing Private Subnets", "VPC", "DPDP-R6-NET-05",
        "Route tables with Internet Gateway routes on private subnets expose "
        "internal resources processing personal data to the internet.",
        70, "Medium", non_compliant,
        "Remove IGW routes from private subnet route tables. Use NAT gateways for outbound access.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🔑 SECRETS MANAGER ENHANCED CHECKS (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_secrets_old(session, meta):
    """DPDP-R6-SEC-01 — Detect secrets older than 90 days without rotation."""
    sm = session.client("secretsmanager")
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                total += 1
                last_rotated = secret.get("LastRotatedDate")
                last_changed = secret.get("LastChangedDate")
                reference_date = last_rotated or last_changed or secret.get("CreatedDate")
                if reference_date:
                    age = (now - reference_date).days
                    if age > 90:
                        non_compliant.append({
                            "resource_name": secret["Name"],
                            "age_days": age,
                            "note": f"Secret not rotated in {age} days"
                        })
    except Exception as e:
        print(f"dpdp_secrets_old error: {e}")
    _update_meta(meta, "SecretsManager", max(total, 1), non_compliant, "High")
    return _result(
        "DPDP R2025 — Secrets Older Than 90 Days", "SecretsManager", "DPDP-R6-SEC-01",
        "Secrets not rotated within 90 days increase the risk of credential compromise, "
        "potentially allowing unauthorized access to personal data.",
        80, "High", non_compliant,
        "Rotate all secrets at least every 90 days. Enable automatic rotation "
        "using Lambda rotation functions.", max(total, 1))


def dpdp_secrets_no_rotation_schedule(session, meta):
    """DPDP-R6-SEC-02 — Secrets must have rotation schedule configured."""
    sm = session.client("secretsmanager")
    non_compliant = []
    total = 0
    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                total += 1
                if not secret.get("RotationEnabled"):
                    non_compliant.append({
                        "resource_name": secret["Name"],
                        "note": "No rotation schedule configured"
                    })
    except Exception as e:
        print(f"dpdp_secrets_no_rotation_schedule error: {e}")
    _update_meta(meta, "SecretsManager", max(total, 1), non_compliant, "High")
    return _result(
        "DPDP R2025 — Secrets Without Rotation Schedule", "SecretsManager", "DPDP-R6-SEC-02",
        "Secrets without automatic rotation rely on manual processes, "
        "increasing the risk of stale credentials accessing personal data.",
        80, "High", non_compliant,
        "Enable automatic rotation for all secrets. Configure rotation Lambda functions "
        "with appropriate intervals.", max(total, 1))


def dpdp_secrets_unused(session, meta):
    """DPDP-R6-SEC-03 — Detect secrets not accessed recently."""
    sm = session.client("secretsmanager")
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    try:
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                total += 1
                last_accessed = secret.get("LastAccessedDate")
                if last_accessed:
                    days_unused = (now - last_accessed).days
                    if days_unused > 90:
                        non_compliant.append({
                            "resource_name": secret["Name"],
                            "days_unused": days_unused,
                            "note": f"Secret not accessed in {days_unused} days — likely unused"
                        })
                else:
                    # Never accessed
                    created = secret.get("CreatedDate")
                    if created and (now - created).days > 30:
                        non_compliant.append({
                            "resource_name": secret["Name"],
                            "note": "Secret never accessed since creation"
                        })
    except Exception as e:
        print(f"dpdp_secrets_unused error: {e}")
    _update_meta(meta, "SecretsManager", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Unused Secrets", "SecretsManager", "DPDP-R6-SEC-03",
        "Unused secrets are dormant credentials that increase attack surface "
        "without serving an active purpose.",
        65, "Medium", non_compliant,
        "Review and delete unused secrets. They represent unnecessary risk "
        "of credential compromise.", max(total, 1))



# ═══════════════════════════════════════════════════════════════════════════════
# 🌍 DATA RESIDENCY / CROSS-BORDER TRANSFER (5 checks)
# ═══════════════════════════════════════════════════════════════════════════════

APPROVED_REGIONS = ["ap-south-1", "ap-south-2"]  # India regions


def dpdp_data_residency_resources(session, meta):
    """DPDP-R12-DATA-01 — Detect resources deployed outside approved regions."""
    ec2 = session.client("ec2")
    rds = session.client("rds")
    non_compliant = []
    total = 0
    current_region = session.region_name
    if current_region in APPROVED_REGIONS:
        # This check only flags resources in non-approved regions
        pass
    else:
        # Check EC2 instances
        try:
            reservations = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ).get("Reservations", [])
            for r in reservations:
                for inst in r.get("Instances", []):
                    total += 1
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                    non_compliant.append({
                        "resource_name": name,
                        "instance_id": inst["InstanceId"],
                        "region": current_region,
                        "note": f"EC2 instance in {current_region} — outside approved India regions"
                    })
        except Exception:
            pass
        # Check RDS instances
        try:
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                total += 1
                non_compliant.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "region": current_region,
                    "note": f"RDS instance in {current_region} — outside approved India regions"
                })
        except Exception:
            pass
    _update_meta(meta, "Multi-Service", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Resources Outside Approved Regions", "Multi-Service", "DPDP-R12-DATA-01",
        "Rule 12 restricts transfer of personal data outside approved jurisdictions. "
        "Resources in non-India regions may store or process personal data in violation.",
        80, "High", non_compliant,
        "Migrate resources processing personal data to approved India regions (ap-south-1/ap-south-2) "
        "or document transfer justification under Rule 12.", total)


def dpdp_data_residency_kms(session, meta):
    """DPDP-R12-DATA-02 — KMS keys outside approved regions."""
    kms = session.client("kms")
    non_compliant = []
    total = 0
    current_region = session.region_name
    if current_region not in APPROVED_REGIONS:
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    try:
                        key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                        if key_meta.get("KeyManager") == "AWS":
                            continue
                        if key_meta.get("KeyState") != "Enabled":
                            continue
                        total += 1
                        non_compliant.append({
                            "resource_name": key_meta["KeyId"],
                            "region": current_region,
                            "note": f"CMK in {current_region} — may encrypt personal data outside India"
                        })
                    except Exception:
                        pass
        except Exception as e:
            print(f"dpdp_data_residency_kms error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — KMS Keys Outside Approved Regions", "KMS", "DPDP-R12-DATA-02",
        "KMS keys in non-India regions may be used to encrypt personal data stored outside "
        "approved jurisdictions, indicating cross-border data transfer.",
        80, "High", non_compliant,
        "Review KMS keys outside India regions. If they encrypt personal data, "
        "migrate to approved regions.", total)


def dpdp_data_residency_s3_replication(session, meta):
    """DPDP-R12-DATA-03 — S3 cross-region replication to foreign regions."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                repl = s3.get_bucket_replication(Bucket=b["Name"])
                rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
                for rule in rules:
                    if rule.get("Status") == "Enabled":
                        dest = rule.get("Destination", {})
                        dest_bucket = dest.get("Bucket", "")
                        # Try to determine destination region from bucket ARN
                        non_compliant.append({
                            "resource_name": b["Name"],
                            "destination": dest_bucket,
                            "note": "Active cross-region replication — verify destination is DPDP-compliant"
                        })
            except ClientError as e:
                if "ReplicationConfigurationNotFoundError" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_data_residency_s3_replication error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 Cross-Region Replication to Foreign Regions", "S3", "DPDP-R12-DATA-03",
        "S3 cross-region replication may transfer personal data to regions outside India, "
        "potentially violating Rule 12 cross-border restrictions.",
        80, "High", non_compliant,
        "Review S3 replication destinations. Ensure personal data is only replicated "
        "to approved India regions (ap-south-1, ap-south-2).", total)


def dpdp_data_residency_backup_copy(session, meta):
    """DPDP-R12-DATA-04 — Cross-region backup copy to foreign regions."""
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = len(plans) if plans else 1
        for plan in plans:
            try:
                detail = backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"])
                rules = detail.get("BackupPlan", {}).get("Rules", [])
                for rule in rules:
                    for copy in rule.get("CopyActions", []):
                        dest_arn = copy.get("DestinationBackupVaultArn", "")
                        # Check if destination is outside India
                        for region in APPROVED_REGIONS:
                            if region in dest_arn:
                                break
                        else:
                            if dest_arn:
                                non_compliant.append({
                                    "resource_name": plan.get("BackupPlanName", plan["BackupPlanId"]),
                                    "destination": dest_arn,
                                    "note": "Backup copy to non-India region"
                                })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_data_residency_backup_copy error: {e}")
    _update_meta(meta, "Backup", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Cross-Region Backup Copy to Foreign Regions", "Backup", "DPDP-R12-DATA-04",
        "Backup copies to regions outside India transfer personal data "
        "to potentially restricted jurisdictions under Rule 12.",
        80, "High", non_compliant,
        "Ensure backup copy destinations are within approved India regions "
        "unless cross-border transfer is explicitly permitted.", total)


def dpdp_data_residency_cloudtrail_logs(session, meta):
    """DPDP-R12-DATA-05 — CloudTrail logs stored outside approved regions."""
    ct = session.client("cloudtrail")
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        for trail in trails:
            bucket = trail.get("S3BucketName", "")
            if bucket:
                try:
                    location = s3.get_bucket_location(Bucket=bucket)
                    region = location.get("LocationConstraint") or "us-east-1"
                    if region not in APPROVED_REGIONS:
                        non_compliant.append({
                            "resource_name": trail["Name"],
                            "log_bucket": bucket,
                            "bucket_region": region,
                            "note": f"CloudTrail logs stored in {region} — outside approved regions"
                        })
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_data_residency_cloudtrail_logs error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — CloudTrail Logs Stored Outside Approved Regions", "CloudTrail", "DPDP-R12-DATA-05",
        "CloudTrail logs may contain personal data (user identifiers, IP addresses). "
        "Storing them outside India may violate Rule 12.",
        70, "Medium", non_compliant,
        "Ensure CloudTrail log S3 buckets are in approved India regions. "
        "Consider this when setting up multi-region trails.", total)



# ═══════════════════════════════════════════════════════════════════════════════
# 🏢 ORGANIZATIONS ENHANCED CHECKS (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_org_scps_configured(session, meta):
    """DPDP-R10-ORG-01 — Organizations SCPs must be configured."""
    org = session.client("organizations")
    non_compliant = []
    try:
        org.describe_organization()
        # If org exists, check for SCPs
        try:
            policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
            # Exclude the default FullAWSAccess policy
            custom_scps = [p for p in policies if p.get("Name") != "FullAWSAccess"]
            if not custom_scps:
                non_compliant.append({
                    "resource_name": "AWS Organizations",
                    "note": "No custom SCPs configured — no preventive guardrails"
                })
        except ClientError as e:
            if "PolicyTypeNotEnabledException" in str(e):
                non_compliant.append({
                    "resource_name": "AWS Organizations",
                    "note": "SCPs not enabled — no service control policies active"
                })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            non_compliant.append({
                "resource_name": "AWS Organizations",
                "note": "Not using Organizations — SCPs unavailable"
            })
        elif code == "AccessDeniedException":
            pass  # Can't check from member account
    except Exception as e:
        print(f"dpdp_org_scps_configured error: {e}")
    _update_meta(meta, "Organizations", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — SCPs Not Configured", "Organizations", "DPDP-R10-ORG-01",
        "Without Service Control Policies, there are no preventive guardrails preventing "
        "member accounts from accessing personal data in unauthorized ways.",
        80, "High", non_compliant,
        "Enable and configure SCPs to restrict data transfer outside approved regions, "
        "prevent disabling of security services, and enforce encryption.", 1)


def dpdp_org_security_services_delegated(session, meta):
    """DPDP-R10-ORG-02 — Security services should be delegated to security account."""
    org = session.client("organizations")
    non_compliant = []
    try:
        org.describe_organization()
        try:
            delegated = org.list_delegated_administrators().get("DelegatedAdministrators", [])
            if not delegated:
                non_compliant.append({
                    "resource_name": "AWS Organizations",
                    "note": "No delegated administrators — security services not centrally managed"
                })
        except Exception:
            pass
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            non_compliant.append({
                "resource_name": "AWS Organizations",
                "note": "Organizations not in use"
            })
        elif code == "AccessDeniedException":
            pass
    except Exception as e:
        print(f"dpdp_org_security_services_delegated error: {e}")
    _update_meta(meta, "Organizations", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Security Services Not Delegated", "Organizations", "DPDP-R10-ORG-02",
        "Without delegated security administration, security services like GuardDuty, "
        "SecurityHub, and Config are not centrally managed.",
        70, "Medium", non_compliant,
        "Delegate security services (GuardDuty, SecurityHub, Config, Macie) to a dedicated "
        "security account for centralized management.", 1)


def dpdp_org_member_security(session, meta):
    """DPDP-R10-ORG-03 — Member accounts should have security services enabled."""
    org = session.client("organizations")
    non_compliant = []
    try:
        org.describe_organization()
        try:
            accounts = org.list_accounts().get("Accounts", [])
            # Check if organization-wide services are configured
            enabled_services = org.list_aws_service_access_for_organization().get("EnabledServicePrincipals", [])
            service_names = [s.get("ServicePrincipal", "") for s in enabled_services]
            required_services = [
                "guardduty.amazonaws.com",
                "securityhub.amazonaws.com",
                "config.amazonaws.com"
            ]
            missing = [s for s in required_services if s not in service_names]
            if missing:
                non_compliant.append({
                    "resource_name": "AWS Organizations",
                    "missing_services": missing,
                    "note": f"Organization-wide access not enabled for: {', '.join(missing)}"
                })
        except Exception:
            pass
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            non_compliant.append({
                "resource_name": "AWS Organizations",
                "note": "Organizations not in use"
            })
        elif code == "AccessDeniedException":
            pass
    except Exception as e:
        print(f"dpdp_org_member_security error: {e}")
    _update_meta(meta, "Organizations", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Member Accounts Missing Security Services", "Organizations", "DPDP-R10-ORG-03",
        "Without organization-wide security service access, member accounts may not have "
        "GuardDuty, SecurityHub, or Config enabled for personal data protection.",
        70, "Medium", non_compliant,
        "Enable trusted access for GuardDuty, SecurityHub, and Config at the organization level. "
        "Deploy security services to all member accounts.", 1)



# ═══════════════════════════════════════════════════════════════════════════════
# 🔍 INSPECTOR ENHANCED CHECKS (4 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_inspector_ec2_scanning(session, meta):
    """DPDP-R10-INSP-01 — Inspector EC2 scanning must be enabled."""
    inspector = session.client("inspector2")
    non_compliant = []
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        status = inspector.batch_get_account_status(accountIds=[account_id])
        accounts = status.get("accounts", [])
        if accounts:
            resource_state = accounts[0].get("resourceState", {})
            ec2_state = resource_state.get("ec2", {}).get("status", "")
            if ec2_state != "ENABLED":
                non_compliant.append({
                    "resource_name": "Inspector EC2",
                    "status": ec2_state,
                    "note": "EC2 scanning not enabled"
                })
        else:
            non_compliant.append({
                "resource_name": "Inspector",
                "note": "Unable to determine Inspector EC2 scanning status"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ValidationException"):
            non_compliant.append({"resource_name": "Inspector", "note": "Inspector not enabled"})
    except Exception as e:
        print(f"dpdp_inspector_ec2_scanning error: {e}")
    _update_meta(meta, "Inspector", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Inspector EC2 Scanning Disabled", "Inspector", "DPDP-R10-INSP-01",
        "Without EC2 vulnerability scanning, instances processing personal data may have "
        "unpatched vulnerabilities exploitable by attackers.",
        80, "High", non_compliant,
        "Enable Amazon Inspector EC2 scanning for continuous vulnerability assessment.", 1)


def dpdp_inspector_ecr_scanning(session, meta):
    """DPDP-R10-INSP-02 — Inspector ECR scanning must be enabled."""
    inspector = session.client("inspector2")
    non_compliant = []
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        status = inspector.batch_get_account_status(accountIds=[account_id])
        accounts = status.get("accounts", [])
        if accounts:
            resource_state = accounts[0].get("resourceState", {})
            ecr_state = resource_state.get("ecr", {}).get("status", "")
            if ecr_state != "ENABLED":
                non_compliant.append({
                    "resource_name": "Inspector ECR",
                    "status": ecr_state,
                    "note": "ECR container image scanning not enabled"
                })
        else:
            non_compliant.append({
                "resource_name": "Inspector",
                "note": "Unable to determine Inspector ECR scanning status"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ValidationException"):
            non_compliant.append({"resource_name": "Inspector", "note": "Inspector not enabled"})
    except Exception as e:
        print(f"dpdp_inspector_ecr_scanning error: {e}")
    _update_meta(meta, "Inspector", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Inspector ECR Scanning Disabled", "Inspector", "DPDP-R10-INSP-02",
        "Without ECR scanning, container images deployed to ECS/EKS may contain vulnerabilities "
        "that could be exploited to access personal data.",
        80, "High", non_compliant,
        "Enable Amazon Inspector ECR scanning for all container image repositories.", 1)


def dpdp_inspector_lambda_scanning(session, meta):
    """DPDP-R10-INSP-03 — Inspector Lambda scanning must be enabled."""
    inspector = session.client("inspector2")
    non_compliant = []
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        status = inspector.batch_get_account_status(accountIds=[account_id])
        accounts = status.get("accounts", [])
        if accounts:
            resource_state = accounts[0].get("resourceState", {})
            lambda_state = resource_state.get("lambda", {}).get("status", "")
            if lambda_state != "ENABLED":
                non_compliant.append({
                    "resource_name": "Inspector Lambda",
                    "status": lambda_state,
                    "note": "Lambda function scanning not enabled"
                })
        else:
            non_compliant.append({
                "resource_name": "Inspector",
                "note": "Unable to determine Inspector Lambda scanning status"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ValidationException"):
            non_compliant.append({"resource_name": "Inspector", "note": "Inspector not enabled"})
    except Exception as e:
        print(f"dpdp_inspector_lambda_scanning error: {e}")
    _update_meta(meta, "Inspector", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Inspector Lambda Scanning Disabled", "Inspector", "DPDP-R10-INSP-03",
        "Without Lambda scanning, serverless functions processing personal data may have "
        "vulnerable dependencies that go undetected.",
        80, "High", non_compliant,
        "Enable Amazon Inspector Lambda scanning for all function code and layers.", 1)


def dpdp_inspector_critical_vulns(session, meta):
    """DPDP-R10-INSP-04 — Detect open critical vulnerabilities in Inspector."""
    inspector = session.client("inspector2")
    non_compliant = []
    try:
        findings = inspector.list_findings(
            filterCriteria={
                "severity": [{"comparison": "EQUALS", "value": "CRITICAL"}],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
            },
            maxResults=100
        ).get("findings", [])
        if findings:
            # Group by resource type
            resource_count = {}
            for f in findings:
                res_type = f.get("type", "Unknown")
                resource_count[res_type] = resource_count.get(res_type, 0) + 1
            non_compliant.append({
                "resource_name": "Inspector",
                "total_critical": len(findings),
                "by_type": resource_count,
                "note": f"{len(findings)} open CRITICAL vulnerabilities"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ValidationException"):
            pass  # Inspector not enabled — caught by other check
    except Exception as e:
        print(f"dpdp_inspector_critical_vulns error: {e}")
    _update_meta(meta, "Inspector", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Critical Vulnerabilities Open", "Inspector", "DPDP-R10-INSP-04",
        "Open critical vulnerabilities on resources processing personal data represent "
        "exploitable attack vectors that could lead to data breaches.",
        75, "Medium", non_compliant,
        "Patch all critical vulnerabilities within 48 hours. Prioritize resources "
        "processing personal data. Use SSM Patch Manager for automated patching.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🗄️ S3 ACCESS POINTS (2 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_s3_public_access_points(session, meta):
    """DPDP-R6-S3-08 — S3 Access Points must not allow public access."""
    s3control = session.client("s3control")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        aps = s3control.list_access_points(AccountId=account_id).get("AccessPointList", [])
        total = len(aps)
        for ap in aps:
            ap_name = ap.get("Name", "")
            try:
                detail = s3control.get_access_point(AccountId=account_id, Name=ap_name)
                public_config = detail.get("PublicAccessBlockConfiguration", {})
                if not all([
                    public_config.get("BlockPublicAcls"),
                    public_config.get("IgnorePublicAcls"),
                    public_config.get("BlockPublicPolicy"),
                    public_config.get("RestrictPublicBuckets")
                ]):
                    non_compliant.append({
                        "resource_name": ap_name,
                        "bucket": ap.get("Bucket", ""),
                        "note": "Access Point Block Public Access not fully enabled"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_public_access_points error: {e}")
    _update_meta(meta, "S3", max(total, 1), non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 Public Access Points", "S3", "DPDP-R6-S3-08",
        "S3 Access Points without Block Public Access can expose personal data "
        "via a secondary access path bypassing bucket-level controls.",
        80, "High", non_compliant,
        "Enable all four Block Public Access settings on every S3 Access Point.", max(total, 1))


def dpdp_s3_cross_account_access_points(session, meta):
    """DPDP-R6-S3-09 — Detect S3 Access Points shared cross-account."""
    s3control = session.client("s3control")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        aps = s3control.list_access_points(AccountId=account_id).get("AccessPointList", [])
        total = len(aps)
        for ap in aps:
            ap_name = ap.get("Name", "")
            try:
                policy_result = s3control.get_access_point_policy(
                    AccountId=account_id, Name=ap_name
                )
                policy_str = policy_result.get("Policy", "{}")
                doc = _json.loads(policy_str)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            if p == "*":
                                non_compliant.append({
                                    "resource_name": ap_name,
                                    "note": "Access Point policy has Principal:* — public"
                                })
                                break
                            elif "arn:aws:iam::" in str(p) and account_id not in str(p):
                                non_compliant.append({
                                    "resource_name": ap_name,
                                    "external_principal": p,
                                    "note": "Access Point shared cross-account"
                                })
                                break
            except ClientError as e:
                if "NoSuchAccessPointPolicy" in str(e):
                    pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_cross_account_access_points error: {e}")
    _update_meta(meta, "S3", max(total, 1), non_compliant, "High")
    return _result(
        "DPDP R2025 — S3 Cross-Account Access Points", "S3", "DPDP-R6-S3-09",
        "S3 Access Points with cross-account policies share personal data with external "
        "entities requiring documented data processor agreements under Rule 14.",
        80, "High", non_compliant,
        "Review Access Point policies for external principals. Ensure each is a documented "
        "data processor with DPDP-compliant contracts.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 📋 CLOUDTRAIL — Organization Trail (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_ct_organization_trail(session, meta):
    """DPDP-R7-CT-07 — CloudTrail Organization Trail must be configured."""
    ct = session.client("cloudtrail")
    non_compliant = []
    total = 0
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        total = len(trails) if trails else 1
        has_org_trail = any(t.get("IsOrganizationTrail") for t in trails)
        if not has_org_trail:
            non_compliant.append({
                "resource_name": "CloudTrail",
                "note": "No Organization Trail — member account activity not centrally logged"
            })
    except Exception as e:
        print(f"dpdp_ct_organization_trail error: {e}")
    _update_meta(meta, "CloudTrail", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — CloudTrail Organization Trail Configured", "CloudTrail", "DPDP-R7-CT-07",
        "Without an Organization Trail, API activity in member accounts is not centrally "
        "audited, leaving gaps in breach detection across the organization.",
        80, "High", non_compliant,
        "Create an Organization Trail from the management account to capture API activity "
        "across all member accounts.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 💾 BACKUP — Resource Coverage (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_backup_rds_not_covered(session, meta):
    """DPDP-R10-BKP-05 — RDS instances must be covered by AWS Backup plans."""
    rds = session.client("rds")
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        # Get all resources covered by backup plans
        covered_arns = set()
        try:
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            for plan in plans:
                try:
                    selections = backup.list_backup_selections(
                        BackupPlanId=plan["BackupPlanId"]
                    ).get("BackupSelectionsList", [])
                    for sel in selections:
                        try:
                            detail = backup.get_backup_selection(
                                BackupPlanId=plan["BackupPlanId"],
                                SelectionId=sel["SelectionId"]
                            )
                            resources = detail.get("BackupSelection", {}).get("Resources", [])
                            for r in resources:
                                if r == "*" or "rds" in r.lower():
                                    covered_arns.add("ALL_RDS")
                                    break
                                covered_arns.add(r)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        if "ALL_RDS" not in covered_arns:
            for db in instances:
                arn = db.get("DBInstanceArn", "")
                if arn not in covered_arns:
                    non_compliant.append({
                        "resource_name": db["DBInstanceIdentifier"],
                        "note": "RDS instance not covered by any AWS Backup plan"
                    })
    except Exception as e:
        print(f"dpdp_backup_rds_not_covered error: {e}")
    _update_meta(meta, "Backup", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — RDS Instances Not Covered by Backup Plans", "Backup", "DPDP-R10-BKP-05",
        "RDS instances without centralized backup plans may not have consistent recovery "
        "capability for personal data.",
        80, "High", non_compliant,
        "Add all RDS instances storing personal data to AWS Backup plans with appropriate "
        "retention and cross-region copy rules.", total)


def dpdp_backup_efs_not_covered(session, meta):
    """DPDP-R10-BKP-06 — EFS file systems must be covered by backup plans."""
    efs = session.client("efs")
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        filesystems = efs.describe_file_systems().get("FileSystems", [])
        total = len(filesystems)
        covered_arns = set()
        try:
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            for plan in plans:
                try:
                    selections = backup.list_backup_selections(
                        BackupPlanId=plan["BackupPlanId"]
                    ).get("BackupSelectionsList", [])
                    for sel in selections:
                        try:
                            detail = backup.get_backup_selection(
                                BackupPlanId=plan["BackupPlanId"],
                                SelectionId=sel["SelectionId"]
                            )
                            resources = detail.get("BackupSelection", {}).get("Resources", [])
                            for r in resources:
                                if r == "*" or "elasticfilesystem" in r.lower():
                                    covered_arns.add("ALL_EFS")
                                    break
                                covered_arns.add(r)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        if "ALL_EFS" not in covered_arns:
            for fs in filesystems:
                fs_arn = fs.get("FileSystemArn", "")
                if fs_arn not in covered_arns:
                    non_compliant.append({
                        "resource_name": fs["FileSystemId"],
                        "note": "EFS file system not covered by any AWS Backup plan"
                    })
    except Exception as e:
        print(f"dpdp_backup_efs_not_covered error: {e}")
    _update_meta(meta, "Backup", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — EFS File Systems Not Covered by Backup Plans", "Backup", "DPDP-R10-BKP-06",
        "EFS file systems without backup plans risk permanent loss of personal data "
        "stored in shared file systems.",
        80, "High", non_compliant,
        "Add all EFS file systems storing personal data to AWS Backup plans.", total)


def dpdp_backup_dynamodb_not_covered(session, meta):
    """DPDP-R10-BKP-07 — DynamoDB tables must be covered by backup plans."""
    ddb = session.client("dynamodb")
    backup = session.client("backup")
    non_compliant = []
    total = 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        covered_arns = set()
        try:
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            for plan in plans:
                try:
                    selections = backup.list_backup_selections(
                        BackupPlanId=plan["BackupPlanId"]
                    ).get("BackupSelectionsList", [])
                    for sel in selections:
                        try:
                            detail = backup.get_backup_selection(
                                BackupPlanId=plan["BackupPlanId"],
                                SelectionId=sel["SelectionId"]
                            )
                            resources = detail.get("BackupSelection", {}).get("Resources", [])
                            for r in resources:
                                if r == "*" or "dynamodb" in r.lower():
                                    covered_arns.add("ALL_DDB")
                                    break
                                covered_arns.add(r)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        if "ALL_DDB" not in covered_arns:
            account_id = session.client("sts").get_caller_identity()["Account"]
            region = session.region_name
            for t in tables:
                arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{t}"
                if arn not in covered_arns:
                    non_compliant.append({
                        "resource_name": t,
                        "note": "DynamoDB table not covered by any AWS Backup plan"
                    })
    except Exception as e:
        print(f"dpdp_backup_dynamodb_not_covered error: {e}")
    _update_meta(meta, "Backup", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — DynamoDB Tables Not Covered by Backup Plans", "Backup", "DPDP-R10-BKP-07",
        "DynamoDB tables without centralized backup plans rely only on PITR, which does not "
        "support cross-region or long-term retention requirements.",
        80, "High", non_compliant,
        "Add all DynamoDB tables storing personal data to AWS Backup plans with "
        "retention aligned to DPDP requirements.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🛡️ SECURITY HUB — Auto-Enable (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_securityhub_auto_enable(session, meta):
    """DPDP-R7-SH-04 — Security Hub auto-enable for new accounts."""
    sh = session.client("securityhub")
    non_compliant = []
    try:
        org_config = sh.describe_organization_configuration()
        if not org_config.get("AutoEnable"):
            non_compliant.append({
                "resource_name": "Security Hub",
                "note": "Auto-enable for new member accounts is disabled"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "SubscriptionRequiredException"):
            pass  # Not enabled or not org admin
        elif "not the delegated" in str(e).lower() or "not a member" in str(e).lower():
            pass  # Not the org admin account
        else:
            non_compliant.append({
                "resource_name": "Security Hub",
                "note": "Cannot determine auto-enable status — may not be org admin"
            })
    except Exception as e:
        print(f"dpdp_securityhub_auto_enable error: {e}")
    _update_meta(meta, "SecurityHub", 1, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Security Hub Auto-Enable Disabled", "SecurityHub", "DPDP-R7-SH-04",
        "Without auto-enable, new member accounts will not have Security Hub active, "
        "creating blind spots for personal data protection monitoring.",
        70, "Medium", non_compliant,
        "Enable auto-enable in Security Hub organization configuration so new accounts "
        "automatically get Security Hub with default standards.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🛡️ GUARDDUTY — Organization Deployment (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_guardduty_org_deployment(session, meta):
    """DPDP-R7-GD-06 — GuardDuty must be deployed across all org accounts."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if detectors:
            did = detectors[0]
            try:
                org_config = gd.describe_organization_configuration(DetectorId=did)
                if not org_config.get("AutoEnable"):
                    non_compliant.append({
                        "resource_name": "GuardDuty",
                        "note": "Organization-wide auto-enable is disabled — new accounts unprotected"
                    })
            except ClientError as e:
                if "not a GuardDuty delegated" in str(e).lower():
                    pass  # Not the delegated admin
                else:
                    non_compliant.append({
                        "resource_name": "GuardDuty",
                        "note": "Cannot verify org deployment — may not be delegated admin"
                    })
        else:
            non_compliant.append({
                "resource_name": "GuardDuty",
                "note": "GuardDuty not enabled in this region"
            })
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            non_compliant.append({"resource_name": "GuardDuty", "note": "Service not enabled"})
    except Exception as e:
        print(f"dpdp_guardduty_org_deployment error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Organization-Wide GuardDuty Deployment", "GuardDuty", "DPDP-R7-GD-06",
        "Without organization-wide GuardDuty deployment, member accounts processing personal data "
        "have no threat detection capability.",
        80, "High", non_compliant,
        "Enable GuardDuty auto-enable for all organization accounts from the delegated admin.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# ⚙️ AWS CONFIG — Organization Coverage (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_config_org_coverage(session, meta):
    """DPDP-R7-CFG-04 — AWS Config must be enabled across organization accounts."""
    org = session.client("organizations")
    non_compliant = []
    try:
        org.describe_organization()
        enabled_services = org.list_aws_service_access_for_organization().get(
            "EnabledServicePrincipals", []
        )
        service_names = [s.get("ServicePrincipal", "") for s in enabled_services]
        if "config.amazonaws.com" not in service_names:
            non_compliant.append({
                "resource_name": "AWS Config",
                "note": "Config not enabled as org-wide trusted service — member accounts may lack Config"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            pass  # No org — covered by org existence check
        elif code == "AccessDeniedException":
            pass  # Not management account
    except Exception as e:
        print(f"dpdp_config_org_coverage error: {e}")
    _update_meta(meta, "Config", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — AWS Config Not Enabled Across Organization", "Config", "DPDP-R7-CFG-04",
        "Without org-wide Config deployment, member accounts may not track configuration changes "
        "to resources storing personal data.",
        80, "High", non_compliant,
        "Enable AWS Config trusted access in Organizations and deploy Config "
        "to all member accounts via stacksets or delegated admin.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔍 OPENSEARCH CHECKS (3 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_opensearch_encryption_at_rest(session, meta):
    """DPDP-R6-OS-01 — OpenSearch encryption at rest must be enabled."""
    es = session.client("opensearch")
    non_compliant = []
    total = 0
    try:
        domains = es.list_domain_names().get("DomainNames", [])
        total = len(domains)
        for d in domains:
            try:
                config = es.describe_domain(DomainName=d["DomainName"])["DomainStatus"]
                enc = config.get("EncryptionAtRestOptions", {})
                if not enc.get("Enabled"):
                    non_compliant.append({
                        "resource_name": d["DomainName"],
                        "note": "Encryption at rest disabled"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_opensearch_encryption_at_rest error: {e}")
    _update_meta(meta, "OpenSearch", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — OpenSearch Encryption at Rest Disabled", "OpenSearch", "DPDP-R6-OS-01",
        "OpenSearch domains without encryption at rest leave indexed personal data "
        "unprotected on disk, violating Rule 6 security safeguards.",
        85, "High", non_compliant,
        "Enable encryption at rest with KMS CMK on all OpenSearch domains.", total)


def dpdp_opensearch_node_to_node(session, meta):
    """DPDP-R6-OS-02 — OpenSearch node-to-node encryption must be enabled."""
    es = session.client("opensearch")
    non_compliant = []
    total = 0
    try:
        domains = es.list_domain_names().get("DomainNames", [])
        total = len(domains)
        for d in domains:
            try:
                config = es.describe_domain(DomainName=d["DomainName"])["DomainStatus"]
                n2n = config.get("NodeToNodeEncryptionOptions", {})
                if not n2n.get("Enabled"):
                    non_compliant.append({
                        "resource_name": d["DomainName"],
                        "note": "Node-to-node encryption disabled"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_opensearch_node_to_node error: {e}")
    _update_meta(meta, "OpenSearch", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — OpenSearch Node-to-Node Encryption Disabled", "OpenSearch", "DPDP-R6-OS-02",
        "Without node-to-node encryption, data in transit between OpenSearch cluster nodes "
        "is unencrypted, exposing personal data to network interception.",
        80, "High", non_compliant,
        "Enable node-to-node encryption on all OpenSearch domains.", total)


def dpdp_opensearch_https_enforcement(session, meta):
    """DPDP-R6-OS-03 — OpenSearch must enforce HTTPS."""
    es = session.client("opensearch")
    non_compliant = []
    total = 0
    try:
        domains = es.list_domain_names().get("DomainNames", [])
        total = len(domains)
        for d in domains:
            try:
                config = es.describe_domain(DomainName=d["DomainName"])["DomainStatus"]
                domain_ep = config.get("DomainEndpointOptions", {})
                if not domain_ep.get("EnforceHTTPS"):
                    non_compliant.append({
                        "resource_name": d["DomainName"],
                        "note": "HTTPS not enforced — HTTP access allowed"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_opensearch_https_enforcement error: {e}")
    _update_meta(meta, "OpenSearch", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — OpenSearch HTTPS Enforcement Disabled", "OpenSearch", "DPDP-R6-OS-03",
        "Without HTTPS enforcement, OpenSearch domains accept unencrypted HTTP connections, "
        "exposing personal data queries and results in transit.",
        85, "High", non_compliant,
        "Enable EnforceHTTPS with TLS 1.2 minimum on all OpenSearch domains.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 📊 REDSHIFT (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_redshift_encryption(session, meta):
    """DPDP-R6-RS-01 — Redshift clusters must be encrypted."""
    rs = session.client("redshift")
    non_compliant = []
    total = 0
    try:
        clusters = rs.describe_clusters().get("Clusters", [])
        total = len(clusters)
        for c in clusters:
            if not c.get("Encrypted"):
                non_compliant.append({
                    "resource_name": c["ClusterIdentifier"],
                    "note": "Redshift cluster not encrypted at rest"
                })
    except Exception as e:
        print(f"dpdp_redshift_encryption error: {e}")
    _update_meta(meta, "Redshift", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — Redshift Encryption Disabled", "Redshift", "DPDP-R6-RS-01",
        "Unencrypted Redshift clusters leave data warehouse contents including personal data "
        "unprotected at rest, violating Rule 6.",
        85, "High", non_compliant,
        "Enable encryption on all Redshift clusters. Use KMS CMK for key management control.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 📁 EFS — Backup Policy (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_efs_backup_policy(session, meta):
    """DPDP-R10-EFS-01 — EFS backup policy must be enabled."""
    efs = session.client("efs")
    non_compliant = []
    total = 0
    try:
        filesystems = efs.describe_file_systems().get("FileSystems", [])
        total = len(filesystems)
        for fs in filesystems:
            try:
                bp = efs.describe_backup_policy(FileSystemId=fs["FileSystemId"])
                status = bp.get("BackupPolicy", {}).get("Status", "")
                if status != "ENABLED":
                    non_compliant.append({
                        "resource_name": fs["FileSystemId"],
                        "status": status,
                        "note": "EFS automatic backup policy not enabled"
                    })
            except ClientError as e:
                if "PolicyNotFound" in str(e):
                    non_compliant.append({
                        "resource_name": fs["FileSystemId"],
                        "note": "No backup policy configured"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_efs_backup_policy error: {e}")
    _update_meta(meta, "EFS", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — EFS Backup Policy Disabled", "EFS", "DPDP-R10-EFS-01",
        "EFS file systems without automatic backup policies risk permanent loss of "
        "personal data stored in shared file systems.",
        65, "Medium", non_compliant,
        "Enable automatic backup policy on all EFS file systems storing personal data.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# ⚡ LAMBDA — Deprecated Runtimes (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_lambda_deprecated_runtime(session, meta):
    """DPDP-R6-LAMBDA-01 — Lambda functions must not use deprecated runtimes."""
    lam = session.client("lambda")
    non_compliant = []
    total = 0
    DEPRECATED_RUNTIMES = [
        "python2.7", "python3.6", "python3.7",
        "nodejs10.x", "nodejs12.x", "nodejs14.x",
        "dotnetcore2.1", "dotnetcore3.1",
        "ruby2.5", "ruby2.7",
        "java8", "go1.x",
    ]
    try:
        functions = lam.list_functions().get("Functions", [])
        total = len(functions)
        for fn in functions:
            runtime = fn.get("Runtime", "")
            if runtime in DEPRECATED_RUNTIMES:
                non_compliant.append({
                    "resource_name": fn["FunctionName"],
                    "runtime": runtime,
                    "note": f"Using deprecated runtime: {runtime}"
                })
    except Exception as e:
        print(f"dpdp_lambda_deprecated_runtime error: {e}")
    _update_meta(meta, "Lambda", total, non_compliant, "Medium")
    return _result(
        "DPDP R2025 — Lambda Deprecated Runtime Versions", "Lambda", "DPDP-R6-LAMBDA-01",
        "Lambda functions on deprecated runtimes no longer receive security patches, "
        "exposing personal data processing to known vulnerabilities.",
        70, "Medium", non_compliant,
        "Upgrade Lambda functions to supported runtime versions. "
        "Deprecated runtimes do not receive security patches.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🌐 API GATEWAY — Logging (2 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_apigateway_access_logging(session, meta):
    """DPDP-R6-API-01 — API Gateway access logging must be enabled."""
    apigw = session.client("apigateway")
    non_compliant = []
    total = 0
    try:
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            try:
                stages = apigw.get_stages(restApiId=api["id"]).get("item", [])
                for stage in stages:
                    total += 1
                    access_log = stage.get("accessLogSettings", {})
                    if not access_log.get("destinationArn"):
                        non_compliant.append({
                            "resource_name": f"{api['name']}/{stage['stageName']}",
                            "note": "Access logging not configured"
                        })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_apigateway_access_logging error: {e}")
    _update_meta(meta, "APIGateway", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — API Gateway Access Logging Disabled", "APIGateway", "DPDP-R6-API-01",
        "Without access logging, API requests accessing personal data cannot be audited "
        "for breach detection under Rule 7.",
        70, "Medium", non_compliant,
        "Enable access logging on all API Gateway stages with CloudWatch Logs destination.", max(total, 1))


def dpdp_apigateway_execution_logging(session, meta):
    """DPDP-R6-API-02 — API Gateway execution logging must be enabled."""
    apigw = session.client("apigateway")
    non_compliant = []
    total = 0
    try:
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            try:
                stages = apigw.get_stages(restApiId=api["id"]).get("item", [])
                for stage in stages:
                    total += 1
                    method_settings = stage.get("methodSettings", {})
                    # Check default (*/*) settings
                    default = method_settings.get("*/*", {})
                    logging_level = default.get("loggingLevel", "OFF")
                    if logging_level == "OFF":
                        non_compliant.append({
                            "resource_name": f"{api['name']}/{stage['stageName']}",
                            "note": "Execution logging disabled"
                        })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_apigateway_execution_logging error: {e}")
    _update_meta(meta, "APIGateway", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — API Gateway Execution Logging Disabled", "APIGateway", "DPDP-R6-API-02",
        "Without execution logging, API errors and integration failures that may affect "
        "personal data processing are invisible.",
        65, "Medium", non_compliant,
        "Enable execution logging (INFO or ERROR level) on all API Gateway stages.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 🧱 WAF — Logging (1 check)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_waf_logging_disabled(session, meta):
    """DPDP-R6-WAF-01 — WAF logging must be enabled."""
    waf = session.client("wafv2")
    non_compliant = []
    total = 0
    try:
        # Check REGIONAL scope
        acls = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        total = len(acls)
        for acl in acls:
            try:
                log_config = waf.get_logging_configuration(
                    ResourceArn=acl["ARN"]
                )
                # If we get here, logging is configured
            except ClientError as e:
                if "WAFNonexistentItemException" in str(e):
                    non_compliant.append({
                        "resource_name": acl["Name"],
                        "note": "WAF logging not configured"
                    })
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_waf_logging_disabled error: {e}")
    _update_meta(meta, "WAF", max(total, 1), non_compliant, "Medium")
    return _result(
        "DPDP R2025 — WAF Logging Disabled", "WAF", "DPDP-R6-WAF-01",
        "WAF without logging cannot provide evidence of blocked attacks or detect "
        "attack patterns targeting personal data endpoints.",
        70, "Medium", non_compliant,
        "Enable logging on all WAF WebACLs. Send logs to S3, CloudWatch, or Kinesis Firehose.", max(total, 1))


# ═══════════════════════════════════════════════════════════════════════════════
# 🤝 DATA PROCESSOR — External Access Inventory (2 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_processor_external_data_access(session, meta):
    """DPDP-R14-PROC-04 — Inventory of external accounts with data access."""
    iam = session.client("iam")
    non_compliant = []
    total = 0
    external_accounts = set()
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        for role in roles:
            try:
                doc = role.get("AssumeRolePolicyDocument", {})
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]
                        for p in aws_p:
                            if "arn:aws:iam::" in str(p) and account_id not in str(p):
                                # Extract account ID from ARN
                                parts = str(p).split(":")
                                if len(parts) >= 5:
                                    ext_acct = parts[4]
                                    external_accounts.add(ext_acct)
            except Exception:
                pass
        if external_accounts:
            non_compliant.append({
                "resource_name": "IAM Trust Policies",
                "external_account_count": len(external_accounts),
                "accounts": list(external_accounts)[:20],
                "note": f"{len(external_accounts)} external accounts have trust relationships — verify all are documented data processors"
            })
    except Exception as e:
        print(f"dpdp_processor_external_data_access error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — External AWS Accounts with Data Access Inventory", "IAM", "DPDP-R14-PROC-04",
        "Rule 14 requires documentation of all data processors. This check identifies all "
        "external AWS accounts with trust relationships into your account.",
        80, "High", non_compliant,
        "Maintain a documented inventory of all external accounts with access. Verify each "
        "has a DPDP-compliant data processing agreement.", total)


def dpdp_processor_external_kms_access(session, meta):
    """DPDP-R14-PROC-05 — External principals using customer-managed KMS keys."""
    kms_client = session.client("kms")
    non_compliant = []
    total = 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        paginator = kms_client.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                try:
                    key_meta = kms_client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if key_meta.get("KeyManager") == "AWS":
                        continue
                    if key_meta.get("KeyState") != "Enabled":
                        continue
                    total += 1
                    policy = kms_client.get_key_policy(KeyId=key["KeyId"], PolicyName="default")
                    doc = _json.loads(policy["Policy"])
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                            if isinstance(aws_p, str):
                                aws_p = [aws_p]
                            for p in aws_p:
                                if "arn:aws:iam::" in str(p) and account_id not in str(p):
                                    non_compliant.append({
                                        "resource_name": key_meta["KeyId"],
                                        "external_principal": p,
                                        "note": "External principal can use this KMS key to decrypt personal data"
                                    })
                                    break
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_processor_external_kms_access error: {e}")
    _update_meta(meta, "KMS", total, non_compliant, "High")
    return _result(
        "DPDP R2025 — External Principals Using Customer Managed KMS Keys", "KMS", "DPDP-R14-PROC-05",
        "External principals with KMS key access can decrypt personal data encrypted by your account. "
        "Rule 14 requires these to be documented data processors.",
        80, "High", non_compliant,
        "Review all KMS key policies granting external access. Ensure each external principal "
        "is a documented data processor.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🏢 SIGNIFICANT DATA FIDUCIARY — Multi-Region Coverage (2 checks)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_sdf_macie_all_regions(session, meta):
    """DPDP-R10-SDF-04 — Macie must be enabled across all regions for PII discovery."""
    macie = session.client("macie2")
    non_compliant = []
    try:
        status = macie.get_macie_session()
        if status.get("status") != "ENABLED":
            non_compliant.append({
                "resource_name": f"Macie ({session.region_name})",
                "note": f"Macie not enabled in {session.region_name}"
            })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "ForbiddenException"):
            non_compliant.append({
                "resource_name": f"Macie ({session.region_name})",
                "note": f"Macie not enabled in {session.region_name}"
            })
    except Exception as e:
        print(f"dpdp_sdf_macie_all_regions error: {e}")
    _update_meta(meta, "Macie", 1, non_compliant, "High")
    return _result(
        "DPDP R2025 — Macie Not Enabled Across All Regions", "Macie", "DPDP-R10-SDF-04",
        "Rule 10 requires SDFs to know where personal data resides. Macie must be enabled "
        "in all regions to discover PII in S3 buckets.",
        80, "High", non_compliant,
        "Enable Amazon Macie in all active regions. Configure automated discovery jobs "
        "for S3 buckets storing personal data.", 1)


def dpdp_sdf_security_services_coverage(session, meta):
    """DPDP-R10-SDF-05 — All security services must be enabled in current region."""
    non_compliant = []
    region = session.region_name
    missing_services = []

    # Check GuardDuty
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            missing_services.append("GuardDuty")
    except ClientError as e:
        if "SubscriptionRequiredException" in str(e):
            missing_services.append("GuardDuty")
    except Exception:
        pass

    # Check Security Hub
    try:
        sh = session.client("securityhub")
        sh.get_enabled_standards()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "SubscriptionRequiredException"):
            missing_services.append("SecurityHub")
    except Exception:
        pass

    # Check Inspector
    try:
        inspector = session.client("inspector2")
        account_id = session.client("sts").get_caller_identity()["Account"]
        status = inspector.batch_get_account_status(accountIds=[account_id])
        accounts = status.get("accounts", [])
        if accounts:
            state = accounts[0].get("state", {}).get("status", "")
            if state != "ENABLED":
                missing_services.append("Inspector")
        else:
            missing_services.append("Inspector")
    except ClientError:
        missing_services.append("Inspector")
    except Exception:
        pass

    # Check Macie
    try:
        macie = session.client("macie2")
        macie_status = macie.get_macie_session()
        if macie_status.get("status") != "ENABLED":
            missing_services.append("Macie")
    except ClientError:
        missing_services.append("Macie")
    except Exception:
        pass

    # Check Config
    try:
        cfg = session.client("config")
        recorders = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        if not any(r.get("recording") for r in recorders):
            missing_services.append("Config")
    except ClientError:
        missing_services.append("Config")
    except Exception:
        pass

    if missing_services:
        non_compliant.append({
            "resource_name": f"Region: {region}",
            "missing_services": missing_services,
            "note": f"Missing: {', '.join(missing_services)}"
        })

    _update_meta(meta, "Multi-Service", 5, non_compliant, "High")
    return _result(
        "DPDP R2025 — Security Services Coverage Incomplete", "Multi-Service", "DPDP-R10-SDF-05",
        "Rule 10 requires SDFs to maintain comprehensive security posture. "
        "Not all security services (GuardDuty, SecurityHub, Inspector, Macie, Config) are active.",
        85, "High", non_compliant,
        "Enable all five security services in every active region: GuardDuty, SecurityHub, "
        "Inspector, Macie, and AWS Config.", 5)
