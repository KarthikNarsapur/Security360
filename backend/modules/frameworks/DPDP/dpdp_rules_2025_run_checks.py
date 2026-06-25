"""
DPDP Rules 2025 — Runner
Orchestrates all Rule-specific checks (global + regional).
Integrates with the existing framework_scan.py infrastructure.
"""

from modules.frameworks.DPDP.dpdp_rules_2025_checks import (
    # Rule 3/4 — Notice & Consent (Data Classification)
    dpdp_r4_data_classification_tagging,
    dpdp_r4_rds_data_classification,
    dpdp_r4_dynamodb_data_classification,
    # Rule 5 — Rights of Data Principal
    dpdp_r5_s3_intelligent_tiering,
    dpdp_r5_api_gateway_auth,
    # Rule 6 — Security Safeguards (Enhanced)
    dpdp_r6_kms_key_rotation,
    dpdp_r6_rds_audit_logging,
    dpdp_r6_one_year_log_retention,
    dpdp_r6_s3_ssl_enforcement,
    dpdp_r6_rds_ssl_enforcement,
    dpdp_r6_waf_protection,
    dpdp_r6_iam_access_analyzer,
    # Rule 7 — Breach Notification (72-hour readiness)
    dpdp_r7_eventbridge_rules,
    dpdp_r7_securityhub_enabled,
    dpdp_r7_cloudwatch_alarms,
    dpdp_r7_macie_enabled,
    # Rule 8 — Data Retention & Erasure
    dpdp_r8_s3_object_lock,
    dpdp_r8_rds_deletion_protection,
    dpdp_r8_dynamodb_ttl,
    # Rule 9 — Children's Data Protection
    dpdp_r9_cognito_age_verification,
    # Rule 10 — Significant Data Fiduciary
    dpdp_r10_backup_cross_region,
    dpdp_r10_inspector_enabled,
    dpdp_r10_multi_account_org,
    # Rule 12 — Cross-Border Data Transfer
    dpdp_r12_s3_replication_regions,
    dpdp_r12_rds_cross_region_replicas,
    dpdp_r12_dynamodb_global_tables,
    # Rule 14 — Data Processor Obligations
    dpdp_r14_cross_account_access,
    dpdp_r14_s3_cross_account_policies,
    dpdp_r14_lambda_third_party_layers,
)


def run_dpdp_rules_2025_global_checks(session, scan_meta_data):
    """
    Global checks for DPDP Rules 2025.
    Run once per account — covers S3, IAM, Organizations.
    """
    results = []

    # Rule 3/4 — Data Classification (S3 is global)
    results.append(dpdp_r4_data_classification_tagging(session, scan_meta_data))

    # Rule 5 — Data Accessibility
    results.append(dpdp_r5_s3_intelligent_tiering(session, scan_meta_data))

    # Rule 6 — Security Safeguards (Global: S3 SSL, IAM)
    results.append(dpdp_r6_s3_ssl_enforcement(session, scan_meta_data))

    # Rule 8 — Erasure (S3 Object Lock)
    results.append(dpdp_r8_s3_object_lock(session, scan_meta_data))

    # Rule 10 — SDF (Organizations)
    results.append(dpdp_r10_multi_account_org(session, scan_meta_data))

    # Rule 12 — Cross-Border (S3 Replication)
    results.append(dpdp_r12_s3_replication_regions(session, scan_meta_data))

    # Rule 14 — Data Processors (IAM cross-account, S3 policies)
    results.append(dpdp_r14_cross_account_access(session, scan_meta_data))
    results.append(dpdp_r14_s3_cross_account_policies(session, scan_meta_data))

    return results


def run_dpdp_rules_2025_regional_checks(session, scan_meta_data):
    """
    Regional checks for DPDP Rules 2025.
    Run per-region — covers RDS, DynamoDB, Lambda, WAF, EventBridge, etc.
    """
    region = session.region_name or "unknown"
    results = []

    # Rule 3/4 — Data Classification (Regional)
    results.append(dpdp_r4_rds_data_classification(session, scan_meta_data))
    results.append(dpdp_r4_dynamodb_data_classification(session, scan_meta_data))

    # Rule 5 — Rights (API Gateway)
    results.append(dpdp_r5_api_gateway_auth(session, scan_meta_data))

    # Rule 6 — Security Safeguards (Regional)
    results.append(dpdp_r6_kms_key_rotation(session, scan_meta_data))
    results.append(dpdp_r6_rds_audit_logging(session, scan_meta_data))
    results.append(dpdp_r6_one_year_log_retention(session, scan_meta_data))
    results.append(dpdp_r6_rds_ssl_enforcement(session, scan_meta_data))
    results.append(dpdp_r6_waf_protection(session, scan_meta_data))
    results.append(dpdp_r6_iam_access_analyzer(session, scan_meta_data))

    # Rule 7 — Breach Notification (Regional)
    results.append(dpdp_r7_eventbridge_rules(session, scan_meta_data))
    results.append(dpdp_r7_securityhub_enabled(session, scan_meta_data))
    results.append(dpdp_r7_cloudwatch_alarms(session, scan_meta_data))
    results.append(dpdp_r7_macie_enabled(session, scan_meta_data))

    # Rule 8 — Erasure (Regional)
    results.append(dpdp_r8_rds_deletion_protection(session, scan_meta_data))
    results.append(dpdp_r8_dynamodb_ttl(session, scan_meta_data))

    # Rule 9 — Children's Data
    results.append(dpdp_r9_cognito_age_verification(session, scan_meta_data))

    # Rule 10 — SDF (Regional)
    results.append(dpdp_r10_backup_cross_region(session, scan_meta_data))
    results.append(dpdp_r10_inspector_enabled(session, scan_meta_data))

    # Rule 12 — Cross-Border (Regional)
    results.append(dpdp_r12_rds_cross_region_replicas(session, scan_meta_data))
    results.append(dpdp_r12_dynamodb_global_tables(session, scan_meta_data))

    # Rule 14 — Data Processors (Regional)
    results.append(dpdp_r14_lambda_third_party_layers(session, scan_meta_data))

    # Tag all with actual region
    for r in results:
        r["region"] = region

    return results


def run_dpdp_rules_2025_checks(session, scan_meta_data):
    """
    Legacy entry point — runs both global + regional for current session region.
    """
    results = []
    results.extend(run_dpdp_rules_2025_global_checks(session, scan_meta_data))
    results.extend(run_dpdp_rules_2025_regional_checks(session, scan_meta_data))
    return results


async def dpdp_rules_2025_scan_function(data):
    """Entry point for direct API calls."""
    from utils.framework_scan import run_framework_scan
    return run_framework_scan(data, framework="dpdp_rules_2025")
