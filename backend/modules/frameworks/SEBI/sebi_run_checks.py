"""
SEBI CSCRF 2024 Unified Runner — All Checks
Total: 118 core + 10 enhanced = 128 checks
Functions: Governance → Identify → Protect → Detect → Respond → Recover → Data Localization → Enhanced
"""

# ═══════════════════════════════════════════════════════════════════════════════
# PROTECT Checks (43 functions)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.SEBI.sebi_protect_checks import (
    # PR.AA — IAM / Access Control (Global)
    sebi_root_access_keys_present,
    sebi_inactive_iam_users,
    sebi_unused_access_keys,
    sebi_iam_admin_access_users,
    sebi_wildcard_iam_policies,
    sebi_console_without_mfa_enforcement,
    sebi_access_key_rotation,
    sebi_iam_roles_external_trust,
    # PR.AA — Application Auth (Regional)
    sebi_cognito_mfa_config,
    sebi_api_gateway_no_auth,
    sebi_cloudfront_oai,
    # PR.DS — Data Security (Global - S3)
    sebi_s3_encryption,
    sebi_s3_ssl_enforcement,
    sebi_s3_bucket_public,
    sebi_s3_public_access_block_account,
    # PR.DS — Data Security (Regional - RDS, DynamoDB, EFS, Redshift)
    sebi_rds_encryption,
    sebi_dynamodb_encryption,
    sebi_efs_encryption,
    sebi_redshift_encryption,
    sebi_rds_ssl_enforcement,
    sebi_alb_https_only,
    sebi_kms_key_rotation,
    sebi_kms_pending_deletion,
    # PR.DS — Secrets (Regional)
    sebi_secrets_rotation,
    sebi_lambda_env_secrets,
    # PR.AC — Network Access Control (Regional)
    sebi_sg_unrestricted_ingress,
    sebi_sg_ssh_rdp_open,
    sebi_default_sg_open,
    sebi_public_subnet_igw,
    sebi_opensearch_public,
    sebi_redshift_public,
    sebi_elasticache_no_vpc,
    sebi_ec2_public_ip_private_subnet,
    sebi_nacl_permissive,
    sebi_route_tables_igw_exposure,
    # PR.PT — Protective Technology (Regional)
    sebi_lb_without_waf,
    sebi_shield_advanced,
    sebi_waf_rate_limiting,
    sebi_cloudfront_waf,
    sebi_alb_deletion_protection,
    sebi_rds_deletion_protection,
    sebi_s3_object_lock,
    # PR.PT — Instance Security (Regional)
    sebi_ec2_imdsv2_not_enforced,
)

# ═══════════════════════════════════════════════════════════════════════════════
# DETECT Checks (19 functions)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.SEBI.sebi_detect_checks import (
    # DE.CM — GuardDuty (Regional)
    sebi_guardduty_s3_protection,
    sebi_guardduty_eks_protection,
    sebi_guardduty_malware_protection,
    sebi_guardduty_unresolved_findings,
    # DE.CM — Security Hub (Regional)
    sebi_securityhub_enabled,
    sebi_securityhub_standards,
    # DE.CM — AWS Config (Regional)
    sebi_config_enabled,
    sebi_config_all_resources,
    sebi_config_delivery_channel,
    sebi_config_aggregator,
    # DE.AE — Monitoring & Alerting (Regional)
    sebi_cloudwatch_log_retention,
    sebi_eventbridge_security_rules,
    sebi_cloudwatch_alarms_critical,
    # DE.AE — CloudTrail (Global)
    sebi_cloudtrail_log_validation,
    sebi_cloudtrail_kms_encryption,
    sebi_cloudtrail_data_events,
    # DE.CM — Logging (Regional)
    sebi_rds_audit_logging,
    sebi_elb_access_logging,
    sebi_opensearch_audit_logging,
)

# ═══════════════════════════════════════════════════════════════════════════════
# RECOVER + RESPOND Checks (20 functions)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.SEBI.sebi_recover_checks import (
    # RC — Backup & Recovery (Regional)
    sebi_rds_backup_enabled,
    sebi_rds_multi_az,
    sebi_dynamodb_pitr,
    sebi_backup_vault_exists,
    sebi_backup_vault_lock,
    sebi_backup_cross_region,
    sebi_ec2_backup_coverage,
    sebi_rds_backup_coverage,
    sebi_s3_versioning,
    sebi_efs_backup,
    sebi_rds_snapshot_retention,
    sebi_aurora_global_db,
    # RS — Respond (Regional)
    sebi_sns_security_topics,
    sebi_cloudwatch_alarm_actions,
    sebi_guardduty_export_config,
    sebi_eventbridge_securityhub,
    sebi_lambda_dlq,
    sebi_cloudtrail_insights,
    sebi_detective_enabled,
    sebi_cloudwatch_logs_insights,
)

# ═══════════════════════════════════════════════════════════════════════════════
# IDENTIFY + GOVERNANCE + DATA LOCALIZATION Checks (25 functions)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.SEBI.sebi_identify_governance_checks import (
    # GV — Governance (Global)
    sebi_organizations_enabled,
    sebi_scps_configured,
    sebi_cross_account_trust_audit,
    sebi_access_analyzer_enabled,
    sebi_cloudtrail_org_trail,
    # ID.AM — Asset Management (Global - S3)
    sebi_s3_inventory_config,
    sebi_s3_data_classification,
    # ID.AM — Asset Management (Regional)
    sebi_ec2_ssm_managed,
    sebi_unattached_ebs,
    sebi_unassociated_eips,
    sebi_dynamodb_classification,
    # ID.RA — Risk Assessment (Regional)
    sebi_inspector_enabled,
    sebi_securityhub_findings_summary,
    sebi_securityhub_critical_findings,
    sebi_macie_enabled,
    sebi_public_amis,
    sebi_public_ebs_snapshots,
    # GV — Governance (Regional)
    sebi_lambda_third_party_layers,
    sebi_config_tag_rules,
    sebi_trusted_advisor_checks,
    # DL — Data Localization (Global - S3)
    sebi_s3_india_localization,
    sebi_s3_replication_non_india,
    # DL — Data Localization (Regional)
    sebi_rds_india_localization,
    sebi_dynamodb_india_localization,
    sebi_rds_replicas_non_india,
)

# ═══════════════════════════════════════════════════════════════════════════════
# ENHANCED Checks (10 functions)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.SEBI.sebi_enhanced_checks import (
    sebi_org_delegated_admin,
    sebi_cross_account_data_exposure,
    sebi_advanced_kms_assessment,
    sebi_advanced_secrets_manager,
    sebi_securityhub_compliance_score,
    sebi_ransomware_readiness,
    sebi_enhanced_data_localization,
    sebi_vulnerability_aging,
    sebi_attack_path_analysis,
    sebi_cyber_resilience_score,
)


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CHECKS — Run once per account
# ═══════════════════════════════════════════════════════════════════════════════


def run_sebi_global_checks(session, scan_meta_data):
    """
    All global checks: IAM, S3, CloudTrail, Organizations, CloudFront.
    Run once per account (not per region).
    """
    checks = [
        ("Scanning SEBI Governance & Organizations...", [
            (sebi_organizations_enabled, [session, scan_meta_data]),
            (sebi_scps_configured, [session, scan_meta_data]),
            (sebi_cross_account_trust_audit, [session, scan_meta_data]),
            (sebi_access_analyzer_enabled, [session, scan_meta_data]),
            (sebi_cloudtrail_org_trail, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI IAM Access & Authentication...", [
            (sebi_root_access_keys_present, [session, scan_meta_data]),
            (sebi_inactive_iam_users, [session, scan_meta_data]),
            (sebi_unused_access_keys, [session, scan_meta_data]),
            (sebi_iam_admin_access_users, [session, scan_meta_data]),
            (sebi_wildcard_iam_policies, [session, scan_meta_data]),
            (sebi_console_without_mfa_enforcement, [session, scan_meta_data]),
            (sebi_access_key_rotation, [session, scan_meta_data]),
            (sebi_iam_roles_external_trust, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI S3 Data Security...", [
            (sebi_s3_encryption, [session, scan_meta_data]),
            (sebi_s3_ssl_enforcement, [session, scan_meta_data]),
            (sebi_s3_bucket_public, [session, scan_meta_data]),
            (sebi_s3_public_access_block_account, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI S3 Asset Management...", [
            (sebi_s3_inventory_config, [session, scan_meta_data]),
            (sebi_s3_data_classification, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI CloudTrail Anomaly Detection...", [
            (sebi_cloudtrail_log_validation, [session, scan_meta_data]),
            (sebi_cloudtrail_kms_encryption, [session, scan_meta_data]),
            (sebi_cloudtrail_data_events, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Data Localization (S3)...", [
            (sebi_s3_india_localization, [session, scan_meta_data]),
            (sebi_s3_replication_non_india, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI CloudFront Security...", [
            (sebi_cloudfront_oai, [session, scan_meta_data]),
            (sebi_cloudfront_waf, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Enhanced Global Assessments...", [
            (sebi_org_delegated_admin, [session, scan_meta_data]),
            (sebi_cross_account_data_exposure, [session, scan_meta_data]),
            (sebi_advanced_kms_assessment, [session, scan_meta_data]),
            (sebi_enhanced_data_localization, [session, scan_meta_data]),
            (sebi_cyber_resilience_score, [session, scan_meta_data]),
        ]),
    ]

    results = []
    for category_msg, fns in checks:
        print(category_msg)
        for fn, args in fns:
            try:
                results.append(fn(*args))
            except Exception as e:
                print(f"  Error: {fn.__name__}: {e}")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL CHECKS — Run per region
# ═══════════════════════════════════════════════════════════════════════════════


def run_sebi_regional_checks(session, scan_meta_data):
    """
    All regional checks: EC2, RDS, VPC, GuardDuty, DynamoDB, Lambda, ELB, etc.
    Run per-region via framework_scan.py.
    """
    region = session.region_name or "unknown"

    REGION_NAMES = {
        "us-east-1": "N. Virginia", "us-east-2": "Ohio", "us-west-1": "N. California",
        "us-west-2": "Oregon", "ap-south-1": "Mumbai", "ap-south-2": "Hyderabad",
        "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney", "ap-northeast-1": "Tokyo",
        "ap-northeast-2": "Seoul", "ap-northeast-3": "Osaka", "eu-west-1": "Ireland",
        "eu-west-2": "London", "eu-west-3": "Paris", "eu-central-1": "Frankfurt",
        "eu-north-1": "Stockholm", "sa-east-1": "Sao Paulo", "ca-central-1": "Canada",
        "me-south-1": "Bahrain", "af-south-1": "Cape Town",
    }
    region_name = REGION_NAMES.get(region, region)

    checks = [
        ("Scanning SEBI Network Access Controls...", [
            (sebi_sg_unrestricted_ingress, [session, scan_meta_data]),
            (sebi_sg_ssh_rdp_open, [session, scan_meta_data]),
            (sebi_default_sg_open, [session, scan_meta_data]),
            (sebi_public_subnet_igw, [session, scan_meta_data]),
            (sebi_opensearch_public, [session, scan_meta_data]),
            (sebi_redshift_public, [session, scan_meta_data]),
            (sebi_elasticache_no_vpc, [session, scan_meta_data]),
            (sebi_ec2_public_ip_private_subnet, [session, scan_meta_data]),
            (sebi_nacl_permissive, [session, scan_meta_data]),
            (sebi_route_tables_igw_exposure, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Protective Technology...", [
            (sebi_lb_without_waf, [session, scan_meta_data]),
            (sebi_shield_advanced, [session, scan_meta_data]),
            (sebi_waf_rate_limiting, [session, scan_meta_data]),
            (sebi_alb_deletion_protection, [session, scan_meta_data]),
            (sebi_rds_deletion_protection, [session, scan_meta_data]),
            (sebi_s3_object_lock, [session, scan_meta_data]),
            (sebi_ec2_imdsv2_not_enforced, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Regional Data Security...", [
            (sebi_rds_encryption, [session, scan_meta_data]),
            (sebi_dynamodb_encryption, [session, scan_meta_data]),
            (sebi_efs_encryption, [session, scan_meta_data]),
            (sebi_redshift_encryption, [session, scan_meta_data]),
            (sebi_rds_ssl_enforcement, [session, scan_meta_data]),
            (sebi_alb_https_only, [session, scan_meta_data]),
            (sebi_kms_key_rotation, [session, scan_meta_data]),
            (sebi_kms_pending_deletion, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Secrets Management...", [
            (sebi_secrets_rotation, [session, scan_meta_data]),
            (sebi_lambda_env_secrets, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Application Authentication...", [
            (sebi_cognito_mfa_config, [session, scan_meta_data]),
            (sebi_api_gateway_no_auth, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI GuardDuty Threat Detection...", [
            (sebi_guardduty_s3_protection, [session, scan_meta_data]),
            (sebi_guardduty_eks_protection, [session, scan_meta_data]),
            (sebi_guardduty_malware_protection, [session, scan_meta_data]),
            (sebi_guardduty_unresolved_findings, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Security Hub & Config...", [
            (sebi_securityhub_enabled, [session, scan_meta_data]),
            (sebi_securityhub_standards, [session, scan_meta_data]),
            (sebi_config_enabled, [session, scan_meta_data]),
            (sebi_config_all_resources, [session, scan_meta_data]),
            (sebi_config_delivery_channel, [session, scan_meta_data]),
            (sebi_config_aggregator, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Monitoring & Alerting...", [
            (sebi_cloudwatch_log_retention, [session, scan_meta_data]),
            (sebi_eventbridge_security_rules, [session, scan_meta_data]),
            (sebi_cloudwatch_alarms_critical, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Audit Logging...", [
            (sebi_rds_audit_logging, [session, scan_meta_data]),
            (sebi_elb_access_logging, [session, scan_meta_data]),
            (sebi_opensearch_audit_logging, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Incident Response...", [
            (sebi_sns_security_topics, [session, scan_meta_data]),
            (sebi_cloudwatch_alarm_actions, [session, scan_meta_data]),
            (sebi_guardduty_export_config, [session, scan_meta_data]),
            (sebi_eventbridge_securityhub, [session, scan_meta_data]),
            (sebi_lambda_dlq, [session, scan_meta_data]),
            (sebi_cloudtrail_insights, [session, scan_meta_data]),
            (sebi_detective_enabled, [session, scan_meta_data]),
            (sebi_cloudwatch_logs_insights, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Backup & Recovery...", [
            (sebi_rds_backup_enabled, [session, scan_meta_data]),
            (sebi_rds_multi_az, [session, scan_meta_data]),
            (sebi_dynamodb_pitr, [session, scan_meta_data]),
            (sebi_backup_vault_exists, [session, scan_meta_data]),
            (sebi_backup_vault_lock, [session, scan_meta_data]),
            (sebi_backup_cross_region, [session, scan_meta_data]),
            (sebi_ec2_backup_coverage, [session, scan_meta_data]),
            (sebi_rds_backup_coverage, [session, scan_meta_data]),
            (sebi_s3_versioning, [session, scan_meta_data]),
            (sebi_efs_backup, [session, scan_meta_data]),
            (sebi_rds_snapshot_retention, [session, scan_meta_data]),
            (sebi_aurora_global_db, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Asset Management (Regional)...", [
            (sebi_ec2_ssm_managed, [session, scan_meta_data]),
            (sebi_unattached_ebs, [session, scan_meta_data]),
            (sebi_unassociated_eips, [session, scan_meta_data]),
            (sebi_dynamodb_classification, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Risk Assessment...", [
            (sebi_inspector_enabled, [session, scan_meta_data]),
            (sebi_securityhub_findings_summary, [session, scan_meta_data]),
            (sebi_securityhub_critical_findings, [session, scan_meta_data]),
            (sebi_macie_enabled, [session, scan_meta_data]),
            (sebi_public_amis, [session, scan_meta_data]),
            (sebi_public_ebs_snapshots, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Governance (Regional)...", [
            (sebi_lambda_third_party_layers, [session, scan_meta_data]),
            (sebi_config_tag_rules, [session, scan_meta_data]),
            (sebi_trusted_advisor_checks, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Data Localization (Regional)...", [
            (sebi_rds_india_localization, [session, scan_meta_data]),
            (sebi_dynamodb_india_localization, [session, scan_meta_data]),
            (sebi_rds_replicas_non_india, [session, scan_meta_data]),
        ]),
        ("Scanning SEBI Enhanced Regional Assessments...", [
            (sebi_advanced_secrets_manager, [session, scan_meta_data]),
            (sebi_securityhub_compliance_score, [session, scan_meta_data]),
            (sebi_ransomware_readiness, [session, scan_meta_data]),
            (sebi_vulnerability_aging, [session, scan_meta_data]),
            (sebi_attack_path_analysis, [session, scan_meta_data]),
        ]),
    ]

    results = []
    for category_msg, fns in checks:
        print(f"{category_msg} [{region_name}]")
        for fn, args in fns:
            try:
                results.append(fn(*args))
            except Exception as e:
                print(f"  Error: {fn.__name__}: {e}")

    for r in results:
        r["region"] = region

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════════


def run_sebi_checks(session, scan_meta_data):
    """
    Full SEBI CSCRF scan — runs all global + regional checks.
    128 checks total (118 core + 10 enhanced).
    """
    results = []
    results.extend(run_sebi_global_checks(session, scan_meta_data))
    results.extend(run_sebi_regional_checks(session, scan_meta_data))
    return results


async def sebi_scan_function(data):
    """Entry point for direct API calls — full SEBI CSCRF scan."""
    from utils.framework_scan import run_framework_scan
    return run_framework_scan(data, framework="sebi")
