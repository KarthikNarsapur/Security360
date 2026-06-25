"""
DPDP Unified Runner — All Checks (Act 2023 + Rules 2025 + Enhanced)
Orchestrates all DPDP checks from a single entry point.

Total: 148 checks
  - DPDP Act 2023:    27 checks (dpdp_checks.py)
  - DPDP Rules 2025:  29 checks (dpdp_rules_2025_checks.py)
  - DPDP Enhanced:    92 checks (dpdp_enhanced_checks.py)
"""

# ═══════════════════════════════════════════════════════════════════════════════
# DPDP Act 2023 Imports
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.DPDP.dpdp_checks import (
    # Data Layer — Global (S3)
    dpdp_s3_public_bucket,
    dpdp_s3_encryption,
    dpdp_s3_versioning,
    dpdp_s3_access_logging,
    dpdp_s3_lifecycle,
    # Data Layer — Regional (RDS, DynamoDB, EFS)
    dpdp_rds_public_access,
    dpdp_rds_encryption,
    dpdp_rds_backup_retention,
    dpdp_dynamodb_pitr,
    dpdp_efs_encryption,
    # IAM Layer — Global
    dpdp_root_mfa,
    dpdp_iam_user_mfa,
    dpdp_access_key_age,
    dpdp_wildcard_policy,
    dpdp_password_policy,
    # Network Layer — Regional
    dpdp_security_group_open_ports,
    dpdp_vpc_flow_logs,
    # Infrastructure Layer — Regional
    dpdp_ec2_public_ip,
    dpdp_ebs_encryption,
    # Logging & Monitoring
    dpdp_cloudtrail_enabled,
    dpdp_guardduty_enabled,
    dpdp_config_enabled,
    dpdp_cloudwatch_log_retention,
    # Secrets Management — Regional
    dpdp_secrets_manager_usage,
    dpdp_lambda_env_secrets,
    # Application Layer — Regional
    dpdp_lambda_public_access,
    # Alerting — Regional
    dpdp_sns_topic_exists,
)

# ═══════════════════════════════════════════════════════════════════════════════
# DPDP Rules 2025 Imports
# ═══════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════
# DPDP Enhanced Checks Imports (92 checks)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.frameworks.DPDP.dpdp_enhanced_checks import (
    # S3 Enhanced
    dpdp_s3_account_level_bpa,
    dpdp_s3_bucket_policy_wildcard,
    dpdp_s3_bucket_policy_cross_account,
    dpdp_s3_lifecycle_configured,
    dpdp_s3_cmk_encryption,
    dpdp_s3_ownership_controls,
    dpdp_s3_inventory_disabled,
    # CloudTrail Enhanced
    dpdp_ct_multi_region,
    dpdp_ct_log_validation,
    dpdp_ct_kms_encryption,
    dpdp_ct_all_regions,
    dpdp_ct_management_events,
    dpdp_ct_data_events,
    # KMS Enhanced
    dpdp_kms_scheduled_deletion,
    dpdp_kms_no_rotation,
    dpdp_kms_external_principals,
    dpdp_kms_unused_keys,
    # IAM Enhanced
    dpdp_iam_root_access_keys,
    dpdp_iam_inactive_users,
    dpdp_iam_unused_access_keys,
    dpdp_iam_admin_access_users,
    dpdp_iam_cross_account_trust,
    dpdp_iam_anonymous_federated,
    dpdp_iam_password_rotation,
    dpdp_iam_console_without_mfa,
    # EC2 Enhanced
    dpdp_ec2_imdsv2,
    dpdp_ec2_instance_profile_overprivileged,
    dpdp_ec2_unused_security_groups,
    dpdp_ec2_default_sg_open,
    dpdp_ec2_public_amis,
    dpdp_ec2_public_snapshots,
    # RDS Enhanced
    dpdp_rds_enhanced_monitoring,
    dpdp_rds_performance_insights,
    dpdp_rds_multi_az,
    dpdp_rds_public_snapshots,
    dpdp_rds_cross_account_snapshots,
    # DynamoDB Enhanced
    dpdp_dynamodb_cmk,
    dpdp_dynamodb_streams_disabled,
    dpdp_dynamodb_cross_account_access,
    # AWS Config Enhanced
    dpdp_config_all_resources,
    dpdp_config_delivery_channel,
    dpdp_config_aggregator,
    # GuardDuty Enhanced
    dpdp_guardduty_malware_protection,
    dpdp_guardduty_s3_protection,
    dpdp_guardduty_eks_protection,
    dpdp_guardduty_high_findings,
    dpdp_guardduty_critical_findings,
    # Security Hub Enhanced
    dpdp_securityhub_critical_findings,
    dpdp_securityhub_high_findings,
    dpdp_securityhub_standards,
    # Backup Enhanced
    dpdp_backup_vault_encryption,
    dpdp_backup_cross_region_missing,
    dpdp_backup_vault_lock,
    dpdp_backup_recovery_retention,
    # Network Security
    dpdp_net_internet_facing_lb,
    dpdp_net_internet_facing_opensearch,
    dpdp_net_internet_facing_redshift,
    dpdp_net_default_nacl_permissive,
    dpdp_net_route_tables_igw,
    # Secrets Manager Enhanced
    dpdp_secrets_old,
    dpdp_secrets_no_rotation_schedule,
    dpdp_secrets_unused,
    # Data Residency / Cross-Border
    dpdp_data_residency_resources,
    dpdp_data_residency_kms,
    dpdp_data_residency_s3_replication,
    dpdp_data_residency_backup_copy,
    dpdp_data_residency_cloudtrail_logs,
    # Organizations Enhanced
    dpdp_org_scps_configured,
    dpdp_org_security_services_delegated,
    dpdp_org_member_security,
    # Inspector Enhanced
    dpdp_inspector_ec2_scanning,
    dpdp_inspector_ecr_scanning,
    dpdp_inspector_lambda_scanning,
    dpdp_inspector_critical_vulns,
    # S3 Access Points
    dpdp_s3_public_access_points,
    dpdp_s3_cross_account_access_points,
    # CloudTrail Organization
    dpdp_ct_organization_trail,
    # Backup Resource Coverage
    dpdp_backup_rds_not_covered,
    dpdp_backup_efs_not_covered,
    dpdp_backup_dynamodb_not_covered,
    # Security Hub Auto-Enable
    dpdp_securityhub_auto_enable,
    # GuardDuty Organization
    dpdp_guardduty_org_deployment,
    # Config Organization
    dpdp_config_org_coverage,
    # OpenSearch
    dpdp_opensearch_encryption_at_rest,
    dpdp_opensearch_node_to_node,
    dpdp_opensearch_https_enforcement,
    # Redshift
    dpdp_redshift_encryption,
    # EFS Backup
    dpdp_efs_backup_policy,
    # Lambda Deprecated Runtimes
    dpdp_lambda_deprecated_runtime,
    # API Gateway Logging
    dpdp_apigateway_access_logging,
    dpdp_apigateway_execution_logging,
    # WAF Logging
    dpdp_waf_logging_disabled,
    # Data Processor External Access
    dpdp_processor_external_data_access,
    dpdp_processor_external_kms_access,
    # SDF Multi-Region Coverage
    dpdp_sdf_macie_all_regions,
    dpdp_sdf_security_services_coverage,
)


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CHECKS — Run once per account
# ═══════════════════════════════════════════════════════════════════════════════


def run_dpdp_global_checks(session, scan_meta_data):
    """
    All global checks: S3, IAM, CloudTrail, Organizations.
    Run once per account (not per region).
    """
    iam = session.client("iam")
    users = iam.list_users().get("Users", [])

    # Checks grouped by scan category (printed to terminal + WebSocket)
    checks = [
        ("Scanning S3 Security & Exposure...", [
            (dpdp_s3_public_bucket, [session, scan_meta_data]),
            (dpdp_s3_encryption, [session, scan_meta_data]),
            (dpdp_s3_versioning, [session, scan_meta_data]),
            (dpdp_s3_access_logging, [session, scan_meta_data]),
            (dpdp_s3_lifecycle, [session, scan_meta_data]),
        ]),
        ("Scanning IAM Security & Privilege Analysis...", [
            (dpdp_root_mfa, [session, scan_meta_data]),
            (dpdp_iam_user_mfa, [session, scan_meta_data, users, iam]),
            (dpdp_access_key_age, [session, scan_meta_data, users, iam]),
            (dpdp_wildcard_policy, [session, scan_meta_data, iam]),
            (dpdp_password_policy, [session, scan_meta_data]),
        ]),
        ("Scanning CloudTrail Governance...", [
            (dpdp_cloudtrail_enabled, [session, scan_meta_data]),
        ]),
        ("Scanning Organizations Governance...", [
            (dpdp_r10_multi_account_org, [session, scan_meta_data]),
        ]),
        ("Scanning Cross-Account Access...", [
            (dpdp_r14_cross_account_access, [session, scan_meta_data]),
            (dpdp_r14_s3_cross_account_policies, [session, scan_meta_data]),
        ]),
        ("Scanning Cross-Border Data Transfer...", [
            (dpdp_r12_s3_replication_regions, [session, scan_meta_data]),
        ]),
        ("Scanning Data Residency...", [
            (dpdp_data_residency_s3_replication, [session, scan_meta_data]),
            (dpdp_data_residency_cloudtrail_logs, [session, scan_meta_data]),
        ]),
        ("Scanning Data Classification...", [
            (dpdp_r4_data_classification_tagging, [session, scan_meta_data]),
            (dpdp_r5_s3_intelligent_tiering, [session, scan_meta_data]),
        ]),
        ("Scanning S3 Access Points...", [
            (dpdp_s3_public_access_points, [session, scan_meta_data]),
            (dpdp_s3_cross_account_access_points, [session, scan_meta_data]),
        ]),
        ("Scanning CloudTrail Organization Trail...", [
            (dpdp_ct_organization_trail, [session, scan_meta_data]),
        ]),
        ("Scanning AWS Config Organization Compliance...", [
            (dpdp_config_org_coverage, [session, scan_meta_data]),
        ]),
        ("Scanning Data Processor Inventory...", [
            (dpdp_processor_external_data_access, [session, scan_meta_data]),
        ]),
        ("Scanning S3 Public Exposure & Security Controls...", [
            (dpdp_s3_account_level_bpa, [session, scan_meta_data]),
            (dpdp_s3_bucket_policy_wildcard, [session, scan_meta_data]),
            (dpdp_s3_bucket_policy_cross_account, [session, scan_meta_data]),
            (dpdp_s3_lifecycle_configured, [session, scan_meta_data]),
            (dpdp_s3_cmk_encryption, [session, scan_meta_data]),
            (dpdp_s3_ownership_controls, [session, scan_meta_data]),
            (dpdp_s3_inventory_disabled, [session, scan_meta_data]),
            (dpdp_r6_s3_ssl_enforcement, [session, scan_meta_data]),
            (dpdp_r8_s3_object_lock, [session, scan_meta_data]),
        ]),
        ("Scanning IAM Advanced Security Review...", [
            (dpdp_iam_root_access_keys, [session, scan_meta_data]),
            (dpdp_iam_inactive_users, [session, scan_meta_data]),
            (dpdp_iam_unused_access_keys, [session, scan_meta_data]),
            (dpdp_iam_admin_access_users, [session, scan_meta_data]),
            (dpdp_iam_cross_account_trust, [session, scan_meta_data]),
            (dpdp_iam_anonymous_federated, [session, scan_meta_data]),
            (dpdp_iam_password_rotation, [session, scan_meta_data]),
            (dpdp_iam_console_without_mfa, [session, scan_meta_data]),
        ]),
        ("Scanning Organization-Level Compliance Controls...", [
            (dpdp_org_scps_configured, [session, scan_meta_data]),
            (dpdp_org_security_services_delegated, [session, scan_meta_data]),
            (dpdp_org_member_security, [session, scan_meta_data]),
            (dpdp_ct_multi_region, [session, scan_meta_data]),
            (dpdp_ct_log_validation, [session, scan_meta_data]),
            (dpdp_ct_kms_encryption, [session, scan_meta_data]),
            (dpdp_ct_all_regions, [session, scan_meta_data]),
            (dpdp_ct_management_events, [session, scan_meta_data]),
            (dpdp_ct_data_events, [session, scan_meta_data]),
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


def run_dpdp_regional_checks(session, scan_meta_data):
    """
    All regional checks: EC2, RDS, VPC, GuardDuty, DynamoDB, Lambda, etc.
    Run per-region via framework_scan.py.
    """
    region = session.region_name or "unknown"

    # Region code → friendly name only
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

    # Checks grouped by scan category
    checks = [
        ("Scanning RDS Security & Compliance...", [
            (dpdp_rds_public_access, [session, scan_meta_data]),
            (dpdp_rds_encryption, [session, scan_meta_data]),
            (dpdp_rds_backup_retention, [session, scan_meta_data]),
        ]),
        ("Scanning DynamoDB Security...", [
            (dpdp_dynamodb_pitr, [session, scan_meta_data]),
        ]),
        ("Scanning EFS Security...", [
            (dpdp_efs_encryption, [session, scan_meta_data]),
        ]),
        ("Scanning Network Security...", [
            (dpdp_security_group_open_ports, [session, scan_meta_data]),
            (dpdp_vpc_flow_logs, [session, scan_meta_data]),
        ]),
        ("Scanning EC2 Security...", [
            (dpdp_ec2_public_ip, [session, scan_meta_data]),
            (dpdp_ebs_encryption, [session, scan_meta_data]),
            (dpdp_ec2_imdsv2, [session, scan_meta_data]),
            (dpdp_ec2_instance_profile_overprivileged, [session, scan_meta_data]),
            (dpdp_ec2_unused_security_groups, [session, scan_meta_data]),
            (dpdp_ec2_default_sg_open, [session, scan_meta_data]),
            (dpdp_ec2_public_amis, [session, scan_meta_data]),
            (dpdp_ec2_public_snapshots, [session, scan_meta_data]),
        ]),
        ("Scanning Threat Detection...", [
            (dpdp_guardduty_enabled, [session, scan_meta_data]),
            (dpdp_config_enabled, [session, scan_meta_data]),
        ]),
        ("Scanning Logging & Monitoring...", [
            (dpdp_cloudwatch_log_retention, [session, scan_meta_data]),
            (dpdp_r6_one_year_log_retention, [session, scan_meta_data]),
        ]),
        ("Scanning Secrets Management...", [
            (dpdp_secrets_manager_usage, [session, scan_meta_data]),
            (dpdp_lambda_env_secrets, [session, scan_meta_data]),
            (dpdp_secrets_old, [session, scan_meta_data]),
            (dpdp_secrets_no_rotation_schedule, [session, scan_meta_data]),
            (dpdp_secrets_unused, [session, scan_meta_data]),
        ]),
        ("Scanning Lambda Security...", [
            (dpdp_lambda_public_access, [session, scan_meta_data]),
            (dpdp_r14_lambda_third_party_layers, [session, scan_meta_data]),
        ]),
        ("Scanning Alerting & Incident Response...", [
            (dpdp_sns_topic_exists, [session, scan_meta_data]),
        ]),
        ("Scanning API Gateway Security...", [
            (dpdp_r5_api_gateway_auth, [session, scan_meta_data]),
            (dpdp_apigateway_access_logging, [session, scan_meta_data]),
            (dpdp_apigateway_execution_logging, [session, scan_meta_data]),
        ]),
        ("Scanning KMS & Encryption...", [
            (dpdp_r6_kms_key_rotation, [session, scan_meta_data]),
            (dpdp_kms_scheduled_deletion, [session, scan_meta_data]),
            (dpdp_kms_no_rotation, [session, scan_meta_data]),
            (dpdp_kms_external_principals, [session, scan_meta_data]),
            (dpdp_kms_unused_keys, [session, scan_meta_data]),
        ]),
        ("Scanning WAF Protection...", [
            (dpdp_r6_waf_protection, [session, scan_meta_data]),
            (dpdp_waf_logging_disabled, [session, scan_meta_data]),
        ]),
        ("Scanning IAM Access Analyzer...", [
            (dpdp_r6_iam_access_analyzer, [session, scan_meta_data]),
        ]),
        ("Scanning Breach Notification Readiness...", [
            (dpdp_r7_eventbridge_rules, [session, scan_meta_data]),
            (dpdp_r7_securityhub_enabled, [session, scan_meta_data]),
            (dpdp_r7_cloudwatch_alarms, [session, scan_meta_data]),
            (dpdp_r7_macie_enabled, [session, scan_meta_data]),
        ]),
        ("Scanning Data Retention Compliance...", [
            (dpdp_r8_rds_deletion_protection, [session, scan_meta_data]),
            (dpdp_r8_dynamodb_ttl, [session, scan_meta_data]),
        ]),
        ("Scanning Children's Data Protection...", [
            (dpdp_r9_cognito_age_verification, [session, scan_meta_data]),
        ]),
        ("Scanning Backup & Recovery...", [
            (dpdp_r10_backup_cross_region, [session, scan_meta_data]),
            (dpdp_backup_vault_encryption, [session, scan_meta_data]),
            (dpdp_backup_cross_region_missing, [session, scan_meta_data]),
            (dpdp_backup_vault_lock, [session, scan_meta_data]),
            (dpdp_backup_recovery_retention, [session, scan_meta_data]),
        ]),
        ("Scanning Amazon Inspector Coverage...", [
            (dpdp_r10_inspector_enabled, [session, scan_meta_data]),
            (dpdp_inspector_ec2_scanning, [session, scan_meta_data]),
            (dpdp_inspector_ecr_scanning, [session, scan_meta_data]),
            (dpdp_inspector_lambda_scanning, [session, scan_meta_data]),
            (dpdp_inspector_critical_vulns, [session, scan_meta_data]),
        ]),
        ("Scanning Cross-Border Data Movement...", [
            (dpdp_r12_rds_cross_region_replicas, [session, scan_meta_data]),
            (dpdp_r12_dynamodb_global_tables, [session, scan_meta_data]),
            (dpdp_data_residency_resources, [session, scan_meta_data]),
            (dpdp_data_residency_kms, [session, scan_meta_data]),
            (dpdp_data_residency_backup_copy, [session, scan_meta_data]),
        ]),
        ("Scanning Data Processor Security...", [
            (dpdp_processor_external_kms_access, [session, scan_meta_data]),
        ]),
        ("Scanning AWS Config Compliance...", [
            (dpdp_config_all_resources, [session, scan_meta_data]),
            (dpdp_config_delivery_channel, [session, scan_meta_data]),
            (dpdp_config_aggregator, [session, scan_meta_data]),
        ]),
        ("Scanning GuardDuty Coverage...", [
            (dpdp_guardduty_malware_protection, [session, scan_meta_data]),
            (dpdp_guardduty_s3_protection, [session, scan_meta_data]),
            (dpdp_guardduty_eks_protection, [session, scan_meta_data]),
            (dpdp_guardduty_high_findings, [session, scan_meta_data]),
            (dpdp_guardduty_critical_findings, [session, scan_meta_data]),
            (dpdp_guardduty_org_deployment, [session, scan_meta_data]),
        ]),
        ("Scanning Security Hub Compliance...", [
            (dpdp_securityhub_critical_findings, [session, scan_meta_data]),
            (dpdp_securityhub_high_findings, [session, scan_meta_data]),
            (dpdp_securityhub_standards, [session, scan_meta_data]),
            (dpdp_securityhub_auto_enable, [session, scan_meta_data]),
        ]),
        ("Scanning Data Residency Validation...", [
            (dpdp_r4_rds_data_classification, [session, scan_meta_data]),
            (dpdp_r4_dynamodb_data_classification, [session, scan_meta_data]),
        ]),
        ("Scanning Backup Coverage Assessment...", [
            (dpdp_backup_rds_not_covered, [session, scan_meta_data]),
            (dpdp_backup_efs_not_covered, [session, scan_meta_data]),
            (dpdp_backup_dynamodb_not_covered, [session, scan_meta_data]),
        ]),
        ("Scanning OpenSearch Security...", [
            (dpdp_opensearch_encryption_at_rest, [session, scan_meta_data]),
            (dpdp_opensearch_node_to_node, [session, scan_meta_data]),
            (dpdp_opensearch_https_enforcement, [session, scan_meta_data]),
        ]),
        ("Scanning Redshift Security...", [
            (dpdp_redshift_encryption, [session, scan_meta_data]),
            (dpdp_net_internet_facing_redshift, [session, scan_meta_data]),
        ]),
        ("Scanning Runtime & Version Compliance (Lambda)...", [
            (dpdp_lambda_deprecated_runtime, [session, scan_meta_data]),
        ]),
        ("Scanning Sensitive Data Flow (SDF) Coverage...", [
            (dpdp_sdf_macie_all_regions, [session, scan_meta_data]),
            (dpdp_sdf_security_services_coverage, [session, scan_meta_data]),
            (dpdp_net_internet_facing_lb, [session, scan_meta_data]),
            (dpdp_net_internet_facing_opensearch, [session, scan_meta_data]),
            (dpdp_net_default_nacl_permissive, [session, scan_meta_data]),
            (dpdp_net_route_tables_igw, [session, scan_meta_data]),
            (dpdp_efs_backup_policy, [session, scan_meta_data]),
            (dpdp_rds_enhanced_monitoring, [session, scan_meta_data]),
            (dpdp_rds_performance_insights, [session, scan_meta_data]),
            (dpdp_rds_multi_az, [session, scan_meta_data]),
            (dpdp_rds_public_snapshots, [session, scan_meta_data]),
            (dpdp_rds_cross_account_snapshots, [session, scan_meta_data]),
            (dpdp_r6_rds_audit_logging, [session, scan_meta_data]),
            (dpdp_r6_rds_ssl_enforcement, [session, scan_meta_data]),
            (dpdp_dynamodb_cmk, [session, scan_meta_data]),
            (dpdp_dynamodb_streams_disabled, [session, scan_meta_data]),
            (dpdp_dynamodb_cross_account_access, [session, scan_meta_data]),
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

    # Tag all with actual region
    for r in results:
        r["region"] = region

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════════


def run_dpdp_checks(session, scan_meta_data):
    """
    Full DPDP scan — runs all global + regional checks for current session.
    148 checks total (Act 2023 + Rules 2025 + Enhanced).
    """
    results = []
    results.extend(run_dpdp_global_checks(session, scan_meta_data))
    results.extend(run_dpdp_regional_checks(session, scan_meta_data))
    return results


async def dpdp_scan_function(data):
    """Entry point for direct API calls — full DPDP scan."""
    from utils.framework_scan import run_framework_scan
    return run_framework_scan(data, framework="dpdp")
