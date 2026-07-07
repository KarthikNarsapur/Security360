"""
RBI CSF — Unified Runner
Orchestrates all RBI CSF checks: existing (migrated) + expanded checks.

Registered in framework_scan.py as "rbi" with "hybrid" mode.
Total: ~100 implemented checks across 5 check files.
"""

from modules.frameworks.RBI_CSF.rbi_csf_existing_checks import (
    rbi_data_localization,
    rbi_public_s3_buckets,
    rbi_privileged_users_without_mfa,
    rbi_unencrypted_rds,
    rbi_cloudtrail_audit_logs,
    rbi_open_security_groups,
    rbi_rds_backup_disabled,
)

from modules.frameworks.RBI_CSF.rbi_csf_global_checks import (
    rbi_iam_root_secured,
    rbi_iam_password_policy,
    rbi_iam_password_reuse,
    rbi_iam_access_key_rotation,
    rbi_iam_wildcard_permissions,
    rbi_iam_admin_minimized,
    rbi_iam_access_analyzer,
    rbi_iam_cross_account_trust,
    rbi_s3_ssl_enforcement,
    rbi_s3_bucket_policy_wildcard,
    rbi_s3_versioning,
    rbi_s3_logging,
    rbi_s3_encryption_kms,
    rbi_ct_kms_encryption,
    rbi_ct_data_events,
    rbi_ct_insights,
    rbi_dr_s3_replication,
    rbi_gov_conformance_packs,
    rbi_gov_config_recorder,
)

from modules.frameworks.RBI_CSF.rbi_csf_regional_checks import (
    rbi_kms_rotation,
    rbi_kms_disabled_pending,
    rbi_kms_key_policy,
    rbi_soc_guardduty,
    rbi_soc_guardduty_s3,
    rbi_soc_securityhub,
    rbi_soc_cw_alarms,
    rbi_net_vpc_flow_logs,
    rbi_net_waf_alb,
    rbi_rds_not_public,
    rbi_rds_deletion_protection,
    rbi_rds_multi_az,
    rbi_rds_india_region,
    rbi_secrets_rotation,
    rbi_backup_vault_encryption,
    rbi_ir_eventbridge_guardduty,
    rbi_ir_incident_plans,
    rbi_api_authorization,
    rbi_api_access_logging,
    rbi_api_acm_expiry,
    rbi_ebs_encryption,
    rbi_ebs_default_encryption,
    rbi_log_retention,
)

from modules.frameworks.RBI_CSF.rbi_csf_soc_monitoring_checks import (
    rbi_soc_guardduty_malware,
    rbi_soc_guardduty_rds,
    rbi_soc_guardduty_all_plans,
    rbi_soc_macie,
    rbi_soc_inspector,
    rbi_soc_sns_actions,
    rbi_soc_mf_root_login,
    rbi_soc_mf_unauthorized_api,
    rbi_soc_mf_iam_changes,
    rbi_soc_mf_sg_changes,
    rbi_soc_mf_kms_changes,
    rbi_soc_mf_cloudtrail_changes,
    rbi_soc_mf_config_changes,
    rbi_soc_mf_console_failures,
    rbi_soc_mf_s3_policy_changes,
    rbi_vul_lambda_deprecated,
    rbi_vul_ecr_scan_on_push,
    rbi_vul_ecr_immutable,
    rbi_vul_ssm_managed,
    rbi_log_cw_encryption,
    rbi_log_trail_protected,
    rbi_log_api_gateway,
)

from modules.frameworks.RBI_CSF.rbi_csf_bfsi_checks import (
    rbi_pay_keys_inventory,
    rbi_pay_key_rotation,
    rbi_nfw_deployed,
    rbi_nfw_rule_groups,
    rbi_fwm_policies,
    rbi_shield_subscription,
    rbi_shield_protections,
    rbi_identity_center,
    rbi_verified_access,
    rbi_mq_encryption,
    rbi_mq_not_public,
    rbi_msk_encryption,
    rbi_msk_auth,
    rbi_opensearch_fgac,
    rbi_opensearch_audit_logs,
    rbi_redshift_audit_logging,
    rbi_redshift_not_public,
    rbi_redshift_enhanced_vpc,
    rbi_rds_activity_streams,
    rbi_detective_enabled,
    rbi_cw_anomaly_detection,
    rbi_resource_explorer,
    rbi_resilience_hub,
    rbi_tgw_route_isolation,
    rbi_tgw_flow_logs,
    rbi_bwi_tagging_compliance,
)

from modules.frameworks.RBI_CSF.rbi_csf_infra_dlp_checks import (
    rbi_ast_config_recorder,
    rbi_ast_tagging,
    rbi_ast_ssm_managed,
    rbi_dlp_s3_ownership,
    rbi_dlp_object_lock,
    rbi_dlp_public_snapshots,
    rbi_dlp_public_rds_snapshots,
    rbi_inf_imdsv2,
    rbi_inf_lambda_vpc,
    rbi_inf_lambda_dlq,
    rbi_inf_elasticache_encryption,
    rbi_net_default_sg,
    rbi_net_ssh_restricted,
    rbi_dr_dynamodb_global,
    rbi_dr_backup_india,
    rbi_tpr_sns_policy,
    rbi_tpr_sqs_policy,
    rbi_tpr_sqs_dlq,
)

from modules.frameworks.RBI_CSF.rbi_csf_network_extended import (
    rbi_net_segmentation,
    rbi_net_nacl_permissive,
    rbi_net_vpc_endpoint_kms,
    rbi_net_vpc_endpoint_secretsmanager,
    rbi_net_public_subnets_db,
    rbi_net_tls_enforcement,
    rbi_net_dnssec,
)

from modules.frameworks.RBI_CSF.rbi_csf_encryption_backup_extended import (
    rbi_enc_kms_cmk_usage,
    rbi_enc_dynamodb,
    rbi_sec_rotation_schedule,
    rbi_sec_pending_deletion,
    rbi_sec_resource_policy,
    rbi_sec_cmk_encryption,
    rbi_bkp_plans_exist,
    rbi_bkp_vault_policy,
    rbi_bkp_vault_lock,
    rbi_bkp_recovery_points,
    rbi_bkp_retention,
    rbi_bkp_cross_region_dr,
    rbi_bkp_all_dbs_covered,
    rbi_bkp_dynamodb_pitr,
    rbi_gov_audit_manager,
    rbi_gov_config_compliance,
    rbi_gov_config_delivery,
    rbi_adv_s3_inventory,
    rbi_adv_cloudtrail_lake,
    rbi_adv_route53_query_logging,
    rbi_adv_route53_health_checks,
)


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CHECKS — Run once per account
# ═══════════════════════════════════════════════════════════════════════════════

def run_rbi_csf_global_checks(session, scan_meta_data):
    """All global RBI CSF checks (S3, IAM, CloudTrail, Data Residency, Governance, DLP, Assets)."""
    checks = [
        ("Scanning RBI Asset Inventory & Classification...", [
            rbi_ast_config_recorder, rbi_ast_tagging, rbi_ast_ssm_managed,
        ]),
        ("Scanning RBI Data Localization & S3 Security...", [
            rbi_data_localization, rbi_public_s3_buckets,
            rbi_s3_ssl_enforcement, rbi_s3_bucket_policy_wildcard,
            rbi_s3_versioning, rbi_s3_logging, rbi_s3_encryption_kms,
            rbi_dr_s3_replication,
        ]),
        ("Scanning RBI Data Leak Prevention...", [
            rbi_dlp_s3_ownership, rbi_dlp_object_lock,
        ]),
        ("Scanning RBI IAM & Access Control...", [
            rbi_privileged_users_without_mfa, rbi_iam_root_secured,
            rbi_iam_password_policy, rbi_iam_password_reuse,
            rbi_iam_access_key_rotation, rbi_iam_wildcard_permissions,
            rbi_iam_admin_minimized, rbi_iam_access_analyzer,
            rbi_iam_cross_account_trust,
        ]),
        ("Scanning RBI Audit Trail & CloudTrail...", [
            rbi_cloudtrail_audit_logs, rbi_ct_kms_encryption,
            rbi_ct_data_events, rbi_ct_insights,
        ]),
        ("Scanning RBI IT Governance & Compliance...", [
            rbi_gov_conformance_packs, rbi_gov_config_recorder,
            rbi_gov_audit_manager, rbi_gov_config_compliance, rbi_gov_config_delivery,
        ]),
        ("Scanning RBI Payment Cryptography...", [
            rbi_pay_keys_inventory, rbi_pay_key_rotation,
        ]),
        ("Scanning RBI Identity Center...", [
            rbi_identity_center,
        ]),
        ("Scanning RBI Banking Workload Identification...", [
            rbi_bwi_tagging_compliance,
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


# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL CHECKS — Run per region
# ═══════════════════════════════════════════════════════════════════════════════

def run_rbi_csf_regional_checks(session, scan_meta_data):
    """All regional RBI CSF checks — comprehensive coverage."""
    region = session.region_name or "unknown"

    checks = [
        ("Scanning RBI SOC & GuardDuty...", [
            rbi_soc_guardduty, rbi_soc_guardduty_s3,
            rbi_soc_guardduty_malware, rbi_soc_guardduty_rds,
            rbi_soc_guardduty_all_plans,
            rbi_soc_securityhub, rbi_soc_macie, rbi_soc_inspector,
        ]),
        ("Scanning RBI CloudWatch Alarms & Metric Filters...", [
            rbi_soc_cw_alarms, rbi_soc_sns_actions,
            rbi_soc_mf_root_login, rbi_soc_mf_unauthorized_api,
            rbi_soc_mf_iam_changes, rbi_soc_mf_sg_changes,
            rbi_soc_mf_kms_changes, rbi_soc_mf_cloudtrail_changes,
            rbi_soc_mf_config_changes, rbi_soc_mf_console_failures,
            rbi_soc_mf_s3_policy_changes,
        ]),
        ("Scanning RBI KMS Controls...", [
            rbi_kms_rotation, rbi_kms_disabled_pending, rbi_kms_key_policy,
        ]),
        ("Scanning RBI Network Security...", [
            rbi_open_security_groups, rbi_net_vpc_flow_logs, rbi_net_waf_alb,
            rbi_net_default_sg, rbi_net_ssh_restricted,
            rbi_net_segmentation, rbi_net_nacl_permissive,
            rbi_net_vpc_endpoint_kms, rbi_net_vpc_endpoint_secretsmanager,
            rbi_net_public_subnets_db, rbi_net_tls_enforcement, rbi_net_dnssec,
        ]),
        ("Scanning RBI Database Security...", [
            rbi_unencrypted_rds, rbi_rds_backup_disabled,
            rbi_rds_not_public, rbi_rds_deletion_protection,
            rbi_rds_multi_az, rbi_rds_india_region,
            rbi_rds_activity_streams,
        ]),
        ("Scanning RBI Encryption & Infrastructure...", [
            rbi_ebs_encryption, rbi_ebs_default_encryption,
            rbi_inf_imdsv2, rbi_inf_elasticache_encryption,
            rbi_enc_kms_cmk_usage, rbi_enc_dynamodb,
        ]),
        ("Scanning RBI Lambda & Compute...", [
            rbi_vul_lambda_deprecated, rbi_inf_lambda_vpc, rbi_inf_lambda_dlq,
        ]),
        ("Scanning RBI Container Security...", [
            rbi_vul_ecr_scan_on_push, rbi_vul_ecr_immutable, rbi_vul_ssm_managed,
        ]),
        ("Scanning RBI Secrets & Backup...", [
            rbi_secrets_rotation, rbi_backup_vault_encryption,
            rbi_sec_rotation_schedule, rbi_sec_pending_deletion,
            rbi_sec_resource_policy, rbi_sec_cmk_encryption,
            rbi_bkp_plans_exist, rbi_bkp_vault_policy, rbi_bkp_vault_lock,
            rbi_bkp_recovery_points, rbi_bkp_retention,
            rbi_bkp_cross_region_dr, rbi_bkp_all_dbs_covered, rbi_bkp_dynamodb_pitr,
        ]),
        ("Scanning RBI Incident Response...", [
            rbi_ir_eventbridge_guardduty, rbi_ir_incident_plans,
        ]),
        ("Scanning RBI API Security...", [
            rbi_api_authorization, rbi_api_access_logging, rbi_api_acm_expiry,
        ]),
        ("Scanning RBI Log Protection...", [
            rbi_log_retention, rbi_log_cw_encryption,
            rbi_log_trail_protected, rbi_log_api_gateway,
        ]),
        ("Scanning RBI DLP & Snapshots...", [
            rbi_dlp_public_snapshots, rbi_dlp_public_rds_snapshots,
        ]),
        ("Scanning RBI Data Residency...", [
            rbi_dr_dynamodb_global, rbi_dr_backup_india,
        ]),
        ("Scanning RBI Third-Party Risk...", [
            rbi_tpr_sns_policy, rbi_tpr_sqs_policy, rbi_tpr_sqs_dlq,
        ]),
        ("Scanning RBI Network Firewall & Shield...", [
            rbi_nfw_deployed, rbi_nfw_rule_groups, rbi_fwm_policies,
            rbi_shield_subscription, rbi_shield_protections,
        ]),
        ("Scanning RBI Messaging & Streaming...", [
            rbi_mq_encryption, rbi_mq_not_public,
            rbi_msk_encryption, rbi_msk_auth,
        ]),
        ("Scanning RBI OpenSearch & Redshift...", [
            rbi_opensearch_fgac, rbi_opensearch_audit_logs,
            rbi_redshift_audit_logging, rbi_redshift_not_public,
            rbi_redshift_enhanced_vpc,
        ]),
        ("Scanning RBI SOC Maturity...", [
            rbi_detective_enabled, rbi_cw_anomaly_detection, rbi_resource_explorer,
        ]),
        ("Scanning RBI Resilience & Transit Gateway...", [
            rbi_resilience_hub, rbi_tgw_route_isolation, rbi_tgw_flow_logs,
            rbi_verified_access,
        ]),
        ("Scanning RBI Advanced Hardening...", [
            rbi_adv_s3_inventory, rbi_adv_cloudtrail_lake,
            rbi_adv_route53_query_logging, rbi_adv_route53_health_checks,
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
