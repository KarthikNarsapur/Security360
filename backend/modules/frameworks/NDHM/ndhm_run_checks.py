"""
NDHM/ABDM — National Digital Health Mission (India)
Unified Runner — Orchestrates all NDHM checks.

Structure:
  - ndhm_core_checks.py     → Sections A-F (Global: Consent, Processing, Rights, Storage, Security, Auth)
  - ndhm_regional_checks.py → Sections G-H + Service checks (Audit, Breach, KMS, Network, RDS, API)
  - ndhm_extended_checks.py → Extended deep-dive checks (ECS, EKS, ECR, CloudWatch, etc.)

Total: 268 checks
"""

from modules.frameworks.NDHM.ndhm_core_checks import (
    # A — Consent Management
    ndhm_a1_consent_audit_trail,
    ndhm_a2_consent_artefact_integrity,
    ndhm_a3_purpose_limitation,
    ndhm_a4_consent_expiry_enforcement,
    ndhm_a5_consent_revocation_notification,
    ndhm_a6_consent_scope_validation,
    ndhm_a7_granular_consent_logging,
    ndhm_a8_data_principal_notification,
    # B — Health Data Collection
    ndhm_b1_data_minimization,
    ndhm_b2_health_data_classification,
    ndhm_b3_processing_boundaries,
    ndhm_b4_collection_limitation,
    ndhm_b5_data_integrity,
    ndhm_b6_lawful_processing,
    ndhm_b7_fhir_compliance,
    ndhm_b8_record_linkage_security,
    # C — Data Principal Rights
    ndhm_c1_right_to_access,
    ndhm_c2_right_to_correction,
    ndhm_c3_right_to_erasure,
    ndhm_c4_right_to_portability,
    ndhm_c5_right_to_restrict_processing,
    ndhm_c6_right_to_nominate,
    ndhm_c7_grievance_mechanisms,
    ndhm_c8_abha_deactivation,
    # D — Storage, Retention, Disposal
    ndhm_d1_retention_controls,
    ndhm_d2_secure_disposal,
    ndhm_d3_storage_encryption,
    ndhm_d4_data_residency_india,
    ndhm_d5_cross_border_restriction,
    ndhm_d6_backup_encryption,
    ndhm_d7_data_versioning,
    ndhm_d8_archival_mechanisms,
    # E — Security Safeguards
    ndhm_e1_encryption_at_rest,
    ndhm_e2_encryption_in_transit,
    ndhm_e3_e2e_encryption,
    ndhm_e4_access_control,
    ndhm_e5_privileged_access,
    ndhm_e6_network_security,
    ndhm_e7_intrusion_detection,
    ndhm_e8_vulnerability_management,
    ndhm_e9_anti_malware,
    ndhm_e10_security_config_management,
    # F — Authentication & Identity
    ndhm_f1_password_policy,
    ndhm_f2_mfa_enforcement,
    ndhm_f3_root_account_security,
    ndhm_f4_access_key_rotation,
    ndhm_f5_session_management,
    ndhm_f6_service_account_security,
    ndhm_f7_identity_federation,
    ndhm_f8_credential_report,
)

from modules.frameworks.NDHM.ndhm_regional_checks import (
    # G — Audit Trail & Logging
    ndhm_g1_health_data_access_logging,
    ndhm_g2_log_integrity,
    ndhm_g3_centralized_log_management,
    ndhm_g4_log_encryption,
    ndhm_g5_health_record_access_monitoring,
    ndhm_g6_admin_activity_logging,
    ndhm_g7_consent_operation_logging,
    ndhm_g8_log_retention_compliance,
    ndhm_g9_realtime_alerting,
    ndhm_g10_data_sharing_audit,
    # H — Breach Notification
    ndhm_h1_breach_detection,
    ndhm_h2_breach_notification,
    ndhm_h3_incident_response_plans,
    ndhm_h4_security_event_correlation,
    ndhm_h5_automated_escalation,
    ndhm_h6_evidence_preservation,
    ndhm_h7_regulatory_notification,
    ndhm_h8_post_incident_review,
    # KMS
    ndhm_kms_rotation,
    ndhm_kms_disabled,
    ndhm_kms_pending_deletion,
    ndhm_kms_key_policy,
    ndhm_kms_cmk_usage,
    # Network
    ndhm_net_db_sg_exposed,
    ndhm_net_vpc_flow_logs,
    ndhm_net_vpc_endpoint_s3,
    ndhm_net_waf_alb,
    # Database
    ndhm_db_encryption,
    ndhm_db_not_public,
    ndhm_db_deletion_protection,
    ndhm_db_backup_retention,
    ndhm_db_india_region,
    # API
    ndhm_api_authorization,
    ndhm_api_access_logging,
    ndhm_api_tls_version,
    ndhm_api_acm_expiry,
)

from modules.frameworks.NDHM.ndhm_extended_checks import (
    # Extended checks
    ndhm_ext_s3_public_access_block,
    ndhm_ext_s3_ssl_enforcement,
    ndhm_ext_iam_access_analyzer,
    ndhm_ext_iam_password_reuse,
    ndhm_ext_secrets_rotation,
    ndhm_ext_secrets_age,
    ndhm_ext_guardduty_s3_protection,
    ndhm_ext_guardduty_rds_protection,
    ndhm_ext_config_delivery_channel,
    ndhm_ext_config_conformance,
    ndhm_ext_backup_vault_lock,
    ndhm_ext_backup_recovery_points,
    ndhm_ext_eventbridge_guardduty,
    ndhm_ext_eventbridge_securityhub,
    ndhm_ext_sns_subscribers,
    ndhm_ext_rds_multi_az,
    ndhm_ext_rds_enhanced_monitoring,
    ndhm_ext_dynamodb_pitr,
    ndhm_ext_ebs_default_encryption,
    ndhm_ext_cloudtrail_kms,
)


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CHECKS — Run once per account
# ═══════════════════════════════════════════════════════════════════════════════


def run_ndhm_global_checks(session, scan_meta_data):
    """All global NDHM checks (S3, IAM, CloudTrail, consent, data residency)."""
    checks = [
        ("Scanning NDHM Consent Management...", [
            ndhm_a1_consent_audit_trail, ndhm_a2_consent_artefact_integrity,
            ndhm_a3_purpose_limitation, ndhm_a4_consent_expiry_enforcement,
            ndhm_a5_consent_revocation_notification, ndhm_a6_consent_scope_validation,
            ndhm_a7_granular_consent_logging, ndhm_a8_data_principal_notification,
        ]),
        ("Scanning NDHM Health Data Processing...", [
            ndhm_b1_data_minimization, ndhm_b2_health_data_classification,
            ndhm_b3_processing_boundaries, ndhm_b4_collection_limitation,
            ndhm_b5_data_integrity, ndhm_b6_lawful_processing,
            ndhm_b7_fhir_compliance, ndhm_b8_record_linkage_security,
        ]),
        ("Scanning NDHM Data Principal Rights...", [
            ndhm_c1_right_to_access, ndhm_c2_right_to_correction,
            ndhm_c3_right_to_erasure, ndhm_c4_right_to_portability,
            ndhm_c5_right_to_restrict_processing, ndhm_c6_right_to_nominate,
            ndhm_c7_grievance_mechanisms, ndhm_c8_abha_deactivation,
        ]),
        ("Scanning NDHM Data Storage & Residency...", [
            ndhm_d1_retention_controls, ndhm_d2_secure_disposal,
            ndhm_d3_storage_encryption, ndhm_d4_data_residency_india,
            ndhm_d5_cross_border_restriction, ndhm_d6_backup_encryption,
            ndhm_d7_data_versioning, ndhm_d8_archival_mechanisms,
        ]),
        ("Scanning NDHM Security Safeguards...", [
            ndhm_e1_encryption_at_rest, ndhm_e2_encryption_in_transit,
            ndhm_e3_e2e_encryption, ndhm_e4_access_control,
            ndhm_e5_privileged_access, ndhm_e6_network_security,
            ndhm_e7_intrusion_detection, ndhm_e8_vulnerability_management,
            ndhm_e9_anti_malware, ndhm_e10_security_config_management,
        ]),
        ("Scanning NDHM Authentication & Identity...", [
            ndhm_f1_password_policy, ndhm_f2_mfa_enforcement,
            ndhm_f3_root_account_security, ndhm_f4_access_key_rotation,
            ndhm_f5_session_management, ndhm_f6_service_account_security,
            ndhm_f7_identity_federation, ndhm_f8_credential_report,
        ]),
        ("Scanning NDHM S3 & IAM Extended...", [
            ndhm_ext_s3_public_access_block, ndhm_ext_s3_ssl_enforcement,
            ndhm_ext_iam_access_analyzer, ndhm_ext_iam_password_reuse,
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


def run_ndhm_regional_checks(session, scan_meta_data):
    """All regional NDHM checks (KMS, Network, RDS, API, Logging, Monitoring)."""
    region = session.region_name or "unknown"

    checks = [
        ("Scanning NDHM Audit & Logging...", [
            ndhm_g1_health_data_access_logging, ndhm_g2_log_integrity,
            ndhm_g3_centralized_log_management, ndhm_g4_log_encryption,
            ndhm_g5_health_record_access_monitoring, ndhm_g6_admin_activity_logging,
            ndhm_g7_consent_operation_logging, ndhm_g8_log_retention_compliance,
            ndhm_g9_realtime_alerting, ndhm_g10_data_sharing_audit,
        ]),
        ("Scanning NDHM Breach & Incident Management...", [
            ndhm_h1_breach_detection, ndhm_h2_breach_notification,
            ndhm_h3_incident_response_plans, ndhm_h4_security_event_correlation,
            ndhm_h5_automated_escalation, ndhm_h6_evidence_preservation,
            ndhm_h7_regulatory_notification, ndhm_h8_post_incident_review,
        ]),
        ("Scanning NDHM KMS Controls...", [
            ndhm_kms_rotation, ndhm_kms_disabled,
            ndhm_kms_pending_deletion, ndhm_kms_key_policy, ndhm_kms_cmk_usage,
        ]),
        ("Scanning NDHM Network Security...", [
            ndhm_net_db_sg_exposed, ndhm_net_vpc_flow_logs,
            ndhm_net_vpc_endpoint_s3, ndhm_net_waf_alb,
        ]),
        ("Scanning NDHM Database Security...", [
            ndhm_db_encryption, ndhm_db_not_public,
            ndhm_db_deletion_protection, ndhm_db_backup_retention, ndhm_db_india_region,
        ]),
        ("Scanning NDHM API Security...", [
            ndhm_api_authorization, ndhm_api_access_logging,
            ndhm_api_tls_version, ndhm_api_acm_expiry,
        ]),
        ("Scanning NDHM Extended Controls...", [
            ndhm_ext_secrets_rotation, ndhm_ext_secrets_age,
            ndhm_ext_guardduty_s3_protection, ndhm_ext_guardduty_rds_protection,
            ndhm_ext_config_delivery_channel, ndhm_ext_config_conformance,
            ndhm_ext_backup_vault_lock, ndhm_ext_backup_recovery_points,
            ndhm_ext_eventbridge_guardduty, ndhm_ext_eventbridge_securityhub,
            ndhm_ext_sns_subscribers, ndhm_ext_rds_multi_az,
            ndhm_ext_rds_enhanced_monitoring, ndhm_ext_dynamodb_pitr,
            ndhm_ext_ebs_default_encryption, ndhm_ext_cloudtrail_kms,
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
