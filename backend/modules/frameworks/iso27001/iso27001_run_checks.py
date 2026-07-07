"""
ISO 27001 — Run Checks Orchestrator
Registers all 72 active checks grouped by domain.
Called by the framework adapter for framework_scan.py integration.
"""


def get_iso27001_checks():
    """Returns the full registry of ISO 27001 check functions."""
    from modules.frameworks.iso27001.checks.iam_checks import (
        check_password_policy,
        check_mfa_enforcement,
        check_root_account_security,
        check_access_key_rotation,
        check_unused_credentials,
        check_least_privilege,
        check_wildcard_permissions,
        check_inline_policies,
        check_privileged_role_review,
        check_segregation_of_duties,
    )
    from modules.frameworks.iso27001.checks.logging_checks import (
        check_cloudtrail_enabled,
        check_cloudtrail_multiregion,
        check_cloudtrail_log_validation,
        check_cloudtrail_data_events,
        check_cloudwatch_log_groups,
        check_cloudwatch_log_retention,
        check_security_alarms,
        check_guardduty_enabled,
        check_guardduty_findings,
        check_security_hub_enabled,
    )
    from modules.frameworks.iso27001.checks.network_checks import (
        check_security_groups,
        check_network_acls,
        check_vpc_flow_logs,
        check_vpc_endpoints,
        check_vpn_configuration,
        check_https_load_balancers,
        check_waf_association,
        check_network_segregation,
    )
    from modules.frameworks.iso27001.checks.encryption_checks import (
        check_s3_encryption,
        check_ebs_encryption,
        check_rds_encryption,
        check_kms_key_rotation,
        check_acm_certificates,
        check_s3_public_access_block,
        check_s3_object_lock,
        check_s3_versioning,
        check_s3_lifecycle,
        check_s3_bucket_logging,
        check_s3_bucket_ownership,
        check_s3_replication,
        check_secure_transport,
    )
    from modules.frameworks.iso27001.checks.vulnerability_checks import (
        check_inspector_findings,
        check_ecr_image_scanning,
        check_ssm_patch_compliance,
        check_macie_enabled,
        check_data_classification_tags,
        check_pii_protection,
    )
    from modules.frameworks.iso27001.checks.backup_checks import (
        check_backup_plans,
        check_protected_resources,
        check_backup_vault_review,
        check_rds_automated_backups,
        check_rds_multi_az,
        check_multi_az_validation,
    )
    from modules.frameworks.iso27001.checks.config_checks import (
        check_config_recorder,
        check_config_rules,
        check_conformance_packs,
        check_compliance_status,
        check_cloudformation_stacks,
    )
    from modules.frameworks.iso27001.checks.appsec_checks import (
        check_api_gateway_auth,
        check_codepipeline,
        check_codebuild,
        check_codecommit,
        check_cloudfront_https,
        check_vpc_endpoints_appsec,
    )
    from modules.frameworks.iso27001.checks.compute_checks import (
        check_managed_ec2_ssm,
        check_ec2_inventory,
        check_lambda_inventory,
        check_resource_tagging,
        check_resource_inventory,
    )
    from modules.frameworks.iso27001.checks.incident_checks import (
        check_eventbridge_rules,
        check_sns_notifications,
        check_incident_manager_plans,
        check_audit_manager,
        check_trusted_advisor,
    )

    return {
        # === Identity & Access Management (10 checks) ===
        "ISO27001-IAM-01": check_password_policy,
        "ISO27001-IAM-02": check_mfa_enforcement,
        "ISO27001-IAM-03": check_root_account_security,
        "ISO27001-IAM-04": check_access_key_rotation,
        "ISO27001-IAM-05": check_unused_credentials,
        "ISO27001-IAM-06": check_least_privilege,
        "ISO27001-IAM-07": check_wildcard_permissions,
        "ISO27001-IAM-08": check_inline_policies,
        "ISO27001-IAM-09": check_privileged_role_review,
        "ISO27001-IAM-10": check_segregation_of_duties,
        # === Logging & Monitoring (10 checks) ===
        "ISO27001-LOG-01": check_cloudtrail_enabled,
        "ISO27001-LOG-02": check_cloudtrail_multiregion,
        "ISO27001-LOG-03": check_cloudtrail_log_validation,
        "ISO27001-LOG-04": check_cloudtrail_data_events,
        "ISO27001-LOG-05": check_cloudwatch_log_groups,
        "ISO27001-LOG-06": check_cloudwatch_log_retention,
        "ISO27001-LOG-07": check_security_alarms,
        "ISO27001-LOG-08": check_guardduty_enabled,
        "ISO27001-LOG-09": check_guardduty_findings,
        "ISO27001-LOG-10": check_security_hub_enabled,
        # === Network Security (8 checks) ===
        "ISO27001-NET-01": check_security_groups,
        "ISO27001-NET-02": check_network_acls,
        "ISO27001-NET-03": check_vpc_flow_logs,
        "ISO27001-NET-04": check_vpc_endpoints,
        "ISO27001-NET-05": check_vpn_configuration,
        "ISO27001-NET-06": check_https_load_balancers,
        "ISO27001-NET-07": check_waf_association,
        "ISO27001-NET-08": check_network_segregation,
        # === Encryption & Data Protection (13 checks) ===
        "ISO27001-ENC-01": check_s3_encryption,
        "ISO27001-ENC-02": check_ebs_encryption,
        "ISO27001-ENC-03": check_rds_encryption,
        "ISO27001-ENC-04": check_kms_key_rotation,
        "ISO27001-ENC-05": check_acm_certificates,
        "ISO27001-ENC-06": check_s3_public_access_block,
        "ISO27001-ENC-07": check_s3_object_lock,
        "ISO27001-ENC-08": check_s3_versioning,
        "ISO27001-ENC-09": check_s3_lifecycle,
        "ISO27001-ENC-10": check_s3_bucket_logging,
        "ISO27001-ENC-11": check_s3_bucket_ownership,
        "ISO27001-ENC-12": check_s3_replication,
        "ISO27001-ENC-13": check_secure_transport,
        # === Threat & Vulnerability (6 checks) ===
        "ISO27001-VUL-01": check_inspector_findings,
        "ISO27001-VUL-02": check_ecr_image_scanning,
        "ISO27001-VUL-03": check_ssm_patch_compliance,
        "ISO27001-VUL-04": check_macie_enabled,
        "ISO27001-VUL-05": check_data_classification_tags,
        "ISO27001-VUL-06": check_pii_protection,
        # === Backup & Resilience (6 checks) ===
        "ISO27001-BAK-01": check_backup_plans,
        "ISO27001-BAK-02": check_protected_resources,
        "ISO27001-BAK-03": check_backup_vault_review,
        "ISO27001-BAK-04": check_rds_automated_backups,
        "ISO27001-BAK-05": check_rds_multi_az,
        "ISO27001-BAK-06": check_multi_az_validation,
        # === Configuration (5 checks) ===
        "ISO27001-CFG-01": check_config_recorder,
        "ISO27001-CFG-02": check_config_rules,
        "ISO27001-CFG-03": check_conformance_packs,
        "ISO27001-CFG-04": check_compliance_status,
        "ISO27001-CFG-05": check_cloudformation_stacks,
        # === Application Security (6 checks) ===
        "ISO27001-APP-01": check_api_gateway_auth,
        "ISO27001-APP-02": check_codepipeline,
        "ISO27001-APP-03": check_codebuild,
        "ISO27001-APP-04": check_codecommit,
        "ISO27001-APP-05": check_cloudfront_https,
        "ISO27001-APP-06": check_vpc_endpoints_appsec,
        # === Compute & Inventory (5 checks) ===
        "ISO27001-CMP-01": check_managed_ec2_ssm,
        "ISO27001-CMP-02": check_ec2_inventory,
        "ISO27001-CMP-03": check_lambda_inventory,
        "ISO27001-CMP-04": check_resource_tagging,
        "ISO27001-CMP-05": check_resource_inventory,
        # === Incident Response (5 checks) ===
        "ISO27001-INC-01": check_eventbridge_rules,
        "ISO27001-INC-02": check_sns_notifications,
        "ISO27001-INC-03": check_incident_manager_plans,
        "ISO27001-INC-04": check_audit_manager,
        "ISO27001-INC-05": check_trusted_advisor,
    }
