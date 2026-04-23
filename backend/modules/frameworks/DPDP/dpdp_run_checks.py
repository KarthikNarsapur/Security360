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


def run_dpdp_global_checks(session, scan_meta_data):
    """Global checks: S3 + IAM + CloudTrail. Run once per account."""
    iam = session.client("iam")
    users = iam.list_users().get("Users", [])

    results = []
    # S3 — global
    results.append(dpdp_s3_public_bucket(session, scan_meta_data))
    results.append(dpdp_s3_encryption(session, scan_meta_data))
    results.append(dpdp_s3_versioning(session, scan_meta_data))
    results.append(dpdp_s3_access_logging(session, scan_meta_data))
    results.append(dpdp_s3_lifecycle(session, scan_meta_data))
    # IAM — global
    results.append(dpdp_root_mfa(session, scan_meta_data))
    results.append(dpdp_iam_user_mfa(session, scan_meta_data, users, iam))
    results.append(dpdp_access_key_age(session, scan_meta_data, users, iam))
    results.append(dpdp_wildcard_policy(session, scan_meta_data, iam))
    results.append(dpdp_password_policy(session, scan_meta_data))
    # CloudTrail — global (multi-region by nature)
    results.append(dpdp_cloudtrail_enabled(session, scan_meta_data))
    return results


def run_dpdp_regional_checks(session, scan_meta_data):
    """Regional checks: EC2, RDS, VPC, GuardDuty, etc. Run per-region."""
    region = session.region_name or "unknown"
    results = []

    results.append(dpdp_rds_public_access(session, scan_meta_data))
    results.append(dpdp_rds_encryption(session, scan_meta_data))
    results.append(dpdp_rds_backup_retention(session, scan_meta_data))
    results.append(dpdp_dynamodb_pitr(session, scan_meta_data))
    results.append(dpdp_efs_encryption(session, scan_meta_data))
    results.append(dpdp_security_group_open_ports(session, scan_meta_data))
    results.append(dpdp_vpc_flow_logs(session, scan_meta_data))
    results.append(dpdp_ec2_public_ip(session, scan_meta_data))
    results.append(dpdp_ebs_encryption(session, scan_meta_data))
    results.append(dpdp_guardduty_enabled(session, scan_meta_data))
    results.append(dpdp_config_enabled(session, scan_meta_data))
    results.append(dpdp_cloudwatch_log_retention(session, scan_meta_data))
    results.append(dpdp_secrets_manager_usage(session, scan_meta_data))
    results.append(dpdp_lambda_env_secrets(session, scan_meta_data))
    results.append(dpdp_lambda_public_access(session, scan_meta_data))
    results.append(dpdp_sns_topic_exists(session, scan_meta_data))

    # Tag all with actual region
    for r in results:
        r["region"] = region

    return results


def run_dpdp_checks(session, scan_meta_data):
    """
    Legacy entry point — runs both global + regional for current session region.
    Used when framework_scan.py calls with is_global_only=True (backward compat).
    """
    results = []
    results.extend(run_dpdp_global_checks(session, scan_meta_data))
    results.extend(run_dpdp_regional_checks(session, scan_meta_data))
    return results


async def dpdp_scan_function(data):
    """Entry point for direct API calls."""
    from utils.framework_scan import run_framework_scan
    return run_framework_scan(data, framework="dpdp")
