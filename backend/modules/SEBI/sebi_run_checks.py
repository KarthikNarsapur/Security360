import boto3
from modules.SEBI.sebi_checks import (
    sebi_guardduty_not_enabled,
    sebi_waf_not_enabled_on_albs,
    sebi_cloudtrail_not_multiregion,
    sebi_mfa_not_enabled_on_iam_users,
    sebi_s3_logging_disabled,
    sebi_vpc_flow_logs_disabled,
    sebi_ebs_volumes_unencrypted,
    sebi_password_policy_weak,
    sebi_rds_publicly_accessible,
    sebi_untagged_critical_resources,
    sebi_root_account_used_recently,
)


def run_sebi_checks(session, scan_meta_data):
    """
    Called by framework_scan.py wrapper.
    Receives session + scan_meta_data, returns list of check results.
    """
    iam = session.client("iam")
    users = iam.list_users().get("Users", [])

    results = []
    results.append(sebi_guardduty_not_enabled(session, scan_meta_data))
    results.append(sebi_waf_not_enabled_on_albs(session, scan_meta_data))
    results.append(sebi_cloudtrail_not_multiregion(session, scan_meta_data))
    results.append(
        sebi_mfa_not_enabled_on_iam_users(session, scan_meta_data, users, iam)
    )
    results.append(sebi_s3_logging_disabled(session, scan_meta_data))
    results.append(sebi_vpc_flow_logs_disabled(session, scan_meta_data))
    results.append(sebi_ebs_volumes_unencrypted(session, scan_meta_data))
    results.append(sebi_password_policy_weak(session, scan_meta_data))
    results.append(sebi_rds_publicly_accessible(session, scan_meta_data))
    results.append(sebi_untagged_critical_resources(session, scan_meta_data))
    results.append(sebi_root_account_used_recently(session, scan_meta_data))

    return results


# ── Keep this for direct API calls from main.py ──────────────────────────────
async def sebi_rules_scan_function(data):
    from utils.framework_scan import run_framework_scan

    return run_framework_scan(data, framework="sebi")
