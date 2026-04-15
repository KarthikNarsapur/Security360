import boto3
from modules.RBI.rbi_checks import (
    rbi_data_localization,
    rbi_public_s3_buckets,
    rbi_privileged_users_without_mfa,
    rbi_unencrypted_rds,
    rbi_cloudtrail_audit_logs,
    rbi_open_security_groups,
    rbi_rds_backup_disabled,
)


def run_rbi_checks(session, scan_meta_data):
    """
    Called by framework_scan.py wrapper.
    Receives session + scan_meta_data, returns list of check results.
    """
    iam = session.client("iam")
    users = iam.list_users().get("Users", [])

    results = []
    results.append(rbi_data_localization(session, scan_meta_data))
    results.append(rbi_public_s3_buckets(session, scan_meta_data))
    results.append(
        rbi_privileged_users_without_mfa(session, scan_meta_data, users, iam)
    )
    results.append(rbi_unencrypted_rds(session, scan_meta_data))
    results.append(rbi_cloudtrail_audit_logs(session, scan_meta_data))
    results.append(rbi_open_security_groups(session, scan_meta_data))
    results.append(rbi_rds_backup_disabled(session, scan_meta_data))

    return results


# ── Keep this for direct API calls from main.py ──────────────────────────────
async def rbi_rules_scan_function(data):
    from utils.framework_scan import run_framework_scan

    return run_framework_scan(data, framework="rbi")
