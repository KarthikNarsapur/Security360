import boto3
from modules.PCIDSS.pcidss_checks import (
    pcidss_default_sg_allows_traffic,
    pcidss_ssh_rdp_open_to_internet,
    pcidss_s3_buckets_not_encrypted,
    pcidss_rds_not_encrypted,
    pcidss_ssl_tls_on_load_balancers,
    pcidss_mfa_not_on_all_users,
    pcidss_password_policy_weak,
    pcidss_cloudtrail_disabled,
    pcidss_guardduty_disabled,
    pcidss_ebs_snapshots_public,
    pcidss_secrets_in_env_variables,
    pcidss_vpc_flow_logs_disabled,
)


def run_pcidss_checks(session, scan_meta_data):
    """
    Called by framework_scan.py wrapper.
    Receives session + scan_meta_data, returns list of check results.
    """
    iam = session.client("iam")
    users = iam.list_users().get("Users", [])

    results = []
    results.append(pcidss_default_sg_allows_traffic(session, scan_meta_data))
    results.append(pcidss_ssh_rdp_open_to_internet(session, scan_meta_data))
    results.append(pcidss_s3_buckets_not_encrypted(session, scan_meta_data))
    results.append(pcidss_rds_not_encrypted(session, scan_meta_data))
    results.append(pcidss_ssl_tls_on_load_balancers(session, scan_meta_data))
    results.append(pcidss_mfa_not_on_all_users(session, scan_meta_data, users, iam))
    results.append(pcidss_password_policy_weak(session, scan_meta_data))
    results.append(pcidss_cloudtrail_disabled(session, scan_meta_data))
    results.append(pcidss_guardduty_disabled(session, scan_meta_data))
    results.append(pcidss_ebs_snapshots_public(session, scan_meta_data))
    results.append(pcidss_secrets_in_env_variables(session, scan_meta_data))
    results.append(pcidss_vpc_flow_logs_disabled(session, scan_meta_data))

    return results


# ── Keep this for direct API calls from main.py ──────────────────────────────
async def pcidss_rules_scan_function(data):
    from utils.framework_scan import run_framework_scan

    return run_framework_scan(data, framework="pcidss")
