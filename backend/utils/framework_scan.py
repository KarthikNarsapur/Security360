import boto3
from datetime import datetime, timezone, timedelta
from Model.model import AccessTokenModel
from utils.upload_to_s3 import upload_to_s3, save_report
from utils.scan_progress import update_progress, start_capture, stop_capture

IST = timezone(timedelta(hours=5, minutes=30))


# ─────────────────────────────────────────────────────────────────────────────
# FRAMEWORK REGISTRY
# Register any new framework here — nothing else needs to change.
#
# Key   → framework name (must match what frontend sends)
# Value → tuple of (run_checks_fn, is_global_only)
#
#   is_global_only=True  → runs once per account (IAM, S3, CloudTrail etc.)
#   is_global_only=False → runs once per region
# ─────────────────────────────────────────────────────────────────────────────
def _get_framework_registry():
    from modules.RBI.rbi_run_checks import run_rbi_checks
    from modules.frameworks.SEBI.sebi_run_checks import run_sebi_global_checks, run_sebi_regional_checks
    from modules.PCIDSS.pcidss_run_checks import run_pcidss_checks
    from modules.frameworks.DPDP.dpdp_run_checks import run_dpdp_global_checks, run_dpdp_regional_checks
    from modules.frameworks.DPDP.dpdp_rules_2025_run_checks import (
        run_dpdp_rules_2025_global_checks, run_dpdp_rules_2025_regional_checks,
    )

    return {
        "rbi": (run_rbi_checks, None, "global_only"),
        "sebi": (run_sebi_global_checks, run_sebi_regional_checks, "hybrid"),
        "pcidss": (run_pcidss_checks, None, "global_only"),
        "dpdp": (run_dpdp_global_checks, run_dpdp_regional_checks, "hybrid"),
        "dpdp_rules_2025": (run_dpdp_rules_2025_global_checks, run_dpdp_rules_2025_regional_checks, "hybrid"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# Called from main.py route — same signature as run_scan()
# ─────────────────────────────────────────────────────────────────────────────
def run_framework_scan(data: AccessTokenModel, framework: str, scan_id: str = None):
    _real_stdout = None
    try:
        # step 1: validate input
        if not data.username:
            return {"status": "error", "error_message": "Username is missing."}
        if not data.accounts or len(data.accounts) == 0:
            return {
                "status": "error",
                "error_message": "AWS accounts list is missing or empty.",
            }
        if not data.regions or len(data.regions) == 0:
            return {
                "status": "error",
                "error_message": "AWS regions list is missing or empty.",
            }

        # Progress helper — updates percent only; messages come from print()
        def _progress(percent):
            if scan_id:
                update_progress(scan_id, percent, "")

        # Start capturing stdout → WebSocket
        if scan_id:
            _real_stdout = start_capture(scan_id)

        framework = framework.lower().strip()
        registry = _get_framework_registry()

        if framework not in registry:
            return {
                "status": "error",
                "error_message": f"Unknown framework '{framework}'. Available: {list(registry.keys())}",
            }

        entry = registry[framework]
        scan_mode = entry[2] if len(entry) > 2 else "global_only"

        # Backward compat: old format (fn, bool) → new format
        if len(entry) == 2:
            run_checks_fn, is_global = entry
            if is_global:
                scan_mode = "global_only"
                global_fn = run_checks_fn
                regional_fn = None
            else:
                scan_mode = "regional_only"
                global_fn = None
                regional_fn = run_checks_fn
        else:
            global_fn, regional_fn, scan_mode = entry

        username = data.username
        roles_info = data.accounts
        REGIONS = data.regions
        notifications = {"success": [], "error": []}

        # step 2: loop through each account
        for role in roles_info:
            account_id = role.account_id or ""
            role_arn = role.role_arn or ""
            account_name = role.account_name or ""

            if not account_id or not role_arn:
                print(f"Missing account details: {account_id}")
                continue

            try:
                # step 3: assume role
                sts_client = boto3.client("sts")
                try:
                    assumed_role = sts_client.assume_role(
                        RoleArn=role_arn, RoleSessionName="FrameworkAuditSession"
                    )
                except Exception as e:
                    print(f"Error assuming role for {account_id}: {e}")
                    notifications["error"].append(f"Role assume failed: {account_id}")
                    continue

                credentials = assumed_role["Credentials"]
                access_key = credentials["AccessKeyId"]
                secret_key = credentials["SecretAccessKey"]
                session_token = credentials["SessionToken"]

                # step 4: run checks based on scan mode
                scan_results = []

                if scan_mode == "global_only":
                    # Global services only — run once per account
                    scan_meta_data = _fresh_meta(framework)
                    session = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        aws_session_token=session_token,
                        region_name="ap-south-1",
                    )
                    try:
                        results = global_fn(session, scan_meta_data)
                        scan_results.append(
                            {
                                "region": "global",
                                "data": results,
                                "scan_meta_data": scan_meta_data,
                            }
                        )
                    except Exception as e:
                        print(
                            f"Error running {framework} global checks for {account_id}: {e}"
                        )
                        notifications["error"].append(
                            f"{framework} global check failed: {account_id}"
                        )
                        continue

                elif scan_mode == "hybrid":
                    # Hybrid: global checks once + regional checks per region
                    # 1. Run global checks once
                    _progress(2)
                    print("Connecting to AWS...")
                    _progress(5)
                    print("Starting scans...")
                    global_meta = _fresh_meta(framework)
                    session = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        aws_session_token=session_token,
                        region_name="ap-south-1",
                    )
                    try:
                        global_results = global_fn(session, global_meta)
                        scan_results.append(
                            {
                                "region": "global",
                                "data": global_results,
                                "scan_meta_data": global_meta,
                            }
                        )
                    except Exception as e:
                        print(f"Error running {framework} global checks for {account_id}: {e}")
                        notifications["error"].append(f"{framework} global check failed: {account_id}")

                    # 2. Run regional checks per selected region
                    if regional_fn:
                        failed_regions = []
                        total_regions = len(REGIONS)
                        for idx, region in enumerate(REGIONS):
                            session = boto3.Session(
                                aws_access_key_id=access_key,
                                aws_secret_access_key=secret_key,
                                aws_session_token=session_token,
                                region_name=region,
                            )
                            print(f"  {framework} scanning region: {region}")
                            try:
                                regional_meta = _fresh_meta(framework)
                                regional_results = regional_fn(session, regional_meta)
                                scan_results.append(
                                    {
                                        "region": region,
                                        "data": regional_results,
                                        "scan_meta_data": regional_meta,
                                    }
                                )
                            except Exception as e:
                                print(f"Error scanning region {region} for {account_id}: {e}")
                                failed_regions.append(region)
                        if failed_regions:
                            print(f"Failed regions for {account_id}: {failed_regions}")
                            notifications["error"].append(
                                f"Failed in regions: {', '.join(failed_regions)} for {account_id}"
                            )

                else:
                    # Regional only — run once per region
                    failed_regions = []
                    for region in REGIONS:
                        session = boto3.Session(
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key,
                            aws_session_token=session_token,
                            region_name=region,
                        )
                        print(f"Checking region: {region}")
                        try:
                            scan_meta_data = _fresh_meta(framework)
                            results = (regional_fn or global_fn)(session, scan_meta_data)
                            scan_results.append(
                                {
                                    "region": region,
                                    "data": results,
                                    "scan_meta_data": scan_meta_data,
                                }
                            )
                        except Exception as e:
                            print(
                                f"Error scanning region {region} for {account_id}: {e}"
                            )
                            failed_regions.append(region)

                    if failed_regions:
                        print(f"Failed regions for {account_id}: {failed_regions}")

                # step 5: save report and upload to S3
                _progress(96)
                print("Saving findings...")
                try:
                    saved_filename = save_report(
                        account_id=account_id,
                        username=username,
                        account_name=account_name,
                        results=scan_results,
                        type=framework,
                        scan_meta_data=[],
                        security_services_scan=[],
                        global_services_scan_results={},
                        scan_meta_data_global_services=_merge_meta(scan_results),
                        output_dir=f"scan-reports/{framework}/{username}",
                        regions=REGIONS,
                    )
                except Exception as e:
                    print(f"Error saving {framework} report for {account_id}: {e}")
                    notifications["error"].append(f"Report save failed: {account_id}")
                    continue

                try:
                    _progress(98)
                    print("Uploading reports...")
                    upload_to_s3(
                        file_name=saved_filename,
                        folder_name=f"scan-reports/{framework}/{username}",
                        s3_folder_name=f"aws-account-security-reports/{username}/{framework}",
                    )
                    print("Upload complete")
                except Exception as e:
                    print(
                        f"Error uploading {framework} report to S3 for {account_id}: {e}"
                    )
                    notifications["error"].append(f"S3 upload failed: {account_id}")

                notifications["success"].append(
                    f"{framework} scan successful: {account_id}"
                )

            except Exception as e:
                print(f"Unexpected error for account {account_id}: {e}")
                notifications["error"].append(
                    f"Unknown error for account: {account_id}"
                )

        return {
            "status": "ok",
            "framework": framework.upper(),
            "notifications": notifications,
        }

    except Exception as e:
        print(f"Unexpected error in run_framework_scan: {e}")
        return {"status": "error", "error_message": "Unknown error occurred"}
    finally:
        # Restore stdout if we were capturing
        if _real_stdout:
            stop_capture(_real_stdout)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _fresh_meta(framework: str) -> dict:
    """Returns a clean scan_meta_data dict for each scan run."""
    return {
        "total_scanned": 0,
        "affected": 0,
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "services_scanned": [],
        "framework": framework.upper(),
        "scan_time": datetime.now(IST).isoformat(),
    }


def _merge_meta(scan_results: list) -> dict:
    """Merges scan_meta_data from all regions into one summary dict."""
    merged = _fresh_meta("merged")
    for result in scan_results:
        meta = result.get("scan_meta_data", {})
        merged["total_scanned"] += meta.get("total_scanned", 0)
        merged["affected"] += meta.get("affected", 0)
        merged["Critical"] += meta.get("Critical", 0)
        merged["High"] += meta.get("High", 0)
        merged["Medium"] += meta.get("Medium", 0)
        merged["Low"] += meta.get("Low", 0)
        for svc in meta.get("services_scanned", []):
            if svc not in merged["services_scanned"]:
                merged["services_scanned"].append(svc)
    return merged
