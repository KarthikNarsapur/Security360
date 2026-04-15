import boto3
import os
import json
from datetime import datetime, timezone, timedelta

# from backend.modules.Other import ou
from modules import (
    ec2_checks,
    iam_checks,
    nacl_checks,
    rds_checks,
    s3_checks,
    security_checks,
    vpc_checks,
    ssm_checks,
    secrets_manager_checks,
    guardduty_checks,
    cloudtrail_checks
)
from Model.model import AccessTokenModel
from utils.upload_to_s3 import upload_to_s3

CONFIG_FILE = "./config/accounts.json"
REPORT_FILE = "./reports"
IST = timezone(timedelta(hours=5, minutes=30))


def run_checks(session, scan_meta_data={}, security_services_scan={}):

    security_services_scan["Amazon GuardDuty"] = security_checks.guardduty_enabled(
        session
    )
    security_services_scan["AWS Config"] = security_checks.aws_config_enabled(session)
    security_services_scan["Amazon Inspector"] = security_checks.inspector_enabled(
        session
    )
    security_services_scan["AWS Security Hub"] = security_checks.security_hub_enabled(
        session
    )
    security_services_scan["AWS Access Analyzer"] = (
        security_checks.access_analyzer_enabled(session)
    )
    security_services_scan["AWS Cloudtrail"] = security_checks.cloudtrail_enabled(
        session
    )
    security_services_scan["AWS WAF"] = security_checks.check_waf_enabled(session)
    return {
        "default_vpcs": vpc_checks.check_default_vpcs(session, scan_meta_data),
        "open_security_groups": ec2_checks.check_open_security_groups(
            session, scan_meta_data
        ),
        "unused_security_groups": ec2_checks.find_unused_security_groups(
            session, scan_meta_data
        ),
        "unencrypted_ebs_volumes": ec2_checks.unencrypted_ebs_volumes(
            session, scan_meta_data
        ),
        "termination_protection": ec2_checks.check_ec2_termination_protection(
            session, scan_meta_data
        ),
        "rds_public": rds_checks.check_public_rds(session, scan_meta_data),
        "rds_unencrypted": rds_checks.check_unencrypted_rds(session, scan_meta_data),
        "delete protection": rds_checks.check_rds_cluster_deletion_protection(
            session, scan_meta_data
        ),
        "secrets_manager": secrets_manager_checks.check_secrets_manager_enabled(
            session, scan_meta_data
        ),
        "guardduty_findings": guardduty_checks.check_guardduty_enabled(
            session, scan_meta_data
        ),
        "iam_access_analyzer_findings": iam_checks.check_iam_access_analyzer(
            session, scan_meta_data
        ),
        "ssm_patch_manager": ssm_checks.non_compliant_patch_instances(
            session, scan_meta_data
        ),
        
    }


def run_global_services_checks(session, scan_meta_data_global_services):

    iam = session.client("iam")

    # === Pre-fetch data ===
    users = iam.list_users()["Users"]
    policies = iam.list_policies(Scope="Local")["Policies"]
    account_summary = iam.get_account_summary()["SummaryMap"]
    roles = iam.list_roles()["Roles"]
    access_keys_map = {
        user["UserName"]: iam.list_access_keys(UserName=user["UserName"])[
            "AccessKeyMetadata"
        ]
        for user in users
    }

    return {
        "public_s3_buckets": s3_checks.public_s3_buckets(
            session, scan_meta_data_global_services
        ),
        "users_without_mfa": iam_checks.users_without_mfa(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            users=users,
        ),
        "overly_permissive_policies": iam_checks.overly_permissive_policies(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            policies=policies,
        ),
        "root_account_mfa_enabled": iam_checks.root_account_without_mfa(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            account_summary=account_summary,
        ),
        "access_keys_older_than_90_days": iam_checks.access_keys_older_than_90_days(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "active_access_keys_with_high_age": iam_checks.active_access_keys_with_high_age(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "iam_users_with_no_recent_activity": iam_checks.iam_users_with_no_recent_activity(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "passwords_older_than_90_days": iam_checks.passwords_older_than_90_days(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
        ),
        "multiple_active_access_keys": iam_checks.multiple_active_access_keys(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "iam_roles_without_recent_use": iam_checks.iam_roles_without_recent_use(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            roles=roles,
        ),
        "access_keys_last_used_over_90_days_ago": iam_checks.access_keys_last_used_over_90_days_ago(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "cloudtrail_and_logging": cloudtrail_checks.cloudtrail_and_logging_check(
            session=session
        ),
    }


def run_scan(data: AccessTokenModel):

    try:
        from utils.upload_to_s3 import save_report
        from db.crud import increament_scan_count, check_scan_threshold

        # step 1 check data
        if not data.username:
            return {
                "status": "error",
                "error_message": "Username is missing.",
            }
        if not data.regions or len(data.regions) == 0:
            return {
                "status": "error",
                "error_message": "AWS regions list is missing or empty.",
            }
        if not data.accounts or len(data.accounts) == 0:
            return {
                "status": "error",
                "error_message": "AWS accounts list is missing or empty.",
            }

        REGIONS = data.regions
        username = data.username
        roles_info = data.accounts

        threshold_response = check_scan_threshold(username=username, scan_type="basic")
        if threshold_response.get("status") == "error":
            return threshold_response

        # print("Username: ", username)
        # print("Regions: ", REGIONS)
        # print("Roles Info: ", roles_info)

        notifications = {"success": [], "error": []}
        # step 2: loop through roles and run scan
        for role in roles_info:
            account_id = role.account_id or ""
            role_arn = role.role_arn or ""
            account_name = role.account_name or ""
            if account_id == "" or role_arn == "":
                print(f"Missing account details: {account_id}")
                continue
            try:
                # step 3: assume Role
                sts_client = boto3.client("sts")
                try:
                    assumed_role = sts_client.assume_role(
                        RoleArn=role_arn, RoleSessionName="SecurityAuditSession"
                    )
                except Exception as e:
                    print(f"Error assuming role for {account_id}: {e}")
                    notifications["error"].append(f"Role assume failed: {account_id}")
                    continue

                credentials = assumed_role["Credentials"]
                access_key = credentials["AccessKeyId"]
                secret_key = credentials["SecretAccessKey"]
                session_token = credentials["SessionToken"]

                regional_results = []
                region_scan_meta_data = []
                region_security_services_scan = []

                scan_meta_data_global_services = {
                    "total_scanned": 0,
                    "affected": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Critical": 0,
                    "services_scanned": [],
                }
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token,
                    region_name="ap-south-1",
                )
                global_services_scan_results = run_global_services_checks(
                    session, scan_meta_data_global_services
                )
                failed_regions = []
                for region in REGIONS:
                    session = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        aws_session_token=session_token,
                        region_name=region,
                    )

                    if not session:
                        print(f" Failed to create session for account {account_id}")
                        failed_regions.append(region)
                        continue

                    print(f" Checking region: {region}")
                    try:
                        scan_meta_data = {
                            "total_scanned": 0,
                            "affected": 0,
                            "High": 0,
                            "Medium": 0,
                            "Low": 0,
                            "Critical": 0,
                            "services_scanned": [],
                        }
                        security_services_scan = {}
                        results = run_checks(
                            session, scan_meta_data, security_services_scan
                        )
                        regional_results.append({"region": region, "data": results})
                        region_scan_meta_data.append(
                            {"region": region, "data": scan_meta_data}
                        )
                        region_security_services_scan.append(
                            {"region": region, "data": security_services_scan}
                        )
                    except Exception as e:
                        print(
                            f" Error scanning region {region} for account {account_id}: {e}"
                        )
                        failed_regions.append(region)

                if len(failed_regions) > 0:
                    print(f"failed scan for {account_id} in regions: {failed_regions}")

                # step 5: save report and upload to S3
                try:
                    saved_filename = save_report(
                        account_id=account_id,
                        username=username,
                        account_name=account_name,
                        results=regional_results,
                        type="summary",
                        scan_meta_data=region_scan_meta_data,
                        security_services_scan=region_security_services_scan,
                        global_services_scan_results=global_services_scan_results,
                        scan_meta_data_global_services=scan_meta_data_global_services,
                        output_dir=f"scan-reports/best-practices/{username}",
                        regions=REGIONS,
                    )
                except Exception as e:
                    print(f"Error saving scan report for account {account_id}: {e}")
                    notifications["error"].append(f"Report save failed: {account_id}")
                    continue
                try:
                    upload_to_s3(
                        file_name=saved_filename,
                        folder_name=f"scan-reports/best-practices/{username}",
                        s3_folder_name=f"aws-account-security-reports/{username}",
                    )

                except Exception as e:
                    print(f" Error uploading data to S3: {e}")
                    notifications["error"].append(
                        f" Error uploading data to S3 for account id: {account_id}"
                    )

                try:
                    increament_scan_count(username=username, scan_type="basic")
                    notifications["success"].append(f"scan successfull : {account_id}")
                except Exception as e:
                    print(
                        f"Error incrementing scan count for account {account_id}: {e}"
                    )
                    notifications["error"].append(
                        f"Failed to increment scan count for account: {account_id}"
                    )

            except Exception as e:
                print(f"got error for account id: {account_id}: {str(e)}")
                notifications["error"].append(
                    f"Unknown error occured for account id: {account_id}"
                )
        return {"status": "ok", "notifications": notifications}

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {"status": "error", "error_message": "Unknown error occured"}
