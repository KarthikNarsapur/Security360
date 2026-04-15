from modules.CIS.cis_account import check_account_security_contact
from modules.CIS.cis_cloudtrail import (
    check_cloudtrail_multi_region_enabled,
    check_cloudtrail_encryption_at_rest,
    check_cloudtrail_log_file_validation,
    check_cloudtrail_s3_logging,
)
from modules.CIS.cis_config import check_aws_config_enabled
from modules.CIS.cis_ec2 import (
    check_vpc_default_sg_traffic,
    check_vpc_flow_logs_enabled,
    check_ebs_default_encryption,
    check_ec2_imdsv2_enabled,
    check_network_acl_restricted_ports,
    check_ec2_security_group_restricted_admin_ports,
    check_ec2_security_group_ipv6_admin_ports,
)
from modules.CIS.cis_efs import check_efs_encryption_at_rest
from modules.CIS.cis_iam import (
    check_iam_user_policies,
    check_iam_access_key_rotation,
    check_root_access_key,
    check_iam_mfa_enabled,
    check_root_hardware_mfa,
    check_root_mfa_enabled,
    check_iam_password_policy_length,
    check_iam_password_reuse_prevention,
    check_support_role_exists,
    check_unused_iam_credentials,
    check_expired_iam_certificates,
    check_cloudshell_full_access_policy,
    check_access_analyzer_enabled,
)
from modules.CIS.cis_kms import check_kms_key_rotation
from modules.CIS.cis_rds import (
    check_rds_public_access,
    check_rds_encryption_at_rest,
    check_rds_auto_minor_version_upgrade,
)
from modules.CIS.cis_s3 import (
    check_s3_block_public_access,
    check_s3_ssl_requirement,
    check_s3_bucket_public_access_block,
    check_s3_mfa_delete,
    check_s3_object_write_logging,
    check_s3_object_read_logging,
)
from Model.model import AccessTokenModel
import boto3
import os
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime, timezone, timedelta
from utils.upload_to_s3 import upload_to_s3, save_report


IST = timezone(timedelta(hours=5, minutes=30))


def calculate_total_functions(regions_cnt, accounts_cnt):
    """Calculate total functions to be executed"""
    cis_checks_count = len(cis_checks)
    print(
        "len(regions) * cis_checks_count: ",
        regions_cnt * cis_checks_count * accounts_cnt,
    )
    return regions_cnt * cis_checks_count * accounts_cnt


active_connections = []


async def websocket_manager(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def send_progress_update(
    progress: int, status: str = "scanning", message: str = ""
):
    data = {"progress": progress, "status": status, "message": message}

    # Remove disconnected clients
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_json(data)
        except:
            disconnected.append(connection)

    for conn in disconnected:
        active_connections.remove(conn)


cis_checks = {
    #   Account checks
    "Account.1": check_account_security_contact,
    #   CloudTrail checks
    "CloudTrail.1": check_cloudtrail_multi_region_enabled,
    "CloudTrail.2": check_cloudtrail_encryption_at_rest,
    "CloudTrail.4": check_cloudtrail_log_file_validation,
    "CloudTrail.7": check_cloudtrail_s3_logging,
    #   Config checks
    "Config.1": check_aws_config_enabled,
    #   EC2 checks
    "EC2.2": check_vpc_default_sg_traffic,
    "EC2.6": check_vpc_flow_logs_enabled,
    "EC2.7": check_ebs_default_encryption,
    "EC2.8": check_ec2_imdsv2_enabled,
    "EC2.21": check_network_acl_restricted_ports,
    "EC2.53": check_ec2_security_group_restricted_admin_ports,
    "EC2.54": check_ec2_security_group_ipv6_admin_ports,
    #   EFS checks
    "EFS.1": check_efs_encryption_at_rest,
    #   IAM checks
    "IAM.2": check_iam_user_policies,
    "IAM.3": check_iam_access_key_rotation,
    "IAM.4": check_root_access_key,
    "IAM.5": check_iam_mfa_enabled,
    "IAM.6": check_root_hardware_mfa,
    "IAM.9": check_root_mfa_enabled,
    "IAM.15": check_iam_password_policy_length,
    "IAM.16": check_iam_password_reuse_prevention,
    "IAM.18": check_support_role_exists,
    "IAM.22": check_unused_iam_credentials,
    "IAM.26": check_expired_iam_certificates,
    "IAM.27": check_cloudshell_full_access_policy,
    "IAM.28": check_access_analyzer_enabled,
    #   KMS checks
    "KMS.4": check_kms_key_rotation,
    #   RDS checks
    "RDS.2": check_rds_public_access,
    "RDS.3": check_rds_encryption_at_rest,
    "RDS.13": check_rds_auto_minor_version_upgrade,
    #   S3 checks
    "S3.1": check_s3_block_public_access,
    "S3.5": check_s3_ssl_requirement,
    "S3.8": check_s3_bucket_public_access_block,
    "S3.20": check_s3_mfa_delete,
    "S3.22": check_s3_object_write_logging,
    "S3.23": check_s3_object_read_logging,
    
}


async def run_cis_checks(session, total_functions, completed_functions, region):
    cisScanResults = {}
    # current_completed = completed_functions

    for check_id, check_function in cis_checks.items():
        print("completed functions: ", completed_functions)
        try:
            # print(f"Executing check: {check_id}")
            cisScanResults[check_id] = check_function(session)
            completed_functions += 1

            progress = int((completed_functions / total_functions) * 95)
            await send_progress_update(
                progress, "scanning", f"Completed {check_id} in {region}"
            )

            await asyncio.sleep(0.1)

        except Exception as e:
            print(f"Error in check {check_id}: {e}")

            completed_functions += 1
            progress = int((completed_functions / total_functions) * 95)

            await send_progress_update(
                progress, "scanning", f"Error in {check_id} in {region}: {str(e)}"
            )

    return cisScanResults


async def cis_rules_scan_function(data: AccessTokenModel):

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

        threshold_response = check_scan_threshold(username=username, scan_type="cis")
        if threshold_response.get("status") == "error":
            return threshold_response

        total_functions = calculate_total_functions(
            regions_cnt=len(REGIONS), accounts_cnt=len(roles_info)
        )
        completed_functions = 0
        await send_progress_update(0, "scanning", "Initializing CIS scan...")

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
                    await send_progress_update(
                        int((completed_functions / total_functions) * 95),
                        "error",
                        f"Failed to assume role for account {account_id}",
                    )
                    continue

                credentials = assumed_role["Credentials"]
                access_key = credentials["AccessKeyId"]
                secret_key = credentials["SecretAccessKey"]
                session_token = credentials["SessionToken"]
                regional_results = []
                failed_regions = []

                for region in REGIONS:
                    print(f"\n Scanning account ({account_id})...")
                    session = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        aws_session_token=session_token,
                        region_name=region,
                    )

                    if not session:
                        print(f" Failed to create session for account {account_id}")
                        completed_functions += len(cis_checks)
                        failed_regions.append(region)
                        continue

                    print(f" Checking region: {region}")
                    try:
                        region_progress = int(
                            (completed_functions / total_functions) * 95
                        )

                        await send_progress_update(
                            region_progress,
                            "scanning",
                            f"Scanning region {region} ",
                        )
                        results = await run_cis_checks(
                            session=session,
                            total_functions=total_functions,
                            completed_functions=completed_functions,
                            region=region,
                        )
                        completed_functions += len(cis_checks)
                        regional_results.append({"region": region, "data": results})
                    except Exception as e:
                        completed_functions += len(cis_checks)
                        await send_progress_update(
                            int((completed_functions / total_functions) * 100),
                            "error",
                            f"Error scanning region {region}: {str(e)}",
                        )
                        print(
                            f" Error scanning region {region} for account {account_id}: {e}"
                        )
                await send_progress_update(95, "scanning", "Saving scan results...")
                if len(failed_regions) > 0:
                    print(f"failed scan for {account_id} in regions: {failed_regions}")

                if len(failed_regions) == len(REGIONS):
                    print(f"failed scan for {account_id} in all regions")

                try:

                    # save report and upload to S3
                    print("sending this report: ", regional_results)
                    saved_filename = save_report(
                        account_id=account_id,
                        username=username,
                        account_name=account_name,
                        results=regional_results,
                        type="cis",
                        output_dir=f"scan-reports/cis/{username}",
                        regions=REGIONS,
                    )
                except Exception as e:
                    print(f"Error saving scan report for account {account_id}: {e}")
                    notifications["error"].append(f"Report save failed: {account_id}")
                    continue

                try:
                    await send_progress_update(
                        98, "scanning", "Uploading results to S3..."
                    )
                    upload_to_s3(
                        file_name=saved_filename,
                        folder_name=f"cis-reports/{username}",
                        s3_folder_name=f"CIS-rules/{username}",
                    )
                except Exception as e:
                    await send_progress_update(0, "error", f"Upload failed: {str(e)}")
                    notifications["error"].append(
                        f" Error uploading data to S3 for account id: {account_id}"
                    )

                try:
                    increament_scan_count(username=username, scan_type="cis")
                    await send_progress_update(
                        100, "completed", "Scan completed successfully"
                    )
                    notifications["success"].append(f"scan successfull : {account_id}")
                except Exception as e:
                    print(
                        f"Error incrementing scan count for account {account_id}: {e}"
                    )

                    print(f" Error uploading data to S3: {e}")

            except Exception as e:
                print(f"got error for account id: {account_id}: {str(e)}")
                notifications["error"].append(
                    f"Unknown error occured for account id: {account_id}"
                )
        return {"status": "ok", "notifications": notifications}

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        await send_progress_update(0, "error", f"Scanning failed: {str(e)}")
        return {"status": "error", "message": str(e)}
