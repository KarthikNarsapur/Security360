from Model.model import AccessTokenModel
import boto3
import os
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime, timezone, timedelta
from utils.upload_to_s3 import upload_to_s3, save_report


IST = timezone(timedelta(hours=5, minutes=30))

awaf_checks = {}


import importlib
import pkgutil
import inspect
from modules import AWAF

import importlib.util
import inspect
import os

import os
import importlib.util
import inspect


def load_awaf_checks(pillars: list[str]):
    awaf_checks = {}

    base_dir = os.path.dirname(__file__)

    for pillar in pillars:
        pillar_folder_name = pillar
        # .replace(" ", "_").lower()
        pillar_path = os.path.join(base_dir, pillar_folder_name)

        if not os.path.exists(pillar_path):
            print(f"Pillar folder not found: {pillar_path}")
            continue

        for root, dirs, files in os.walk(pillar_path):
            for file in files:
                if file.endswith(".py") and file != "__init__.py":
                    full_path = os.path.join(root, file)

                    rel_path = os.path.relpath(full_path, base_dir)
                    module_name = "modules.AWAF." + rel_path[:-3].replace(
                        os.path.sep, "."
                    )

                    spec = importlib.util.spec_from_file_location(
                        module_name, full_path
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    for name, func in inspect.getmembers(module, inspect.isfunction):
                        if name.startswith("check_"):
                            check_id = name.replace("check_", "")
                            awaf_checks[check_id] = func

    print(f"Loaded {len(awaf_checks)} checks from pillars: {pillars}")
    return awaf_checks


# active_connections = []


# async def websocket_manager(websocket: WebSocket):
#     await websocket.accept()
#     active_connections.append(websocket)
#     try:
#         while True:
#             await websocket.receive_text()
#     except WebSocketDisconnect:
#         active_connections.remove(websocket)


# async def send_progress_update(
#     progress: int, status: str = "scanning", message: str = ""
# ):
#     data = {"progress": progress, "status": status, "message": message}

#     # Remove disconnected clients
#     disconnected = []
#     for connection in active_connections:
#         try:
#             await connection.send_json(data)
#         except:
#             disconnected.append(connection)

#     for conn in disconnected:
#         active_connections.remove(conn)


async def run_awaf_checks(
    session,
    #  total_functions,
    # completed_functions,
    region,
    pillars,
):
    awafScanResults = {}
    # current_completed = completed_functions
    awaf_checks = load_awaf_checks(pillars=pillars)
    for check_id, check_function in awaf_checks.items():
        # print("completed functions: ", completed_functions)
        try:
            print(f"Executing check: {check_id}")
            awafScanResults[check_id] = check_function(session)
            # completed_functions += 1

            # progress = int((completed_functions / total_functions) * 95)
            # await send_progress_update(
            #     progress, "scanning", f"Completed {check_id} in {region}"
            # )

            # await asyncio.sleep(0.1)

        except Exception as e:
            print(f"Error in check {check_id}: {e}")

            # completed_functions += 1
            # progress = int((completed_functions / total_functions) * 95)

            # await send_progress_update(
            #     progress, "scanning", f"Error in {check_id} in {region}: {str(e)}"
            # )

    return awafScanResults


async def awaf_rules_scan_function(data: AccessTokenModel):

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

        if not data.pillars or len(data.pillars) == 0:
            return {"status": "error", "error_message": "Pillar is missing."}

        REGIONS = data.regions
        username = data.username
        roles_info = data.accounts
        pillars = data.pillars

        # threshold_response = check_scan_threshold(username=username, scan_type="cis")
        # if threshold_response.get("status") == "error":
        #     return threshold_response

        # total_functions = calculate_total_functions(
        #     regions_cnt=len(REGIONS), accounts_cnt=len(roles_info)
        # )
        # completed_functions = 0
        # await send_progress_update(0, "scanning", "Initializing CIS scan...")

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
                    # await send_progress_update(
                    #     int((completed_functions / total_functions) * 95),
                    #     "error",
                    #     f"Failed to assume role for account {account_id}",
                    # )
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
                        # completed_functions += len(cis_checks)
                        failed_regions.append(region)
                        continue

                    print(f" Checking region: {region}")
                    try:
                        # region_progress = int(
                        #     (completed_functions / total_functions) * 95
                        # )

                        # await send_progress_update(
                        #     region_progress,
                        #     "scanning",
                        #     f"Scanning region {region} ",
                        # )
                        results = await run_awaf_checks(
                            session=session,
                            # total_functions=total_functions,
                            # completed_functions=completed_functions,
                            region=region,
                            pillars=pillars,
                        )
                        # completed_functions += len(cis_checks)
                        regional_results.append({"region": region, "data": results})
                    except Exception as e:
                        # completed_functions += len(cis_checks)
                        # await send_progress_update(
                        #     int((completed_functions / total_functions) * 100),
                        #     "error",
                        #     f"Error scanning region {region}: {str(e)}",
                        # )
                        print(
                            f" Error scanning region {region} for account {account_id}: {e}"
                        )

                # await send_progress_update(95, "scanning", "Saving scan results...")
                if len(failed_regions) > 0:
                    print(f"failed scan for {account_id} in regions: {failed_regions}")

                if len(failed_regions) == len(REGIONS):
                    print(f"failed scan for {account_id} in all regions")

                try:

                    # save report and upload to S3
                    # print("sending this report: ", regional_results)
                    saved_filename = save_report(
                        account_id=account_id,
                        username=username,
                        account_name=account_name,
                        results=regional_results,
                        type="awaf",
                        output_dir=f"scan-reports/awaf/{username}",
                        regions=REGIONS,
                    )
                except Exception as e:
                    print(f"Error saving scan report for account {account_id}: {e}")
                    notifications["error"].append(f"Report save failed: {account_id}")
                    continue

                try:
                    # await send_progress_update(
                    #     98, "scanning", "Uploading results to S3..."
                    # )
                    print("file upload to s3")
                    upload_to_s3(
                        file_name=saved_filename,
                        folder_name=f"scan-reports/awaf/{username}",
                        s3_folder_name=f"AWAF-rules/{username}",
                    )
                except Exception as e:
                    # await send_progress_update(0, "error", f"Upload failed: {str(e)}")
                    notifications["error"].append(
                        f" Error uploading data to S3 for account id: {account_id}"
                    )

                    # try:
                    #     increament_scan_count(username=username, scan_type="cis")
                    #     await send_progress_update(
                    #         100, "completed", "Scan completed successfully"
                    #     )
                    #     notifications["success"].append(f"scan successfull : {account_id}")
                    # except Exception as e:
                    #     print(
                    #         f"Error incrementing scan count for account {account_id}: {e}"
                    #     )

                    print(f" Error uploading data to S3: {e}")

            except Exception as e:
                print(f"got error for account id: {account_id}: {str(e)}")
                notifications["error"].append(
                    f"Unknown error occured for account id: {account_id}"
                )
        return {"status": "ok", "notifications": notifications}

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        # await send_progress_update(0, "error", f"Scanning failed: {str(e)}")
        return {"status": "error", "message": str(e)}
