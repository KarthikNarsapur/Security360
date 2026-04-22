import pandas as pd
import numpy as np
import json
import requests
import os
from botocore.exceptions import ClientError
from sklearn.preprocessing import StandardScaler
import boto3

from utils.exceptions import handle_error
from utils.upload_to_s3 import save_report, upload_to_s3
from ML.VpcFlowLogs.isolation_forest import getIsolationForestPrediction
from ML.VpcFlowLogs.one_class_svm import getOneClassSVMPrediction
from ML.VpcFlowLogs.autoencoder import getAutoEncoderPrediction
from ML.VpcFlowLogs.getDF import getDataframe
from Model.model import AccessTokenModel


def get_VPC_flow_log_findings(data: AccessTokenModel):
    try:

        from db.crud import increament_scan_count, check_scan_threshold

        BOTO3_REGION = os.getenv("BOTO3_REGION")

        # Validate input
        if not data.username:
            return {"status": "error", "error_message": "Username is missing."}
        if not data.regions:
            return {
                "status": "error",
                "error_message": "AWS regions list is missing or empty.",
            }
        if not data.accounts:
            return {
                "status": "error",
                "error_message": "AWS accounts list is missing or empty.",
            }

        REGIONS = data.regions
        username = data.username
        roles_info = data.accounts

        threshold_response = check_scan_threshold(
            username=username, scan_type="vpc-flow-logs"
        )
        if threshold_response.get("status") == "error":
            return threshold_response

        notifications = {"success": [], "error": []}

        # Loop over each AWS account
        for role in roles_info:
            account_id = role.account_id or ""
            role_arn = role.role_arn or ""
            account_name = role.account_name or ""

            if not account_id or not role_arn:
                print(f"Missing account details for account_id: {account_id}")
                continue

            try:
                # Assume role
                sts_client = boto3.client("sts", region_name=BOTO3_REGION)
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn, RoleSessionName="SecurityAuditSession"
                )
                credentials = assumed_role["Credentials"]

            except Exception as e:
                print(f"Error assuming role for {account_id}: {e}")
                notifications["error"].append(f"Role assume failed: {account_id}")
                continue

            # Loop over each region
            failed_regions = []
            failed_region_error_message = ""
            all_findings = []
            for region in REGIONS:

                # Get dataframe from CloudWatch logs
                cw_client = boto3.client(
                    "logs",
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    region_name=region,
                )
                print(data.vpcFlowLogNames.get(account_id, {}))
                log_group_name = (
                    data.vpcFlowLogNames.get(account_id, {}).get(region)
                    if data.vpcFlowLogNames
                    else None
                )
                if not log_group_name:
                    print(f"No log group selected for {account_id} in {region}")
                    failed_regions.append(region)
                    continue

                df = getDataframe(cw_client=cw_client, log_group_name=log_group_name)
                if isinstance(df, dict) and df.get("status") == "error":
                    print(f"Error: ", df.get("error_message"))
                    if failed_region_error_message == "":
                        failed_region_error_message = df.get("error_message")
                    failed_regions.append(region)
                    continue

                if df.empty:
                    print(f"No logs found for account {account_id} in region {region}")
                    failed_regions.append(region)
                    continue

                # Data cleaning
                df = df.replace("-", pd.NA)
                if "traffic-path" in df.columns:
                    df = df.drop(columns=["traffic-path"])

                categorical = ["action", "flow-direction", "dstaddr", "srcaddr"]
                numerical = [
                    "bytes",
                    "packets",
                    "protocol",
                    "dstport",
                    "srcport",
                    "tcp-flags",
                ]
                df[numerical] = df[numerical].apply(pd.to_numeric, errors="coerce")
                all_needed = categorical + numerical
                df = df.dropna(subset=all_needed).reset_index(drop=True)

                # One-hot encoding
                X_cat = pd.get_dummies(df[categorical], drop_first=True)
                X = pd.concat([df[numerical], X_cat], axis=1)

                # Scale
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

                # ML anomaly detection
                df = getIsolationForestPrediction(df, X_scaled)
                df = getOneClassSVMPrediction(df, X_scaled)
                df = getAutoEncoderPrediction(df, X_scaled)

                # Filter anomalies
                anomalies = df[
                    ((df["isf_anomaly"]) & (df["svm_anomaly"]))
                    | ((df["isf_anomaly"]) & (df["is_anomaly_auto_encoder"]))
                    | ((df["svm_anomaly"]) & (df["is_anomaly_auto_encoder"]))
                ]

                # Group anomalies
                group_keys = [
                    "bytes",
                    "instance-id",
                    "interface-id",
                    "region",
                    "subnet-id",
                    "vpc-id",
                    "srcaddr",
                    "dstaddr",
                    "dstport",
                    "protocol",
                    "action",
                ]
                grouped_df = (
                    anomalies.groupby(group_keys).size().reset_index(name="count")
                )

                # Sample findings
                sampled_findings = grouped_df.sample(
                    n=min(20, len(grouped_df)), random_state=42
                ).to_dict(orient="records")

                # Call external function
                function_url = os.getenv("FUNCTION_URL")
                response = requests.post(
                    function_url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps({"query": sampled_findings, "logs_type": "vpc"}),
                )
                result = response.json()
                output_findings = result.get("findingsData", {}).get("findings", [])
                all_findings.extend(output_findings)

            if len(failed_regions) > 0:
                print(f"failed scan for {account_id} in regions: {failed_regions}")

            if len(failed_regions) == len(REGIONS):
                print(f"failed scan for {account_id} in all regions")
                notifications["error"].append(
                    f"{failed_region_error_message} {account_id}"
                )
                continue

            try:
                # Save to S3
                saved_filename = save_report(
                    account_id=account_id,
                    username=username,
                    account_name=account_name,
                    results=all_findings,
                    type="threat_detection",
                    output_dir=f"scan-reports/threat-detection-reports/{username}/vpc-flow-logs"
                )
            except Exception as e:
                print(f"Error saving scan report for account {account_id}: {e}")
                notifications["error"].append(f"Report save failed: {account_id}")
                continue

            try:
                upload_to_s3(
                    file_name=saved_filename,
                    folder_name=f"threat_detection_reports/{username}/VPC_flow_logs",
                    s3_folder_name=f"AWS-Threat-Detection/{username}/VPC_flow_logs",
                )
            except Exception as e:
                print(f"Error uploading data to S3: {e}")
                notifications["error"].append(f"Report upload failed: {account_id}")
            try:
                increament_scan_count(username=username, scan_type="vpc-flow-logs")
                notifications["success"].append(
                    f"VPC flow logs scan successfull : {account_id}"
                )
            except Exception as e:
                print(f"Error incrementing scan count for account {account_id}: {e}")

        return {"status": "ok", "notifications": notifications}

    except ClientError as e:
        print(f"AWS ClientError: {str(e)}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {"status": "error", "error_message": str(e)}
