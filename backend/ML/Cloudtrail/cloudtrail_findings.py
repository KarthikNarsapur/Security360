import pandas as pd
import numpy as np
import json
import requests
import os
from botocore.exceptions import ClientError

from utils.exceptions import handle_error

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from datetime import datetime

from ML.Cloudtrail.getCTDF import getCTLogsDF
from ML.Cloudtrail.isolation_forest import getIsolationForestPrediction
from ML.Cloudtrail.one_class_svm import getOneClassSVMPrediction
from ML.Cloudtrail.autoencoder import getAutoEncoderPrediction

from Model.model import DateRangeModel, AccessTokenModel

from utils.upload_to_s3 import save_report, upload_to_s3
import boto3


def flag_keywords(row, keywords):
    full_text = (
        str(row.get("event_name", ""))
        + " "
        + str(row.get("user_agent", ""))
        + " "
        + str(row.get("request_params", ""))
    ).lower()
    return sum(word in full_text for word in keywords)


def get_cloudtrail_findings(data: AccessTokenModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        from db.crud import increament_scan_count, check_scan_threshold

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
            username=username, scan_type="cloudtrail"
        )
        if threshold_response.get("status") == "error":
            return threshold_response

        notifications = {"success": [], "error": []}

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
                ct_client = boto3.client(
                    "cloudtrail",
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                    region_name=region,
                )

                df = getCTLogsDF(ct_client=ct_client)
                # print(len(df))

                if df.get("status") == "error":
                    print(f"Error: ", df.get("error_message"))
                    if failed_region_error_message == "":
                        failed_region_error_message = df.get("error_message")
                    failed_regions.append(region)
                    continue

                if df.empty:
                    print(f"No logs found for account {account_id} in region {region}")
                    failed_regions.append(region)
                    continue

                df = df.replace("-", pd.NA)
                categorical = [
                    "event_source",
                    "event_name",
                    "aws_region",
                    "user_type",
                    "source_ip_address",
                    "user_agent",
                    "event_type",
                    "arn",
                ]
                numerical = []

                df = df.dropna(subset=categorical).reset_index(drop=True)
                # df = df.groupby(categorical)
                grouped_df = (
                    df.groupby(categorical).size().reset_index(name="event_count")
                )
                # return grouped_counts.sort_values('event_count', ascending=False).to_dict(orient="records")

                # feature eng
                keywords = [
                    "delete",
                    "remove",
                    "drop",
                    "terminate",
                    "shutdown",
                    "root",
                    "privilege",
                    "access",
                    "unauthorized",
                    "admin",
                    "bypass",
                    "escalate",
                ]

                grouped_df["keyword_flag"] = grouped_df.apply(
                    lambda row: flag_keywords(row, keywords), axis=1
                )

                text_data = (
                    grouped_df["event_name"].fillna("")
                    + " "
                    + grouped_df["event_type"].fillna("")
                )
                vectorizer = TfidfVectorizer(max_features=10)
                tfidf_matrix = vectorizer.fit_transform(text_data).toarray()
                tfidf_df = pd.DataFrame(
                    tfidf_matrix, columns=vectorizer.get_feature_names_out()
                )

                columns_to_be_drop = list(tfidf_df.columns)
                columns_to_be_drop.append("keyword_flag")
                # print("columns_to_be_drop: ", columns_to_be_drop)

                grouped_df = pd.concat([grouped_df, tfidf_df], axis=1)

                df_encoded = pd.get_dummies(grouped_df[categorical], drop_first=True)

                # scaler = StandardScaler()
                scaler = MinMaxScaler()
                X_scaled = scaler.fit_transform(df_encoded)

                grouped_df = getIsolationForestPrediction(grouped_df, X_scaled)
                grouped_df = getOneClassSVMPrediction(grouped_df, X_scaled)
                grouped_df = getAutoEncoderPrediction(grouped_df, X_scaled)

                grouped_df = grouped_df.drop(columns=columns_to_be_drop)
                anomaly_df = grouped_df[
                    (
                        (grouped_df["isf_anomaly"] == True)
                        & (grouped_df["svm_anomaly"] == True)
                    )
                    | (
                        (grouped_df["isf_anomaly"] == True)
                        & (grouped_df["is_anomaly_auto_encoder"] == True)
                    )
                    | (
                        (grouped_df["svm_anomaly"] == True)
                        & (grouped_df["is_anomaly_auto_encoder"] == True)
                    )
                ].copy()

                sampled_findings = anomaly_df.sample(
                    n=min(50, len(anomaly_df)), random_state=42
                ).to_dict(orient="records")

                function_url = os.getenv("FUNCTION_URL")
                response = requests.post(
                    function_url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(
                        {"query": sampled_findings, "logs_type": "cloudtrail"}
                    ),
                )

                result = response.json()
                # print("result: ", result["findingsData"]["findings"])
                output_findings = result["findingsData"]["findings"]
                all_findings.extend(output_findings)

            if len(failed_regions) > 0:
                print(f"failed scan for {account_id} in regions: {failed_regions}")

            if len(failed_regions) == len(REGIONS):
                print(f"failed scan for {account_id} in all regions")
                notifications["error"].append(
                    f"{failed_region_error_message} {account_id}"
                )

            try:
                # save to s3
                saved_filename = save_report(
                    account_id=account_id,
                    account_name=account_name,
                    username=username,
                    results=all_findings,
                    type="threat_detection",
                    output_dir=f"scan-reports/threat-detection-reports/{username}/cloudtrail",
                )
            except Exception as e:
                print(f"Error saving scan report for account {account_id}: {e}")
                notifications["error"].append(f"Report save failed: {account_id}")
                continue

            try:
                upload_to_s3(
                    file_name=saved_filename,
                    folder_name=f"threat_detection_reports/{username}/Cloudtrail",
                    s3_folder_name=f"AWS-Threat-Detection/{username}/Cloudtrail",
                )
            except Exception as e:
                print(f" Error uploading data to S3: {e}")
                notifications["error"].append(f"Report upload failed: {account_id}")

            try:
                increament_scan_count(username=username, scan_type="cloudtrail")
                notifications["success"].append(
                    f"Cloudtrail logs scan successfull : {account_id}"
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
