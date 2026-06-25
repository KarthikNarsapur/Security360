import boto3
import os
from botocore.exceptions import ClientError
from Model.model import AccessTokenModel


def get_vpc_flow_logs_function(data: AccessTokenModel):
    """
    Fetch all VPC Flow Logs (all destination types) grouped by
    account_id -> region -> [flow log details]

    Supports:
    - cloud-watch-logs (CloudWatch Log Groups)
    - s3 (S3 Buckets)
    - kinesis-data-firehose (Firehose delivery streams)
    """
    try:
        if not data.username:
            return {"status": "error", "error_message": "Username is missing."}
        if not data.regions or len(data.regions) == 0:
            return {"status": "error", "error_message": "Regions list is missing."}
        if not data.accounts or len(data.accounts) == 0:
            return {"status": "error", "error_message": "Accounts list is missing."}

        results = {}
        notifications = {"success": [], "error": []}

        for role in data.accounts:
            account_id = role.account_id
            role_arn = role.role_arn
            account_name = role.account_name or ""

            if account_id not in results:
                results[account_id] = {}

            if not account_id or not role_arn:
                notifications["error"].append(f"Missing role details for {account_id}")
                continue

            try:
                # 1. Assume role into target account
                sts_client = boto3.client("sts")
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn, RoleSessionName="VpcFlowLogsSession"
                )

                credentials = assumed_role["Credentials"]
                access_key = credentials["AccessKeyId"]
                secret_key = credentials["SecretAccessKey"]
                session_token = credentials["SessionToken"]

                # 2. Loop through regions
                for region in data.regions:
                    try:
                        ec2_client = boto3.client(
                            "ec2",
                            region_name=region,
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key,
                            aws_session_token=session_token,
                        )

                        # Fetch ALL flow logs (no destination-type filter)
                        paginator = ec2_client.get_paginator("describe_flow_logs")
                        pages = paginator.paginate()

                        vpc_flow_logs = []
                        for page in pages:
                            for fl in page.get("FlowLogs", []):
                                destination_type = fl.get("LogDestinationType", "cloud-watch-logs")
                                log_entry = {
                                    "flowLogId": fl.get("FlowLogId"),
                                    "destinationType": destination_type,
                                }

                                if destination_type == "cloud-watch-logs":
                                    log_entry["logGroupName"] = fl.get("LogGroupName")
                                elif destination_type == "s3":
                                    log_destination = fl.get("LogDestination", "")
                                    # LogDestination for S3 is like: arn:aws:s3:::bucket-name/prefix
                                    log_entry["s3Destination"] = log_destination
                                    bucket, prefix = _parse_s3_destination(log_destination)
                                    log_entry["s3Bucket"] = bucket
                                    log_entry["s3Prefix"] = prefix
                                elif destination_type == "kinesis-data-firehose":
                                    log_entry["firehoseArn"] = fl.get("LogDestination", "")

                                vpc_flow_logs.append(log_entry)

                        results[account_id][region] = vpc_flow_logs
                        notifications["success"].append(
                            f"Fetched VPC Flow Logs for {account_id} in {region}"
                        )

                    except ClientError as e:
                        results[account_id][region] = []
                        notifications["error"].append(
                            f"Error in {account_id}-{region}: {e.response['Error']['Code']}"
                        )

            except Exception as e:
                notifications["error"].append(
                    f"Role assume failed for {account_id}: {str(e)}"
                )
                continue

        return {"status": "ok", "response": results, "notifications": notifications}

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {"status": "error", "error_message": str(e)}


def _parse_s3_destination(log_destination: str):
    """
    Parse S3 ARN destination into bucket and prefix.
    Example: arn:aws:s3:::my-bucket/my-prefix -> ("my-bucket", "my-prefix")
    Example: arn:aws:s3:::my-bucket -> ("my-bucket", "")
    """
    try:
        # Remove the ARN prefix: arn:aws:s3:::
        if log_destination.startswith("arn:aws:s3:::"):
            path = log_destination.replace("arn:aws:s3:::", "")
        else:
            path = log_destination

        if "/" in path:
            bucket = path.split("/")[0]
            prefix = "/".join(path.split("/")[1:])
        else:
            bucket = path
            prefix = ""

        return bucket, prefix
    except Exception:
        return "", ""
