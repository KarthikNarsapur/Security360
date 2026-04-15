import boto3
import os
from botocore.exceptions import ClientError
from Model.model import AccessTokenModel


def get_vpc_flow_logs_function(data: AccessTokenModel):
    """
    Fetch all CloudWatch log groups for VPC Flow Logs
    grouped by account_id -> region -> [logGroupNames]
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

                        paginator = ec2_client.get_paginator("describe_flow_logs")
                        pages = paginator.paginate(
                            Filters=[
                                {
                                    "Name": "log-destination-type",
                                    "Values": ["cloud-watch-logs"],
                                }
                            ]
                        )
                        vpc_flow_logs = []
                        for page in pages:
                            for fl in page.get("FlowLogs", []):
                                vpc_flow_logs.append(
                                    {
                                        "flowLogId": fl.get("FlowLogId"),
                                        "logGroupName": fl.get("LogGroupName"),
                                    }
                                )

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
