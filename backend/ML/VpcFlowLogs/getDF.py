import json
import pandas as pd

from modules.Logs.cloudwatch import get_cloudwatch_logs
from modules.Logs.s3_flow_logs import get_s3_flow_logs
from modules.Logs.firehose_flow_logs import get_firehose_flow_logs
from Model.model import DateRangeModel


def getDataframe(cw_client=None, log_group_name=None, s3_client=None,
                 bucket=None, prefix=None, account_id=None, region=None,
                 firehose_client=None, firehose_arn=None,
                 destination_type="cloud-watch-logs"):
    """
    Build a DataFrame from VPC Flow Logs regardless of source.

    Supports:
    - cloud-watch-logs: reads from CloudWatch Log Groups
    - s3: reads from S3 bucket
    - kinesis-data-firehose: reads from Firehose (which delivers to S3)
    """

    if destination_type == "cloud-watch-logs":
        data = get_cloudwatch_logs(cw_client=cw_client, log_group_name=log_group_name)
    elif destination_type == "s3":
        data = get_s3_flow_logs(
            s3_client=s3_client,
            bucket=bucket,
            prefix=prefix,
            account_id=account_id,
            region=region,
        )
    elif destination_type == "kinesis-data-firehose":
        data = get_firehose_flow_logs(
            firehose_client=firehose_client,
            s3_client=s3_client,
            firehose_arn=firehose_arn,
            region=region,
        )
    else:
        return {
            "status": "error",
            "error_message": f"Unsupported destination type: {destination_type}",
        }

    if isinstance(data, dict) and data.get("status") == "error":
        return data

    if not data:
        return {
            "status": "error",
            "error_message": "No log data returned from source.",
        }

    col = "account-id action az-id bytes dstaddr dstport end flow-direction instance-id interface-id log-status packets pkt-dst-aws-service pkt-dstaddr pkt-src-aws-service pkt-srcaddr protocol region reject-reason srcaddr srcport start sublocation-id sublocation-type subnet-id tcp-flags traffic-path type version vpc-id"
    columns = col.split(" ")
    log_lines = [entry["message"] for entry in data if entry["message"].strip()]
    parsed_logs = [
        line.split() for line in log_lines if len(line.split()) == len(columns)
    ]

    df = pd.DataFrame(parsed_logs, columns=columns)
    return df
