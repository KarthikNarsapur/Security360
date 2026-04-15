import boto3
from datetime import datetime, timedelta, timezone
import json
import os
from botocore.exceptions import ClientError

IST = timezone(timedelta(hours=5, minutes=30))

from Model.model import DateRangeModel


def get_cloudwatch_logs(cw_client, log_group_name):

    # print("Log streams: ", response["logStreams"])
    all_logs = []

    # start_date = date_range.start_date
    # end_date = date_range.end_date
    IST = timezone(timedelta(hours=5, minutes=30))
    end_date = datetime.now(IST).strftime("%Y-%m-%d")
    start_date = (datetime.now(IST) - timedelta(days=60)).strftime("%Y-%m-%d")
    print(start_date, end_date)

    try:
        response = cw_client.describe_log_streams(
            logGroupName=log_group_name,
            orderBy="LastEventTime",
            descending=True,
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            print(f"Log group '{log_group_name}' not found.")
            return {
                "status": "error",
                "error_message": f"Log group '{log_group_name}' not found.",
            }
        else:
            print(f"Error describing log streams: {str(e)}")
            return {
                "status": "error",
                "error_message": f"Log group '{log_group_name}' not found.",
            }
    for stream in response["logStreams"]:
        stream_name = stream["logStreamName"]
        start_time = (
            int(datetime.strptime(start_date, "%Y-%m-%d").timestamp() * 1000)
            if start_date
            else None
        )
        end_time = (
            int(datetime.strptime(end_date, "%Y-%m-%d").timestamp() * 1000)
            if end_date
            else None
        )

        kwargs = {
            "logGroupName": log_group_name,
            "logStreamName": stream_name,
            "startFromHead": True,
        }
        if start_time:
            kwargs["startTime"] = start_time
        if end_time:
            kwargs["endTime"] = end_time

        response = cw_client.get_log_events(**kwargs)
        if "events" in response:
            all_logs.extend(response["events"])

        # all_logs.extend(events)
    return all_logs

    # with open(filepath, "w", encoding="utf-8") as f:
    #     json.dump(all_logs, f, indent=4, ensure_ascii=False)

    # print(f"Logs saved to {filepath}")


# get_cloudwatch_logs()
