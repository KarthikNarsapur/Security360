import json
import pandas as pd

from modules.Logs.cloudwatch import get_cloudwatch_logs
from Model.model import DateRangeModel


def getDataframe(cw_client, log_group_name):
    data = get_cloudwatch_logs(cw_client=cw_client, log_group_name=log_group_name)
    
    if isinstance(data, dict) and data.get("status") == "error":
        return data

    col = "account-id action az-id bytes dstaddr dstport end flow-direction instance-id interface-id log-status packets pkt-dst-aws-service pkt-dstaddr pkt-src-aws-service pkt-srcaddr protocol region reject-reason srcaddr srcport start sublocation-id sublocation-type subnet-id tcp-flags traffic-path type version vpc-id"
    columns = col.split(" ")
    log_lines = [entry["message"] for entry in data if entry["message"].strip()]
    parsed_logs = [
        line.split() for line in log_lines if len(line.split()) == len(columns)
    ]
    # print(parsed_logs[0])
    df = pd.DataFrame(parsed_logs, columns=columns)
    # print(df)
    return df
