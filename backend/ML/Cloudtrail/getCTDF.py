import pandas as pd
import json

from Model.model import DateRangeModel
from modules.Logs.cloudtrail import get_cloud_trail_logs


def getCTLogsDF(ct_client):

    # filepath = "modules/Logs/Cloudtrail/output2.json"
    # with open(filepath, "r") as f:
    #     events = json.load(f)

    data = get_cloud_trail_logs(ct_client)
    if data.get("status") == "error":
        return data
    all_events = data.get("all_events", [])

    parsed_events = []

    for event in all_events:
        try:
            ct_event = json.loads(event.get("CloudTrailEvent", "{}"))

            user_identity = ct_event.get("userIdentity", {})
            request_params = ct_event.get("requestParameters", {})
            response_elements = ct_event.get("responseElements", {})

            base_event = {
                "event_time": ct_event.get("eventTime"),
                "event_source": ct_event.get("eventSource"),
                "event_name": ct_event.get("eventName"),
                "aws_region": ct_event.get("awsRegion"),
                "source_ip_address": ct_event.get("sourceIPAddress"),
                "user_agent": ct_event.get("userAgent"),
                "event_type": ct_event.get("eventType"),
                "user_type": user_identity.get("type"),
                "principal_id": user_identity.get("principalId"),
                "arn": user_identity.get("arn"),
                "account_id": user_identity.get("accountId"),
                "request_params": json.dumps(request_params),
                "response_elements": json.dumps(response_elements),
            }

            parsed_events.append(base_event)

        except Exception as e:
            print(f"Error parsing event: {e}")

    df = pd.DataFrame(parsed_events)
    df["event_time"] = df["event_time"].apply(lambda x: pd.to_datetime(x).isoformat())

    return df
