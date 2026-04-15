import datetime
from datetime import datetime, timedelta, timezone
import boto3
import json

IST = timezone(timedelta(hours=5, minutes=30))
filepath = "Cloudtrail/output.json"


def get_cloud_trail_logs(ct_client):
    all_events = []

    # start_date = date_range.start_date
    # end_date = date_range.end_date
    IST = timezone(timedelta(hours=5, minutes=30))
    end_date = datetime.now(IST).strftime("%Y-%m-%d")
    start_date = (datetime.now(IST) - timedelta(days=60)).strftime("%Y-%m-%d")
    print(start_date, end_date)

    try:
        kwargs = {}
        if start_date:
            kwargs["StartTime"] = datetime.strptime(start_date, "%Y-%m-%d")
        if end_date:
            kwargs["EndTime"] = datetime.strptime(end_date, "%Y-%m-%d")
        cnt = 20
        while True:
            print("cnt: ", cnt)
            cnt = cnt - 1
            response = ct_client.lookup_events(**kwargs)
            all_events.extend(response["Events"])

            if (cnt > 0) and ("NextToken" in response):
                kwargs["NextToken"] = response["NextToken"]
            else:
                break

        for e in response["Events"]:
            all_events.append(e)
    except Exception as e:
        print(f"Error retrieving events: {str(e)}")
        return {"status": "error", "error_message": "Error retrieving events"}
    return {"all_events": all_events}

    # Save to output.json
    # with open(filepath, "w") as f:
    #     json.dump(all_events, f, indent=2, default=str)

    # print(f"Saved {len(all_events)} events to output.json")


# get_cloud_trail_logs("2025-05-10", "2025-05-15")
