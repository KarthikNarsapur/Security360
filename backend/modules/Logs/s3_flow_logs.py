import boto3
import gzip
import io
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

IST = timezone(timedelta(hours=5, minutes=30))


def get_s3_flow_logs(s3_client, bucket, prefix, account_id, region):
    """
    Read VPC Flow Logs from an S3 bucket.

    VPC Flow Logs in S3 follow this structure:
    {bucket}/{prefix}/AWSLogs/{account_id}/vpcflowlogs/{region}/YYYY/MM/DD/

    Files are gzipped (.log.gz).
    """
    all_logs = []

    end_date = datetime.now(IST)
    start_date = end_date - timedelta(days=60)

    # Build the S3 prefix path for VPC flow logs
    base_prefix = prefix.rstrip("/") + "/" if prefix else ""
    log_prefix = f"{base_prefix}AWSLogs/{account_id}/vpcflowlogs/{region}/"

    try:
        # Iterate over each day in the date range
        current_date = start_date
        while current_date <= end_date:
            date_prefix = (
                f"{log_prefix}"
                f"{current_date.strftime('%Y')}/"
                f"{current_date.strftime('%m')}/"
                f"{current_date.strftime('%d')}/"
            )

            try:
                paginator = s3_client.get_paginator("list_objects_v2")
                pages = paginator.paginate(Bucket=bucket, Prefix=date_prefix)

                for page in pages:
                    for obj in page.get("Contents", []):
                        key = obj["Key"]
                        if not key.endswith(".log.gz") and not key.endswith(".log"):
                            continue

                        try:
                            response = s3_client.get_object(Bucket=bucket, Key=key)
                            body = response["Body"].read()

                            # Decompress if gzipped
                            if key.endswith(".gz"):
                                body = gzip.decompress(body)

                            content = body.decode("utf-8")
                            lines = content.strip().split("\n")

                            # Skip header line (first line contains column names)
                            for line in lines[1:]:
                                if line.strip():
                                    all_logs.append({"message": line.strip()})

                        except ClientError as e:
                            print(f"Error reading S3 object {key}: {e}")
                            continue

            except ClientError as e:
                # No objects for this date, continue
                if e.response["Error"]["Code"] == "NoSuchKey":
                    pass
                else:
                    print(f"Error listing S3 objects for {date_prefix}: {e}")

            current_date += timedelta(days=1)

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchBucket":
            return {
                "status": "error",
                "error_message": f"S3 bucket '{bucket}' not found.",
            }
        elif error_code == "AccessDenied":
            return {
                "status": "error",
                "error_message": f"Access denied to S3 bucket '{bucket}'. Check IAM permissions.",
            }
        else:
            return {
                "status": "error",
                "error_message": f"Error accessing S3 bucket '{bucket}': {error_code}",
            }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Unexpected error reading S3 flow logs: {str(e)}",
        }

    if not all_logs:
        return {
            "status": "error",
            "error_message": f"No flow log files found in s3://{bucket}/{log_prefix} for the last 60 days.",
        }

    return all_logs
