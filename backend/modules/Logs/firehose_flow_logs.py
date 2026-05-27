import boto3
import gzip
import io
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

IST = timezone(timedelta(hours=5, minutes=30))


def get_firehose_flow_logs(firehose_client, s3_client, firehose_arn, region):
    """
    Read VPC Flow Logs delivered via Amazon Data Firehose.

    Firehose delivers logs to an S3 bucket with this structure:
    {bucket}/{prefix}/YYYY/MM/DD/HH/

    We first describe the delivery stream to find the S3 destination,
    then read the log files from S3.
    """
    try:
        # Extract delivery stream name from ARN
        # ARN format: arn:aws:firehose:{region}:{account}:deliverystream/{name}
        stream_name = firehose_arn.split("/")[-1] if "/" in firehose_arn else firehose_arn

        # Describe the delivery stream to get S3 destination
        response = firehose_client.describe_delivery_stream(
            DeliveryStreamName=stream_name
        )

        delivery_stream = response.get("DeliveryStreamDescription", {})
        destinations = delivery_stream.get("Destinations", [])

        if not destinations:
            return {
                "status": "error",
                "error_message": f"No destinations found for Firehose stream '{stream_name}'.",
            }

        # Find the S3 or extended S3 destination
        bucket = None
        prefix = ""

        for dest in destinations:
            # Check ExtendedS3DestinationDescription (most common)
            ext_s3 = dest.get("ExtendedS3DestinationDescription")
            if ext_s3:
                bucket_arn = ext_s3.get("BucketARN", "")
                bucket = bucket_arn.split(":::")[-1] if ":::" in bucket_arn else ""
                prefix = ext_s3.get("Prefix", "")
                break

            # Fallback: check S3DestinationDescription
            s3_dest = dest.get("S3DestinationDescription")
            if s3_dest:
                bucket_arn = s3_dest.get("BucketARN", "")
                bucket = bucket_arn.split(":::")[-1] if ":::" in bucket_arn else ""
                prefix = s3_dest.get("Prefix", "")
                break

        if not bucket:
            return {
                "status": "error",
                "error_message": f"Could not determine S3 destination for Firehose stream '{stream_name}'.",
            }

        # Now read logs from S3 (Firehose uses YYYY/MM/DD/HH/ structure)
        all_logs = []
        end_date = datetime.now(IST)
        start_date = end_date - timedelta(days=60)

        base_prefix = prefix.rstrip("/") + "/" if prefix else ""

        current_date = start_date
        while current_date <= end_date:
            # Firehose partitions by YYYY/MM/DD/HH
            for hour in range(24):
                date_prefix = (
                    f"{base_prefix}"
                    f"{current_date.strftime('%Y')}/"
                    f"{current_date.strftime('%m')}/"
                    f"{current_date.strftime('%d')}/"
                    f"{hour:02d}/"
                )

                try:
                    paginator = s3_client.get_paginator("list_objects_v2")
                    pages = paginator.paginate(Bucket=bucket, Prefix=date_prefix)

                    for page in pages:
                        for obj in page.get("Contents", []):
                            key = obj["Key"]
                            try:
                                response = s3_client.get_object(Bucket=bucket, Key=key)
                                body = response["Body"].read()

                                # Firehose may gzip the files
                                if key.endswith(".gz"):
                                    body = gzip.decompress(body)

                                content = body.decode("utf-8")
                                lines = content.strip().split("\n")

                                for line in lines:
                                    stripped = line.strip()
                                    if stripped and not stripped.startswith("version"):
                                        all_logs.append({"message": stripped})

                            except ClientError as e:
                                print(f"Error reading Firehose S3 object {key}: {e}")
                                continue

                except ClientError:
                    # No objects for this hour, continue
                    continue

            current_date += timedelta(days=1)

        if not all_logs:
            return {
                "status": "error",
                "error_message": f"No flow log files found in Firehose stream '{stream_name}' (s3://{bucket}/{base_prefix}) for the last 60 days.",
            }

        return all_logs

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            return {
                "status": "error",
                "error_message": f"Firehose delivery stream '{stream_name}' not found.",
            }
        elif error_code == "AccessDeniedException":
            return {
                "status": "error",
                "error_message": f"Access denied to Firehose stream '{stream_name}'. Check IAM permissions.",
            }
        else:
            return {
                "status": "error",
                "error_message": f"Error accessing Firehose stream: {error_code}",
            }
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Unexpected error reading Firehose flow logs: {str(e)}",
        }
