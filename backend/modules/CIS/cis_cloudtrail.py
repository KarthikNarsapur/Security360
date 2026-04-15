import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_cloudtrail_multi_region_enabled(session):
    # [CloudTrail.1]
    print("Checking CloudTrail multi-region configuration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = session.region_name

    try:
        trails_response = cloudtrail.list_trails()
        all_trails = trails_response.get("Trails", [])
        trail_details = []

        has_compliant_trail = False
        for trail in all_trails:
            trail_name = trail["Name"]

            try:
                details = cloudtrail.get_trail(Name=trail_name).get("Trail", {})
                status = cloudtrail.get_trail_status(Name=trail_name)
                selectors = cloudtrail.get_event_selectors(TrailName=trail_name)

                is_compliant = (
                    details.get("IsMultiRegionTrail", False)
                    and status.get("IsLogging", False)
                    and any(
                        selector.get("IncludeManagementEvents", False)
                        and selector.get("ReadWriteType", "") == "All"
                        for selector in selectors.get("EventSelectors", [])
                    )
                )

                trail_info = {
                    "trail_name": trail_name,
                    "trail_arn": details.get("TrailARN"),
                    "is_multi_region": details.get("IsMultiRegionTrail", False),
                    "is_logging": status.get("IsLogging", False),
                    "management_events": any(
                        s.get("IncludeManagementEvents", False)
                        for s in selectors.get("EventSelectors", [])
                    ),
                    "read_write_type": next(
                        (
                            s.get("ReadWriteType", "")
                            for s in selectors.get("EventSelectors", [])
                            if s.get("IncludeManagementEvents", False)
                        ),
                        None,
                    ),
                    "s3_bucket": details.get("S3BucketName"),
                    "home_region": details.get("HomeRegion"),
                    "last_updated": datetime.now(IST).isoformat(),
                }
                trail_details.append(trail_info)

                if is_compliant:
                    has_compliant_trail = True
                    break

            except Exception as e:
                print(f"Error processing trail {trail_name}: {e}")

        return {
            "id": "CloudTrail.1",
            "check_name": "CloudTrail Multi-Region Configuration",
            "status": "passed" if has_compliant_trail else "failed",
            "severity_level": "High",
            "problem_statement": "At least one multi-region CloudTrail must log all management events",
            "resources_affected": [] if has_compliant_trail else trail_details,
            "additional_info": {
                "total_scanned": 0 if has_compliant_trail else len(all_trails),
                "affected": 0 if has_compliant_trail else len(all_trails),
            },
            "remediation_steps": [
                "1. Navigate to AWS CloudTrail service",
                "2. Create a new trail or modify an existing one",
                "3. Enable 'Apply trail to all regions' option",
                "4. Configure event selectors to include 'Management events' with 'Read and write' events",
                "5. Ensure trail logging is enabled",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail configuration: {e}")


def check_cloudtrail_encryption_at_rest(session):
    # [CloudTrail.2]
    print("Checking CloudTrail encryption at rest")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        trails_response = cloudtrail.list_trails()
        trails = trails_response.get("Trails", [])
        account_id = sts.get_caller_identity()["Account"]

        for trail in trails:
            trail_name = trail["Name"]
            trail_response = cloudtrail.get_trail(Name=trail_name)
            trail_info = trail_response.get("Trail", {})

            if not trail_info.get("KmsKeyId"):
                
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "trail_name": trail_name,
                        "trail_arn": trail_info.get("TrailARN"),
                        "home_region": trail_info.get("HomeRegion"),
                        "s3_bucket_name": trail_info.get("S3BucketName"),
                        "sns_topic_name": trail_info.get("SnsTopicName"),
                        "creation_time": str(trail_info.get("CreationTime")),
                        "region": session.region_name,
                        "issue": "CloudTrail not encrypted with KMS key",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(trails)
        affected = len(resources_affected)
        return {
            "id": "CloudTrail.2",
            "check_name": "CloudTrail Encryption at Rest",
            "problem_statement": "CloudTrail should have encryption at-rest enabled",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "recommendation": "Enable KMS encryption for all CloudTrail trails",
            "status": "passed" if affected == 0 else "failed",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to AWS CloudTrail service",
                "2. Select the trail without encryption",
                "3. Click 'Edit' and enable KMS encryption",
                "4. Select or create a KMS key for encryption",
                "5. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail encryption: {e}")
        return None


def check_cloudtrail_log_file_validation(session):
    # [CloudTrail.4]
    print("Checking CloudTrail log file validation")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        trails_response = cloudtrail.list_trails()
        trails = trails_response.get("Trails", [])
        account_id = sts.get_caller_identity()["Account"]

        for trail in trails:
            trail_name = trail["Name"]
            trail_response = cloudtrail.get_trail(Name=trail_name)
            trail_info = trail_response.get("Trail", {})

            if not trail_info.get("LogFileValidationEnabled", False):
                
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "trail_name": trail_name,
                        "trail_arn": trail_info.get("TrailARN"),
                        "home_region": trail_info.get("HomeRegion"),
                        "is_multi_region": trail_info.get("IsMultiRegionTrail", False),
                        "s3_bucket_name": trail_info.get("S3BucketName"),
                        "sns_topic_name": trail_info.get("SnsTopicName"),
                        "creation_time": str(trail_info.get("CreationTime")),
                        "region": session.region_name,
                        "issue": "CloudTrail log file validation disabled",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(trails)
        affected = len(resources_affected)
        return {
            "id": "CloudTrail.4",
            "check_name": "CloudTrail Log File Validation",
            "problem_statement": "CloudTrail log file validation should be enabled",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable log file validation for all CloudTrail trails",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to AWS CloudTrail service",
                "2. Select the trail without validation",
                "3. Click 'Edit' and enable 'Log file validation'",
                "4. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail validation: {e}")
        return None


def check_cloudtrail_s3_logging(session):
    # [CloudTrail.7]
    print("Checking CloudTrail S3 bucket access logging")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    s3 = session.client("s3")

    resources_affected = []

    try:
        trails_response = cloudtrail.list_trails()
        trails = trails_response.get("Trails", [])
        account_id = sts.get_caller_identity()["Account"]

        for trail in trails:
            trail_name = trail["Name"]
            trail_response = cloudtrail.get_trail(Name=trail_name)
            trail_info = trail_response.get("Trail", {})

            s3_bucket = trail_info.get("S3BucketName")
            if s3_bucket:
                logging_status = s3.get_bucket_logging(Bucket=s3_bucket)
                if not logging_status.get("LoggingEnabled"):
                    try:
                        bucket_location = s3.get_bucket_location(Bucket=s3_bucket)
                        bucket_region = (
                            bucket_location.get("LocationConstraint") or "us-east-1"
                        )
                    except Exception:
                        bucket_region = "Unknown"

                    try:
                        bucket_info = s3.head_bucket(Bucket=s3_bucket)
                        buckets = s3.list_buckets().get("Buckets", [])
                        creation_date = None
                        for b in buckets:
                            if b["Name"] == s3_bucket:
                                creation_date = str(b["CreationDate"])
                                break
                    except Exception:
                        creation_date = "Unknown"

                    try:
                        policy_status = s3.get_bucket_policy_status(
                            Bucket=s3_bucket
                        ).get("PolicyStatus", {})
                        is_public = policy_status.get("IsPublic", False)
                    except Exception:
                        is_public = "Unknown"

                    try:
                        tags_response = s3.get_bucket_tagging(Bucket=s3_bucket)
                        tags = {
                            tag["Key"]: tag["Value"]
                            for tag in tags_response.get("TagSet", [])
                        }
                    except Exception:
                        tags = {}

                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "trail_name": trail_name,
                            "resource_id": s3_bucket,
                            "creation_date": creation_date,
                            "bucket_region": bucket_region,
                            "is_public_policy": is_public,
                            "tags": tags,
                            "issue": "S3 bucket access logging disabled for CloudTrail bucket",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(trails)
        affected = len(resources_affected)
        return {
            "id": "CloudTrail.7",
            "check_name": "CloudTrail S3 Bucket Access Logging",
            "problem_statement": "S3 bucket access logging should be enabled on the CloudTrail S3 bucket",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable access logging for the CloudTrail S3 bucket",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to AWS S3 service",
                "2. Select the CloudTrail bucket",
                "3. Go to Properties tab",
                "4. Enable 'Server access logging'",
                "5. Specify target bucket for logs",
                "6. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail S3 logging: {e}")
        return None
