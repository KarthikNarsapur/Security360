import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_cloudtrail_has_one_multi_region_trail(session):
    # [CloudTrail.1]
    print("Checking CloudTrail multi-region trail configuration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        trails = cloudtrail.describe_trails().get("trailList", [])
        multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail")]

        if not multi_region_trails:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "None",
                    "resource_id_type": "CloudTrail",
                    "issue": "No multi-region CloudTrail found",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = len(trails)
        affected = len(resources_affected)

        return {
            "id": "CloudTrail.1",
            "check_name": "Multi-region CloudTrail enabled",
            "problem_statement": "There should be at least one multi-region CloudTrail to record activity across all regions.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Create or enable a multi-region CloudTrail in the account.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to CloudTrail console.",
                "2. Choose 'Create trail' or edit an existing one.",
                "3. Enable 'Apply trail to all regions'.",
                "4. Save changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail multi-region trail: {e}")
        return None


def check_cloudtrail_requires_kms_key(session):
    # [CloudTrail.2]
    print("Checking CloudTrail KMS encryption configuration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        trails = cloudtrail.describe_trails().get("trailList", [])

        for trail in trails:
            trail_name = trail.get("Name")
            kms_key_id = trail.get("KmsKeyId")

            if not kms_key_id:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": trail_name,
                        "resource_id_type": "CloudTrailTrail",
                        "issue": "CloudTrail not encrypted with a KMS key",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(trails)
        affected = len(resources_affected)

        return {
            "id": "CloudTrail.2",
            "check_name": "CloudTrail encryption using KMS",
            "problem_statement": "CloudTrail trails should be encrypted with AWS KMS for log file protection.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Assign a KMS key to CloudTrail trails for log encryption.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open CloudTrail console.",
                "2. Edit the trail.",
                "3. Under 'Log file encryption', specify a KMS key ARN.",
                "4. Save changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail KMS encryption: {e}")
        return None


def check_cloudtrail_log_file_validation_enabled(session):
    # [CloudTrail.4]
    print("Checking CloudTrail log file validation configuration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])

        for trail in trails:
            trail_name = trail.get("Name")
            trail_arn = trail.get("TrailARN")

            try:
                status = cloudtrail.get_trail_status(Name=trail_name)
                validation = status.get("LogFileValidationEnabled", False)
                if not validation:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": trail_name,
                            "resource_id_type": "CloudTrailTrail",
                            "trail_arn": trail_arn,
                            "issue": "Log file integrity validation not enabled",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception as e:
                print(f"Error getting CloudTrail status for {trail_name}: {e}")

        total_scanned = len(trails)
        affected = len(resources_affected)

        return {
            "id": "CloudTrail.4",
            "check_name": "CloudTrail log file validation enabled",
            "problem_statement": "Log file validation ensures integrity of CloudTrail logs and should be enabled.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable log file validation in CloudTrail settings.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to CloudTrail console.",
                "2. Edit the trail.",
                "3. Enable 'Log file validation'.",
                "4. Save and apply changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail log file validation: {e}")
        return None


def check_cloudtrail_cloudwatch_logs_log_group_arn(session):
    # [CloudTrail.5]
    print("Checking CloudTrail CloudWatch Logs integration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])

        for trail in trails:
            trail_name = trail.get("Name")
            log_group_arn = trail.get("CloudWatchLogsLogGroupArn")

            if not log_group_arn:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": trail_name,
                        "resource_id_type": "CloudTrailTrail",
                        "issue": "No CloudWatch Logs integration configured for CloudTrail",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(trails)
        affected = len(resources_affected)

        return {
            "id": "CloudTrail.5",
            "check_name": "CloudTrail integrated with CloudWatch Logs",
            "problem_statement": "CloudTrail logs should be delivered to CloudWatch Logs for real-time monitoring and alerting.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Integrate CloudTrail with CloudWatch Logs to enable log streaming and alerting.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to CloudTrail console.",
                "2. Edit the trail.",
                "3. Under 'CloudWatch Logs', specify a log group ARN.",
                "4. Provide the necessary IAM permissions and save changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudTrail CloudWatch Logs integration: {e}")
        return None
