"""
ISO 42001 Extended Checks — CloudTrail & Logging (AI-042 to AI-047)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_cloudtrail_insights_enabled(session):
    """AI-042: CloudTrail Insights enabled"""
    print("Checking CloudTrail Insights enabled")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])
        total_scanned = 0

        for trail in trails:
            trail_name = trail.get("Name", "Unknown")
            trail_arn = trail.get("TrailARN", "")

            # Only check trails owned by this account
            if trail.get("HomeRegion") and trail.get("HomeRegion") != cloudtrail.meta.region_name:
                continue

            total_scanned += 1
            try:
                insight_selectors = cloudtrail.get_insight_selectors(
                    TrailName=trail_name
                ).get("InsightSelectors", [])

                if not insight_selectors:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": trail_name,
                        "resource_id_type": "CloudTrailTrail",
                        "issue": f"CloudTrail '{trail_name}' does not have Insights enabled",
                        "region": cloudtrail.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": trail_name,
                    "resource_id_type": "CloudTrailTrail",
                    "issue": f"CloudTrail '{trail_name}' — unable to verify Insights configuration",
                    "region": cloudtrail.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-042",
            "check_name": "CloudTrail Insights enabled",
            "problem_statement": "CloudTrail Insights should be enabled to detect unusual API activity in AI services",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable CloudTrail Insights on trails to detect anomalous API patterns for AI services",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Open CloudTrail console and select the trail",
                "2. Enable Insights events for ApiCallRateInsight and ApiErrorRateInsight",
                "3. Configure CloudWatch alarms for Insights findings",
                "4. Monitor for unusual patterns in AI service API calls",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking CloudTrail Insights: {e}")
        return None


def check_organization_trail(session):
    """AI-043: Organization trail detection"""
    print("Checking organization trail detection")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])
        total_scanned = len(trails)

        org_trail_found = False
        for trail in trails:
            if trail.get("IsOrganizationTrail", False):
                org_trail_found = True
                break

        if not org_trail_found and total_scanned > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "OrganizationTrail",
                "resource_id_type": "CloudTrailConfig",
                "issue": "No organization trail configured — AI activity across member accounts may not be centrally logged",
                "region": cloudtrail.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-043",
            "check_name": "Organization trail detection",
            "problem_statement": "An organization trail should exist to centrally log AI service activity across all accounts",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create an organization trail to centralize AI service audit logs",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. From the management account, create an organization trail",
                "2. Ensure the trail covers all regions",
                "3. Configure log file validation and encryption",
                "4. Set up centralized log analysis for AI service events",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking organization trail: {e}")
        return None


def check_s3_data_events_enabled(session):
    """AI-044: S3 data events enabled"""
    print("Checking S3 data events enabled in CloudTrail")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])
        total_scanned = 0

        for trail in trails:
            trail_name = trail.get("Name", "Unknown")

            if trail.get("HomeRegion") and trail.get("HomeRegion") != cloudtrail.meta.region_name:
                continue

            total_scanned += 1
            s3_data_events = False

            try:
                event_selectors = cloudtrail.get_event_selectors(
                    TrailName=trail_name
                )

                # Check standard event selectors
                for selector in event_selectors.get("EventSelectors", []):
                    for data_resource in selector.get("DataResources", []):
                        if data_resource.get("Type") == "AWS::S3::Object":
                            s3_data_events = True
                            break

                # Check advanced event selectors
                for selector in event_selectors.get("AdvancedEventSelectors", []):
                    for field_selector in selector.get("FieldSelectors", []):
                        if field_selector.get("Field") == "resources.type":
                            if "AWS::S3::Object" in field_selector.get("Equals", []):
                                s3_data_events = True
                                break
            except Exception:
                pass

            if not s3_data_events:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": trail_name,
                    "resource_id_type": "CloudTrailTrail",
                    "issue": f"CloudTrail '{trail_name}' does not log S3 data events — AI training data access not audited",
                    "region": cloudtrail.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-044",
            "check_name": "S3 data events enabled",
            "problem_statement": "S3 data events should be logged to audit access to AI training data and model artifacts",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable S3 data event logging on CloudTrail trails for AI data buckets",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Edit CloudTrail trail event selectors",
                "2. Add S3 data events for AI-related buckets (training data, model artifacts)",
                "3. Consider using advanced event selectors for targeted logging",
                "4. Monitor S3 access patterns for unauthorized data access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 data events: {e}")
        return None


def check_lambda_data_events_enabled(session):
    """AI-045: Lambda data events enabled"""
    print("Checking Lambda data events enabled in CloudTrail")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])
        total_scanned = 0

        for trail in trails:
            trail_name = trail.get("Name", "Unknown")

            if trail.get("HomeRegion") and trail.get("HomeRegion") != cloudtrail.meta.region_name:
                continue

            total_scanned += 1
            lambda_data_events = False

            try:
                event_selectors = cloudtrail.get_event_selectors(
                    TrailName=trail_name
                )

                # Check standard event selectors
                for selector in event_selectors.get("EventSelectors", []):
                    for data_resource in selector.get("DataResources", []):
                        if data_resource.get("Type") == "AWS::Lambda::Function":
                            lambda_data_events = True
                            break

                # Check advanced event selectors
                for selector in event_selectors.get("AdvancedEventSelectors", []):
                    for field_selector in selector.get("FieldSelectors", []):
                        if field_selector.get("Field") == "resources.type":
                            if "AWS::Lambda::Function" in field_selector.get("Equals", []):
                                lambda_data_events = True
                                break
            except Exception:
                pass

            if not lambda_data_events:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": trail_name,
                    "resource_id_type": "CloudTrailTrail",
                    "issue": f"CloudTrail '{trail_name}' does not log Lambda data events — AI inference function invocations not audited",
                    "region": cloudtrail.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-045",
            "check_name": "Lambda data events enabled",
            "problem_statement": "Lambda data events should be logged to audit AI inference function invocations",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable Lambda data event logging for AI-related Lambda functions",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Edit CloudTrail trail event selectors",
                "2. Add Lambda data events for AI inference functions",
                "3. Use advanced event selectors to target specific functions",
                "4. Monitor invocation patterns for anomalies",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Lambda data events: {e}")
        return None


def check_cloudwatch_logs_retention(session):
    """AI-046: CloudWatch Logs retention configured"""
    print("Checking CloudWatch Logs retention configured")

    logs = session.client("logs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        log_groups = []
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            log_groups.extend(page.get("logGroups", []))

        # Filter for AI-related log groups
        ai_keywords = ["sagemaker", "bedrock", "comprehend", "rekognition", "textract", "ai", "ml", "inference"]
        ai_log_groups = [
            lg for lg in log_groups
            if any(kw in lg.get("logGroupName", "").lower() for kw in ai_keywords)
        ]

        total_scanned = len(ai_log_groups) if ai_log_groups else len(log_groups)
        groups_to_check = ai_log_groups if ai_log_groups else log_groups

        for lg in groups_to_check:
            log_group_name = lg.get("logGroupName", "Unknown")
            retention = lg.get("retentionInDays")

            if retention is None:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": log_group_name,
                    "resource_id_type": "CloudWatchLogGroup",
                    "issue": f"Log group '{log_group_name}' has no retention policy — logs retained indefinitely",
                    "region": logs.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-046",
            "check_name": "CloudWatch Logs retention configured",
            "problem_statement": "CloudWatch log groups should have retention policies to manage costs and compliance",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Set retention policies on CloudWatch log groups for AI services",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify log groups without retention policies",
                "2. Set appropriate retention period (e.g., 90, 180, or 365 days)",
                "3. Consider archiving to S3 for long-term compliance requirements",
                "4. Automate retention policy assignment with AWS Config rules",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking CloudWatch Logs retention: {e}")
        return None


def check_log_groups_encrypted(session):
    """AI-047: Log groups encrypted with KMS"""
    print("Checking log groups encrypted with KMS")

    logs = session.client("logs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        log_groups = []
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            log_groups.extend(page.get("logGroups", []))

        # Filter for AI-related log groups
        ai_keywords = ["sagemaker", "bedrock", "comprehend", "rekognition", "textract", "ai", "ml", "inference"]
        ai_log_groups = [
            lg for lg in log_groups
            if any(kw in lg.get("logGroupName", "").lower() for kw in ai_keywords)
        ]

        total_scanned = len(ai_log_groups) if ai_log_groups else len(log_groups)
        groups_to_check = ai_log_groups if ai_log_groups else log_groups

        for lg in groups_to_check:
            log_group_name = lg.get("logGroupName", "Unknown")
            kms_key_id = lg.get("kmsKeyId")

            if not kms_key_id:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": log_group_name,
                    "resource_id_type": "CloudWatchLogGroup",
                    "issue": f"Log group '{log_group_name}' is not encrypted with KMS",
                    "region": logs.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-047",
            "check_name": "Log groups encrypted with KMS",
            "problem_statement": "CloudWatch log groups containing AI service logs should be encrypted with KMS",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Encrypt CloudWatch log groups with customer-managed KMS keys",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create a KMS key for CloudWatch Logs encryption",
                "2. Associate KMS key with log groups using associate-kms-key API",
                "3. Ensure KMS key policy allows CloudWatch Logs service access",
                "4. Verify encryption is applied to new and existing log data",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking log groups encryption: {e}")
        return None
