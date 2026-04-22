import boto3
from botocore.exceptions import ClientError


def aws_config_enabled(session):
    print("aws_config_enabled")
    client = session.client("config")
    try:
        response = client.describe_configuration_recorder_status()
        recorders = response.get("ConfigurationRecordersStatus", [])
        enabled = [r for r in recorders if r.get("recording")]

        return {
            "check_name": "AWS Config Recording",
            "service": "Config",
            "problem_statement": "AWS Config is not enabled.",
            "severity_score": 80,
            "severity_level": "High",
            "is_enabled": "Yes" if len(enabled) > 0 else "No",
            # "resources_affected": ,
            "recommendation": "Enable AWS Config to track configuration changes.",
        }
    except ClientError as e:
        print("error in Config: ", str(e))
        return None


def guardduty_enabled(session):
    print("guardduty_enabled")
    client = session.client("guardduty")
    try:
        detectors = client.list_detectors()["DetectorIds"]
        enabled = len(detectors) > 0

        return {
            "check_name": "Amazon GuardDuty",
            "service": "GuardDuty",
            "problem_statement": "GuardDuty is not enabled.",
            "severity_score": 80,
            "severity_level": "High" if not enabled else "None",
            "is_enabled": "Yes" if enabled else "No",
            # "resources_affected": [] if enabled else ["No Detectors Found"],
            "recommendation": "Enable GuardDuty for threat detection.",
        }
    except ClientError as e:
        print("error in Guardduty: ", str(e))
        return None


def inspector_enabled(session):
    print("inspector_enabled")
    client = session.client("inspector2")
    try:
        # Get current account ID (for single account use)
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        # Call batch_get_account_status
        response = client.batch_get_account_status(accountIds=[account_id])
        accounts = response.get("accounts", [])
        failed = response.get("failedAccounts", [])
        print(accounts, failed)

        enabled = False
        disabled_services = []

        if accounts:
            for acc in accounts:
                account_status = acc.get("state", {}).get("status", "DISABLED")
                if account_status == "ENABLED":
                    enabled = True

                resource_state = acc.get("resourceState", {})
                for resource, res_data in resource_state.items():
                    if res_data.get("status") != "ENABLED":
                        disabled_services.append(
                            f"{resource} ({res_data.get('status')})"
                        )
        return {
            "check_name": "Amazon Inspector",
            "service": "Inspector",
            "problem_statement": "Amazon Inspector is not enabled.",
            "severity_score": 70,
            "severity_level": "Medium",
            "is_enabled": "Yes" if enabled else "No",
            # "resources_affected": [] if enabled else details,
            "recommendation": "Enable Amazon Inspector for vulnerability scanning.",
        }
    except client.exceptions.AccessDeniedException as e:
        print("error in inspector with AccessDeniedException: ", str(e))
        return None

    except Exception as e:
        print("error in inspector : ", str(e))
        return None


def security_hub_enabled(session):
    print("security_hub_enabled")
    client = session.client("securityhub")
    try:
        response = client.describe_hub()
        enabled = "HubArn" in response

        return {
            "check_name": "AWS Security Hub",
            "service": "SecurityHub",
            "problem_statement": "Security Hub is not enabled.",
            "severity_score": 75,
            "severity_level": "Medium" if not enabled else "None",
            "is_enabled": "Yes" if enabled else "No",
            # "resources_affected": [] if enabled else ["Security Hub Not Enabled"],
            "recommendation": "Enable AWS Security Hub to aggregate findings.",
        }
    except client.exceptions.InvalidAccessException as e:
        print("error in security hub with InvalidAccessException: ", str(e))

        #
        # scan_meta_data["affected"] += 1
        return {
            "check_name": "AWS Security Hub",
            "service": "SecurityHub",
            "problem_statement": "Security Hub is not enabled.",
            "severity_score": 75,
            "severity_level": "Medium",
            "is_enabled": "No",
            # "resources_affected": ["Security Hub Not Found"],
            "recommendation": "Enable Security Hub in this region.",
        }
    except ClientError as e:
        print("error in security hub: ", str(e))
        return None


def access_analyzer_enabled(session):
    print("access_analyzer_enabled")
    client = session.client("accessanalyzer")
    try:
        analyzers = client.list_analyzers()["analyzers"]
        enabled = len(analyzers) > 0

        return {
            "check_name": "IAM Access Analyzer",
            "service": "IAM",
            "problem_statement": "Access Analyzer is not enabled.",
            "severity_score": 65,
            "severity_level": "Low" if not enabled else "None",
            "is_enabled": "Yes" if enabled else "No",
            # "resources_affected": [] if enabled else ["No Analyzers Found"],
            "recommendation": "Enable IAM Access Analyzer for policy validation.",
        }
    except ClientError as e:
        print("error in IAM Access Analyzer: ", str(e))

        return None


def cloudtrail_enabled(session):
    print("cloudtrail_enabled")
    client = session.client("cloudtrail")
    try:
        trails = client.describe_trails()["trailList"]
        print("trails in security: ", trails)
        enabled = any(
            trail.get("IsMultiRegionTrail") or trail.get("HomeRegion")
            for trail in trails
        )

        return {
            "check_name": "AWS CloudTrail",
            "service": "CloudTrail",
            "problem_statement": "CloudTrail is not enabled.",
            "severity_score": 90,
            "severity_level": "High",
            "is_enabled": "Yes" if enabled else "No",
            # "resources_affected": [] if enabled else ["No Trails Found"],
            "recommendation": "Enable CloudTrail to log account activity.",
        }
    except ClientError as e:
        print("error in Cloudtrail: ", str(e))
        return None


def check_waf_enabled(session):
    print("check_waf_enabled")
    wafv2_client = session.client("wafv2")
    enabled = False
    resources_affected = []

    try:
        # Check for regional Web ACLs
        regional_response = wafv2_client.list_web_acls(Scope="REGIONAL")
        regional_web_acls = regional_response.get("WebACLs", [])

        # Check for global Web ACLs (for CloudFront) - only available in us-east-1 region
        if session.region_name == "us-east-1":
            global_response = wafv2_client.list_web_acls(Scope="CLOUDFRONT")
            global_web_acls = global_response.get("WebACLs", [])
        else:
            global_web_acls = []

        if regional_web_acls or global_web_acls:
            enabled = True
            for web_acl in regional_web_acls:
                resources_affected.append(
                    {
                        "region": session.region_name,
                        "resource_id": web_acl.get("Id"),
                        "resource_name": web_acl.get("Name"),
                        "scope": "REGIONAL",
                        "message": f"WAF Web ACL '{web_acl.get('Name')}' found in region '{session.region_name}'.",
                    }
                )
            for web_acl in global_web_acls:
                resources_affected.append(
                    {
                        "region": "us-east-1",
                        "resource_id": web_acl.get("Id"),
                        "resource_name": web_acl.get("Name"),
                        "scope": "CLOUDFRONT",
                        "message": f"Global WAF Web ACL '{web_acl.get('Name')}' found for CloudFront.",
                    }
                )

    except Exception as e:
        print(f"Error while checking WAF: {e}")

    return {
        "check_name": "AWS WAF Enabled",
        "service": "WAF",
        "problem_statement": "Checks if AWS WAF is being used or not in the region or globally.",
        "severity_score": 10,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Consider enabling AWS WAF to protect your web applications from common web exploits and bots.",
        "is_enabled": "Yes" if enabled else "No",
    }
