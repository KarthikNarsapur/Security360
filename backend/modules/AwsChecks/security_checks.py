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
            "recommendation": "Enable GuardDuty for threat detection.",
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "SubscriptionRequiredException":
            print(f"guardduty_enabled: Service not subscribed in {session.region_name} — marking as not enabled")
            return {
                "check_name": "Amazon GuardDuty",
                "service": "GuardDuty",
                "problem_statement": "GuardDuty has never been enabled in this region.",
                "severity_score": 80,
                "severity_level": "High",
                "is_enabled": "No",
                "recommendation": "Enable GuardDuty for threat detection.",
            }
        print(f"guardduty_enabled: Unexpected error — {error_code}")
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
        print(f"inspector_enabled: Access denied — {e}")
        return {
            "check_name": "Amazon Inspector",
            "service": "Inspector",
            "problem_statement": "Amazon Inspector access denied. Insufficient permissions to check status.",
            "severity_score": 70,
            "severity_level": "Medium",
            "is_enabled": "No",
            "recommendation": "Enable Amazon Inspector for vulnerability scanning.",
        }

    except Exception as e:
        error_msg = str(e)
        if "SubscriptionRequiredException" in error_msg:
            print(f"inspector_enabled: Service not subscribed in {session.region_name} — marking as not enabled")
            return {
                "check_name": "Amazon Inspector",
                "service": "Inspector",
                "problem_statement": "Amazon Inspector has never been enabled in this region.",
                "severity_score": 70,
                "severity_level": "Medium",
                "is_enabled": "No",
                "recommendation": "Enable Amazon Inspector for vulnerability scanning.",
            }
        print(f"inspector_enabled: Unexpected error — {error_msg}")
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
        print(f"security_hub_enabled: Not enabled in {session.region_name} — marking as not enabled")
        return {
            "check_name": "AWS Security Hub",
            "service": "SecurityHub",
            "problem_statement": "Security Hub is not enabled.",
            "severity_score": 75,
            "severity_level": "Medium",
            "is_enabled": "No",
            "recommendation": "Enable Security Hub in this region.",
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "SubscriptionRequiredException":
            print(f"security_hub_enabled: Service not subscribed in {session.region_name} — marking as not enabled")
            return {
                "check_name": "AWS Security Hub",
                "service": "SecurityHub",
                "problem_statement": "Security Hub has never been enabled in this region.",
                "severity_score": 75,
                "severity_level": "Medium",
                "is_enabled": "No",
                "recommendation": "Enable AWS Security Hub to aggregate findings.",
            }
        print(f"security_hub_enabled: Unexpected error — {error_code}")
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


import json


def check_kms_permissive_policies(session):
    print("check_kms_permissive_policies")
    kms = session.client("kms")
    resources = []

    paginator = kms.get_paginator("list_keys")
    all_keys = []
    for page in paginator.paginate():
        all_keys.extend(page.get("Keys", []))

    for key in all_keys:
        key_id = key["KeyId"]
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            if meta.get("KeyState") != "Enabled":
                continue

            policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            policy = json.loads(policy_str)

            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                has_wildcard = False
                if principal == "*":
                    has_wildcard = True
                elif isinstance(principal, dict):
                    for v in principal.values():
                        vals = v if isinstance(v, list) else [v]
                        if "*" in vals:
                            has_wildcard = True
                            break

                if has_wildcard and not stmt.get("Condition"):
                    resources.append({
                        "resource_name": key_id,
                        "key_arn": meta.get("Arn"),
                        "description": meta.get("Description", ""),
                        "statement_sid": stmt.get("Sid", "N/A"),
                        "issue": "Key policy grants access to Principal \"*\" without conditions.",
                    })
                    break
        except Exception as e:
            print(f"Error checking KMS key {key_id}: {e}")

    return {
        "check_name": "KMS Overly Permissive Key Policies",
        "service": "KMS",
        "problem_statement": "Customer-managed KMS keys have policies granting access to Principal \"*\" without restrictive conditions.",
        "severity_score": 80,
        "severity_level": "High",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Restrict KMS key policies to specific AWS accounts, roles, or services. Add conditions where broad access is needed.",
    }


def check_cloudwatch_log_retention(session):
    print("check_cloudwatch_log_retention")
    logs = session.client("logs")
    resources = []

    paginator = logs.get_paginator("describe_log_groups")
    all_groups = []
    for page in paginator.paginate():
        all_groups.extend(page.get("logGroups", []))

    for group in all_groups:
        if not group.get("retentionInDays"):
            resources.append({
                "resource_name": group.get("logGroupName"),
                "stored_bytes": group.get("storedBytes", 0),
                "issue": "Log group has no retention policy (logs never expire).",
            })

    return {
        "check_name": "CloudWatch Log Retention",
        "service": "CloudWatch",
        "problem_statement": "CloudWatch Log Groups have no retention policy, causing unbounded log storage and costs.",
        "severity_score": 40,
        "severity_level": "Low",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Set a retention policy on all CloudWatch Log Groups (e.g., 30, 60, or 90 days).",
    }


def check_cloudwatch_critical_alarms(session):
    print("check_cloudwatch_critical_alarms")
    logs = session.client("logs")
    resources = []

    required_filters = {
        "RootAccountUsage": '{ $.userIdentity.type = "Root" }',
        "UnauthorizedAPICalls": '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }',
        "IAMPolicyChanges": '{ ($.eventName = "DeleteGroupPolicy") || ($.eventName = "PutGroupPolicy") || ($.eventName = "CreatePolicy") || ($.eventName = "DeletePolicy") }',
        "ConsoleSignInFailures": '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }',
    }

    paginator = logs.get_paginator("describe_log_groups")
    all_groups = []
    for page in paginator.paginate():
        all_groups.extend(page.get("logGroups", []))

    found_filters = set()
    for group in all_groups:
        try:
            filters = logs.describe_metric_filters(logGroupName=group["logGroupName"]).get("metricFilters", [])
            for f in filters:
                pattern = f.get("filterPattern", "")
                for name, expected in required_filters.items():
                    if name not in found_filters:
                        # Simple heuristic: check if key terms are present
                        if "Root" in pattern and name == "RootAccountUsage":
                            found_filters.add(name)
                        elif "UnauthorizedAccess" in pattern or "AccessDenied" in pattern:
                            found_filters.add("UnauthorizedAPICalls")
                        elif "DeleteGroupPolicy" in pattern or "PutGroupPolicy" in pattern or "CreatePolicy" in pattern:
                            found_filters.add("IAMPolicyChanges")
                        elif "ConsoleLogin" in pattern and "Failed" in pattern:
                            found_filters.add("ConsoleSignInFailures")
        except Exception:
            continue

    missing = [name for name in required_filters if name not in found_filters]
    if missing:
        resources.append({
            "resource_name": "CloudWatch Metric Filters",
            "missing_filters": ", ".join(missing),
            "issue": f"Missing {len(missing)} critical metric filter(s): {', '.join(missing)}.",
        })

    return {
        "check_name": "CloudWatch Critical Event Alarms",
        "service": "CloudWatch",
        "problem_statement": "CloudWatch is missing metric filters and alarms for critical security events.",
        "severity_score": 65,
        "severity_level": "Medium",
        "is_enabled": "Yes" if not missing else "No",
        "resources_affected": resources,
        "recommendation": "Create metric filters and alarms for root usage, unauthorized API calls, IAM policy changes, and console sign-in failures.",
    }


def check_elb_access_logs(session):
    print("check_elb_access_logs")
    elbv2 = session.client("elbv2")
    resources = []

    lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
    for lb in lbs:
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb["LoadBalancerName"]
        try:
            attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn).get("Attributes", [])
            access_logs_enabled = False
            for attr in attrs:
                if attr.get("Key") == "access_logs.s3.enabled" and attr.get("Value") == "true":
                    access_logs_enabled = True
                    break
            if not access_logs_enabled:
                resources.append({
                    "resource_name": lb_name,
                    "lb_type": lb.get("Type"),
                    "lb_arn": lb_arn,
                    "issue": "Access logging is not enabled.",
                })
        except Exception as e:
            print(f"Error checking ELB access logs for {lb_name}: {e}")

    return {
        "check_name": "ELB Access Logs Enabled",
        "service": "ELB",
        "problem_statement": "Load balancers do not have access logging enabled for audit and troubleshooting.",
        "severity_score": 50,
        "severity_level": "Medium",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Enable access logging on all ALBs/NLBs and configure an S3 bucket for log storage.",
    }


def check_shield_advanced(session):
    print("check_shield_advanced")
    resources = []
    try:
        shield = session.client("shield", region_name="us-east-1")
        subscription = shield.describe_subscription()
        # If we get here, Shield Advanced is active
    except shield.exceptions.ResourceNotFoundException:
        resources.append({
            "resource_name": "AWS Shield Advanced",
            "issue": "Shield Advanced is not subscribed.",
        })
    except Exception as e:
        if "ResourceNotFoundException" in str(e) or "SubscriptionNotFoundException" in str(e):
            resources.append({
                "resource_name": "AWS Shield Advanced",
                "issue": "Shield Advanced is not subscribed.",
            })
        else:
            print(f"Error checking Shield Advanced: {e}")

    return {
        "check_name": "AWS Shield Advanced",
        "service": "Shield",
        "problem_statement": "AWS Shield Advanced is not enabled for DDoS protection.",
        "severity_score": 45,
        "severity_level": "Medium",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Consider enabling AWS Shield Advanced for enhanced DDoS protection on critical resources.",
    }


def check_https_enforcement(session):
    print("check_https_enforcement")
    resources = []

    # Check ALB listeners
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            if lb.get("Type") != "application":
                continue
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
            for listener in listeners:
                if listener.get("Protocol") == "HTTP":
                    # Check if it redirects to HTTPS
                    actions = listener.get("DefaultActions", [])
                    is_redirect = any(
                        a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                        for a in actions
                    )
                    if not is_redirect:
                        resources.append({
                            "resource_name": lb["LoadBalancerName"],
                            "service_type": "ALB",
                            "listener_port": listener.get("Port"),
                            "issue": "HTTP listener without HTTPS redirect.",
                        })
    except Exception as e:
        print(f"Error checking ALB HTTPS: {e}")

    # Check API Gateway
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            if api.get("endpointConfiguration", {}).get("types", []) != ["EDGE"]:
                continue
            # REST APIs are HTTPS by default, but check for HTTP API (apigatewayv2)
    except Exception:
        pass

    try:
        apigwv2 = session.client("apigatewayv2")
        http_apis = apigwv2.get_apis().get("Items", [])
        for api in http_apis:
            if not api.get("DisableExecuteApiEndpoint", False):
                # HTTP APIs support both HTTP and HTTPS by default
                pass
    except Exception:
        pass

    return {
        "check_name": "HTTPS Enforced Everywhere",
        "service": "ELB",
        "problem_statement": "Load balancers have HTTP listeners without HTTPS redirect, allowing unencrypted traffic.",
        "severity_score": 70,
        "severity_level": "Medium",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Redirect all HTTP listeners to HTTPS. Ensure all endpoints enforce TLS.",
    }


def check_tls_policy_strength(session):
    print("check_tls_policy_strength")
    resources = []

    weak_policies = [
        "ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01",
    ]

    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
            for listener in listeners:
                if listener.get("Protocol") == "HTTPS":
                    ssl_policy = listener.get("SslPolicy", "")
                    if ssl_policy in weak_policies:
                        resources.append({
                            "resource_name": lb["LoadBalancerName"],
                            "service_type": "ALB/NLB",
                            "listener_port": listener.get("Port"),
                            "ssl_policy": ssl_policy,
                            "issue": f"Weak TLS policy: {ssl_policy}.",
                        })
    except Exception as e:
        print(f"Error checking TLS policies: {e}")

    return {
        "check_name": "Weak TLS Policies",
        "service": "ELB",
        "problem_statement": "Load balancers use outdated TLS policies that support TLS 1.0 or 1.1.",
        "severity_score": 65,
        "severity_level": "Medium",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Update to ELBSecurityPolicy-TLS13-1-2-2021-06 or ELBSecurityPolicy-FS-1-2-Res-2020-10 for TLS 1.2+ only.",
    }


def check_waf_on_api_gateway(session):
    print("check_waf_on_api_gateway")
    resources = []

    try:
        apigw = session.client("apigateway")
        wafv2 = session.client("wafv2")
        stages_to_check = []

        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            api_id = api["id"]
            api_name = api.get("name", api_id)
            try:
                stages = apigw.get_stages(restApiId=api_id).get("item", [])
                for stage in stages:
                    stage_name = stage.get("stageName")
                    stage_arn = f"arn:aws:apigateway:{session.region_name}::/restapis/{api_id}/stages/{stage_name}"
                    try:
                        waf_resp = wafv2.get_web_acl_for_resource(ResourceArn=stage_arn)
                        if not waf_resp.get("WebACL"):
                            resources.append({
                                "resource_name": f"{api_name}/{stage_name}",
                                "api_id": api_id,
                                "stage": stage_name,
                                "issue": "No WAF Web ACL associated with API Gateway stage.",
                            })
                    except Exception:
                        resources.append({
                            "resource_name": f"{api_name}/{stage_name}",
                            "api_id": api_id,
                            "stage": stage_name,
                            "issue": "No WAF Web ACL associated with API Gateway stage.",
                        })
            except Exception as e:
                print(f"Error checking stages for API {api_name}: {e}")
    except Exception as e:
        print(f"Error checking WAF on API Gateway: {e}")

    return {
        "check_name": "WAF on API Gateway",
        "service": "API Gateway",
        "problem_statement": "API Gateway stages do not have AWS WAF Web ACLs associated for protection against web attacks.",
        "severity_score": 70,
        "severity_level": "Medium",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Associate a WAF Web ACL with all API Gateway stages to protect against common web exploits.",
    }


def check_unresolved_security_findings(session):
    print("check_unresolved_security_findings")
    resources = []

    # Check GuardDuty
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if detectors:
            detector_id = detectors[0]
            findings = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "severity": {"Gte": 7},
                        "service.archived": {"Eq": ["false"]},
                    }
                },
            ).get("FindingIds", [])
            if findings:
                resources.append({
                    "resource_name": "GuardDuty",
                    "finding_count": len(findings),
                    "issue": f"{len(findings)} unresolved HIGH/CRITICAL GuardDuty finding(s).",
                })
    except Exception as e:
        print(f"Error checking GuardDuty findings: {e}")

    return {
        "check_name": "Unresolved Security Findings",
        "service": "GuardDuty",
        "problem_statement": "There are unresolved HIGH or CRITICAL security findings that require attention.",
        "severity_score": 75,
        "severity_level": "High",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Review and remediate all HIGH/CRITICAL findings in GuardDuty and Security Hub.",
    }


def check_automated_remediation(session):
    print("check_automated_remediation")
    resources = []

    try:
        config_client = session.client("config")
        rules = config_client.describe_config_rules().get("ConfigRules", [])
        rules_with_remediation = 0
        for rule in rules:
            try:
                remediations = config_client.describe_remediation_configurations(
                    ConfigRuleNames=[rule["ConfigRuleName"]]
                ).get("RemediationConfigurations", [])
                if remediations:
                    rules_with_remediation += 1
            except Exception:
                continue

        if rules and rules_with_remediation == 0:
            resources.append({
                "resource_name": "AWS Config Rules",
                "total_rules": len(rules),
                "rules_with_remediation": 0,
                "issue": "No Config Rules have auto-remediation configured.",
            })
    except Exception as e:
        print(f"Error checking automated remediation: {e}")

    return {
        "check_name": "Automated Remediation",
        "service": "Config",
        "problem_statement": "No AWS Config Rules have automated remediation actions configured.",
        "severity_score": 40,
        "severity_level": "Low",
        "is_enabled": "Yes" if not resources else "No",
        "resources_affected": resources,
        "recommendation": "Configure auto-remediation on critical Config Rules using SSM Automation documents or Lambda functions.",
    }
