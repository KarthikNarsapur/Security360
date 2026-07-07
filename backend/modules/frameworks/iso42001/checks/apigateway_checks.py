"""
ISO 42001 Extended Checks — API Gateway (AI-068 to AI-070)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_api_authorization_enabled(session):
    """AI-068: API authorization enabled"""
    print("Checking API Gateway authorization enabled")

    apigw = session.client("apigateway")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            apis = apigw.get_rest_apis().get("items", [])
        except Exception:
            apis = []

        for api in apis:
            api_id = api.get("id", "")
            api_name = api.get("name", api_id)
            try:
                resources = apigw.get_resources(restApiId=api_id).get("items", [])
                for resource in resources:
                    methods = resource.get("resourceMethods", {})
                    for method_name in methods:
                        if method_name == "OPTIONS":
                            continue
                        try:
                            method = apigw.get_method(
                                restApiId=api_id,
                                resourceId=resource["id"],
                                httpMethod=method_name,
                            )
                            auth_type = method.get("authorizationType", "NONE")
                            if auth_type == "NONE":
                                resources_affected.append({
                                    "account_id": account_id,
                                    "resource_id": f"{api_name}/{resource.get('path', '')}/{method_name}",
                                    "resource_id_type": "APIMethod",
                                    "issue": f"API '{api_name}' method {method_name} on {resource.get('path', '')} has no authorization",
                                    "region": apigw.meta.region_name,
                                    "last_updated": datetime.now(IST).isoformat(),
                                })
                        except Exception:
                            continue
            except Exception:
                continue

        return {
            "id": "AI-068",
            "check_name": "API authorization enabled",
            "problem_statement": "API Gateway methods serving AI should have authorization configured",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure IAM, Cognito, or Lambda authorizers on API methods",
            "additional_info": {"total_scanned": max(len(apis), 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Identify API methods without authorization",
                "2. Add IAM authorization, Cognito authorizer, or Lambda authorizer",
                "3. Test with authenticated requests",
                "4. Remove public access unless intentional",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking API authorization: {e}")
        return None


def check_api_logging_enabled(session):
    """AI-069: API logging enabled"""
    print("Checking API Gateway logging enabled")

    apigw = session.client("apigateway")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            apis = apigw.get_rest_apis().get("items", [])
        except Exception:
            apis = []

        for api in apis:
            api_id = api.get("id", "")
            api_name = api.get("name", api_id)
            try:
                stages = apigw.get_stages(restApiId=api_id).get("item", [])
                for stage in stages:
                    stage_name = stage.get("stageName", "")
                    method_settings = stage.get("methodSettings", {})
                    # Check default settings
                    default = method_settings.get("*/*", {})
                    logging_level = default.get("loggingLevel", "OFF")
                    if logging_level == "OFF":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": f"{api_name}/{stage_name}",
                            "resource_id_type": "APIStage",
                            "issue": f"API '{api_name}' stage '{stage_name}' has logging disabled",
                            "region": apigw.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-069",
            "check_name": "API logging enabled",
            "problem_statement": "API Gateway stages should have execution logging enabled for audit",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable execution logging on all API Gateway stages",
            "additional_info": {"total_scanned": max(len(apis), 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Navigate to API Gateway stage settings",
                "2. Enable CloudWatch logging (INFO or ERROR level)",
                "3. Configure access logging with appropriate format",
                "4. Review logs for anomalous AI API usage patterns",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking API logging: {e}")
        return None


def check_api_stages_encrypted(session):
    """AI-070: API stages encrypted"""
    print("Checking API Gateway stages encryption (cache)")

    apigw = session.client("apigateway")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            apis = apigw.get_rest_apis().get("items", [])
        except Exception:
            apis = []

        for api in apis:
            api_id = api.get("id", "")
            api_name = api.get("name", api_id)
            try:
                stages = apigw.get_stages(restApiId=api_id).get("item", [])
                for stage in stages:
                    stage_name = stage.get("stageName", "")
                    method_settings = stage.get("methodSettings", {})
                    default = method_settings.get("*/*", {})
                    cache_enabled = default.get("cachingEnabled", False)
                    cache_encrypted = default.get("cacheDataEncrypted", False)
                    if cache_enabled and not cache_encrypted:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": f"{api_name}/{stage_name}",
                            "resource_id_type": "APIStage",
                            "issue": f"API '{api_name}' stage '{stage_name}' has cache enabled but not encrypted",
                            "region": apigw.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-070",
            "check_name": "API stages cache encrypted",
            "problem_statement": "API Gateway cache should be encrypted to protect AI response data",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable cache encryption on API Gateway stages with caching",
            "additional_info": {"total_scanned": max(len(apis), 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Navigate to API Gateway stage cache settings",
                "2. Enable 'Encrypt cache data'",
                "3. Verify cache TTL is appropriate for AI responses",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking API stages encryption: {e}")
        return None
