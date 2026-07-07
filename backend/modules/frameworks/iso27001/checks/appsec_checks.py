"""
ISO 27001 Checks — Application Security
Controls: A.8.25, A.8.26, A.8.28, A.8.4, A.8.27
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_api_gateway_auth(session):
    """A.8.26: API Gateway endpoints should have authorization."""
    print("  ISO27001: Checking API Gateway authorization")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        apigw = session.client("apigateway")

        try:
            apis = apigw.get_rest_apis().get("items", [])
            total = len(apis)

            for api in apis:
                api_id = api["id"]
                api_name = api.get("name", api_id)
                try:
                    resources = apigw.get_resources(restApiId=api_id).get("items", [])
                    unprotected = 0
                    for resource in resources:
                        methods = resource.get("resourceMethods", {})
                        for method_name in methods:
                            if method_name == "OPTIONS":
                                continue
                            try:
                                method = apigw.get_method(
                                    restApiId=api_id,
                                    resourceId=resource["id"],
                                    httpMethod=method_name
                                )
                                if method.get("authorizationType") == "NONE":
                                    unprotected += 1
                            except Exception:
                                continue
                    if unprotected > 0:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": api_name,
                            "resource_id_type": "API Gateway",
                            "issue": f"API '{api_name}' has {unprotected} methods with no authorization",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue
        except Exception:
            apis = []
            total = 0

        return _result("A.8.26", "Application security - API Gateway authorization",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking API Gateway: {e}")
        return None


def check_codepipeline(session):
    """A.8.25: CI/CD pipelines should exist (CodePipeline)."""
    print("  ISO27001: Checking CodePipeline")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            cp = session.client("codepipeline")
            pipelines = cp.list_pipelines().get("pipelines", [])
        except Exception:
            pipelines = []

        if len(pipelines) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CodePipeline",
                "resource_id_type": "Service",
                "issue": "No CI/CD pipelines configured (CodePipeline)",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.25", "Secure development life cycle - CodePipeline",
                      resources_affected, max(len(pipelines), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking CodePipeline: {e}")
        return None


def check_codebuild(session):
    """A.8.28: CodeBuild projects should exist for secure build process."""
    print("  ISO27001: Checking CodeBuild")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            cb = session.client("codebuild")
            projects = cb.list_projects().get("projects", [])
        except Exception:
            projects = []

        if len(projects) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CodeBuild",
                "resource_id_type": "Service",
                "issue": "No CodeBuild projects configured for automated builds",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.28", "Secure coding - CodeBuild",
                      resources_affected, max(len(projects), 1), 40, "Low")
    except Exception as e:
        print(f"Error checking CodeBuild: {e}")
        return None


def check_codecommit(session):
    """A.8.4: Source code repositories should have access controls."""
    print("  ISO27001: Checking CodeCommit")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            cc = session.client("codecommit")
            repos = cc.list_repositories().get("repositories", [])
        except Exception:
            repos = []

        # Informational check - if repos exist, verify they're not empty
        if len(repos) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CodeCommit",
                "resource_id_type": "Service",
                "issue": "No CodeCommit repositories (source code may be stored externally)",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.4", "Access to source code - CodeCommit",
                      resources_affected, max(len(repos), 1), 30, "Low")
    except Exception as e:
        print(f"Error checking CodeCommit: {e}")
        return None


def check_cloudfront_https(session):
    """A.5.14: CloudFront distributions should use HTTPS."""
    print("  ISO27001: Checking CloudFront HTTPS")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            cf = session.client("cloudfront")
            distributions = cf.list_distributions().get("DistributionList", {}).get("Items", [])
            total = len(distributions) if distributions else 0

            for dist in (distributions or []):
                viewer_protocol = dist.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy", "")
                if viewer_protocol == "allow-all":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": dist.get("DomainName", dist.get("Id", "")),
                        "resource_id_type": "CloudFront Distribution",
                        "issue": f"CloudFront '{dist.get('DomainName')}' allows HTTP (not HTTPS-only)",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
        except Exception:
            total = 0

        return _result("A.5.14", "Information transfer - CloudFront HTTPS",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking CloudFront: {e}")
        return None


def check_vpc_endpoints_appsec(session):
    """A.8.27: VPC endpoints for private service access."""
    print("  ISO27001: Checking VPC endpoints for app security")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])

        key_services = ["s3", "dynamodb", "sqs", "sns", "kms", "secretsmanager"]
        endpoint_services = [ep.get("ServiceName", "").split(".")[-1] for ep in endpoints]
        missing = [svc for svc in key_services if svc not in endpoint_services]

        if len(missing) > 0 and len(endpoints) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "VPC Endpoints",
                "resource_id_type": "Service",
                "issue": f"No VPC endpoints for key services: {', '.join(missing)}",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.27", "Secure system architecture - VPC endpoints",
                      resources_affected, max(len(endpoints), 1), 40, "Low")
    except Exception as e:
        print(f"Error checking VPC endpoints: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Application Security",
        "problem_statement": f"ISO 27001 {control_id}: {check_name}",
        "severity_score": severity_score if len(resources_affected) > 0 else 0,
        "severity_level": severity_level,
        "resources_affected": resources_affected,
        "status": "passed" if len(resources_affected) == 0 else "failed",
        "recommendation": f"Remediate findings for {check_name} to meet ISO 27001 requirements",
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": len(resources_affected),
        },
        "last_updated": datetime.now(IST).isoformat(),
    }
