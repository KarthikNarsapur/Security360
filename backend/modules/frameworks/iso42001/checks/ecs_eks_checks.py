"""
ISO 42001 Extended Checks — ECS/EKS AI Workloads (AI-074 to AI-078)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_ecr_public_repository(session):
    """AI-074: Public repository detection"""
    print("Checking ECR public repository detection")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check ECR Public repositories
        try:
            ecr_public = session.client("ecr-public", region_name="us-east-1")
            repos = ecr_public.describe_repositories().get("repositories", [])
            for repo in repos:
                repo_name = repo.get("repositoryName", "")
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": repo_name,
                    "resource_id_type": "ECRPublicRepository",
                    "issue": f"Public ECR repository '{repo_name}' detected — AI container images publicly accessible",
                    "region": "us-east-1",
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            # ecr-public not available or no public repos
            pass

        return {
            "id": "AI-074",
            "check_name": "Public repository detection",
            "problem_statement": "AI container images should not be in public ECR repositories",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Move AI container images to private ECR repositories",
            "additional_info": {"total_scanned": 1, "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Identify public ECR repositories with AI images",
                "2. Create private ECR repositories",
                "3. Migrate images to private repos",
                "4. Delete public repositories",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking ECR public repos: {e}")
        return None


def check_ecs_privileged_containers(session):
    """AI-075: Running privileged containers"""
    print("Checking ECS privileged containers")

    ecs = session.client("ecs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get task definitions
        try:
            task_def_arns = ecs.list_task_definitions(status="ACTIVE", maxResults=50).get("taskDefinitionArns", [])
        except Exception:
            task_def_arns = []

        ai_keywords = ["sagemaker", "bedrock", "ml", "ai", "inference", "model", "training"]
        total_scanned = 0

        for arn in task_def_arns:
            try:
                td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
                family = td.get("family", "").lower()

                # Check if AI-related
                is_ai = any(kw in family for kw in ai_keywords)
                if not is_ai:
                    continue

                total_scanned += 1
                containers = td.get("containerDefinitions", [])
                for container in containers:
                    if container.get("privileged", False):
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": f"{td.get('family', '')}:{td.get('revision', '')}",
                            "resource_id_type": "ECSTaskDefinition",
                            "issue": f"Container '{container.get('name', '')}' in task '{td.get('family', '')}' runs privileged",
                            "region": ecs.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-075",
            "check_name": "Running privileged containers",
            "problem_statement": "AI workload containers should not run in privileged mode",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Remove privileged mode from AI container task definitions",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Review AI task definitions for privileged: true",
                "2. Remove privileged flag",
                "3. Use specific Linux capabilities instead if needed",
                "4. Redeploy tasks with updated definitions",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking ECS privileged containers: {e}")
        return None


def check_containers_running_as_root(session):
    """AI-076: Containers running as root"""
    print("Checking containers running as root")

    ecs = session.client("ecs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            task_def_arns = ecs.list_task_definitions(status="ACTIVE", maxResults=50).get("taskDefinitionArns", [])
        except Exception:
            task_def_arns = []

        ai_keywords = ["sagemaker", "bedrock", "ml", "ai", "inference", "model", "training"]
        total_scanned = 0

        for arn in task_def_arns:
            try:
                td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
                family = td.get("family", "").lower()

                is_ai = any(kw in family for kw in ai_keywords)
                if not is_ai:
                    continue

                total_scanned += 1
                containers = td.get("containerDefinitions", [])
                for container in containers:
                    user = container.get("user", "")
                    # Empty user or "root" or "0" means running as root
                    if not user or user == "root" or user == "0":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": f"{td.get('family', '')}:{td.get('revision', '')}",
                            "resource_id_type": "ECSTaskDefinition",
                            "issue": f"Container '{container.get('name', '')}' in task '{td.get('family', '')}' runs as root",
                            "region": ecs.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-076",
            "check_name": "Containers running as root",
            "problem_statement": "AI containers should not run as root user for security isolation",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure AI containers to run as non-root user",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Add USER directive in Dockerfile",
                "2. Set 'user' field in container definition to non-root UID",
                "3. Ensure file permissions work with non-root user",
                "4. Redeploy containers",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking containers root: {e}")
        return None


def check_public_load_balancers_ai(session):
    """AI-077: Public load balancers serving AI"""
    print("Checking public load balancers serving AI")

    elbv2 = session.client("elbv2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        except Exception:
            lbs = []

        ai_keywords = ["sagemaker", "bedrock", "ml", "ai", "inference", "model"]
        total_scanned = 0

        for lb in lbs:
            lb_name = lb.get("LoadBalancerName", "").lower()
            lb_arn = lb.get("LoadBalancerArn", "")
            scheme = lb.get("Scheme", "")

            is_ai = any(kw in lb_name for kw in ai_keywords)

            # Also check tags
            if not is_ai:
                try:
                    tags_resp = elbv2.describe_tags(ResourceArns=[lb_arn])
                    for desc in tags_resp.get("TagDescriptions", []):
                        for tag in desc.get("Tags", []):
                            if any(kw in tag.get("Value", "").lower() for kw in ai_keywords):
                                is_ai = True
                                break
                except Exception:
                    pass

            if not is_ai:
                continue

            total_scanned += 1
            if scheme == "internet-facing":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": lb.get("LoadBalancerName", ""),
                    "resource_id_type": "LoadBalancer",
                    "issue": f"Internet-facing LB '{lb.get('LoadBalancerName', '')}' serving AI workloads",
                    "region": elbv2.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-077",
            "check_name": "Public load balancers serving AI",
            "problem_statement": "AI-serving load balancers should be internal unless public access is intentional",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Use internal load balancers for AI workloads unless public access is required",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Review AI-related load balancers",
                "2. Switch to internal scheme if public access not needed",
                "3. Add WAF protection for intentionally public AI endpoints",
                "4. Restrict security groups to specific IPs",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking public LBs for AI: {e}")
        return None


def check_missing_tls_listeners(session):
    """AI-078: Missing TLS listeners"""
    print("Checking missing TLS listeners on AI load balancers")

    elbv2 = session.client("elbv2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        except Exception:
            lbs = []

        total_scanned = 0
        for lb in lbs:
            lb_arn = lb.get("LoadBalancerArn", "")
            lb_name = lb.get("LoadBalancerName", "")
            total_scanned += 1

            try:
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                has_tls = any(
                    l.get("Protocol") in ("HTTPS", "TLS") for l in listeners
                )
                has_http = any(
                    l.get("Protocol") in ("HTTP", "TCP") for l in listeners
                )

                if has_http and not has_tls:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": lb_name,
                        "resource_id_type": "LoadBalancer",
                        "issue": f"Load balancer '{lb_name}' has HTTP/TCP listeners but no HTTPS/TLS",
                        "region": elbv2.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-078",
            "check_name": "Missing TLS listeners",
            "problem_statement": "Load balancers should use TLS/HTTPS to encrypt AI traffic in transit",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Add HTTPS/TLS listeners to all load balancers serving AI workloads",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Create ACM certificate for the domain",
                "2. Add HTTPS listener on port 443",
                "3. Redirect HTTP to HTTPS",
                "4. Use TLS 1.2+ security policy",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking TLS listeners: {e}")
        return None
