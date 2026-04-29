"""ECR security checks (2 checks)."""


def check_ecr_scan_on_push(session, scan_meta_data):
    print("check_ecr_scan_on_push")
    ecr = session.client("ecr")
    resources = []
    repos = ecr.describe_repositories().get("repositories", [])

    for repo in repos:
        scan_config = repo.get("imageScanningConfiguration", {})
        if not scan_config.get("scanOnPush", False):
            resources.append({
                "resource_name": repo.get("repositoryName"),
                "repository_uri": repo.get("repositoryUri"),
                "issue": "Image scan on push is disabled.",
            })

    scan_meta_data["total_scanned"] += len(repos)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "ECR" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECR")

    return {
        "check_name": "ECR Image Scan on Push",
        "service": "ECR",
        "problem_statement": "ECR repositories do not scan images for vulnerabilities on push.",
        "severity_score": 60, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable image scanning on push for all ECR repositories.",
        "additional_info": {"total_scanned": len(repos), "affected": len(resources)},
    }


def check_ecr_lifecycle_policy(session, scan_meta_data):
    print("check_ecr_lifecycle_policy")
    ecr = session.client("ecr")
    resources = []
    repos = ecr.describe_repositories().get("repositories", [])

    for repo in repos:
        name = repo.get("repositoryName")
        try:
            ecr.get_lifecycle_policy(repositoryName=name)
        except ecr.exceptions.LifecyclePolicyNotFoundException:
            resources.append({
                "resource_name": name,
                "repository_uri": repo.get("repositoryUri"),
                "issue": "No lifecycle policy configured.",
            })
        except Exception:
            pass

    scan_meta_data["total_scanned"] += len(repos)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "ECR" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECR")

    return {
        "check_name": "ECR Lifecycle Policy",
        "service": "ECR",
        "problem_statement": "ECR repositories lack lifecycle policies for image cleanup.",
        "severity_score": 25, "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Add lifecycle policies to automatically clean up old/untagged images.",
        "additional_info": {"total_scanned": len(repos), "affected": len(resources)},
    }
