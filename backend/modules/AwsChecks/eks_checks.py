"""EKS security checks (4 checks)."""


def check_eks_public_endpoint(session, scan_meta_data):
    print("check_eks_public_endpoint")
    eks = session.client("eks")
    resources = []
    clusters = eks.list_clusters().get("clusters", [])

    for name in clusters:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc.get("resourcesVpcConfig", {}).get("endpointPublicAccess", True):
            resources.append({
                "resource_name": name,
                "version": desc.get("version"),
                "status": desc.get("status"),
                "issue": "EKS cluster API endpoint is publicly accessible.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "EKS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EKS")

    return {
        "check_name": "EKS Public API Endpoint",
        "service": "EKS",
        "problem_statement": "EKS cluster API endpoints are publicly accessible.",
        "severity_score": 80, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Disable public access and use private endpoints.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }


def check_eks_version_eol(session, scan_meta_data):
    print("check_eks_version_eol")
    eks = session.client("eks")
    resources = []
    clusters = eks.list_clusters().get("clusters", [])
    supported = ["1.28", "1.29", "1.30", "1.31", "1.32"]

    for name in clusters:
        desc = eks.describe_cluster(name=name)["cluster"]
        version = desc.get("version", "")
        if version not in supported:
            resources.append({
                "resource_name": name, "version": version,
                "issue": f"Cluster running unsupported version {version}.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "EKS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EKS")

    return {
        "check_name": "EKS Cluster Version EOL",
        "service": "EKS",
        "problem_statement": "EKS clusters run unsupported Kubernetes versions.",
        "severity_score": 75, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Upgrade to a supported EKS version.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }


def check_eks_logging(session, scan_meta_data):
    print("check_eks_logging")
    eks = session.client("eks")
    resources = []
    clusters = eks.list_clusters().get("clusters", [])
    required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}

    for name in clusters:
        desc = eks.describe_cluster(name=name)["cluster"]
        enabled = set()
        for entry in desc.get("logging", {}).get("clusterLogging", []):
            if entry.get("enabled"):
                enabled.update(entry.get("types", []))
        missing = required - enabled
        if missing:
            resources.append({
                "resource_name": name, "missing_logs": list(missing),
                "issue": f"Missing log types: {', '.join(missing)}.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "EKS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EKS")

    return {
        "check_name": "EKS Control Plane Logging",
        "service": "EKS",
        "problem_statement": "EKS clusters do not have all control plane log types enabled.",
        "severity_score": 55, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable all 5 log types: api, audit, authenticator, controllerManager, scheduler.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }


def check_eks_secrets_encryption(session, scan_meta_data):
    print("check_eks_secrets_encryption")
    eks = session.client("eks")
    resources = []
    clusters = eks.list_clusters().get("clusters", [])

    for name in clusters:
        desc = eks.describe_cluster(name=name)["cluster"]
        enc_config = desc.get("encryptionConfig", [])
        has_secrets_enc = any(
            "secrets" in (e.get("resources", []))
            for e in enc_config
        )
        if not has_secrets_enc:
            resources.append({
                "resource_name": name, "version": desc.get("version"),
                "issue": "Kubernetes secrets encryption via KMS not enabled.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "EKS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("EKS")

    return {
        "check_name": "EKS Secrets Encryption",
        "service": "EKS",
        "problem_statement": "EKS clusters do not encrypt Kubernetes secrets with KMS.",
        "severity_score": 75, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Enable envelope encryption for Kubernetes secrets using a KMS key.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }
