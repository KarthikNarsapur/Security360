import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_eks_endpoint_public_access(session):
    # [EKS.1]
    print("Checking EKS cluster endpoint public access")

    eks = session.client("eks")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = eks.list_clusters().get("clusters", [])

        for cluster_name in clusters:
            desc = eks.describe_cluster(name=cluster_name)["cluster"]
            endpoint_public = desc.get("resourcesVpcConfig", {}).get(
                "endpointPublicAccess", True
            )
            if endpoint_public:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster_name,
                        "resource_id_type": "EKSClusterName",
                        "issue": "EKS cluster endpoint publicly accessible",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "EKS.1",
            "check_name": "EKS endpoint public access",
            "problem_statement": "EKS cluster API endpoints should not be publicly accessible unless necessary.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Disable public access and use private endpoints for EKS clusters.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open EKS console.",
                "2. Select the cluster.",
                "3. Under Networking, edit the cluster endpoint access settings.",
                "4. Disable public access and enable private access.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EKS endpoint public access: {e}")
        return None


def check_eks_cluster_version_eol(session):
    # [EKS.2]
    print("Checking EKS cluster version for end-of-life")

    eks = session.client("eks")
    sts = session.client("sts")
    resources_affected = []

    # For reference, AWS EKS currently supports versions ~1.27-1.31
    supported_versions = ["1.27", "1.28", "1.29", "1.30", "1.31"]

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = eks.list_clusters().get("clusters", [])

        for cluster_name in clusters:
            desc = eks.describe_cluster(name=cluster_name)["cluster"]
            version = desc.get("version")
            if version not in supported_versions:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster_name,
                        "resource_id_type": "EKSClusterName",
                        "issue": f"EKS cluster running unsupported or EOL version {version}",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "EKS.2",
            "check_name": "EKS cluster version supported",
            "problem_statement": "EKS clusters should run supported Kubernetes versions to receive security updates.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Upgrade clusters to a supported EKS version.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Review EKS supported versions.",
                "2. Plan upgrade to latest stable version.",
                "3. Use 'eks update-cluster-version' via CLI or console.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EKS cluster versions: {e}")
        return None


def check_eks_cluster_logging_enabled(session):
    # [EKS.8]
    print("Checking EKS cluster control plane logging")

    eks = session.client("eks")
    sts = session.client("sts")
    resources_affected = []

    required_logs = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = eks.list_clusters().get("clusters", [])

        for cluster_name in clusters:
            desc = eks.describe_cluster(name=cluster_name)["cluster"]
            enabled_logs = desc.get("logging", {}).get("clusterLogging", [])
            active_types = [
                t for e in enabled_logs if e.get("enabled") for t in e.get("types", [])
            ]
            missing = [l for l in required_logs if l not in active_types]
            if missing:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster_name,
                        "resource_id_type": "EKSClusterName",
                        "issue": f"Cluster missing log types: {', '.join(missing)}",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "EKS.8",
            "check_name": "EKS control plane logging enabled",
            "problem_statement": "EKS control plane logging should be enabled for audit and operational visibility.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable control plane logs for all EKS clusters.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open EKS console.",
                "2. Select a cluster.",
                "3. Under Logging, enable all log types (api, audit, authenticator, etc.).",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EKS cluster logging: {e}")
        return None
