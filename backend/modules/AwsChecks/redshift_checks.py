"""Redshift security checks (3 checks)."""
from botocore.exceptions import ClientError


def _get_clusters(session):
    """Safely get Redshift clusters, handling SubscriptionRequired/OptInRequired."""
    rs = session.client("redshift")
    try:
        return rs, rs.describe_clusters().get("Clusters", [])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("OptInRequired", "SubscriptionRequiredException"):
            print(f"Redshift not subscribed in {session.region_name} — skipping")
            return rs, []
        raise


def check_redshift_encryption(session, scan_meta_data):
    print("check_redshift_encryption")
    rs, clusters = _get_clusters(session)
    resources = []

    for c in clusters:
        if not c.get("Encrypted", False):
            resources.append({
                "resource_name": c.get("ClusterIdentifier"),
                "node_type": c.get("NodeType"),
                "status": c.get("ClusterStatus"),
                "issue": "Cluster is not encrypted.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "Redshift" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Redshift")

    return {
        "check_name": "Redshift Cluster Encryption",
        "service": "Redshift",
        "problem_statement": "Redshift clusters are not encrypted at rest.",
        "severity_score": 80, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Enable encryption on Redshift clusters using KMS.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }


def check_redshift_public(session, scan_meta_data):
    print("check_redshift_public")
    rs, clusters = _get_clusters(session)
    resources = []

    for c in clusters:
        if c.get("PubliclyAccessible", False):
            resources.append({
                "resource_name": c.get("ClusterIdentifier"),
                "endpoint": c.get("Endpoint", {}).get("Address"),
                "port": c.get("Endpoint", {}).get("Port"),
                "issue": "Cluster is publicly accessible.",
            })

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "Redshift" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Redshift")

    return {
        "check_name": "Redshift Publicly Accessible",
        "service": "Redshift",
        "problem_statement": "Redshift clusters are publicly accessible.",
        "severity_score": 85, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Disable public accessibility and restrict to VPC.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }


def check_redshift_audit_logging(session, scan_meta_data):
    print("check_redshift_audit_logging")
    rs, clusters = _get_clusters(session)
    resources = []

    for c in clusters:
        cid = c.get("ClusterIdentifier")
        try:
            log_status = rs.describe_logging_status(ClusterIdentifier=cid)
            if not log_status.get("LoggingEnabled", False):
                resources.append({
                    "resource_name": cid,
                    "issue": "Audit logging is not enabled.",
                })
        except Exception as e:
            print(f"Error checking Redshift logging for {cid}: {e}")

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "Redshift" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Redshift")

    return {
        "check_name": "Redshift Audit Logging",
        "service": "Redshift",
        "problem_statement": "Redshift clusters do not have audit logging enabled.",
        "severity_score": 55, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable audit logging to S3 for compliance and forensics.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }
