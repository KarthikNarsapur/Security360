"""OpenSearch security checks (3 checks)."""


def check_opensearch_encryption(session, scan_meta_data):
    print("check_opensearch_encryption")
    os_client = session.client("opensearch")
    resources = []
    domains = os_client.list_domain_names().get("DomainNames", [])
    domain_names = [d["DomainName"] for d in domains]

    if domain_names:
        details = os_client.describe_domains(DomainNames=domain_names[:5]).get("DomainStatusList", [])
        for d in details:
            enc = d.get("EncryptionAtRestOptions", {})
            if not enc.get("Enabled", False):
                resources.append({
                    "resource_name": d.get("DomainName"),
                    "engine_version": d.get("EngineVersion"),
                    "issue": "Encryption at rest not enabled.",
                })

    scan_meta_data["total_scanned"] += len(domain_names)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "OpenSearch" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("OpenSearch")

    return {
        "check_name": "OpenSearch Encryption at Rest",
        "service": "OpenSearch",
        "problem_statement": "OpenSearch domains do not have encryption at rest enabled.",
        "severity_score": 80, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Enable encryption at rest using KMS.",
        "additional_info": {"total_scanned": len(domain_names), "affected": len(resources)},
    }


def check_opensearch_public(session, scan_meta_data):
    print("check_opensearch_public")
    os_client = session.client("opensearch")
    resources = []
    domains = os_client.list_domain_names().get("DomainNames", [])
    domain_names = [d["DomainName"] for d in domains]

    if domain_names:
        details = os_client.describe_domains(DomainNames=domain_names[:5]).get("DomainStatusList", [])
        for d in details:
            vpc = d.get("VPCOptions", {})
            if not vpc.get("SubnetIds"):
                resources.append({
                    "resource_name": d.get("DomainName"),
                    "endpoint": d.get("Endpoint", ""),
                    "issue": "Domain is not in a VPC (public endpoint).",
                })

    scan_meta_data["total_scanned"] += len(domain_names)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "OpenSearch" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("OpenSearch")

    return {
        "check_name": "OpenSearch Publicly Accessible",
        "service": "OpenSearch",
        "problem_statement": "OpenSearch domains use public endpoints instead of VPC.",
        "severity_score": 85, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Deploy OpenSearch domains within a VPC.",
        "additional_info": {"total_scanned": len(domain_names), "affected": len(resources)},
    }


def check_opensearch_node_encryption(session, scan_meta_data):
    print("check_opensearch_node_encryption")
    os_client = session.client("opensearch")
    resources = []
    domains = os_client.list_domain_names().get("DomainNames", [])
    domain_names = [d["DomainName"] for d in domains]

    if domain_names:
        details = os_client.describe_domains(DomainNames=domain_names[:5]).get("DomainStatusList", [])
        for d in details:
            n2n = d.get("NodeToNodeEncryptionOptions", {})
            if not n2n.get("Enabled", False):
                resources.append({
                    "resource_name": d.get("DomainName"),
                    "issue": "Node-to-node encryption not enabled.",
                })

    scan_meta_data["total_scanned"] += len(domain_names)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "OpenSearch" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("OpenSearch")

    return {
        "check_name": "OpenSearch Node-to-Node Encryption",
        "service": "OpenSearch",
        "problem_statement": "OpenSearch domains lack node-to-node encryption.",
        "severity_score": 60, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable node-to-node encryption for data in transit within the cluster.",
        "additional_info": {"total_scanned": len(domain_names), "affected": len(resources)},
    }
