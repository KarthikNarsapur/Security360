import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_opensearch_encryption_at_rest(session):
    # [Opensearch.1]
    print("Checking OpenSearch domains for encryption at rest")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            if not desc.get("EncryptionAtRestOptions", {}).get("Enabled", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": "Encryption at rest not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.1",
            "check_name": "Encryption at rest enabled",
            "problem_statement": "OpenSearch domains should have encryption at rest enabled to protect stored data.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable encryption at rest for OpenSearch domains.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Open OpenSearch console.",
                "2. Edit domain settings.",
                "3. Enable 'Encryption at rest'.",
                "4. Recreate domain if necessary, as some settings cannot be modified in-place.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OpenSearch encryption at rest: {e}")
        return None


def check_opensearch_domain_within_vpc(session):
    # [Opensearch.2]
    print("Checking OpenSearch domains within VPC")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            if not desc.get("VPCOptions", {}).get("VPCId"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": "Domain not deployed within a VPC",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.2",
            "check_name": "Domain within VPC",
            "problem_statement": "OpenSearch domains should be deployed within a VPC to restrict network access.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Deploy OpenSearch domains inside a VPC instead of public endpoints.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create new OpenSearch domains with VPC access.",
                "2. Migrate existing data.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OpenSearch VPC configuration: {e}")
        return None


def check_opensearch_node_to_node_encryption(session):
    # [Opensearch.3]
    print("Checking OpenSearch node-to-node encryption")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            if not desc.get("NodeToNodeEncryptionOptions", {}).get("Enabled", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": "Node-to-node encryption not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.3",
            "check_name": "Node-to-node encryption enabled",
            "problem_statement": "Node-to-node encryption should be enabled to secure traffic within the cluster.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable node-to-node encryption on domain creation.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create a new domain with node-to-node encryption enabled.",
                "2. Migrate data and decommission unencrypted domain.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OpenSearch node-to-node encryption: {e}")
        return None


def check_opensearch_logging(session):
    # [Opensearch.4, Opensearch.5]
    print("Checking OpenSearch cluster logging configuration")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            logs = desc.get("LogPublishingOptions", {})

            missing = []
            if not logs.get("AUDIT_LOGS", {}).get("Enabled", False):
                missing.append("audit logs")
            if not logs.get("INDEX_SLOW_LOGS", {}).get("Enabled", False):
                missing.append("application/index logs")

            if missing:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": f"Missing {', '.join(missing)} configuration",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.4/5",
            "check_name": "Application and audit logs enabled",
            "problem_statement": "OpenSearch domains should enable both application and audit logs for visibility.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable index slow logs and audit logs in domain logging settings.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Go to OpenSearch domain settings.",
                "2. Under 'Logs', enable 'Index slow logs' and 'Audit logs'.",
                "3. Provide CloudWatch log group ARN.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OpenSearch logging: {e}")
        return None


def check_opensearch_fine_grained_access(session):
    # [Opensearch.7]
    print("Checking OpenSearch fine-grained access control")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            if not desc.get("AdvancedSecurityOptions", {}).get("Enabled", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": "Fine-grained access control not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.7",
            "check_name": "Fine-grained access control enabled",
            "problem_statement": "Fine-grained access control should be enabled to manage user and role-level permissions.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable fine-grained access control when creating or updating the domain.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create a new domain with fine-grained access control enabled.",
                "2. Configure master user credentials.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking fine-grained access: {e}")
        return None


def check_opensearch_tls_enforced(session):
    # [Opensearch.8]
    print("Checking OpenSearch TLS enforcement")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            tls_policy = desc.get("DomainEndpointOptions", {}).get(
                "TLSSecurityPolicy", ""
            )
            if not tls_policy or not tls_policy.startswith("Policy-Min-TLS-1-2"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": f"Weak TLS policy in use ({tls_policy or 'None'})",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.8",
            "check_name": "TLS 1.2 enforced",
            "problem_statement": "Domains should enforce TLS 1.2 or higher for data-in-transit security.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Set the domain's TLS policy to 'Policy-Min-TLS-1-2-2019-07'.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify domain endpoint options.",
                "2. Set TLS policy to minimum TLS 1.2.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking TLS enforcement: {e}")
        return None


def check_opensearch_service_software_version(session):
    # [Opensearch.10]
    print("Checking OpenSearch domain service software versions")

    client = session.client("opensearch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        domains = client.list_domain_names().get("DomainNames", [])

        for d in domains:
            domain_name = d["DomainName"]
            desc = client.describe_domain(DomainName=domain_name)["DomainStatus"]
            if desc.get("ServiceSoftwareOptions", {}).get("UpdateAvailable", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": domain_name,
                        "resource_id_type": "OpenSearchDomain",
                        "issue": "Domain service software update available",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(domains)
        affected = len(resources_affected)
        return {
            "id": "Opensearch.10",
            "check_name": "Service software version up to date",
            "problem_statement": "Domains should run the latest OpenSearch service software to ensure security and stability.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Apply pending OpenSearch service software updates.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Go to OpenSearch console.",
                "2. Check for 'Service software update available'.",
                "3. Apply updates to all domains.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking service software version: {e}")
        return None
