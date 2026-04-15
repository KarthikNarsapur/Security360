import json
import re
from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient


def init_scan_metadata():
    return {
        "total_scanned": 0,
        "affected": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "services_scanned": [],
        "checks_executed": 0
    }


class AzureCosmosDBSecurityScanner:
    def __init__(self, subscription_id):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()

        self.resource_client = ResourceManagementClient(
            self.credential, subscription_id
        )

        self.subscription_client = SubscriptionClient(
            self.credential
        )

        self.lock_client = ManagementLockClient(
            self.credential, subscription_id
        )

        self.cosmos_client = CosmosDBManagementClient(
            self.credential, subscription_id
        )

    def _update_metadata(self, meta, total, affected, severity, service):
        meta["total_scanned"] += total
        meta["affected"] += affected
        meta[severity] += affected
        meta["services_scanned"].append(service)
        meta["checks_executed"] += 1

    def get_subscription_name(self):
        for sub in self.subscription_client.subscriptions.list():
            if sub.subscription_id == self.subscription_id:
                return sub.display_name
        return self.subscription_id

    def get_resource_group_from_id(self, resource_id):
        return resource_id.split("/")[4]

    # =========================
    # CHECK: PUBLIC ACCESS + NETWORK
    # =========================
    def check_cosmos_public_and_network(self, meta):
        findings = []

        for account in self.cosmos_client.database_accounts.list():
            severity = "Medium"
            score = 60
            public_access = True
            broad_network = False

            public_network_access = getattr(
                account, "public_network_access", None
            )

            if str(public_network_access).lower() == "disabled":
                public_access = False
            else:
                severity = "High"
                score = 90
                broad_network = True

            findings.append({
                "resource_name": account.name,
                "service": "Azure Cosmos DB",
                "location": account.location,
                "public_access": public_access,
                "broad_network": broad_network,
                "severity": severity
            })

            self._update_metadata(
                meta,
                1,
                1,
                severity,
                "Azure Cosmos DB"
            )

        return {
            "check_name": "Cosmos DB Network Exposure",
            "service": "Azure Cosmos DB",
            "severity_level": "Dynamic",
            "severity_score": "60 / 90",
            "resources_affected": findings
        }

    # =========================
    # CHECK: DELETE LOCK
    # =========================
    def check_delete_locks(self, meta):
        findings = []
        total = 0

        for resource in self.resource_client.resources.list():
            if resource.type == "Microsoft.DocumentDB/databaseAccounts":
                total += 1
                resource_group = self.get_resource_group_from_id(resource.id)

                has_lock = False

                try:
                    for lock in self.lock_client.management_locks.list_at_resource_level(
                        resource_group_name=resource_group,
                        resource_provider_namespace="Microsoft.DocumentDB",
                        parent_resource_path="",
                        resource_type="databaseAccounts",
                        resource_name=resource.name
                    ):
                        if lock.level == "CanNotDelete":
                            has_lock = True
                except Exception:
                    pass

                if not has_lock:
                    findings.append({
                        "resource_name": resource.name,
                        "service": resource.type,
                        "location": resource.location
                    })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "Cosmos Delete Lock"
        )

        return {
            "check_name": "Cosmos DB Delete Lock Missing",
            "service": "Azure Cosmos DB",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    # =========================
    # CHECK: PRIVATE ENDPOINT
    # =========================
    def check_private_endpoint_missing(self, meta):
        findings = []
        total = 0

        for account in self.cosmos_client.database_accounts.list():
            total += 1
            resource_group = self.get_resource_group_from_id(account.id)

            try:
                pe_connections = list(
                    self.cosmos_client.private_link_resources.list_by_database_account(
                        resource_group_name=resource_group,
                        account_name=account.name
                    )
                )

                if not pe_connections:
                    findings.append({
                        "resource_name": account.name,
                        "service": "Azure Cosmos DB"
                    })

            except Exception:
                findings.append({
                    "resource_name": account.name,
                    "service": "Azure Cosmos DB"
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Low",
            "Private Endpoint"
        )

        return {
            "check_name": "Private Endpoint Missing",
            "service": "Azure Cosmos DB",
            "severity_level": "Low",
            "severity_score": 30,
            "resources_affected": findings
        }

    # =========================
    # CHECK: BACKUP POLICY
    # =========================
    def check_backup_retention(self, meta):
        findings = []
        total = 0

        for account in self.cosmos_client.database_accounts.list():
            total += 1

            backup_policy = getattr(account, "backup_policy", None)

            if not backup_policy:
                findings.append({
                    "resource_name": account.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "Backup"
        )

        return {
            "check_name": "Backup Policy Missing",
            "service": "Azure Cosmos DB",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    # =========================
    # CHECK: HIGH AVAILABILITY
    # =========================
    def check_high_availability(self, meta):
        findings = []
        total = 0

        for account in self.cosmos_client.database_accounts.list():
            total += 1

            locations = getattr(account, "locations", [])

            if len(locations) < 2:
                findings.append({
                    "resource_name": account.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "HA"
        )

        return {
            "check_name": "Geo Redundancy Disabled",
            "service": "Azure Cosmos DB",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    # =========================
    # CHECK: TLS ENFORCEMENT
    # =========================
    def check_tls_enforcement(self, meta):
        findings = []
        total = 0

        for account in self.cosmos_client.database_accounts.list():
            total += 1

            min_tls = getattr(account, "minimal_tls_version", None)

            if not min_tls or str(min_tls) not in ["Tls12", "Tls13"]:
                findings.append({
                    "resource_name": account.name,
                    "minimal_tls_version": str(min_tls)
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "High",
            "TLS"
        )

        return {
            "check_name": "Weak TLS Version",
            "service": "Azure Cosmos DB",
            "severity_level": "High",
            "severity_score": 90,
            "resources_affected": findings
        }

    # =========================
    # CHECK: CUSTOMER MANAGED KEY
    # =========================
    def check_cmk_encryption(self, meta):
        findings = []
        total = 0

        for account in self.cosmos_client.database_accounts.list():
            total += 1

            key_uri = getattr(account, "key_vault_key_uri", None)

            if not key_uri:
                findings.append({
                    "resource_name": account.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "High",
            "CMK"
        )

        return {
            "check_name": "Customer Managed Key Missing",
            "service": "Azure Cosmos DB",
            "severity_level": "High",
            "severity_score": 90,
            "resources_affected": findings
        }

    # ==================== WRITE RESULTS TO JSON ====================
    def write_results_to_json(self, results, meta):
        subscription_name = self.get_subscription_name()
        safe_filename = re.sub(r'[<>:"/\\\\|?*]', "_", subscription_name)

        output = {
            "subscription_name": subscription_name,
            "subscription_id": self.subscription_id,
            "scan_summary": meta,
            "findings": results
        }

        script_dir = Path(__file__).parent.resolve()
        file_path = script_dir / f"{safe_filename}_cosmosdb.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, default=str)

        print(f"Results written to {file_path}")
        return str(file_path)


# ================= MAIN =================

subscription_id = "a2b28c85-1948-4263-90ca-bade2bac4df4"

scanner = AzureCosmosDBSecurityScanner(subscription_id)
meta = init_scan_metadata()

results = []

results.append(scanner.check_cosmos_public_and_network(meta))
results.append(scanner.check_delete_locks(meta))
results.append(scanner.check_private_endpoint_missing(meta))
results.append(scanner.check_backup_retention(meta))
results.append(scanner.check_high_availability(meta))
results.append(scanner.check_tls_enforcement(meta))
results.append(scanner.check_cmk_encryption(meta))

file_name = scanner.write_results_to_json(results, meta)