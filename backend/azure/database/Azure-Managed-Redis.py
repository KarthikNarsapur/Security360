import json
import re
from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.redisenterprise import RedisEnterpriseManagementClient


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


class AzureManagedRedisSecurityScanner:
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

        self.redis_client = RedisEnterpriseManagementClient(
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
    def check_managed_redis_public_and_network(self, meta):
        findings = []

        for cluster in self.redis_client.redis_enterprise.list():
            severity = "Medium"
            public_access = False
            broad_network = False

            subnet_id = getattr(cluster, "subnet_id", None)

            if not subnet_id:
                severity = "High"
                public_access = True
                broad_network = True

            findings.append({
                "resource_name": cluster.name,
                "service": "Azure Managed Redis",
                "location": cluster.location,
                "public_access": public_access,
                "broad_network": broad_network,
                "severity": severity
            })

            self._update_metadata(
                meta,
                1,
                1,
                severity,
                "Azure Managed Redis"
            )

        return {
            "check_name": "Managed Redis Network Exposure",
            "service": "Azure Managed Redis",
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
            if resource.type == "Microsoft.Cache/redisEnterprise":
                total += 1
                resource_group = self.get_resource_group_from_id(resource.id)

                has_lock = False

                try:
                    for lock in self.lock_client.management_locks.list_at_resource_level(
                        resource_group_name=resource_group,
                        resource_provider_namespace="Microsoft.Cache",
                        parent_resource_path="",
                        resource_type="redisEnterprise",
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
            "Managed Redis Delete Lock"
        )

        return {
            "check_name": "Managed Redis Delete Lock Missing",
            "service": "Azure Managed Redis",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    # =========================
    # CHECK: PRIVATE ENDPOINT / VNET
    # =========================
    def check_private_endpoint_missing(self, meta):
        findings = []
        total = 0

        for cluster in self.redis_client.redis_enterprise.list():
            total += 1

            subnet_id = getattr(cluster, "subnet_id", None)

            if not subnet_id:
                findings.append({
                    "resource_name": cluster.name,
                    "service": "Azure Managed Redis"
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Low",
            "Private Endpoint"
        )

        return {
            "check_name": "Private Endpoint / VNet Missing",
            "service": "Azure Managed Redis",
            "severity_level": "Low",
            "severity_score": 30,
            "resources_affected": findings
        }

    # =========================
    # CHECK: BACKUP / PERSISTENCE
    # =========================
    def check_backup_retention(self, meta):
        findings = []
        total = 0

        for cluster in self.redis_client.redis_enterprise.list():
            total += 1

            persistence = getattr(cluster, "persistence", None)

            if not persistence:
                findings.append({
                    "resource_name": cluster.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "Backup"
        )

        return {
            "check_name": "Persistence Disabled",
            "service": "Azure Managed Redis",
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

        for cluster in self.redis_client.redis_enterprise.list():
            total += 1

            sku = getattr(cluster, "sku", None)

            if not sku or "Enterprise" not in str(sku.name):
                findings.append({
                    "resource_name": cluster.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "HA"
        )

        return {
            "check_name": "High Availability Review Required",
            "service": "Azure Managed Redis",
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

        for cluster in self.redis_client.redis_enterprise.list():
            total += 1

            minimum_tls_version = getattr(
                cluster,
                "minimum_tls_version",
                None
            )

            if not minimum_tls_version or str(minimum_tls_version) in ["1.0", "1.1"]:
                findings.append({
                    "resource_name": cluster.name,
                    "minimum_tls_version": str(minimum_tls_version)
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
            "service": "Azure Managed Redis",
            "severity_level": "High",
            "severity_score": 90,
            "resources_affected": findings
        }

    # =========================
    # CHECK: AUTH / NON TLS PORT
    # =========================
    def check_authentication(self, meta):
        findings = []
        total = 0

        for cluster in self.redis_client.redis_enterprise.list():
            total += 1

            if getattr(cluster, "port", None) == 10000:
                findings.append({
                    "resource_name": cluster.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "High",
            "Authentication"
        )

        return {
            "check_name": "Authentication Review Required",
            "service": "Azure Managed Redis",
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
        file_path = script_dir / f"{safe_filename}_managed_redis.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, default=str)

        print(f"Results written to {file_path}")
        return str(file_path)


# ================= MAIN =================

subscription_id = "a2b28c85-1948-4263-90ca-bade2bac4df4"

scanner = AzureManagedRedisSecurityScanner(subscription_id)
meta = init_scan_metadata()

results = []

results.append(scanner.check_managed_redis_public_and_network(meta))
results.append(scanner.check_delete_locks(meta))
results.append(scanner.check_private_endpoint_missing(meta))
results.append(scanner.check_backup_retention(meta))
results.append(scanner.check_high_availability(meta))
results.append(scanner.check_tls_enforcement(meta))
results.append(scanner.check_authentication(meta))

file_name = scanner.write_results_to_json(results, meta)