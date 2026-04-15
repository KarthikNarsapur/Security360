import json
import re
from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.redis import RedisManagementClient


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


class AzureRedisCacheSecurityScanner:
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

        self.redis_client = RedisManagementClient(
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
    def check_redis_public_and_network(self, meta):
        findings = []

        for cache in self.redis_client.redis.list():
            severity = "Medium"
            score = 60
            public_access = True
            broad_network = False

            public_network_access = getattr(cache, "public_network_access", None)

            if str(public_network_access).lower() == "disabled":
                public_access = False
            else:
                severity = "High"
                score = 90
                broad_network = True

            findings.append({
                "resource_name": cache.name,
                "service": "Azure Cache for Redis",
                "location": cache.location,
                "public_access": public_access,
                "broad_network": broad_network,
                "severity": severity
            })

            self._update_metadata(
                meta,
                1,
                1,
                severity,
                "Azure Cache for Redis"
            )

        return {
            "check_name": "Redis Network Exposure",
            "service": "Azure Cache for Redis",
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
            if resource.type == "Microsoft.Cache/Redis":
                total += 1
                resource_group = self.get_resource_group_from_id(resource.id)

                has_lock = False

                try:
                    for lock in self.lock_client.management_locks.list_at_resource_level(
                        resource_group_name=resource_group,
                        resource_provider_namespace="Microsoft.Cache",
                        parent_resource_path="",
                        resource_type="Redis",
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
            "Redis Delete Lock"
        )

        return {
            "check_name": "Redis Delete Lock Missing",
            "service": "Azure Cache for Redis",
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

        for cache in self.redis_client.redis.list():
            total += 1

            pe_connections = getattr(
                cache, "private_endpoint_connections", None
            )

            if not pe_connections:
                findings.append({
                    "resource_name": cache.name,
                    "service": "Azure Cache for Redis"
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
            "service": "Azure Cache for Redis",
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

        for cache in self.redis_client.redis.list():
            total += 1

            redis_config = getattr(cache, "redis_configuration", {})

            if not redis_config.get("rdb-backup-enabled"):
                findings.append({
                    "resource_name": cache.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "Backup"
        )

        return {
            "check_name": "Backup Persistence Disabled",
            "service": "Azure Cache for Redis",
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

        for cache in self.redis_client.redis.list():
            total += 1

            sku = getattr(cache, "sku", None)

            if not sku or sku.name.lower() == "basic":
                findings.append({
                    "resource_name": cache.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "HA"
        )

        return {
            "check_name": "High Availability Disabled",
            "service": "Azure Cache for Redis",
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

        for cache in self.redis_client.redis.list():
            total += 1

            min_tls = getattr(cache, "minimum_tls_version", None)

            if not min_tls or str(min_tls) in ["1.0", "1.1"]:
                findings.append({
                    "resource_name": cache.name,
                    "minimum_tls_version": str(min_tls)
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
            "service": "Azure Cache for Redis",
            "severity_level": "High",
            "severity_score": 90,
            "resources_affected": findings
        }

    # =========================
    # CHECK: ACCESS KEY AUTH
    # =========================
    def check_access_keys_enabled(self, meta):
        findings = []
        total = 0

        for cache in self.redis_client.redis.list():
            total += 1

            enable_non_ssl_port = getattr(cache, "enable_non_ssl_port", None)

            if enable_non_ssl_port:
                findings.append({
                    "resource_name": cache.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "High",
            "Authentication"
        )

        return {
            "check_name": "Non-SSL Port Enabled",
            "service": "Azure Cache for Redis",
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
        file_path = script_dir / f"{safe_filename}_redis.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, default=str)

        print(f"Results written to {file_path}")
        return str(file_path)


# ================= MAIN =================

subscription_id = "a2b28c85-1948-4263-90ca-bade2bac4df4"

scanner = AzureRedisCacheSecurityScanner(subscription_id)
meta = init_scan_metadata()

results = []

results.append(scanner.check_redis_public_and_network(meta))
results.append(scanner.check_delete_locks(meta))
results.append(scanner.check_private_endpoint_missing(meta))
results.append(scanner.check_backup_retention(meta))
results.append(scanner.check_high_availability(meta))
results.append(scanner.check_tls_enforcement(meta))
results.append(scanner.check_access_keys_enabled(meta))

file_name = scanner.write_results_to_json(results, meta)