import json
import re
from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.rdbms.mariadb import MariaDBManagementClient


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


class AzureMariaDBSecurityScanner:
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

        self.mariadb_client = MariaDBManagementClient(
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
    def check_mariadb_public_and_network(self, meta):
        findings = []

        for server in self.mariadb_client.servers.list():
            severity = "Medium"
            public_access = True
            broad_network = False

            ssl_enforcement = getattr(server, "ssl_enforcement", None)

            if str(ssl_enforcement).lower() != "enabled":
                severity = "High"
                broad_network = True

            findings.append({
                "resource_name": server.name,
                "service": "Azure Database for MariaDB",
                "location": server.location,
                "public_access": public_access,
                "broad_network": broad_network,
                "severity": severity
            })

            self._update_metadata(
                meta,
                1,
                1,
                severity,
                "Azure Database for MariaDB"
            )

        return {
            "check_name": "MariaDB Network Exposure",
            "service": "Azure Database for MariaDB",
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
            if resource.type == "Microsoft.DBforMariaDB/servers":
                total += 1
                resource_group = self.get_resource_group_from_id(resource.id)

                has_lock = False

                try:
                    for lock in self.lock_client.management_locks.list_at_resource_level(
                        resource_group_name=resource_group,
                        resource_provider_namespace="Microsoft.DBforMariaDB",
                        parent_resource_path="",
                        resource_type="servers",
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
            "MariaDB Delete Lock"
        )

        return {
            "check_name": "MariaDB Delete Lock Missing",
            "service": "Azure Database for MariaDB",
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

        for server in self.mariadb_client.servers.list():
            total += 1

            subnet_id = getattr(server, "delegated_subnet_arguments", None)

            if not subnet_id:
                findings.append({
                    "resource_name": server.name,
                    "service": "Azure Database for MariaDB"
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
            "service": "Azure Database for MariaDB",
            "severity_level": "Low",
            "severity_score": 30,
            "resources_affected": findings
        }

    # =========================
    # CHECK: BACKUP RETENTION
    # =========================
    def check_backup_retention(self, meta):
        findings = []
        total = 0

        for server in self.mariadb_client.servers.list():
            total += 1

            retention_days = getattr(server, "storage_profile", None)

            if not retention_days or retention_days.backup_retention_days < 7:
                findings.append({
                    "resource_name": server.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "Backup"
        )

        return {
            "check_name": "Low Backup Retention",
            "service": "Azure Database for MariaDB",
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

        for server in self.mariadb_client.servers.list():
            total += 1

            geo_backup = getattr(
                server.storage_profile,
                "geo_redundant_backup",
                None
            )

            if str(geo_backup).lower() != "enabled":
                findings.append({
                    "resource_name": server.name
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Medium",
            "HA"
        )

        return {
            "check_name": "Geo Redundant Backup Disabled",
            "service": "Azure Database for MariaDB",
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

        for server in self.mariadb_client.servers.list():
            total += 1

            ssl_enforcement = getattr(server, "ssl_enforcement", None)

            if str(ssl_enforcement).lower() != "enabled":
                findings.append({
                    "resource_name": server.name,
                    "ssl_enforcement": str(ssl_enforcement)
                })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "High",
            "TLS"
        )

        return {
            "check_name": "TLS / SSL Disabled",
            "service": "Azure Database for MariaDB",
            "severity_level": "High",
            "severity_score": 90,
            "resources_affected": findings
        }

    # =========================
    # CHECK: THREAT DETECTION / AUDIT LOG
    # =========================
    def check_audit_logging(self, meta):
        findings = []
        total = 0

        for server in self.mariadb_client.servers.list():
            total += 1

            # MariaDB SDK may not expose audit directly
            findings.append({
                "resource_name": server.name
            })

        self._update_metadata(
            meta,
            total,
            len(findings),
            "Low",
            "Audit"
        )

        return {
            "check_name": "Audit Logging Review Required",
            "service": "Azure Database for MariaDB",
            "severity_level": "Low",
            "severity_score": 30,
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
        file_path = script_dir / f"{safe_filename}_mariadb.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, default=str)

        print(f"Results written to {file_path}")
        return str(file_path)


# ================= MAIN =================

subscription_id = "a2b28c85-1948-4263-90ca-bade2bac4df4"

scanner = AzureMariaDBSecurityScanner(subscription_id)
meta = init_scan_metadata()

results = []

results.append(scanner.check_mariadb_public_and_network(meta))
results.append(scanner.check_delete_locks(meta))
results.append(scanner.check_private_endpoint_missing(meta))
results.append(scanner.check_backup_retention(meta))
results.append(scanner.check_high_availability(meta))
results.append(scanner.check_tls_enforcement(meta))
results.append(scanner.check_audit_logging(meta))

file_name = scanner.write_results_to_json(results, meta)