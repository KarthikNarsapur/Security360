import json
import re
from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource.locks import ManagementLockClient

from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.redis import RedisManagementClient

from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient
from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient
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


class AzureDBSecurityScanner:
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

        self.sql_client = SqlManagementClient(
            self.credential, subscription_id
        )

        self.cosmos_client = CosmosDBManagementClient(
            self.credential, subscription_id
        )

        self.redis_client = RedisManagementClient(
            self.credential, subscription_id
        )

        self.pg_client = PostgreSQLManagementClient(
            self.credential, subscription_id
        )

        self.mysql_client = MySQLManagementClient(
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

    # =========================
    # CHECK 1 + 2
    # PUBLIC ACCESS + FIREWALL
    # =========================
    def check_postgresql_public_and_firewall(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1
            severity = "Medium"
            score = 60

            public_access = False
            broad_firewall = False

            network = getattr(server, "network", None)

            if network and str(network.public_network_access).lower() == "enabled":
                public_access = True

            # IMPORTANT CORRELATION LOGIC
            # check firewall rules
            try:
                firewall_rules = self.pg_client.firewall_rules.list_by_server(
                    resource_group_name=server.id.split("/")[4],
                    server_name=server.name
                )

                for rule in firewall_rules:
                    if (
                        rule.start_ip_address == "0.0.0.0"
                        and rule.end_ip_address == "255.255.255.255"
                    ):
                        broad_firewall = True
                        severity = "High"
                        score = 90
            except Exception:
                pass

            if public_access:
                findings.append({
                    "resource_name": server.name,
                    "service": "PostgreSQL",
                    "location": server.location,
                    "version": server.version,
                    "public_access": public_access,
                    "broad_firewall": broad_firewall,
                    "severity": severity
                })

                self._update_metadata(
                    meta,
                    1,
                    1,
                    severity,
                    "PostgreSQL"
                )

        return {
            "check_name": "PostgreSQL Public Access + Firewall",
            "service": "PostgreSQL",
            "severity_level": "Dynamic",
            "severity_score": "60 / 90",
            "resources_affected": findings
        }

    # =========================
    # CHECK 3 DELETE LOCK
    # =========================
    def check_delete_locks(self, meta):
        findings = []
        total = 0

        db_types = [
            "Microsoft.Sql/servers",
            "Microsoft.DocumentDB/databaseAccounts",
            "Microsoft.DBforPostgreSQL/flexibleServers",
            "Microsoft.DBforMySQL/flexibleServers",
            "Microsoft.DBforMariaDB/servers",
            "Microsoft.Cache/Redis"
        ]

        for resource in self.resource_client.resources.list():
            if resource.type in db_types:
                total += 1
                resource_group = resource.id.split("/")[4]

                has_lock = False

                try:
                    for lock in self.lock_client.management_locks.list_at_resource_level(
                        resource_group_name=resource_group,
                        resource_provider_namespace=resource.type.split("/")[0],
                        parent_resource_path="",
                        resource_type=resource.type.split("/")[1],
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

        self._update_metadata(meta, total, len(findings), "Medium", "DB Delete Lock")

        return {
            "check_name": "Managed DB Delete Lock",
            "service": "Database",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    # =========================
    # CHECK 4 PRIVATE ENDPOINT
    # =========================
    def check_private_endpoint_missing(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1

            if not getattr(server, "private_endpoint_connections", None):
                findings.append({
                    "resource_name": server.name,
                    "service": "PostgreSQL"
                })

        self._update_metadata(meta, total, len(findings), "Low", "Private Endpoint")

        return {
            "check_name": "Private Endpoint Missing",
            "service": "Database",
            "severity_level": "Low",
            "severity_score": 30,
            "resources_affected": findings
        }

    # =========================
    # CHECK 5 BACKUP RETENTION
    # =========================
    def check_backup_retention(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1

            backup = getattr(server, "backup", None)

            if backup and backup.backup_retention_days < 7:
                findings.append({
                    "resource_name": server.name,
                    "retention_days": backup.backup_retention_days
                })

        self._update_metadata(meta, total, len(findings), "Medium", "Backup")

        return {
            "check_name": "Low Backup Retention",
            "service": "Database",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    # =========================
    # CHECK 6 HA / GEO
    # =========================
    def check_high_availability(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1

            ha = getattr(server, "high_availability", None)

            if not ha or str(ha.mode).lower() == "disabled":
                findings.append({
                    "resource_name": server.name
                })

        self._update_metadata(meta, total, len(findings), "Medium", "HA")

        return {
            "check_name": "High Availability Disabled",
            "service": "Database",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }



    # =========================
    # TLS Enforcement
    # =========================
    def check_tls_enforcement(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1

            min_tls = getattr(server, "minimal_tls_version", None)

            if not min_tls or str(min_tls) in ["TLS1_0", "TLS1_1"]:
                findings.append({
                    "resource_name": server.name,
                    "minimal_tls_version": str(min_tls)
                })

        self._update_metadata(meta, total, len(findings), "High", "TLS")

        return {
            "check_name": "Weak TLS Version",
            "service": "PostgreSQL",
            "severity_level": "High",
            "severity_score": 90,
            "resources_affected": findings
        }



    # =========================
    # Microsoft Entra Authentication
    # =========================
    def check_entra_auth(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1

            aad_admins = list(
                self.pg_client.administrators.list_by_server(
                    resource_group_name=server.id.split("/")[4],
                    server_name=server.name
                )
            )

            if not aad_admins:
                findings.append({
                    "resource_name": server.name
                })


# ==================== Write Results to JSON ====================
    def write_results_to_json(self, results, meta):
        subscription_name = self.get_subscription_name()
        safe_filename = re.sub(r'[<>:"/\\|?*]', "_", subscription_name)

        output = {
            "subscription_name": subscription_name,
            "subscription_id": self.subscription_id,
            "scan_summary": meta,
            "findings": results
        }

        script_dir = Path(__file__).parent.resolve()
        file_path = script_dir / f"{safe_filename}.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, default=str)


        print(f"Results written to {file_path}")
        return str(file_path)


# ================= MAIN =================

subscription_id = "a2b28c85-1948-4263-90ca-bade2bac4df4"

scanner = AzureDBSecurityScanner(subscription_id)
meta = init_scan_metadata()

results = []

results.append(scanner.check_postgresql_public_and_firewall(meta))
results.append(scanner.check_delete_locks(meta))
results.append(scanner.check_private_endpoint_missing(meta))
results.append(scanner.check_backup_retention(meta))
results.append(scanner.check_high_availability(meta))
# results.append(scanner.check_customer_managed_key(meta))

file_name = scanner.write_results_to_json(results, meta)

# print(results)
# print(meta)
# print(file_name)