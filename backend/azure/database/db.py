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
        "services_scanned": []
    }


class AzureDBSecurityScanner:
    def __init__(self, subscription_id):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()

        self.resource_client = ResourceManagementClient(
            self.credential,
            subscription_id
        )

        self.subscription_client = SubscriptionClient(
            self.credential
        )

        self.lock_client = ManagementLockClient(
            self.credential,
            subscription_id
        )

        self.sql_client = SqlManagementClient(
            self.credential,
            subscription_id
        )

        self.cosmos_client = CosmosDBManagementClient(
            self.credential,
            subscription_id
        )

        self.redis_client = RedisManagementClient(
            self.credential,
            subscription_id
        )

        self.pg_client = PostgreSQLManagementClient(
            self.credential,
            subscription_id
        )

        self.mysql_client = MySQLManagementClient(
            self.credential,
            subscription_id
        )

        self.mariadb_client = MariaDBManagementClient(
            self.credential,
            subscription_id
        )

    def _update_metadata(self, meta, total, affected, severity, service):
        meta["total_scanned"] += total
        meta["affected"] += affected
        meta[severity] += affected
        meta["services_scanned"].append(service)

    def get_subscription_name(self):
        for sub in self.subscription_client.subscriptions.list():
            if sub.subscription_id == self.subscription_id:
                return sub.display_name
        return self.subscription_id

    def check_sql(self, meta):
        findings = []
        total = 0

        for server in self.sql_client.servers.list():
            total += 1

            if str(server.public_network_access).lower() == "enabled":
                findings.append({
                    "resource_name": server.name,
                    "service": "Azure SQL",
                    "location": server.location,
                    "version": server.version
                })

        self._update_metadata(meta, total, len(findings), "Medium", "Azure SQL")

        return {
            "check_name": "Azure SQL Public Access",
            "service": "Azure SQL",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    def check_cosmos(self, meta):
        findings = []
        total = 0

        for account in self.cosmos_client.database_accounts.list():
            total += 1

            if str(account.public_network_access).lower() == "enabled":
                findings.append({
                    "resource_name": account.name,
                    "service": "Cosmos DB",
                    "location": account.location,
                    "kind": account.kind
                })

        self._update_metadata(meta, total, len(findings), "Medium", "Cosmos DB")

        return {
            "check_name": "Cosmos DB Public Access",
            "service": "Cosmos DB",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    def check_postgresql(self, meta):
        findings = []
        total = 0

        for server in self.pg_client.servers.list():
            total += 1

            network = getattr(server, "network", None)

            if network and str(network.public_network_access).lower() == "enabled":
                findings.append({
                    "resource_name": server.name,
                    "service": "PostgreSQL",
                    "location": server.location,
                    "version": server.version
                })

        self._update_metadata(meta, total, len(findings), "Medium", "PostgreSQL")

        return {
            "check_name": "PostgreSQL Public Access",
            "service": "PostgreSQL",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    def check_mysql(self, meta):
        findings = []
        total = 0

        for server in self.mysql_client.servers.list():
            total += 1

            network = getattr(server, "network", None)

            if network and str(network.public_network_access).lower() == "enabled":
                findings.append({
                    "resource_name": server.name,
                    "service": "MySQL",
                    "location": server.location,
                    "version": server.version
                })

        self._update_metadata(meta, total, len(findings), "Medium", "MySQL")

        return {
            "check_name": "MySQL Public Access",
            "service": "MySQL",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    def check_mariadb(self, meta):
        findings = []
        total = 0

        for server in self.mariadb_client.servers.list():
            total += 1

            if str(server.public_network_access).lower() == "enabled":
                findings.append({
                    "resource_name": server.name,
                    "service": "MariaDB",
                    "location": server.location,
                    "version": server.version
                })

        self._update_metadata(meta, total, len(findings), "Medium", "MariaDB")

        return {
            "check_name": "MariaDB Public Access",
            "service": "MariaDB",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

    def check_redis(self, meta):
        findings = []
        total = 0

        for cache in self.redis_client.redis.list_by_subscription():
            total += 1

            if str(cache.public_network_access).lower() == "enabled":
                findings.append({
                    "resource_name": cache.name,
                    "service": "Redis",
                    "location": cache.location,
                    "sku": cache.sku.name
                })

        self._update_metadata(meta, total, len(findings), "Medium", "Redis")

        return {
            "check_name": "Redis Public Access",
            "service": "Redis",
            "severity_level": "Medium",
            "severity_score": 60,
            "resources_affected": findings
        }

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

                for lock in self.lock_client.management_locks.list_at_resource_level(
                    resource_group_name=resource_group,
                    resource_provider_namespace=resource.type.split("/")[0],
                    parent_resource_path="",
                    resource_type=resource.type.split("/")[1],
                    resource_name=resource.name
                ):
                    if lock.level == "CanNotDelete":
                        has_lock = True

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
# a2b28c85-1948-4263-90ca-bade2bac4df4
scanner = AzureDBSecurityScanner(subscription_id)
scan_meta_data = init_scan_metadata()

results = []

results.append(scanner.check_sql(scan_meta_data))
results.append(scanner.check_cosmos(scan_meta_data))
results.append(scanner.check_postgresql(scan_meta_data))
results.append(scanner.check_mysql(scan_meta_data))
results.append(scanner.check_mariadb(scan_meta_data))
results.append(scanner.check_redis(scan_meta_data))
results.append(scanner.check_delete_locks(scan_meta_data))

file_name = scanner.write_results_to_json(results, scan_meta_data)

# print(results)
# print(scan_meta_data)
# print(file_name)















    # # =========================
    # # CHECK 7 CMK / BYOK
    # # =========================
    # def check_customer_managed_key(self, meta):
    #     findings = []
    #     total = 0

    #     for server in self.pg_client.servers.list():
    #         total += 1

    #         if not getattr(server, "data_encryption", None):
    #             findings.append({
    #                 "resource_name": server.name
    #             })

    #     self._update_metadata(meta, total, len(findings), "Low", "CMK")

    #     return {
    #         "check_name": "Customer Managed Key Missing",
    #         "service": "Database",
    #         "severity_level": "Low",
    #         "severity_score": 30,
    #         "resources_affected": findings
    # }


