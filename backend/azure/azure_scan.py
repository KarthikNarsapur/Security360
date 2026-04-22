"""
Unified Azure security scanner that combines VM/Network and Database checks.
Uses Service Principal credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
via DefaultAzureCredential.
"""

from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient
from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient


def get_azure_credential(tenant_id=None, client_id=None, client_secret=None):
    """Create credential from provided Service Principal creds."""
    if not all([tenant_id, client_id, client_secret]):
        raise ValueError("Azure credentials (tenant_id, client_id, client_secret) are required")
    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


class AzureUnifiedScanner:
    def __init__(self, subscription_id, credential=None):
        self.subscription_id = subscription_id
        self.credential = credential or get_azure_credential()

        self.network_client = NetworkManagementClient(self.credential, subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, subscription_id)
        self.lock_client = ManagementLockClient(self.credential, subscription_id)
        self.subscription_client = SubscriptionClient(self.credential)
        self.sql_client = SqlManagementClient(self.credential, subscription_id)
        self.cosmos_client = CosmosDBManagementClient(self.credential, subscription_id)
        self.redis_client = RedisManagementClient(self.credential, subscription_id)
        self.pg_client = PostgreSQLManagementClient(self.credential, subscription_id)
        self.mysql_client = MySQLManagementClient(self.credential, subscription_id)

    def get_subscription_name(self):
        try:
            for sub in self.subscription_client.subscriptions.list():
                if sub.subscription_id == self.subscription_id:
                    return sub.display_name
        except Exception:
            pass
        return self.subscription_id

    # ==================== VM / NETWORK CHECKS ====================

    def check_open_nsgs(self):
        findings = []
        total = 0
        risky_ports = {"22", "3389", "1433", "3306", "5432"}
        allowed_web_ports = {"80", "443"}

        try:
            for nsg in self.network_client.network_security_groups.list_all():
                total += 1
                open_ports = []
                for rule in nsg.security_rules:
                    if rule.access.lower() != "allow":
                        continue
                    source = str(rule.source_address_prefix).lower()
                    dest_port = str(rule.destination_port_range)
                    if source not in ["*", "internet", "0.0.0.0/0"]:
                        continue
                    if dest_port in allowed_web_ports:
                        continue
                    if dest_port in risky_ports or dest_port == "*" or "-" in dest_port:
                        open_ports.append(dest_port)
                if open_ports:
                    findings.append({
                        "resource_name": nsg.name,
                        "resource_id": nsg.id,
                        "location": nsg.location,
                        "open_ports": sorted(set(open_ports)),
                    })
        except Exception as e:
            print(f"Error checking NSGs: {e}")

        return {
            "check_name": "Open_NSGs",
            "service": "Network",
            "severity_level": "High",
            "severity_score": 90,
            "description": "NSG rules allow internet access on sensitive ports.",
            "remediation": "Restrict inbound access to specific IP ranges.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_vms_with_public_ips(self):
        findings = []
        total = 0
        try:
            for vm in self.compute_client.virtual_machines.list_all():
                total += 1
                rg = vm.id.split("/")[4]
                for nic_ref in vm.network_profile.network_interfaces:
                    nic_name = nic_ref.id.split("/")[-1]
                    nic = self.network_client.network_interfaces.get(rg, nic_name)
                    for ip_cfg in nic.ip_configurations:
                        if ip_cfg.public_ip_address:
                            findings.append({
                                "resource_name": vm.name,
                                "vm_size": vm.hardware_profile.vm_size,
                                "location": vm.location,
                            })
        except Exception as e:
            print(f"Error checking VM public IPs: {e}")

        return {
            "check_name": "VMs_with_Public_IPs",
            "service": "Compute",
            "severity_level": "Medium",
            "severity_score": 60,
            "description": "Virtual machines have public IP exposure.",
            "remediation": "Use private endpoints, bastion, or firewall.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_unattached_disks(self):
        findings = []
        total = 0
        try:
            for disk in self.compute_client.disks.list():
                total += 1
                if not disk.managed_by:
                    findings.append({
                        "resource_name": disk.name,
                        "disk_size_gb": disk.disk_size_gb,
                        "location": disk.location,
                    })
        except Exception as e:
            print(f"Error checking unattached disks: {e}")

        return {
            "check_name": "Unattached_Managed_Disks",
            "service": "Compute",
            "severity_level": "Low",
            "severity_score": 30,
            "description": "Disks are not attached to any VM.",
            "remediation": "Delete unused disks after validation.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_disk_encryption(self):
        findings = []
        total = 0
        try:
            for disk in self.compute_client.disks.list():
                total += 1
                if not disk.encryption and not disk.disk_encryption_set_id:
                    findings.append({
                        "resource_name": disk.name,
                        "disk_size_gb": disk.disk_size_gb,
                        "location": disk.location,
                    })
        except Exception as e:
            print(f"Error checking disk encryption: {e}")

        return {
            "check_name": "Disk_Encryption",
            "service": "Compute",
            "severity_level": "Medium",
            "severity_score": 60,
            "description": "Managed disks missing encryption metadata.",
            "remediation": "Enable platform or CMK encryption.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    # ==================== DATABASE CHECKS ====================

    def check_sql_public_access(self):
        findings = []
        total = 0
        try:
            for server in self.sql_client.servers.list():
                total += 1
                if str(getattr(server, "public_network_access", "")).lower() == "enabled":
                    findings.append({
                        "resource_name": server.name,
                        "service": "Azure SQL",
                        "location": server.location,
                    })
        except Exception as e:
            print(f"Error checking SQL public access: {e}")

        return {
            "check_name": "Azure_SQL_Public_Access",
            "service": "Azure SQL",
            "severity_level": "Medium",
            "severity_score": 60,
            "description": "Azure SQL servers with public network access enabled.",
            "remediation": "Disable public access and use private endpoints.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_cosmos_public_access(self):
        findings = []
        total = 0
        try:
            for account in self.cosmos_client.database_accounts.list():
                total += 1
                if str(getattr(account, "public_network_access", "")).lower() != "disabled":
                    findings.append({
                        "resource_name": account.name,
                        "service": "Cosmos DB",
                        "location": account.location,
                    })
        except Exception as e:
            print(f"Error checking Cosmos DB public access: {e}")

        return {
            "check_name": "Cosmos_DB_Public_Access",
            "service": "Cosmos DB",
            "severity_level": "High",
            "severity_score": 90,
            "description": "Cosmos DB accounts with public network access.",
            "remediation": "Disable public access and configure private endpoints.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_postgresql_public_access(self):
        findings = []
        total = 0
        try:
            for server in self.pg_client.servers.list():
                total += 1
                network = getattr(server, "network", None)
                if network and str(getattr(network, "public_network_access", "")).lower() == "enabled":
                    findings.append({
                        "resource_name": server.name,
                        "service": "PostgreSQL",
                        "location": server.location,
                    })
        except Exception as e:
            print(f"Error checking PostgreSQL public access: {e}")

        return {
            "check_name": "PostgreSQL_Public_Access",
            "service": "PostgreSQL",
            "severity_level": "High",
            "severity_score": 90,
            "description": "PostgreSQL servers with public network access enabled.",
            "remediation": "Use private endpoint or restrict firewall rules.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_mysql_public_access(self):
        findings = []
        total = 0
        try:
            for server in self.mysql_client.servers.list():
                total += 1
                network = getattr(server, "network", None)
                if network and str(getattr(network, "public_network_access", "")).lower() == "enabled":
                    findings.append({
                        "resource_name": server.name,
                        "service": "MySQL",
                        "location": server.location,
                    })
        except Exception as e:
            print(f"Error checking MySQL public access: {e}")

        return {
            "check_name": "MySQL_Public_Access",
            "service": "MySQL",
            "severity_level": "Medium",
            "severity_score": 60,
            "description": "MySQL servers with public network access enabled.",
            "remediation": "Disable public access and use private endpoints.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }

    def check_redis_public_access(self):
        findings = []
        total = 0
        try:
            for cache in self.redis_client.redis.list_by_subscription():
                total += 1
                if str(getattr(cache, "public_network_access", "")).lower() == "enabled":
                    findings.append({
                        "resource_name": cache.name,
                        "service": "Redis",
                        "location": cache.location,
                    })
        except Exception as e:
            print(f"Error checking Redis public access: {e}")

        return {
            "check_name": "Redis_Public_Access",
            "service": "Redis",
            "severity_level": "Medium",
            "severity_score": 60,
            "description": "Redis caches with public network access enabled.",
            "remediation": "Disable public access and use private endpoints.",
            "additional_info": {"total_scanned": total, "affected": len(findings)},
            "resources_affected": findings,
        }


def run_azure_checks(subscription_id, credential=None):
    """Run all Azure security checks and return results in the standard format."""
    scanner = AzureUnifiedScanner(subscription_id, credential)

    results = {}
    checks = [
        scanner.check_open_nsgs,
        scanner.check_vms_with_public_ips,
        scanner.check_unattached_disks,
        scanner.check_disk_encryption,
        scanner.check_sql_public_access,
        scanner.check_cosmos_public_access,
        scanner.check_postgresql_public_access,
        scanner.check_mysql_public_access,
        scanner.check_redis_public_access,
    ]

    for check_fn in checks:
        try:
            result = check_fn()
            results[result["check_name"]] = result
        except Exception as e:
            print(f"Error running {check_fn.__name__}: {e}")

    return results, scanner.get_subscription_name()
