from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient


def init_scan_metadata():
    return {
        "total_scanned": 0,
        "affected": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "services_scanned": []
    }


class AzureSecurityScanner:
    def __init__(self, subscription_id):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()

        self.network_client = NetworkManagementClient(
            self.credential, subscription_id
        )
        self.compute_client = ComputeManagementClient(
            self.credential, subscription_id
        )
        self.resource_client = ResourceManagementClient(
            self.credential, subscription_id
        )
        self.lock_client = ManagementLockClient(
            self.credential, subscription_id
        )
        self.pg_client = PostgreSQLManagementClient(
            self.credential, subscription_id
        )

    def _update_metadata(self, meta, total, affected, severity, service):
        meta["total_scanned"] += total
        meta["affected"] += affected
        meta[severity] += affected
        meta["services_scanned"].append(service)

    def check_open_nsgs(self, scan_meta_data):
        findings = []
        total_nsgs = 0

        risky_ports = {"22", "3389", "1433", "3306", "5432"}
        allowed_web_ports = {"80", "443"}

        for nsg in self.network_client.network_security_groups.list_all():
            total_nsgs += 1
            open_ports = []

            for rule in nsg.security_rules:
                if rule.access.lower() != "allow":
                    continue

                source = str(rule.source_address_prefix).lower()
                destination_port = str(rule.destination_port_range)

                if source not in ["*", "internet", "0.0.0.0/0"]:
                    continue

                # IMPORTANT false positive prevention
                if destination_port in allowed_web_ports:
                    continue

                # Critical risky ports
                if (
                    destination_port in risky_ports
                    or destination_port == "*"
                    or "-" in destination_port
                ):
                    open_ports.append(destination_port)

            if open_ports:
                findings.append({
                    "resource_name": nsg.name,
                    "resource_id": nsg.id,
                    "location": nsg.location,
                    "open_ports": sorted(set(open_ports))
                })

        self._update_metadata(
            scan_meta_data,
            total_nsgs,
            len(findings),
            "High",
            "NSG"
        )

        return {
            "check_name": "Open NSGs",
            "service": "Network",
            "problem_statement": "NSG rules allow internet access on sensitive ports.",
            "severity_score": 90,
            "severity_level": "High",
            "resources_affected": findings,
            "recommendation": "Restrict inbound access to specific IP ranges.",
            "additional_info": {
                "total_scanned": total_nsgs,
                "affected": len(findings)
            }
        }

    def check_vms_with_public_ips(self, scan_meta_data):
        findings = []
        total_vms = 0

        for vm in self.compute_client.virtual_machines.list_all():
            total_vms += 1
            resource_group = vm.id.split("/")[4]

            nic_refs = vm.network_profile.network_interfaces

            for nic_ref in nic_refs:
                nic_name = nic_ref.id.split("/")[-1]

                nic = self.network_client.network_interfaces.get(
                    resource_group,
                    nic_name
                )

                for ip_config in nic.ip_configurations:
                    if ip_config.public_ip_address:
                        findings.append({
                            "resource_name": vm.name,
                            "vm_size": vm.hardware_profile.vm_size,
                            "public_ip_resource": ip_config.public_ip_address.id,
                            "location": vm.location
                        })

        self._update_metadata(
            scan_meta_data,
            total_vms,
            len(findings),
            "Medium",
            "VM"
        )

        return {
            "check_name": "VMs with Public IPs",
            "service": "Compute",
            "problem_statement": "Virtual machines have public IP exposure.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": findings,
            "recommendation": "Use private endpoints, bastion, or firewall.",
            "additional_info": {
                "total_scanned": total_vms,
                "affected": len(findings)
            }
        }

    def check_unattached_disks(self, scan_meta_data):
        findings = []
        total_disks = 0

        for disk in self.compute_client.disks.list():
            total_disks += 1

            if not disk.managed_by:
                findings.append({
                    "resource_name": disk.name,
                    "disk_size_gb": disk.disk_size_gb,
                    "location": disk.location
                })

        self._update_metadata(
            scan_meta_data,
            total_disks,
            len(findings),
            "Low",
            "Disk"
        )

        return {
            "check_name": "Unattached Managed Disks",
            "service": "Compute",
            "problem_statement": "Disks are not attached to any VM.",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": findings,
            "recommendation": "Delete unused disks after validation.",
            "additional_info": {
                "total_scanned": total_disks,
                "affected": len(findings)
            }
        }

    def check_disk_encryption(self, scan_meta_data):
        findings = []
        total_disks = 0

        for disk in self.compute_client.disks.list():
            total_disks += 1

            # IMPORTANT false-flag logic
            # Azure managed disks are encrypted by default
            # only flag if encryption metadata missing
            if (
                not disk.encryption
                and not disk.disk_encryption_set_id
            ):
                findings.append({
                    "resource_name": disk.name,
                    "disk_size_gb": disk.disk_size_gb,
                    "location": disk.location
                })

        self._update_metadata(
            scan_meta_data,
            total_disks,
            len(findings),
            "Medium",
            "Disk"
        )

        return {
            "check_name": "Disk Encryption",
            "service": "Compute",
            "problem_statement": "Managed disks missing encryption metadata.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": findings,
            "recommendation": "Enable platform or CMK encryption.",
            "additional_info": {
                "total_scanned": total_disks,
                "affected": len(findings)
            }
        }

    def check_vm_delete_lock(self, scan_meta_data):
        findings = []
        total_vms = 0

        for vm in self.compute_client.virtual_machines.list_all():
            total_vms += 1
            has_lock = False

            for lock in self.lock_client.management_locks.list_at_resource_level(
                resource_group_name=vm.id.split("/")[4],
                resource_provider_namespace="Microsoft.Compute",
                parent_resource_path="",
                resource_type="virtualMachines",
                resource_name=vm.name
            ):
                if lock.level == "CanNotDelete":
                    has_lock = True

            if not has_lock:
                findings.append({
                    "resource_name": vm.name,
                    "location": vm.location
                })

        self._update_metadata(
            scan_meta_data,
            total_vms,
            len(findings),
            "Medium",
            "VM"
        )

        return {
            "check_name": "VM Delete Lock",
            "service": "Compute",
            "problem_statement": "VM missing delete protection lock.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": findings,
            "recommendation": "Apply CanNotDelete lock.",
            "additional_info": {
                "total_scanned": total_vms,
                "affected": len(findings)
            }
        }

    def check_postgres_public_access(self, scan_meta_data):
        findings = []
        total_servers = 0

        for server in self.pg_client.servers.list():
            total_servers += 1

            # IMPORTANT false positive prevention
            # public access != insecure if firewall restricted
            if server.network.public_network_access == "Enabled":
                findings.append({
                    "resource_name": server.name,
                    "location": server.location,
                    "version": server.version
                })

        self._update_metadata(
            scan_meta_data,
            total_servers,
            len(findings),
            "High",
            "Database"
        )

        return {
            "check_name": "PostgreSQL Public Access",
            "service": "Database",
            "problem_statement": "Database allows public network access.",
            "severity_score": 90,
            "severity_level": "High",
            "resources_affected": findings,
            "recommendation": "Use private endpoint or restrict firewall rules.",
            "additional_info": {
                "total_scanned": total_servers,
                "affected": len(findings)
            }
        }


subscription_id = "a2b28c85-1948-4263-90ca-bade2bac4df4"

scanner = AzureSecurityScanner(subscription_id)
scan_meta_data = init_scan_metadata()

results = []

results.append(scanner.check_open_nsgs(scan_meta_data))
results.append(scanner.check_vms_with_public_ips(scan_meta_data))
results.append(scanner.check_unattached_disks(scan_meta_data))
results.append(scanner.check_disk_encryption(scan_meta_data))
results.append(scanner.check_vm_delete_lock(scan_meta_data))
results.append(scanner.check_postgres_public_access(scan_meta_data))

print(results)
print(scan_meta_data)