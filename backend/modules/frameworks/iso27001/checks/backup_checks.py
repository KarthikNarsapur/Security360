"""
ISO 27001 Checks — Backup & Resilience
Controls: A.5.29, A.5.30, A.8.13, A.8.14
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_backup_plans(session):
    """A.5.29/A.8.13: AWS Backup plans should be configured."""
    print("  ISO27001: Checking backup plans")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        backup = session.client("backup")

        try:
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            if len(plans) == 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "AWS Backup",
                    "resource_id_type": "Service",
                    "issue": "No AWS Backup plans configured",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AWS Backup",
                "resource_id_type": "Service",
                "issue": "Unable to access AWS Backup service",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
            plans = []

        return _result("A.5.29", "Info security during disruption - Backup plans",
                      resources_affected, max(len(plans), 1), 80, "High")
    except Exception as e:
        print(f"Error checking backup plans: {e}")
        return None


def check_protected_resources(session):
    """A.5.29: Critical resources should be protected by backup."""
    print("  ISO27001: Checking protected resources")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        backup = session.client("backup")

        try:
            protected = backup.list_protected_resources().get("Results", [])
            if len(protected) == 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "AWS Backup",
                    "resource_id_type": "Service",
                    "issue": "No resources are protected by AWS Backup",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            protected = []

        return _result("A.5.29", "Info security during disruption - Protected resources",
                      resources_affected, max(len(protected), 1), 70, "High")
    except Exception as e:
        print(f"Error checking protected resources: {e}")
        return None


def check_backup_vault_review(session):
    """A.5.29: Backup vaults should have encryption."""
    print("  ISO27001: Checking backup vault encryption")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        backup = session.client("backup")

        try:
            vaults = backup.list_backup_vaults().get("BackupVaultList", [])
            total = len(vaults)
            for vault in vaults:
                if not vault.get("EncryptionKeyArn"):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": vault["BackupVaultName"],
                        "resource_id_type": "Backup Vault",
                        "issue": f"Backup vault '{vault['BackupVaultName']}' has no custom encryption key",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
        except Exception:
            vaults = []
            total = 0

        return _result("A.5.29", "Info security during disruption - Backup vault review",
                      resources_affected, max(total, 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking backup vaults: {e}")
        return None


def check_rds_automated_backups(session):
    """A.8.13: RDS automated backups should be enabled with adequate retention."""
    print("  ISO27001: Checking RDS automated backups")
    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)

        for db in instances:
            retention = db.get("BackupRetentionPeriod", 0)
            if retention < 7:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": db["DBInstanceIdentifier"],
                    "resource_id_type": "RDS Instance",
                    "issue": f"RDS '{db['DBInstanceIdentifier']}' backup retention is {retention} days (min 7)",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.13", "Information backup - RDS automated backups",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking RDS backups: {e}")
        return None


def check_rds_multi_az(session):
    """A.5.30/A.8.14: RDS instances should use Multi-AZ for resilience."""
    print("  ISO27001: Checking RDS Multi-AZ")
    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)

        for db in instances:
            if not db.get("MultiAZ", False):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": db["DBInstanceIdentifier"],
                    "resource_id_type": "RDS Instance",
                    "issue": f"RDS '{db['DBInstanceIdentifier']}' is not Multi-AZ",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.5.30", "ICT readiness for business continuity - RDS Multi-AZ",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking RDS Multi-AZ: {e}")
        return None


def check_multi_az_validation(session):
    """A.8.14: Workloads should be distributed across multiple AZs."""
    print("  ISO27001: Checking Multi-AZ validation")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", [])

        azs_used = set()
        total_instances = 0
        for res in reservations:
            for inst in res.get("Instances", []):
                total_instances += 1
                azs_used.add(inst.get("Placement", {}).get("AvailabilityZone", ""))

        if total_instances > 1 and len(azs_used) <= 1:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "EC2",
                "resource_id_type": "Service",
                "issue": f"All {total_instances} instances are in a single AZ ({list(azs_used)[0] if azs_used else 'unknown'})",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.14", "Redundancy of information processing - Multi-AZ",
                      resources_affected, max(total_instances, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking multi-AZ: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Backup & Resilience",
        "problem_statement": f"ISO 27001 {control_id}: {check_name}",
        "severity_score": severity_score if len(resources_affected) > 0 else 0,
        "severity_level": severity_level,
        "resources_affected": resources_affected,
        "status": "passed" if len(resources_affected) == 0 else "failed",
        "recommendation": f"Remediate findings for {check_name} to meet ISO 27001 requirements",
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": len(resources_affected),
        },
        "last_updated": datetime.now(IST).isoformat(),
    }
