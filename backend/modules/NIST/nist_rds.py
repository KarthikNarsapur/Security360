import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_rds_snapshot_public(session):
    # [RDS.1]
    print("Checking RDS snapshots for public access")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        snapshots = rds.describe_db_snapshots().get("DBSnapshots", [])
        for snap in snapshots:
            attrs = rds.describe_db_snapshot_attributes(
                DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]
            )
            for attr in attrs["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]:
                if attr["AttributeName"] == "restore" and "all" in attr.get(
                    "AttributeValues", []
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": snap["DBSnapshotIdentifier"],
                            "resource_id_type": "DBSnapshot",
                            "issue": "RDS snapshot is publicly shared",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total = len(snapshots)
        affected = len(resources_affected)
        return {
            "id": "RDS.1",
            "check_name": "RDS snapshot public access",
            "problem_statement": "RDS snapshots should not be publicly shared to prevent data exposure.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove public sharing from RDS snapshots.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Open RDS console → Snapshots.",
                "2. Select affected snapshot.",
                "3. Modify permissions → Remove 'all' from restore access.",
                "4. Alternatively, use CLI: aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS snapshot public access: {e}")
        return None


def check_rds_publicly_accessible(session):
    # [RDS.2]
    print("Checking RDS instances for public accessibility")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if db.get("PubliclyAccessible", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "resource_id_type": "DBInstance",
                        "issue": "RDS instance publicly accessible",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.2",
            "check_name": "RDS public accessibility",
            "problem_statement": "RDS instances should not be publicly accessible.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Disable public accessibility for all production RDS instances.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify RDS instance → Set Publicly Accessible to 'No'.",
                "2. Ensure instance resides within a private subnet.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS public accessibility: {e}")
        return None


def check_rds_storage_encrypted(session):
    # [RDS.3, RDS.27]
    print("Checking RDS storage encryption")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if not db.get("StorageEncrypted", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "resource_id_type": "DBInstance",
                        "issue": "RDS instance storage not encrypted",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.3/27",
            "check_name": "RDS storage encryption",
            "problem_statement": "RDS instances should have storage encryption enabled to protect data at rest.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable storage encryption for RDS databases at creation time.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create a new RDS instance with 'Enable Encryption' checked.",
                "2. Migrate data from unencrypted DB.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS storage encryption: {e}")
        return None


def check_rds_multi_az(session):
    # [RDS.5, RDS.15]
    print("Checking RDS Multi-AZ configuration")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if not db.get("MultiAZ", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "resource_id_type": "DBInstance",
                        "issue": "RDS instance not configured for Multi-AZ",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.5/15",
            "check_name": "RDS Multi-AZ enabled",
            "problem_statement": "RDS instances should be configured for Multi-AZ to ensure high availability.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Modify RDS instance to enable Multi-AZ deployment.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify RDS instance.",
                "2. Select 'Enable Multi-AZ deployment'.",
                "3. Apply changes during maintenance window.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS Multi-AZ: {e}")
        return None


def check_rds_delete_protection(session):
    # [RDS.7, RDS.8]
    print("Checking RDS delete protection")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if not db.get("DeletionProtection", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "resource_id_type": "DBInstance",
                        "issue": "RDS instance lacks deletion protection",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.7/8",
            "check_name": "RDS deletion protection",
            "problem_statement": "RDS deletion protection should be enabled to prevent accidental database removal.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable deletion protection for critical RDS instances.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify RDS instance → Enable Deletion Protection.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS deletion protection: {e}")
        return None


def check_rds_backup_configuration(session):
    # [RDS.11]
    print("Checking RDS backup configuration")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if db.get("BackupRetentionPeriod", 0) == 0:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "resource_id_type": "DBInstance",
                        "issue": "RDS backup not configured",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.11",
            "check_name": "RDS backup retention",
            "problem_statement": "Automatic backups should be enabled for all RDS databases.",
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Set backup retention period > 0 for RDS instances.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify RDS instance.",
                "2. Set 'Backup retention period' to desired value (e.g., 7 days).",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS backup: {e}")
        return None


def check_rds_auto_minor_version_upgrade(session):
    # [RDS.13, RDS.35]
    print("Checking RDS automatic minor version upgrade setting")

    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            if not db.get("AutoMinorVersionUpgrade", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "resource_id_type": "DBInstance",
                        "issue": "Auto minor version upgrade disabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.13/35",
            "check_name": "RDS automatic minor version upgrade",
            "problem_statement": "Auto minor version upgrades should be enabled for RDS instances to ensure security patches are applied.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable automatic minor version upgrades.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify RDS instance → Enable automatic minor version upgrade.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS auto minor version upgrades: {e}")
        return None
