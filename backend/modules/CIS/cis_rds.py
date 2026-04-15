import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_rds_public_access(session):
    # [ RDS.2 ]
    print("Checking RDS public access configuration")

    rds = session.client("rds")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        instances = []
        marker = None
        while True:
            if marker:
                response = rds.describe_db_instances(Marker=marker)
            else:
                response = rds.describe_db_instances()

            instances.extend(response.get("DBInstances", []))
            if not response.get("Marker"):
                break
            marker = response.get("Marker")

        for instance in instances:
            if instance.get("PubliclyAccessible", False):
                vpc_id = instance.get("DBSubnetGroup", {}).get("VpcId", "N/A")
                instance_class = instance.get("DBInstanceClass", "N/A")
                engine = instance.get("Engine", "N/A")
                engine_version = instance.get("EngineVersion", "N/A")
                multi_az = instance.get("MultiAZ", False)
                storage_type = instance.get("StorageType", "N/A")
                endpoint = instance.get("Endpoint", {}).get("Address", "N/A")

                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": instance["DBInstanceIdentifier"],
                        "arn": instance["DBInstanceArn"],
                        "issue": "RDS instance is publicly accessible",
                        "region": region,
                        "vpc_id": vpc_id,
                        "instance_class": instance_class,
                        "engine": engine,
                        "engine_version": engine_version,
                        "multi_az": multi_az,
                        "storage_type": storage_type,
                        "endpoint": endpoint,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(instances)
        affected = len(resources_affected)

        return {
            "id": "RDS.2",
            "check_name": "RDS Public Access",
            "problem_statement": "RDS DB Instances should prohibit public access",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Disable public access for RDS instances unless explicitly required",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon RDS service",
                "2. Select the publicly accessible DB instance",
                "3. Click 'Modify'",
                "4. Under 'Connectivity', disable 'Public accessibility'",
                "5. Choose 'Continue' and select 'Apply immediately'",
                "6. Confirm the modification",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS public access: {e}")
        return None


def check_rds_encryption_at_rest(session):
    # [ RDS.3 ]
    print("Checking RDS encryption at rest configuration")

    rds = session.client("rds")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        instances = []
        marker = None
        while True:
            if marker:
                response = rds.describe_db_instances(Marker=marker)
            else:
                response = rds.describe_db_instances()

            instances.extend(response.get("DBInstances", []))
            if not response.get("Marker"):
                break
            marker = response.get("Marker")

        for instance in instances:
            if not instance.get("StorageEncrypted", False):
                vpc_id = instance.get("DBSubnetGroup", {}).get("VpcId", "N/A")
                instance_class = instance.get("DBInstanceClass", "N/A")
                engine = instance.get("Engine", "N/A")
                engine_version = instance.get("EngineVersion", "N/A")
                multi_az = instance.get("MultiAZ", False)
                storage_type = instance.get("StorageType", "N/A")
                endpoint = instance.get("Endpoint", {}).get("Address", "N/A")

                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": instance["DBInstanceIdentifier"],
                        "arn": instance["DBInstanceArn"],
                        "issue": "RDS instance does not have encryption at rest enabled",
                        "region": region,
                        "vpc_id": vpc_id,
                        "instance_class": instance_class,
                        "engine": engine,
                        "engine_version": engine_version,
                        "multi_az": multi_az,
                        "storage_type": storage_type,
                        "endpoint": endpoint,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(instances)
        affected = len(resources_affected)

        return {
            "id": "RDS.3",
            "check_name": "RDS Encryption at Rest",
            "problem_statement": "RDS DB instances should have encryption at-rest enabled",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable encryption at rest for all RDS DB instances",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon RDS service",
                "2. Create a new encrypted DB instance",
                "3. Migrate data from unencrypted instance",
                "4. Delete the unencrypted instance",
                "Note: Existing RDS instances cannot be encrypted after creation",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS encryption: {e}")
        return None


def check_rds_auto_minor_version_upgrade(session):
    # [ RDS.13 ]
    print("Checking RDS automatic minor version upgrade configuration")

    rds = session.client("rds")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        instances = []
        marker = None
        while True:
            if marker:
                response = rds.describe_db_instances(Marker=marker)
            else:
                response = rds.describe_db_instances()

            instances.extend(response.get("DBInstances", []))
            if not response.get("Marker"):
                break
            marker = response.get("Marker")

        for instance in instances:
            if not instance.get("AutoMinorVersionUpgrade", True):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": instance["DBInstanceIdentifier"],
                        "arn": instance["DBInstanceArn"],
                        "issue": "Automatic minor version upgrades disabled",
                        "region": region,
                        "engine": instance.get("Engine", "N/A"),
                        "engine_version": instance.get("EngineVersion", "N/A"),
                        "multi_az": instance.get("MultiAZ", False),
                        "db_instance_class": instance.get("DBInstanceClass", "N/A"),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(instances)
        affected = len(resources_affected)
        return {
            "id": "RDS.13",
            "check_name": "RDS Auto Minor Version Upgrade",
            "problem_statement": "RDS automatic minor version upgrades should be enabled",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable automatic minor version upgrades for RDS instances",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon RDS service",
                "2. Select the DB instance with disabled auto upgrades",
                "3. Click 'Modify'",
                "4. Under 'Maintenance', enable 'Auto minor version upgrade'",
                "5. Choose 'Continue' and select when to apply changes",
                "6. Confirm the modification",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking RDS auto minor version upgrades: {e}")
        return None
