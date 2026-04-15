import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_dynamodb_auto_scaling_status(session):
    # [DynamoDB.1]
    print("Checking DynamoDB auto scaling status")

    dynamodb = session.client("dynamodb")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        tables = dynamodb.list_tables().get("TableNames", [])

        for table_name in tables:
            desc = dynamodb.describe_table(TableName=table_name)["Table"]
            throughput = desc.get("ProvisionedThroughput", {})
            if (
                throughput
                and throughput.get("ReadCapacityUnits")
                and throughput.get("WriteCapacityUnits")
            ):
                # DynamoDB auto-scaling uses Application Auto Scaling service, not direct in table config
                autoscaling = session.client("application-autoscaling")
                response = autoscaling.describe_scalable_targets(
                    ServiceNamespace="dynamodb"
                )
                target_found = any(
                    t["ResourceId"].endswith(table_name)
                    for t in response.get("ScalableTargets", [])
                )
                if not target_found:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": table_name,
                            "resource_id_type": "DynamoDBTable",
                            "issue": "Auto scaling not configured for DynamoDB table",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(tables)
        affected = len(resources_affected)
        return {
            "id": "DynamoDB.1",
            "check_name": "DynamoDB auto scaling configured",
            "problem_statement": "DynamoDB tables should use auto scaling to adjust capacity automatically.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable DynamoDB auto scaling for read/write capacity management.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open DynamoDB console.",
                "2. Select the table and go to 'Capacity'.",
                "3. Enable auto scaling for read and write capacity.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking DynamoDB auto scaling: {e}")
        return None


def check_dynamodb_point_in_time_recovery(session):
    # [DynamoDB.2]
    print("Checking DynamoDB point-in-time recovery (PITR) configuration")

    dynamodb = session.client("dynamodb")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        tables = dynamodb.list_tables().get("TableNames", [])

        for table_name in tables:
            try:
                recovery = dynamodb.describe_continuous_backups(TableName=table_name)
                status = recovery["ContinuousBackupsDescription"][
                    "PointInTimeRecoveryDescription"
                ]["PointInTimeRecoveryStatus"]
                if status != "ENABLED":
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": table_name,
                            "resource_id_type": "DynamoDBTable",
                            "issue": "Point-in-time recovery (PITR) disabled",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception as e:
                print(f"Error checking PITR for table {table_name}: {e}")

        total_scanned = len(tables)
        affected = len(resources_affected)
        return {
            "id": "DynamoDB.2",
            "check_name": "DynamoDB point-in-time recovery enabled",
            "problem_statement": "Point-in-time recovery should be enabled for DynamoDB tables to allow data restoration.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable point-in-time recovery for DynamoDB tables.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open DynamoDB console.",
                "2. Select the table.",
                "3. Go to 'Backups'.",
                "4. Enable point-in-time recovery.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking DynamoDB PITR: {e}")
        return None


def check_dynamodb_resources_without_tags(session):
    # [DynamoDB.5]
    print("Checking DynamoDB table tags")

    dynamodb = session.client("dynamodb")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        tables = dynamodb.list_tables().get("TableNames", [])

        for table_name in tables:
            arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]
            tags = dynamodb.list_tags_of_resource(ResourceArn=arn).get("Tags", [])
            if not tags:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": table_name,
                        "resource_id_type": "DynamoDBTable",
                        "issue": "No tags configured on DynamoDB table",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(tables)
        affected = len(resources_affected)
        return {
            "id": "DynamoDB.5",
            "check_name": "DynamoDB tables tagged",
            "problem_statement": "DynamoDB tables should be tagged for ownership and cost tracking.",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Add relevant tags (e.g., Owner, Environment, CostCenter) to all tables.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to DynamoDB console.",
                "2. Select a table.",
                "3. Choose 'Tags' tab and add required tags.",
                "4. Save changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking DynamoDB tags: {e}")
        return None


def check_dynamodb_delete_table_protection(session):
    # [DynamoDB.6]
    print("Checking DynamoDB deletion protection")

    dynamodb = session.client("dynamodb")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        tables = dynamodb.list_tables().get("TableNames", [])

        for table_name in tables:
            desc = dynamodb.describe_table(TableName=table_name)["Table"]
            deletion_protection = desc.get("DeletionProtectionEnabled", False)
            if not deletion_protection:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": table_name,
                        "resource_id_type": "DynamoDBTable",
                        "issue": "Deletion protection not enabled for DynamoDB table",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(tables)
        affected = len(resources_affected)
        return {
            "id": "DynamoDB.6",
            "check_name": "DynamoDB table deletion protection",
            "problem_statement": "Deletion protection should be enabled on DynamoDB tables to prevent accidental data loss.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable deletion protection for critical DynamoDB tables.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to DynamoDB console.",
                "2. Select the table.",
                "3. Edit the settings.",
                "4. Enable 'Deletion protection'.",
                "5. Save changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking DynamoDB deletion protection: {e}")
        return None
