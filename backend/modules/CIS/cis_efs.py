import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_efs_encryption_at_rest(session):
    # [EFS.1]
    print("Checking EFS encryption configuration")

    efs = session.client("efs")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        file_systems = efs.describe_file_systems().get("FileSystems", [])

        for fs in file_systems:
            fs_id = fs["FileSystemId"]
            fs_name = fs.get("Name", "Unnamed")
            resource_details = {
                "account_id": account_id,
                "resource_id": fs_id,
                "name": fs_name,
                "number_of_mount_targets": fs.get("NumberOfMountTargets", 0),
                "encrypted": fs.get("Encrypted", False),
                "kms_key_id": fs.get("KmsKeyId", "None"),
                "tags": {tag["Key"]: tag["Value"] for tag in fs.get("Tags", [])},
                "region": region,
                "performance_mode": fs.get("PerformanceMode", "unknown"),
                "lifecycle_state": fs.get("LifeCycleState", "unknown"),
                "last_updated": datetime.now(IST).isoformat(),
            }

            if not fs.get("Encrypted", False):
                resources_affected.append(
                    {
                        **resource_details,
                        "issue": "EFS not encrypted at rest",
                    }
                )
            elif not fs.get("KmsKeyId"):
                resources_affected.append(
                    {
                        **resource_details,
                        "issue": "EFS not using AWS KMS for encryption",
                    }
                )

        total_scanned = len(file_systems)
        affected = len(resources_affected)
        return {
            "id": "EFS.1",
            "check_name": "EFS Encryption at Rest",
            "problem_statement": "Elastic File System should be configured to encrypt file data at-rest using AWS KMS",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable encryption using AWS KMS for all EFS file systems",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to EFS service in AWS Console",
                "2. Select the file system",
                "3. Click 'Edit' in the Encryption section",
                "4. Enable encryption and select a KMS key",
                "5. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking EFS encryption: {e}")
        return None
