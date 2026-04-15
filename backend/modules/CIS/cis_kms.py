import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_kms_key_rotation(session):
    # [ KMS.4 ]
    print("Checking KMS key rotation configuration")

    kms = session.client("kms")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        keys = []
        marker = None
        while True:
            if marker:
                response = kms.list_keys(Marker=marker)
            else:
                response = kms.list_keys()

            keys.extend(response.get("Keys", []))
            if not response.get("Truncated"):
                break
            marker = response.get("NextMarker")

        for key in keys:
            key_id = key["KeyId"]
            key_rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get(
                "KeyRotationEnabled", False
            )
            if not key_rotation_enabled:
                key_metadata = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if (
                    key_metadata.get("KeyManager") == "CUSTOMER"
                    and key_metadata.get("KeyState") == "Enabled"
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": key_id,
                            "arn": key_metadata.get("Arn"),
                            "alias_names": [
                                alias.get("AliasName")
                                for alias in kms.list_aliases().get("Aliases", [])
                                if alias.get("TargetKeyId") == key_id
                            ],
                            "key_description": key_metadata.get("Description", "N/A"),
                            "key_creation_date": (
                                key_metadata.get("CreationDate").strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                )
                                if key_metadata.get("CreationDate")
                                else "N/A"
                            ),
                            "issue": "KMS key rotation disabled",
                            "region": region,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(keys)
        affected = len(resources_affected)
        return {
            "id": "KMS.4",
            "check_name": "KMS Key Rotation",
            "problem_statement": "AWS KMS key rotation should be enabled",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable automatic key rotation for all customer-managed KMS keys",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to AWS KMS service",
                "2. Select the customer-managed key",
                "3. Under 'Key rotation', click 'Edit'",
                "4. Enable automatic key rotation",
                "5. Click 'Save changes'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking KMS key rotation: {e}")
        return None
