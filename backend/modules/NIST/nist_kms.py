import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_kms_key_in_pending_deletion(session):
    # [KMS.3]
    print("Checking KMS keys pending deletion")

    kms = session.client("kms")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        paginator = kms.get_paginator("list_keys")

        all_keys = []
        for page in paginator.paginate():
            all_keys.extend(page.get("Keys", []))

        for key in all_keys:
            try:
                key_metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if key_metadata.get("KeyState") == "PendingDeletion":
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": key_metadata["KeyId"],
                            "resource_id_type": "KeyId",
                            "issue": "KMS key is pending deletion",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except kms.exceptions.NotFoundException:
                continue
            except Exception as inner_e:
                print(f"Error describing key {key['KeyId']}: {inner_e}")

        total_scanned = len(all_keys)
        affected = len(resources_affected)
        return {
            "id": "KMS.3",
            "check_name": "KMS keys not pending deletion",
            "problem_statement": "Active KMS keys should not be pending deletion to avoid unintended encryption failures.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Cancel deletion or recreate keys still required for encryption operations.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Identify keys marked for deletion.",
                "2. Run 'aws kms cancel-key-deletion --key-id <KeyId>' if they are still required.",
                "3. Verify encryption dependencies before deletion.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking KMS keys pending deletion: {e}")
        return None


def check_kms_key_rotation_enabled(session):
    # [KMS.4]
    print("Checking KMS key rotation configuration")

    kms = session.client("kms")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        paginator = kms.get_paginator("list_keys")

        all_keys = []
        for page in paginator.paginate():
            all_keys.extend(page.get("Keys", []))

        for key in all_keys:
            try:
                key_metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if key_metadata.get(
                    "KeyManager"
                ) == "CUSTOMER" and not key_metadata.get("MultiRegion"):
                    rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
                    if not rotation.get("KeyRotationEnabled", False):
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": key_metadata["KeyId"],
                                "resource_id_type": "KeyId",
                                "issue": "KMS key rotation not enabled",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
            except kms.exceptions.NotFoundException:
                continue
            except Exception as inner_e:
                print(f"Error describing rotation for key {key['KeyId']}: {inner_e}")

        total_scanned = len(all_keys)
        affected = len(resources_affected)
        return {
            "id": "KMS.4",
            "check_name": "KMS key rotation enabled",
            "problem_statement": "Automatic key rotation should be enabled for customer-managed KMS keys to reduce exposure of compromised keys.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable automatic key rotation for customer-managed keys.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open AWS KMS console.",
                "2. Select a customer-managed key.",
                "3. Enable 'Automatic rotation every year'.",
                "4. Alternatively, run: aws kms enable-key-rotation --key-id <KeyId>",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking KMS key rotation: {e}")
        return None
