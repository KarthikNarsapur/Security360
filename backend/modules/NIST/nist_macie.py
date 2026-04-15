import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_macie_enabled(session):
    # [Macie.1]
    print("Checking if Amazon Macie is enabled")

    macie = session.client("macie2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            status = macie.get_macie_session()
            macie_status = status.get("status", "DISABLED")
            if macie_status != "ENABLED":
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": "Macie",
                        "resource_id_type": "Service",
                        "issue": "Amazon Macie is not enabled for this account",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except macie.exceptions.AccessDeniedException:
            # Some partitions or accounts may not have Macie available
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "Macie",
                    "resource_id_type": "Service",
                    "issue": "Unable to access Amazon Macie in this region or account",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
        except macie.exceptions.ResourceNotFoundException:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "Macie",
                    "resource_id_type": "Service",
                    "issue": "Macie session not found — service not enabled",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)
        return {
            "id": "Macie.1",
            "check_name": "Amazon Macie enabled",
            "problem_statement": "Amazon Macie should be enabled to automatically discover and protect sensitive data in S3.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable Amazon Macie and configure it to scan S3 buckets for sensitive data.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open the Amazon Macie console.",
                "2. Choose 'Enable Macie'.",
                "3. Configure Macie to scan S3 buckets.",
                "4. Optionally, automate via: aws macie2 enable-macie --status ENABLED",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Macie enablement: {e}")
        return None
