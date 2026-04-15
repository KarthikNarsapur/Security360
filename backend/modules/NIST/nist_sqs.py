import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_sqs_encryption_at_rest(session):
    # [SQS.1]
    print("Checking SQS encryption at rest")

    sqs = session.client("sqs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        queues = sqs.list_queues().get("QueueUrls", [])

        for q_url in queues:
            attrs = sqs.get_queue_attributes(
                QueueUrl=q_url, AttributeNames=["All"]
            ).get("Attributes", {})
            kms_key_id = attrs.get("KmsMasterKeyId")

            if not kms_key_id:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": q_url,
                        "resource_id_type": "QueueUrl",
                        "issue": "SQS queue does not have encryption at rest enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(queues)
        affected = len(resources_affected)

        return {
            "id": "SQS.1",
            "check_name": "SQS encryption at rest",
            "problem_statement": "All SQS queues should have encryption at rest enabled using AWS KMS.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable server-side encryption for all SQS queues using AWS KMS.",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Open the SQS console.",
                "2. Select the queue → 'Server-side encryption'.",
                "3. Enable SSE and choose an AWS KMS key.",
                "4. Alternatively, use CLI: ",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SQS encryption: {e}")
        return None
