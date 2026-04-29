"""SQS security checks (2 checks)."""
import json


def check_sqs_encryption(session, scan_meta_data):
    print("check_sqs_encryption")
    sqs = session.client("sqs")
    resources = []
    queues = sqs.list_queues().get("QueueUrls", [])

    for url in queues:
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsMasterKeyId", "QueueArn"]).get("Attributes", {})
            if not attrs.get("KmsMasterKeyId"):
                name = url.split("/")[-1]
                resources.append({
                    "resource_name": name, "queue_url": url,
                    "issue": "Queue is not encrypted with KMS.",
                })
        except Exception as e:
            print(f"Error checking SQS encryption: {e}")

    scan_meta_data["total_scanned"] += len(queues)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "SQS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("SQS")

    return {
        "check_name": "SQS Queue Encryption",
        "service": "SQS",
        "problem_statement": "SQS queues are not encrypted with KMS.",
        "severity_score": 55, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable server-side encryption with KMS on all SQS queues.",
        "additional_info": {"total_scanned": len(queues), "affected": len(resources)},
    }


def check_sqs_wildcard_policy(session, scan_meta_data):
    print("check_sqs_wildcard_policy")
    sqs = session.client("sqs")
    resources = []
    queues = sqs.list_queues().get("QueueUrls", [])

    for url in queues:
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {})
            policy_str = attrs.get("Policy", "")
            if not policy_str:
                continue
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and "*" in str(principal.values())):
                    if not stmt.get("Condition"):
                        name = url.split("/")[-1]
                        resources.append({
                            "resource_name": name, "queue_url": url,
                            "issue": "Queue policy allows Principal \"*\" without conditions.",
                        })
                        break
        except Exception as e:
            print(f"Error checking SQS policy: {e}")

    scan_meta_data["total_scanned"] += len(queues)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "SQS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("SQS")

    return {
        "check_name": "SQS Wildcard Principal Policy",
        "service": "SQS",
        "problem_statement": "SQS queues have policies granting access to Principal \"*\".",
        "severity_score": 80, "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Restrict SQS policies to specific principals and add conditions.",
        "additional_info": {"total_scanned": len(queues), "affected": len(resources)},
    }
