"""
ISO 42001 Extended Checks — S3 AI Data Governance (AI-031 to AI-037)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_bucket_object_lock(session):
    """AI-031: Bucket Object Lock enabled"""
    print("Checking S3 bucket Object Lock configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_object_lock_configuration(Bucket=bucket_name)
            except Exception as e:
                if "ObjectLockConfigurationNotFoundError" in str(e):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "BucketName",
                        "issue": f"Bucket '{bucket_name}' does not have Object Lock enabled",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-031",
            "check_name": "Bucket Object Lock enabled",
            "problem_statement": "S3 buckets storing AI training data should have Object Lock for immutability",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable Object Lock on buckets containing critical AI data",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify buckets with AI training/model data",
                "2. Enable Object Lock (requires new bucket creation)",
                "3. Configure retention periods for compliance",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking bucket Object Lock: {e}")
        return None


def check_bucket_ownership_controls(session):
    """AI-032: Bucket ownership controls"""
    print("Checking S3 bucket ownership controls")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                ownership = s3.get_bucket_ownership_controls(Bucket=bucket_name)
                rules = ownership.get("OwnershipControls", {}).get("Rules", [])
                for rule in rules:
                    if rule.get("ObjectOwnership") != "BucketOwnerEnforced":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_id_type": "BucketName",
                            "issue": f"Bucket '{bucket_name}' ownership not set to BucketOwnerEnforced",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break
            except Exception:
                continue

        return {
            "id": "AI-032",
            "check_name": "Bucket ownership controls",
            "problem_statement": "Bucket ownership should be enforced to prevent ACL-based access",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Set BucketOwnerEnforced to disable ACLs",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Navigate to S3 bucket permissions",
                "2. Edit Object Ownership",
                "3. Select 'ACLs disabled (recommended)'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking bucket ownership controls: {e}")
        return None


def check_bucket_acl_usage(session):
    """AI-033: Bucket ACL usage"""
    print("Checking S3 bucket ACL usage")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                grants = acl.get("Grants", [])
                # Check for non-owner grants
                owner_id = acl.get("Owner", {}).get("ID", "")
                for grant in grants:
                    grantee = grant.get("Grantee", {})
                    grantee_id = grantee.get("ID", "")
                    uri = grantee.get("URI", "")
                    if (grantee_id and grantee_id != owner_id) or uri:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_id_type": "BucketName",
                            "issue": f"Bucket '{bucket_name}' has ACL grants beyond owner",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break
            except Exception:
                continue

        return {
            "id": "AI-033",
            "check_name": "Bucket ACL usage",
            "problem_statement": "S3 buckets should not use ACLs — use bucket policies instead",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Disable ACLs and use bucket policies for access control",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review bucket ACLs for non-owner grants",
                "2. Migrate access control to bucket policies",
                "3. Set ownership to BucketOwnerEnforced to disable ACLs",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking bucket ACL usage: {e}")
        return None


def check_bucket_policy_permissive(session):
    """AI-034: Bucket policy overly permissive"""
    print("Checking S3 bucket policy permissions")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    import json

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "{}")
                policy = json.loads(policy_str)
                statements = policy.get("Statement", [])

                for stmt in statements:
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", "")
                        if principal == "*" or principal == {"AWS": "*"}:
                            condition = stmt.get("Condition", {})
                            if not condition:
                                resources_affected.append({
                                    "account_id": account_id,
                                    "resource_id": bucket_name,
                                    "resource_id_type": "BucketName",
                                    "issue": f"Bucket '{bucket_name}' has policy allowing Principal: * without conditions",
                                    "region": "global",
                                    "last_updated": datetime.now(IST).isoformat(),
                                })
                                break
            except s3.exceptions.from_code("NoSuchBucketPolicy"):
                continue
            except Exception:
                continue

        return {
            "id": "AI-034",
            "check_name": "Bucket policy overly permissive",
            "problem_statement": "S3 bucket policies should not allow unrestricted public access",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Remove wildcard Principal (*) from bucket policies or add restricting conditions",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review bucket policies for Principal: *",
                "2. Add condition keys to restrict access",
                "3. Use specific account/role ARNs instead of wildcards",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking bucket policy: {e}")
        return None


def check_sse_kms_vs_s3(session):
    """AI-035: SSE-KMS vs SSE-S3 usage"""
    print("Checking SSE-KMS vs SSE-S3 encryption usage")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                for rule in rules:
                    sse_algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                    if sse_algo == "AES256":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_id_type": "BucketName",
                            "issue": f"Bucket '{bucket_name}' uses SSE-S3 instead of SSE-KMS",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-035",
            "check_name": "SSE-KMS vs SSE-S3 usage",
            "problem_statement": "AI data buckets should use SSE-KMS for key management control",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Upgrade encryption from SSE-S3 to SSE-KMS for better key control",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Change default encryption to aws:kms",
                "2. Use customer-managed KMS key for rotation control",
                "3. Update bucket policies to enforce SSE-KMS",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking SSE-KMS vs SSE-S3: {e}")
        return None


def check_default_encryption_missing(session):
    """AI-036: Default bucket encryption missing"""
    print("Checking default bucket encryption")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except Exception as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "BucketName",
                        "issue": f"Bucket '{bucket_name}' has no default encryption",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-036",
            "check_name": "Default bucket encryption missing",
            "problem_statement": "All S3 buckets must have default encryption enabled",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable default encryption on all S3 buckets",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Navigate to S3 bucket properties",
                "2. Edit default encryption",
                "3. Enable SSE-KMS or SSE-S3 encryption",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking default encryption: {e}")
        return None


def check_bucket_replication(session):
    """AI-037: Bucket replication configured"""
    print("Checking S3 bucket replication configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        # Check AI-related buckets for replication (disaster recovery)
        ai_keywords = ["sagemaker", "bedrock", "model", "training", "ml", "ai", "data"]

        for bucket in buckets:
            bucket_name = bucket["Name"]
            if not any(kw in bucket_name.lower() for kw in ai_keywords):
                continue
            try:
                s3.get_bucket_replication(Bucket=bucket_name)
            except Exception as e:
                if "ReplicationConfigurationNotFoundError" in str(e):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "BucketName",
                        "issue": f"AI bucket '{bucket_name}' has no cross-region replication",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-037",
            "check_name": "Bucket replication configured",
            "problem_statement": "AI data buckets should have replication for disaster recovery",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable cross-region replication for critical AI data buckets",
            "additional_info": {
                "total_scanned": max(len(buckets), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify critical AI data buckets",
                "2. Enable cross-region replication",
                "3. Configure replication rules and destination",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking bucket replication: {e}")
        return None
