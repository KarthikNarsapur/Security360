import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_s3_account_public_access_block(session):
    # [S3.1]
    print("Checking S3 account-level public access block")

    s3control = session.client("s3control")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        pab = s3control.get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]

        if not all(pab.get(key, False) for key in pab):
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": account_id,
                    "resource_id_type": "AWSAccount",
                    "issue": "Account-level public access block not fully enabled",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "S3.1",
            "check_name": "S3 Account Public Access Block",
            "problem_statement": "All S3 public access block settings should be enabled at the account level.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if not resources_affected else "failed",
            "recommendation": "Enable all account-level S3 public access block settings.",
            "additional_info": {
                "total_scanned": 1,
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Go to S3 console → Account settings.",
                "2. Enable all four Public Access Block settings.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
        resources_affected.append(
            {
                "account_id": account_id,
                "resource_id": account_id,
                "resource_id_type": "AWSAccount",
                "issue": "Account-level public access block not configured",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            }
        )
        return {
            "id": "S3.1",
            "check_name": "S3 Account Public Access Block",
            "problem_statement": "Account-level S3 public access block configuration is missing.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "failed",
            "recommendation": "Enable all account-level public access block settings.",
            "additional_info": {"total_scanned": 1, "affected": 1},
            "remediation_steps": [
                "aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 account public access block: {e}")
        return None


def check_s3_bucket_public_access_block(session):
    # [S3.2, S3.3, S3.8]
    print("Checking S3 bucket-level public access block")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            try:
                pab = s3.get_public_access_block(Bucket=bucket["Name"])[
                    "PublicAccessBlockConfiguration"
                ]
                if not all(pab.get(k, False) for k in pab):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": bucket["Name"],
                            "resource_id_type": "Bucket",
                            "issue": "Public access block not fully enabled",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except s3.exceptions.ClientError:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": bucket["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "No public access block configuration found",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.2/3/8",
            "check_name": "S3 bucket public access block",
            "problem_statement": "S3 buckets should have all four public access block settings enabled.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable all bucket-level public access block settings.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 bucket public access block: {e}")
        return None


def check_s3_tls_enforced(session):
    # [S3.5]
    print("Checking S3 bucket TLS enforcement (policies)")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    tls_condition = '"aws:SecureTransport":"false"'

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            try:
                policy = s3.get_bucket_policy(Bucket=bucket["Name"])["Policy"]
                if tls_condition not in policy:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": bucket["Name"],
                            "resource_id_type": "Bucket",
                            "issue": "Bucket policy does not enforce TLS",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except s3.exceptions.ClientError:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": bucket["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "No bucket policy to enforce TLS",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.5",
            "check_name": "S3 TLS enforcement",
            "problem_statement": "S3 bucket policies should enforce HTTPS-only access.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Add a bucket policy that denies non-TLS access (aws:SecureTransport=false).",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "Add Deny statement in bucket policy where 'aws:SecureTransport' equals 'false'.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 TLS enforcement: {e}")
        return None


def check_s3_cross_region_replication(session):
    # [S3.7]
    print("Checking S3 cross-region replication configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for b in buckets:
            try:
                rep = s3.get_bucket_replication(Bucket=b["Name"])
                rules = rep.get("ReplicationConfiguration", {}).get("Rules", [])
                if not rules:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": b["Name"],
                            "resource_id_type": "Bucket",
                            "issue": "Cross-region replication not configured",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except s3.exceptions.ClientError:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "Replication configuration missing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.7",
            "check_name": "S3 cross-region replication",
            "problem_statement": "Buckets should have cross-region replication for durability and DR.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable replication to another region or account.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create destination bucket in another region.",
                "2. Configure replication rule in source bucket → Management → Replication.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 replication: {e}")
        return None


def check_s3_bucket_logging(session):
    # [S3.9]
    print("Checking S3 bucket access logging")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            log = s3.get_bucket_logging(Bucket=b["Name"]).get("LoggingEnabled")
            if not log:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "Access logging not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.9",
            "check_name": "S3 access logging",
            "problem_statement": "Access logging should be enabled for all S3 buckets.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable access logging and specify a target bucket.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Go to bucket → Properties → Server access logging.",
                "2. Enable and select a target bucket.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 logging: {e}")
        return None


def check_s3_bucket_versioning_lifecycle(session):
    # [S3.10, S3.13, S3.14]
    print("Checking S3 versioning and lifecycle configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            ver = s3.get_bucket_versioning(Bucket=b["Name"])
            life = (
                s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                if "Rules" in s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                else {}
            )
            if ver.get("Status") != "Enabled" or not life:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "Missing versioning or lifecycle policy",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.10/13/14",
            "check_name": "S3 versioning and lifecycle configuration",
            "problem_statement": "Buckets should enable versioning and define lifecycle policies for object management.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable versioning and add lifecycle rules for data archiving/deletion.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "Enable versioning: aws s3api put-bucket-versioning --bucket <b> --versioning-configuration Status=Enabled",
                "Add lifecycle rules via console or CLI.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 versioning/lifecycle: {e}")
        return None


def check_s3_event_notifications(session):
    # [S3.11]
    print("Checking S3 event notifications")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            notif = s3.get_bucket_notification_configuration(Bucket=b["Name"])
            if (
                not notif.get("TopicConfigurations")
                and not notif.get("QueueConfigurations")
                and not notif.get("LambdaFunctionConfigurations")
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "No event notifications configured",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.11",
            "check_name": "S3 event notifications",
            "problem_statement": "Buckets should have event notifications for data change monitoring.",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Configure S3 event notifications to SNS, SQS, or Lambda.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "In bucket → Properties → Event notifications → Add notification rule.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 notifications: {e}")
        return None


def check_s3_acl_public_access(session):
    # [S3.12]
    print("Checking S3 ACL public access")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            acl = s3.get_bucket_acl(Bucket=b["Name"])
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ]:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": b["Name"],
                            "resource_id_type": "Bucket",
                            "issue": "Bucket ACL allows public access",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.12",
            "check_name": "S3 ACL public access",
            "problem_statement": "Buckets should not grant access via public ACLs.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove 'AllUsers' and 'AuthenticatedUsers' grants from ACLs.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "aws s3api put-bucket-acl --bucket <b> --acl private",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 ACLs: {e}")
        return None


def check_s3_object_lock(session):
    # [S3.15]
    print("Checking S3 object lock configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            conf = s3.get_object_lock_configuration(Bucket=b["Name"]).get(
                "ObjectLockConfiguration"
            )
            if not conf or conf.get("ObjectLockEnabled") != "Enabled":
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "Object lock not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.15",
            "check_name": "S3 Object Lock",
            "problem_statement": "Object Lock should be enabled for immutability and ransomware protection.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable Object Lock at bucket creation for compliance data.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "Recreate bucket with Object Lock enabled.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 object lock: {e}")
        return None


def check_s3_encryption(session):
    # [S3.17]
    print("Checking S3 server-side encryption")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            try:
                enc = s3.get_bucket_encryption(Bucket=b["Name"])
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                if not rules:
                    raise Exception()
            except Exception:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "Server-side encryption not configured",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.17",
            "check_name": "S3 server-side encryption",
            "problem_statement": "Buckets should enforce encryption at rest (AES-256 or KMS).",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable default bucket encryption (AES-256 or KMS).",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                'aws s3api put-bucket-encryption --bucket <b> --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 encryption: {e}")
        return None


def check_s3_mfa_delete(session):
    # [S3.20]
    print("Checking S3 MFA Delete configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            ver = s3.get_bucket_versioning(Bucket=b["Name"])
            if ver.get("MFADelete") != "Enabled":
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": b["Name"],
                        "resource_id_type": "Bucket",
                        "issue": "MFA Delete not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        total = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.20",
            "check_name": "S3 MFA Delete",
            "problem_statement": "MFA Delete should be enabled to protect against accidental deletions.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable MFA Delete on versioned buckets using root credentials.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "aws s3api put-bucket-versioning --bucket <b> --versioning-configuration MFADelete=Enabled,Status=Enabled --mfa 'arn serial number mfa code'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking S3 MFA delete: {e}")
        return None
