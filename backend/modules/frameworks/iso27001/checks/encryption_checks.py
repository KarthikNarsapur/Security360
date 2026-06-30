"""
ISO 27001 Checks — Encryption & Data Protection
Controls: A.8.24, A.7.10, A.5.33, A.5.34, A.8.10, A.8.12, A.5.14
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_s3_encryption(session):
    """A.7.10/A.8.24: All S3 buckets should have encryption enabled."""
    print("  ISO27001: Checking S3 encryption")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' does not have default encryption enabled",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.7.10", "Storage media - S3 encryption",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking S3 encryption: {e}")
        return None


def check_ebs_encryption(session):
    """A.7.10: All EBS volumes should be encrypted."""
    print("  ISO27001: Checking EBS encryption")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        volumes = ec2.describe_volumes().get("Volumes", [])
        total = len(volumes)

        for vol in volumes:
            if not vol.get("Encrypted", False):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": vol["VolumeId"],
                    "resource_id_type": "EBS Volume",
                    "issue": f"Volume '{vol['VolumeId']}' is not encrypted",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.7.10", "Storage media - EBS encryption",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking EBS encryption: {e}")
        return None


def check_rds_encryption(session):
    """A.7.10: All RDS instances should be encrypted at rest."""
    print("  ISO27001: Checking RDS encryption")
    rds = session.client("rds")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)

        for db in instances:
            if not db.get("StorageEncrypted", False):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": db["DBInstanceIdentifier"],
                    "resource_id_type": "RDS Instance",
                    "issue": f"RDS instance '{db['DBInstanceIdentifier']}' is not encrypted at rest",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.7.10", "Storage media - RDS encryption",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking RDS encryption: {e}")
        return None


def check_kms_key_rotation(session):
    """A.8.24: KMS customer-managed keys should have rotation enabled."""
    print("  ISO27001: Checking KMS key rotation")
    kms = session.client("kms")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        keys = kms.list_keys().get("Keys", [])
        total = 0

        for key in keys:
            key_id = key["KeyId"]
            try:
                key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_meta.get("KeyManager") != "CUSTOMER":
                    continue
                if key_meta.get("KeyState") != "Enabled":
                    continue
                total += 1

                rotation = kms.get_key_rotation_status(KeyId=key_id)
                if not rotation.get("KeyRotationEnabled", False):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": key_id,
                        "resource_id_type": "KMS Key",
                        "issue": f"KMS key '{key_id}' does not have automatic rotation enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.8.24", "Use of cryptography - KMS key rotation",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking KMS key rotation: {e}")
        return None


def check_acm_certificates(session):
    """A.8.24: ACM certificates should be valid and not expiring soon."""
    print("  ISO27001: Checking ACM certificates")
    acm = session.client("acm")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        certs = acm.list_certificates().get("CertificateSummaryList", [])
        total = len(certs)

        for cert in certs:
            status = cert.get("Status", "")
            if status == "EXPIRED":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": cert.get("DomainName", cert["CertificateArn"]),
                    "resource_id_type": "ACM Certificate",
                    "issue": f"Certificate for '{cert.get('DomainName')}' is EXPIRED",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
            elif status == "ISSUED":
                not_after = cert.get("NotAfter")
                if not_after:
                    days_left = (not_after - datetime.now(timezone.utc)).days
                    if days_left < 30:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": cert.get("DomainName", cert["CertificateArn"]),
                            "resource_id_type": "ACM Certificate",
                            "issue": f"Certificate for '{cert.get('DomainName')}' expires in {days_left} days",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })

        return _result("A.8.24", "Use of cryptography - ACM certificates",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking ACM certificates: {e}")
        return None


def check_s3_public_access_block(session):
    """A.5.34/A.8.12: S3 buckets should block public access."""
    print("  ISO27001: Checking S3 public access block")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False),
                ]):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' does not fully block public access",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except s3.exceptions.ClientError:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": bucket_name,
                    "resource_id_type": "S3 Bucket",
                    "issue": f"Bucket '{bucket_name}' has no public access block configuration",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })
            except Exception:
                continue

        return _result("A.5.34", "Privacy and PII protection - S3 public access block",
                      resources_affected, max(total, 1), 90, "Critical")
    except Exception as e:
        print(f"Error checking S3 public access: {e}")
        return None


def check_s3_object_lock(session):
    """A.5.33: S3 Object Lock for record immutability."""
    print("  ISO27001: Checking S3 Object Lock")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        no_lock_count = 0

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_object_lock_configuration(Bucket=bucket_name)
            except s3.exceptions.ClientError:
                no_lock_count += 1
            except Exception:
                continue

        if no_lock_count > 0 and total > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "S3",
                "resource_id_type": "Service",
                "issue": f"{no_lock_count}/{total} buckets do not have Object Lock enabled",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.33", "Protection of records - S3 Object Lock",
                      resources_affected, max(total, 1), 40, "Low")
    except Exception as e:
        print(f"Error checking S3 Object Lock: {e}")
        return None


def check_s3_versioning(session):
    """A.5.33: S3 versioning for data protection."""
    print("  ISO27001: Checking S3 versioning")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' does not have versioning enabled",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.5.33", "Protection of records - S3 versioning",
                      resources_affected, max(total, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking S3 versioning: {e}")
        return None


def check_s3_lifecycle(session):
    """A.8.10: S3 lifecycle policies for information deletion."""
    print("  ISO27001: Checking S3 lifecycle policies")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            except s3.exceptions.ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' has no lifecycle policy for data retention",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.8.10", "Information deletion - S3 lifecycle",
                      resources_affected, max(total, 1), 40, "Low")
    except Exception as e:
        print(f"Error checking S3 lifecycle: {e}")
        return None


def check_s3_bucket_logging(session):
    """A.5.14: S3 bucket access logging enabled."""
    print("  ISO27001: Checking S3 bucket logging")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                if "LoggingEnabled" not in logging_config:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' does not have access logging enabled",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.5.14", "Information transfer - S3 bucket logging",
                      resources_affected, max(total, 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking S3 bucket logging: {e}")
        return None


def check_s3_bucket_ownership(session):
    """A.8.24: S3 bucket ownership controls configured."""
    print("  ISO27001: Checking S3 bucket ownership controls")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                ownership = s3.get_bucket_ownership_controls(Bucket=bucket_name)
                rules = ownership.get("OwnershipControls", {}).get("Rules", [])
                if not rules or rules[0].get("ObjectOwnership") != "BucketOwnerEnforced":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' does not enforce BucketOwnerEnforced ownership",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.8.24", "Use of cryptography - S3 ownership controls",
                      resources_affected, max(total, 1), 40, "Low")
    except Exception as e:
        print(f"Error checking S3 ownership: {e}")
        return None


def check_s3_replication(session):
    """A.8.13: S3 replication for data redundancy."""
    print("  ISO27001: Checking S3 replication")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        no_replication = 0

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                s3.get_bucket_replication(Bucket=bucket_name)
            except s3.exceptions.ClientError:
                no_replication += 1
            except Exception:
                continue

        if no_replication > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "S3",
                "resource_id_type": "Service",
                "issue": f"{no_replication}/{total} buckets have no cross-region replication",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.13", "Information backup - S3 replication",
                      resources_affected, max(total, 1), 30, "Low")
    except Exception as e:
        print(f"Error checking S3 replication: {e}")
        return None


def check_secure_transport(session):
    """A.5.14: S3 bucket policies should enforce HTTPS (SecureTransport)."""
    print("  ISO27001: Checking SecureTransport enforcement")
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
                if "aws:SecureTransport" not in policy_str:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "S3 Bucket",
                        "issue": f"Bucket '{bucket_name}' policy does not enforce SecureTransport (HTTPS)",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except s3.exceptions.ClientError:
                # No bucket policy = no SecureTransport enforcement
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": bucket_name,
                    "resource_id_type": "S3 Bucket",
                    "issue": f"Bucket '{bucket_name}' has no bucket policy (SecureTransport not enforced)",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })
            except Exception:
                continue

        return _result("A.5.14", "Information transfer - SecureTransport enforcement",
                      resources_affected, max(total, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking SecureTransport: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Data Protection",
        "problem_statement": f"ISO 27001 {control_id}: {check_name}",
        "severity_score": severity_score if len(resources_affected) > 0 else 0,
        "severity_level": severity_level,
        "resources_affected": resources_affected,
        "status": "passed" if len(resources_affected) == 0 else "failed",
        "recommendation": f"Remediate findings for {check_name} to meet ISO 27001 requirements",
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": len(resources_affected),
        },
        "last_updated": datetime.now(IST).isoformat(),
    }
