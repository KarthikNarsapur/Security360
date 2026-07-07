"""
ISO 42001 Extended Checks — Secrets, AWS Config, Backup, API Gateway, ECR (AI-058 to AI-074)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_secrets_manager_encrypted(session):
    """AI-058: Secrets Manager secrets encrypted"""
    print("Checking Secrets Manager encryption")

    sm = session.client("secretsmanager")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        secrets = []
        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                secrets.extend(page.get("SecretList", []))
        except Exception:
            secrets = []

        for secret in secrets:
            kms_key = secret.get("KmsKeyId", "")
            if not kms_key or "alias/aws/secretsmanager" in (kms_key or "").lower():
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": secret.get("Name", "Unknown"),
                    "resource_id_type": "SecretName",
                    "issue": f"Secret '{secret.get('Name', '')}' uses default AWS-managed key instead of CMK",
                    "region": sm.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-058",
            "check_name": "Secrets Manager secrets encrypted with CMK",
            "problem_statement": "AI secrets should use customer-managed KMS keys for full control",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure Secrets Manager to use customer-managed KMS keys",
            "additional_info": {"total_scanned": max(len(secrets), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Create a CMK for secrets", "2. Update secrets to use CMK", "3. Rotate secrets"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Secrets Manager encryption: {e}")
        return None


def check_secret_rotation_enabled(session):
    """AI-059: Secret rotation enabled"""
    print("Checking secret rotation enabled")

    sm = session.client("secretsmanager")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        secrets = []
        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                secrets.extend(page.get("SecretList", []))
        except Exception:
            secrets = []

        for secret in secrets:
            rotation = secret.get("RotationEnabled", False)
            if not rotation:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": secret.get("Name", "Unknown"),
                    "resource_id_type": "SecretName",
                    "issue": f"Secret '{secret.get('Name', '')}' does not have automatic rotation enabled",
                    "region": sm.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-059",
            "check_name": "Secret rotation enabled",
            "problem_statement": "AI-related secrets should have automatic rotation enabled",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable automatic rotation for all AI-related secrets",
            "additional_info": {"total_scanned": max(len(secrets), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Configure rotation Lambda", "2. Enable rotation schedule", "3. Test rotation"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking secret rotation: {e}")
        return None


def check_stale_secrets(session):
    """AI-060: Stale secrets (>90 days)"""
    print("Checking stale secrets")

    sm = session.client("secretsmanager")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        secrets = []
        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                secrets.extend(page.get("SecretList", []))
        except Exception:
            secrets = []

        now = datetime.now(timezone.utc)
        for secret in secrets:
            last_changed = secret.get("LastChangedDate") or secret.get("CreatedDate")
            if last_changed:
                age_days = (now - last_changed.replace(tzinfo=timezone.utc)).days
                if age_days > 90:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": secret.get("Name", "Unknown"),
                        "resource_id_type": "SecretName",
                        "issue": f"Secret '{secret.get('Name', '')}' not rotated in {age_days} days",
                        "region": sm.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-060",
            "check_name": "Stale secrets (>90 days)",
            "problem_statement": "Secrets should be rotated within 90 days for security",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Rotate secrets that haven't been changed in over 90 days",
            "additional_info": {"total_scanned": max(len(secrets), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Identify stale secrets", "2. Rotate or regenerate credentials", "3. Enable auto-rotation"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking stale secrets: {e}")
        return None


def check_config_recorder_status(session):
    """AI-061: Config recorder status"""
    print("Checking AWS Config recorder status")

    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            recorders = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        except Exception:
            recorders = []

        total_scanned = max(len(recorders), 1)
        if not recorders:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "ConfigRecorder",
                "resource_id_type": "Service",
                "issue": "No AWS Config recorder configured",
                "region": config.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            for rec in recorders:
                if not rec.get("recording", False):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": rec.get("name", "Unknown"),
                        "resource_id_type": "ConfigRecorder",
                        "issue": f"Config recorder '{rec.get('name', '')}' is not recording",
                        "region": config.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-061",
            "check_name": "Config recorder status",
            "problem_statement": "AWS Config recorder should be active to track AI resource configuration changes",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable and activate AWS Config recorder",
            "additional_info": {"total_scanned": total_scanned, "affected": len(resources_affected)},
            "remediation_steps": ["1. Enable Config recorder", "2. Configure delivery channel", "3. Start recording"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Config recorder: {e}")
        return None


def check_config_delivery_channel(session):
    """AI-062: Config delivery channel configured"""
    print("Checking AWS Config delivery channel")

    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            channels = config.describe_delivery_channels().get("DeliveryChannels", [])
        except Exception:
            channels = []

        if not channels:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "DeliveryChannel",
                "resource_id_type": "Service",
                "issue": "No Config delivery channel configured",
                "region": config.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-062",
            "check_name": "Config delivery channel configured",
            "problem_statement": "AWS Config needs a delivery channel to store configuration history",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure a delivery channel for AWS Config",
            "additional_info": {"total_scanned": 1, "affected": len(resources_affected)},
            "remediation_steps": ["1. Create S3 bucket for config history", "2. Configure delivery channel"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Config delivery channel: {e}")
        return None


def check_backup_recovery_points(session):
    """AI-065: Recovery points exist"""
    print("Checking AWS Backup recovery points")

    backup = session.client("backup")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        except Exception:
            vaults = []

        if not vaults:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AWSBackup",
                "resource_id_type": "Service",
                "issue": "No backup vaults configured — AI data has no backup",
                "region": backup.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        empty_vaults = 0
        for vault in vaults:
            if vault.get("NumberOfRecoveryPoints", 0) == 0:
                empty_vaults += 1

        if empty_vaults > 0 and vaults:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "BackupVaults",
                "resource_id_type": "Service",
                "issue": f"{empty_vaults} backup vault(s) have no recovery points",
                "region": backup.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-065",
            "check_name": "Backup recovery points exist",
            "problem_statement": "AI model artifacts and training data should have backup recovery points",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure backup plans for AI resources with regular recovery points",
            "additional_info": {"total_scanned": max(len(vaults), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Create backup plans for AI data", "2. Configure backup schedules", "3. Verify recovery points"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking backup recovery points: {e}")
        return None


def check_ecr_image_scanning(session):
    """AI-071: ECR repository image scanning enabled"""
    print("Checking ECR image scanning enabled")

    ecr = session.client("ecr")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            repos = ecr.describe_repositories().get("repositories", [])
        except Exception:
            repos = []

        for repo in repos:
            repo_name = repo.get("repositoryName", "")
            scan_config = repo.get("imageScanningConfiguration", {})
            if not scan_config.get("scanOnPush", False):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": repo_name,
                    "resource_id_type": "ECRRepository",
                    "issue": f"ECR repo '{repo_name}' does not have scan-on-push enabled",
                    "region": ecr.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-071",
            "check_name": "ECR repository image scanning enabled",
            "problem_statement": "Container images for AI workloads should be scanned for vulnerabilities",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable scan-on-push for all ECR repositories used by AI workloads",
            "additional_info": {"total_scanned": max(len(repos), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Enable image scanning in ECR settings", "2. Review scan findings", "3. Fix critical vulnerabilities"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking ECR image scanning: {e}")
        return None


def check_ecr_immutable_tags(session):
    """AI-072: ECR repository immutable tags"""
    print("Checking ECR immutable tags")

    ecr = session.client("ecr")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            repos = ecr.describe_repositories().get("repositories", [])
        except Exception:
            repos = []

        for repo in repos:
            repo_name = repo.get("repositoryName", "")
            tag_mutability = repo.get("imageTagMutability", "MUTABLE")
            if tag_mutability != "IMMUTABLE":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": repo_name,
                    "resource_id_type": "ECRRepository",
                    "issue": f"ECR repo '{repo_name}' has mutable tags — images can be overwritten",
                    "region": ecr.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-072",
            "check_name": "ECR repository immutable tags",
            "problem_statement": "AI container image tags should be immutable for reproducibility",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Set image tag mutability to IMMUTABLE for AI container repos",
            "additional_info": {"total_scanned": max(len(repos), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Set imageTagMutability to IMMUTABLE", "2. Use unique tags per build"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking ECR immutable tags: {e}")
        return None


def check_ecr_encryption(session):
    """AI-073: ECR repository encryption"""
    print("Checking ECR repository encryption")

    ecr = session.client("ecr")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            repos = ecr.describe_repositories().get("repositories", [])
        except Exception:
            repos = []

        for repo in repos:
            repo_name = repo.get("repositoryName", "")
            enc_config = repo.get("encryptionConfiguration", {})
            enc_type = enc_config.get("encryptionType", "AES256")
            if enc_type != "KMS":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": repo_name,
                    "resource_id_type": "ECRRepository",
                    "issue": f"ECR repo '{repo_name}' uses {enc_type} instead of KMS encryption",
                    "region": ecr.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-073",
            "check_name": "ECR repository encryption",
            "problem_statement": "AI container repositories should use KMS encryption",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Use KMS encryption for ECR repositories containing AI containers",
            "additional_info": {"total_scanned": max(len(repos), 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Recreate repos with KMS encryption", "2. Migrate images to encrypted repos"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking ECR encryption: {e}")
        return None


def check_resource_tagging_completeness(session):
    """AI-079: Resource tagging completeness"""
    print("Checking resource tagging completeness")

    tagging = session.client("resourcegroupstaggingapi")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check AI-related resources for required tags
        ai_resource_types = [
            "sagemaker:endpoint", "sagemaker:notebook-instance",
            "sagemaker:model", "sagemaker:training-job",
        ]

        total_scanned = 0
        required_tags = ["Owner", "Environment", "Project"]

        try:
            response = tagging.get_resources(
                ResourceTypeFilters=["sagemaker"],
            )
            resources = response.get("ResourceTagMappingList", [])
            total_scanned = len(resources)

            for resource in resources:
                arn = resource.get("ResourceARN", "")
                tags = {t["Key"]: t["Value"] for t in resource.get("Tags", [])}
                missing = [t for t in required_tags if t not in tags]
                if missing:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": arn.split("/")[-1] if "/" in arn else arn,
                        "resource_id_type": "ResourceARN",
                        "issue": f"AI resource missing tags: {', '.join(missing)}",
                        "region": tagging.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
        except Exception:
            pass

        return {
            "id": "AI-079",
            "check_name": "Resource tagging completeness",
            "problem_statement": "AI resources should have governance tags (Owner, Environment, Project)",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Apply required governance tags to all AI resources",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": ["1. Define tagging policy", "2. Apply tags to AI resources", "3. Use tag policies for enforcement"],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking resource tagging: {e}")
        return None
