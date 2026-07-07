"""
ISO 42001 Extended Checks — KMS Key Management (AI-038 to AI-041)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_customer_managed_keys_disabled(session):
    """AI-038: Customer-managed keys disabled"""
    print("Checking customer-managed keys disabled")

    kms = session.client("kms")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        keys = []
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            keys.extend(page.get("Keys", []))

        customer_keys_scanned = 0
        for key_info in keys:
            key_id = key_info["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]

                # Only check customer-managed keys
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue

                customer_keys_scanned += 1
                key_state = key_metadata.get("KeyState", "")

                if key_state != "Enabled":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": key_id,
                        "resource_id_type": "KMSKeyId",
                        "issue": f"Customer-managed key '{key_id}' is not enabled (state: {key_state})",
                        "region": kms.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-038",
            "check_name": "Customer-managed keys disabled",
            "problem_statement": "Customer-managed KMS keys used for AI workloads should be in Enabled state",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Re-enable disabled customer-managed keys or rotate to new keys for AI workloads",
            "additional_info": {
                "total_scanned": max(customer_keys_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify disabled customer-managed keys used by AI services",
                "2. Re-enable keys via KMS console or enable-key API",
                "3. If keys are no longer needed, schedule deletion with appropriate waiting period",
                "4. Update AI resources to use active keys",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking customer-managed keys disabled: {e}")
        return None


def check_pending_deletion_keys(session):
    """AI-039: Pending deletion keys"""
    print("Checking pending deletion KMS keys")

    kms = session.client("kms")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        keys = []
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            keys.extend(page.get("Keys", []))

        total_scanned = 0
        for key_info in keys:
            key_id = key_info["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue

                total_scanned += 1
                key_state = key_metadata.get("KeyState", "")

                if key_state == "PendingDeletion":
                    deletion_date = key_metadata.get("DeletionDate", "Unknown")
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": key_id,
                        "resource_id_type": "KMSKeyId",
                        "issue": f"KMS key '{key_id}' is pending deletion (scheduled: {deletion_date})",
                        "region": kms.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-039",
            "check_name": "Pending deletion KMS keys",
            "problem_statement": "KMS keys pending deletion may cause data loss for AI workloads if still referenced",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Cancel deletion of keys still in use by AI workloads or migrate to new keys",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify AI resources using keys pending deletion",
                "2. Cancel key deletion if key is still needed (cancel-key-deletion)",
                "3. Migrate AI resources to new keys if deletion is intentional",
                "4. Verify no data will become permanently inaccessible",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking pending deletion keys: {e}")
        return None


def check_disabled_kms_keys(session):
    """AI-040: Disabled KMS keys"""
    print("Checking disabled KMS keys")

    kms = session.client("kms")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        keys = []
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            keys.extend(page.get("Keys", []))

        total_scanned = 0
        for key_info in keys:
            key_id = key_info["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue

                total_scanned += 1
                key_state = key_metadata.get("KeyState", "")
                description = key_metadata.get("Description", "")

                if key_state == "Disabled":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": key_id,
                        "resource_id_type": "KMSKeyId",
                        "issue": f"KMS key '{key_id}' is disabled (description: {description or 'N/A'})",
                        "region": kms.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-040",
            "check_name": "Disabled KMS keys",
            "problem_statement": "Disabled KMS keys cannot encrypt/decrypt data for AI workloads",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Re-enable disabled KMS keys required by AI services or clean up unused keys",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review disabled keys and determine if AI services depend on them",
                "2. Re-enable keys using enable-key API if still needed",
                "3. Schedule deletion for keys no longer required",
                "4. Document key lifecycle management processes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking disabled KMS keys: {e}")
        return None


def check_ai_workloads_aws_managed_keys(session):
    """AI-041: AI workloads using AWS-managed keys"""
    print("Checking AI workloads using AWS-managed keys instead of customer-managed")

    sts = session.client("sts")
    sagemaker = session.client("sagemaker")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        total_scanned = 0

        # Check SageMaker endpoints
        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
            for ep in endpoints:
                total_scanned += 1
                try:
                    ep_detail = sagemaker.describe_endpoint(EndpointName=ep["EndpointName"])
                    kms_key = ep_detail.get("KmsKeyId", "")
                    if not kms_key or "alias/aws/" in kms_key.lower():
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": ep["EndpointName"],
                            "resource_id_type": "SageMakerEndpoint",
                            "issue": f"SageMaker endpoint '{ep['EndpointName']}' uses AWS-managed key instead of customer-managed",
                            "region": sagemaker.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue
        except Exception:
            pass

        # Check SageMaker notebooks
        try:
            notebooks = sagemaker.list_notebook_instances().get("NotebookInstances", [])
            for nb in notebooks:
                total_scanned += 1
                try:
                    nb_detail = sagemaker.describe_notebook_instance(
                        NotebookInstanceName=nb["NotebookInstanceName"]
                    )
                    kms_key = nb_detail.get("KmsKeyId", "")
                    if not kms_key or "alias/aws/" in kms_key.lower():
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": nb["NotebookInstanceName"],
                            "resource_id_type": "SageMakerNotebook",
                            "issue": f"SageMaker notebook '{nb['NotebookInstanceName']}' uses AWS-managed key instead of customer-managed",
                            "region": sagemaker.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue
        except Exception:
            pass

        # Check Bedrock custom models (if available)
        try:
            bedrock = session.client("bedrock")
            custom_models = bedrock.list_custom_models().get("modelSummaries", [])
            for model in custom_models:
                total_scanned += 1
                model_name = model.get("modelName", "Unknown")
                # Bedrock custom models without explicit CMK use AWS-managed keys
                try:
                    model_detail = bedrock.get_custom_model(modelIdentifier=model.get("modelArn", ""))
                    kms_key = model_detail.get("outputDataConfig", {}).get("kmsKeyId", "")
                    if not kms_key:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": model_name,
                            "resource_id_type": "BedrockCustomModel",
                            "issue": f"Bedrock custom model '{model_name}' uses AWS-managed key",
                            "region": bedrock.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue
        except Exception:
            pass

        return {
            "id": "AI-041",
            "check_name": "AI workloads using AWS-managed keys",
            "problem_statement": "AI workloads should use customer-managed KMS keys for full control over encryption",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure AI workloads to use customer-managed KMS keys for encryption",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create customer-managed KMS keys for AI workloads",
                "2. Update SageMaker endpoints/notebooks with customer-managed key ARNs",
                "3. Configure Bedrock custom models with customer-managed encryption",
                "4. Enable key rotation on customer-managed keys",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI workloads AWS-managed keys: {e}")
        return None
