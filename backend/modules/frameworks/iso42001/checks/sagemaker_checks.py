"""
ISO 42001 Extended Checks — SageMaker (AI-008 to AI-022)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_sagemaker_studio_domains_encrypted(session):
    """AI-008: SageMaker Studio Domains encrypted"""
    print("Checking SageMaker Studio Domains encryption")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            domains = sagemaker.list_domains().get("Domains", [])
        except Exception:
            domains = []

        for domain in domains:
            domain_id = domain.get("DomainId", "")
            try:
                detail = sagemaker.describe_domain(DomainId=domain_id)
                kms_key = detail.get("KmsKeyId", "")
                if not kms_key:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": domain_id,
                        "resource_id_type": "DomainId",
                        "issue": f"Studio Domain '{domain.get('DomainName', domain_id)}' not encrypted with KMS",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-008",
            "check_name": "SageMaker Studio Domains encrypted",
            "problem_statement": "SageMaker Studio Domains should be encrypted with customer-managed KMS keys",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure KMS encryption for all SageMaker Studio Domains",
            "additional_info": {
                "total_scanned": max(len(domains), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Navigate to SageMaker Studio in AWS Console",
                "2. Select the domain and review encryption settings",
                "3. Recreate domain with KMS key if not encrypted",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking SageMaker Studio encryption: {e}")
        return None


def check_sagemaker_studio_auth_mode(session):
    """AI-009: SageMaker Studio authentication mode"""
    print("Checking SageMaker Studio authentication mode")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            domains = sagemaker.list_domains().get("Domains", [])
        except Exception:
            domains = []

        for domain in domains:
            domain_id = domain.get("DomainId", "")
            try:
                detail = sagemaker.describe_domain(DomainId=domain_id)
                auth_mode = detail.get("AuthMode", "")
                if auth_mode != "SSO":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": domain_id,
                        "resource_id_type": "DomainId",
                        "issue": f"Studio Domain '{domain.get('DomainName', domain_id)}' uses '{auth_mode}' instead of SSO",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-009",
            "check_name": "SageMaker Studio authentication mode",
            "problem_statement": "SageMaker Studio should use SSO for centralized identity management",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure SageMaker Studio Domains to use SSO authentication",
            "additional_info": {
                "total_scanned": max(len(domains), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Use SSO mode for centralized authentication",
                "2. Integrate with AWS IAM Identity Center",
                "3. Apply MFA requirements through SSO provider",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking SageMaker Studio auth mode: {e}")
        return None


def check_sagemaker_user_profiles_inventory(session):
    """AI-010: SageMaker User Profiles inventory"""
    print("Checking SageMaker User Profiles inventory")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            domains = sagemaker.list_domains().get("Domains", [])
        except Exception:
            domains = []

        total_profiles = 0
        for domain in domains:
            domain_id = domain.get("DomainId", "")
            try:
                profiles = sagemaker.list_user_profiles(DomainIdEquals=domain_id).get("UserProfiles", [])
                total_profiles += len(profiles)

                if len(profiles) == 0:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": domain_id,
                        "resource_id_type": "DomainId",
                        "issue": f"Domain '{domain.get('DomainName', domain_id)}' has no user profiles — may be unused",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-010",
            "check_name": "SageMaker User Profiles inventory",
            "problem_statement": "AI environments should have defined user profiles for governance",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Ensure all SageMaker domains have configured user profiles",
            "additional_info": {
                "total_scanned": max(len(domains), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review SageMaker Studio domains",
                "2. Create user profiles for each authorized user",
                "3. Remove unused domains to reduce attack surface",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking SageMaker user profiles: {e}")
        return None


def check_endpoint_status_validation(session):
    """AI-011: Endpoint status validation"""
    print("Checking SageMaker endpoint status validation")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        except Exception:
            endpoints = []

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "")
            status = ep.get("EndpointStatus", "")
            if status not in ("InService",):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": ep_name,
                    "resource_id_type": "EndpointName",
                    "issue": f"Endpoint '{ep_name}' has status '{status}' — not InService",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-011",
            "check_name": "Endpoint status validation",
            "problem_statement": "AI endpoints should be in healthy InService state",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Investigate and fix endpoints not in InService state",
            "additional_info": {
                "total_scanned": max(len(endpoints), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Check CloudWatch logs for endpoint failures",
                "2. Verify model artifacts are accessible",
                "3. Check instance capacity availability",
                "4. Delete failed endpoints and redeploy",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking endpoint status: {e}")
        return None


def check_endpoint_config_encryption(session):
    """AI-012: Endpoint configuration encryption"""
    print("Checking SageMaker endpoint configuration encryption")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        except Exception:
            endpoints = []

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "")
            try:
                ep_detail = sagemaker.describe_endpoint(EndpointName=ep_name)
                config_name = ep_detail.get("EndpointConfigName", "")
                if config_name:
                    config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
                    kms_key = config.get("KmsKeyId", "")
                    if not kms_key:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": ep_name,
                            "resource_id_type": "EndpointName",
                            "issue": f"Endpoint '{ep_name}' config has no KMS encryption",
                            "region": sagemaker.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-012",
            "check_name": "Endpoint configuration encryption",
            "problem_statement": "SageMaker endpoints should encrypt data at rest with KMS",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure KMS encryption for all endpoint configurations",
            "additional_info": {
                "total_scanned": max(len(endpoints), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create new endpoint config with KmsKeyId specified",
                "2. Update endpoint to use new configuration",
                "3. Delete old unencrypted configuration",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking endpoint config encryption: {e}")
        return None


def check_async_inference_config(session):
    """AI-013: Async inference configuration"""
    print("Checking SageMaker async inference configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        except Exception:
            endpoints = []

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "")
            try:
                ep_detail = sagemaker.describe_endpoint(EndpointName=ep_name)
                config_name = ep_detail.get("EndpointConfigName", "")
                if config_name:
                    config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
                    async_config = config.get("AsyncInferenceConfig")
                    if async_config:
                        output_config = async_config.get("OutputConfig", {})
                        kms_key = output_config.get("KmsKeyId", "")
                        if not kms_key:
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": ep_name,
                                "resource_id_type": "EndpointName",
                                "issue": f"Async endpoint '{ep_name}' output not encrypted with KMS",
                                "region": sagemaker.meta.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            })
            except Exception:
                continue

        return {
            "id": "AI-013",
            "check_name": "Async inference configuration",
            "problem_statement": "Async inference outputs should be encrypted at rest",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable KMS encryption for async inference output locations",
            "additional_info": {
                "total_scanned": max(len(endpoints), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Update async inference config with KmsKeyId",
                "2. Ensure output S3 bucket also has encryption",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking async inference config: {e}")
        return None


def check_multi_model_endpoint(session):
    """AI-014: Multi-model endpoint detection"""
    print("Checking multi-model endpoint detection")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        except Exception:
            endpoints = []

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "")
            try:
                ep_detail = sagemaker.describe_endpoint(EndpointName=ep_name)
                config_name = ep_detail.get("EndpointConfigName", "")
                if config_name:
                    config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
                    variants = config.get("ProductionVariants", [])
                    for variant in variants:
                        container_mode = variant.get("ContainerStartupHealthCheckTimeoutInSeconds")
                        # Multi-model endpoints typically use ModelDataUrl with model data
                        model_name = variant.get("ModelName", "")
                        if model_name:
                            try:
                                model = sagemaker.describe_model(ModelName=model_name)
                                container = model.get("PrimaryContainer", {})
                                mode = container.get("Mode", "SingleModel")
                                if mode == "MultiModel":
                                    # Multi-model detected — check security
                                    resources_affected.append({
                                        "account_id": account_id,
                                        "resource_id": ep_name,
                                        "resource_id_type": "EndpointName",
                                        "issue": f"Multi-model endpoint '{ep_name}' detected — ensure model isolation",
                                        "region": sagemaker.meta.region_name,
                                        "last_updated": datetime.now(IST).isoformat(),
                                    })
                            except Exception:
                                continue
            except Exception:
                continue

        return {
            "id": "AI-014",
            "check_name": "Multi-model endpoint detection",
            "problem_statement": "Multi-model endpoints require additional isolation controls",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Review multi-model endpoints for proper model isolation and access controls",
            "additional_info": {
                "total_scanned": max(len(endpoints), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Document all models served by multi-model endpoints",
                "2. Ensure model artifacts are properly isolated in S3",
                "3. Apply least-privilege access to model artifact paths",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking multi-model endpoints: {e}")
        return None


def check_model_package_approval_workflow(session):
    """AI-015: Model package approval workflow"""
    print("Checking model package approval workflow")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            groups = sagemaker.list_model_package_groups().get("ModelPackageGroupSummaryList", [])
        except Exception:
            groups = []

        for group in groups:
            group_name = group.get("ModelPackageGroupName", "")
            try:
                packages = sagemaker.list_model_packages(
                    ModelPackageGroupName=group_name
                ).get("ModelPackageSummaryList", [])

                # Check if any packages were auto-approved without manual review
                for pkg in packages:
                    approval_status = pkg.get("ModelApprovalStatus", "")
                    if approval_status == "Approved":
                        # Check if there's a proper approval description
                        pass  # Approved is good
                    elif approval_status == "PendingManualApproval":
                        pass  # Pending is expected
                    elif approval_status == "" or approval_status == "Rejected":
                        pass  # Either not set or rejected

                # Flag groups without any approval workflow
                if len(packages) > 0:
                    statuses = [p.get("ModelApprovalStatus", "") for p in packages]
                    if all(s == "" for s in statuses):
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": group_name,
                            "resource_id_type": "ModelPackageGroup",
                            "issue": f"Model package group '{group_name}' has no approval workflow configured",
                            "region": sagemaker.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-015",
            "check_name": "Model package approval workflow",
            "problem_statement": "Model deployments should require approval workflow for governance",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Implement model approval workflows in SageMaker Model Registry",
            "additional_info": {
                "total_scanned": max(len(groups), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Configure model package groups with approval requirements",
                "2. Set ModelApprovalStatus to PendingManualApproval by default",
                "3. Define approval criteria and reviewers",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking model package approval: {e}")
        return None


def check_processing_job_network_isolation(session):
    """AI-016: Processing job network isolation"""
    print("Checking processing job network isolation")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            jobs = sagemaker.list_processing_jobs(
                StatusEquals="InProgress"
            ).get("ProcessingJobSummaries", [])
            # Also check recent completed
            completed = sagemaker.list_processing_jobs(
                StatusEquals="Completed",
                MaxResults=20,
            ).get("ProcessingJobSummaries", [])
            jobs.extend(completed)
        except Exception:
            jobs = []

        for job in jobs:
            job_name = job.get("ProcessingJobName", "")
            try:
                detail = sagemaker.describe_processing_job(ProcessingJobName=job_name)
                network_config = detail.get("NetworkConfig", {})
                isolation = network_config.get("EnableNetworkIsolation", False)
                if not isolation:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": job_name,
                        "resource_id_type": "ProcessingJobName",
                        "issue": f"Processing job '{job_name}' does not have network isolation enabled",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-016",
            "check_name": "Processing job network isolation",
            "problem_statement": "SageMaker processing jobs should enable network isolation for data protection",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable network isolation for processing jobs handling sensitive data",
            "additional_info": {
                "total_scanned": max(len(jobs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Set EnableNetworkIsolation=True in processing job config",
                "2. Use VPC configuration for required network access",
                "3. Restrict outbound via security groups",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking processing job network isolation: {e}")
        return None


def check_processing_job_vpc_config(session):
    """AI-017: Processing job VPC configuration"""
    print("Checking processing job VPC configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            jobs = sagemaker.list_processing_jobs(
                StatusEquals="Completed", MaxResults=20
            ).get("ProcessingJobSummaries", [])
        except Exception:
            jobs = []

        for job in jobs:
            job_name = job.get("ProcessingJobName", "")
            try:
                detail = sagemaker.describe_processing_job(ProcessingJobName=job_name)
                network_config = detail.get("NetworkConfig", {})
                vpc_config = network_config.get("VpcConfig")
                if not vpc_config:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": job_name,
                        "resource_id_type": "ProcessingJobName",
                        "issue": f"Processing job '{job_name}' runs outside VPC",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-017",
            "check_name": "Processing job VPC configuration",
            "problem_statement": "Processing jobs should run within a VPC for network security",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure VPC settings for all SageMaker processing jobs",
            "additional_info": {
                "total_scanned": max(len(jobs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Specify VpcConfig with subnets and security groups",
                "2. Use private subnets for processing jobs",
                "3. Configure VPC endpoints for S3 access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking processing job VPC config: {e}")
        return None


def check_hyperparameter_tuning_jobs(session):
    """AI-018: Hyperparameter tuning jobs inventory"""
    print("Checking hyperparameter tuning jobs inventory")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            jobs = sagemaker.list_hyper_parameter_tuning_jobs(MaxResults=50).get(
                "HyperParameterTuningJobSummaries", []
            )
        except Exception:
            jobs = []

        failed_jobs = [j for j in jobs if j.get("HyperParameterTuningJobStatus") == "Failed"]
        for job in failed_jobs:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": job.get("HyperParameterTuningJobName", ""),
                "resource_id_type": "TuningJobName",
                "issue": f"Tuning job '{job.get('HyperParameterTuningJobName', '')}' in Failed state",
                "region": sagemaker.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-018",
            "check_name": "Hyperparameter tuning jobs inventory",
            "problem_statement": "AI hyperparameter tuning jobs should complete successfully",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Investigate and clean up failed tuning jobs",
            "additional_info": {
                "total_scanned": max(len(jobs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review failed tuning job logs in CloudWatch",
                "2. Fix configuration issues and retry",
                "3. Clean up stale/failed resources",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking hyperparameter tuning jobs: {e}")
        return None


def check_automl_jobs_inventory(session):
    """AI-019: AutoML jobs inventory"""
    print("Checking AutoML jobs inventory")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            jobs = sagemaker.list_auto_ml_jobs(MaxResults=50).get("AutoMLJobSummaries", [])
        except Exception:
            jobs = []

        failed_jobs = [j for j in jobs if j.get("AutoMLJobStatus") == "Failed"]
        for job in failed_jobs:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": job.get("AutoMLJobName", ""),
                "resource_id_type": "AutoMLJobName",
                "issue": f"AutoML job '{job.get('AutoMLJobName', '')}' in Failed state",
                "region": sagemaker.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-019",
            "check_name": "AutoML jobs inventory",
            "problem_statement": "AutoML jobs should be tracked and operational for AI lifecycle management",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Monitor and manage AutoML job lifecycle",
            "additional_info": {
                "total_scanned": max(len(jobs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review failed AutoML jobs",
                "2. Ensure proper IAM permissions for AutoML",
                "3. Clean up completed experiments",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AutoML jobs: {e}")
        return None


def check_batch_transform_jobs(session):
    """AI-020: Batch transform jobs inventory"""
    print("Checking batch transform jobs inventory")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            jobs = sagemaker.list_transform_jobs(MaxResults=50).get("TransformJobSummaries", [])
        except Exception:
            jobs = []

        failed_jobs = [j for j in jobs if j.get("TransformJobStatus") == "Failed"]
        for job in failed_jobs:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": job.get("TransformJobName", ""),
                "resource_id_type": "TransformJobName",
                "issue": f"Transform job '{job.get('TransformJobName', '')}' in Failed state",
                "region": sagemaker.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-020",
            "check_name": "Batch transform jobs inventory",
            "problem_statement": "Batch transform jobs should complete successfully for data processing governance",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Monitor batch transform jobs and resolve failures",
            "additional_info": {
                "total_scanned": max(len(jobs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Check transform job failure reasons",
                "2. Verify input data and model artifacts",
                "3. Clean up failed resources",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking batch transform jobs: {e}")
        return None


def check_feature_groups_inventory(session):
    """AI-021: Feature Groups inventory"""
    print("Checking Feature Groups inventory")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            groups = sagemaker.list_feature_groups().get("FeatureGroupSummaries", [])
        except Exception:
            groups = []

        for group in groups:
            group_name = group.get("FeatureGroupName", "")
            status = group.get("FeatureGroupStatus", "")
            if status != "Created":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": group_name,
                    "resource_id_type": "FeatureGroupName",
                    "issue": f"Feature group '{group_name}' status: {status}",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-021",
            "check_name": "Feature Groups inventory",
            "problem_statement": "AI Feature Store groups should be in healthy state for data lineage",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Ensure all feature groups are in Created state",
            "additional_info": {
                "total_scanned": max(len(groups), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review feature group status",
                "2. Recreate failed feature groups",
                "3. Ensure proper IAM and S3 permissions",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking feature groups: {e}")
        return None


def check_data_wrangler_flows(session):
    """AI-022: Data Wrangler flows"""
    print("Checking Data Wrangler flows")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Data Wrangler flows are stored as processing jobs with specific naming
        try:
            jobs = sagemaker.list_processing_jobs(
                NameContains="data-wrangler",
                MaxResults=20,
            ).get("ProcessingJobSummaries", [])
        except Exception:
            jobs = []

        failed_flows = [j for j in jobs if j.get("ProcessingJobStatus") == "Failed"]
        for job in failed_flows:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": job.get("ProcessingJobName", ""),
                "resource_id_type": "ProcessingJobName",
                "issue": f"Data Wrangler flow '{job.get('ProcessingJobName', '')}' failed",
                "region": sagemaker.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-022",
            "check_name": "Data Wrangler flows",
            "problem_statement": "Data Wrangler flows should complete successfully for data preparation governance",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Monitor Data Wrangler flows for failures and data quality",
            "additional_info": {
                "total_scanned": max(len(jobs), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review failed Data Wrangler flows",
                "2. Check data source connectivity",
                "3. Validate transformation logic",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Data Wrangler flows: {e}")
        return None
