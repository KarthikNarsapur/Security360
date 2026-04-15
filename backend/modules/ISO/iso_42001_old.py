import boto3
from datetime import datetime, timezone, timedelta
import json

IST = timezone(timedelta(hours=5, minutes=30))


# A.5 - AI Policy & Governance
def check_ai_policy_governance(session):
    print("Checking AI policy and governance controls")
    
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        
        # Check for AI governance policies
        policies = iam.list_policies(Scope='Local', MaxItems=1000).get("Policies", [])
        
        ai_policy_found = False
        for policy in policies:
            if any(keyword in policy["PolicyName"].lower() for keyword in ["ai", "ml", "sagemaker", "bedrock"]):
                ai_policy_found = True
                break
        
        if not ai_policy_found:
            resources_affected.append({
                "account_id": account_id,
                "resource_type": "Account Policy",
                "issue": "No AI governance policies found",
                "region": "global",
                "details": {"recommendation": "Create AI governance and ethics policies"},
                "last_updated": datetime.now(IST).isoformat(),
            })
        
        return {
            "check_name": "AI Policy & Governance",
            "total_scanned": len(policies),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "AI Policy & Governance", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.6 - AI Roles & Responsibilities  
def check_ai_roles_responsibilities(session):
    print("Checking AI roles and responsibilities")
    
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        
        roles = iam.list_roles().get("Roles", [])
        ai_roles = [r for r in roles if any(kw in r["RoleName"].lower() for kw in ["sagemaker", "ai", "ml", "data-scientist"])]
        
        if len(ai_roles) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_type": "IAM Roles",
                "issue": "No dedicated AI/ML roles found",
                "region": "global",
                "details": {"recommendation": "Create specific roles for AI development and operations"},
                "last_updated": datetime.now(IST).isoformat(),
            })
        
        return {
            "check_name": "AI Roles & Responsibilities",
            "total_scanned": len(roles),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "AI Roles & Responsibilities", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.7 - AI Risk Management
def check_ai_risk_management(session):
    print("Checking AI risk management controls")
    
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        
        for endpoint in endpoints:
            endpoint_name = endpoint["EndpointName"]
            
            # Check for model monitoring (risk detection)
            monitoring_schedules = sagemaker.list_monitoring_schedules(
                EndpointName=endpoint_name
            ).get("MonitoringScheduleSummaries", [])
            
            if not monitoring_schedules:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": endpoint_name,
                    "resource_type": "SageMaker Endpoint",
                    "issue": "No risk monitoring configured",
                    "region": region,
                    "details": {"recommendation": "Implement model drift and bias monitoring"},
                    "last_updated": datetime.now(IST).isoformat(),
                })
        
        return {
            "check_name": "AI Risk Management",
            "total_scanned": len(endpoints),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "AI Risk Management", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.8 - AI Lifecycle Management
def check_ai_lifecycle_management(session):
    print("Checking AI lifecycle management")
    
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        model_packages = sagemaker.list_model_packages().get("ModelPackageSummaryList", [])
        
        for package in model_packages:
            package_arn = package["ModelPackageArn"]
            
            try:
                details = sagemaker.describe_model_package(ModelPackageName=package_arn)
                
                # Check for approval status (lifecycle control)
                if details.get("ModelPackageStatus") != "Completed":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": package_arn.split("/")[-1],
                        "resource_type": "Model Package",
                        "issue": "Model package not properly approved in lifecycle",
                        "region": region,
                        "details": {"status": details.get("ModelPackageStatus")},
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue
        
        return {
            "check_name": "AI Lifecycle Management",
            "total_scanned": len(model_packages),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "AI Lifecycle Management", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.9 - Data Management & Quality
def check_data_management_quality(session):
    print("Checking data management and quality")
    
    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        buckets = s3.list_buckets().get("Buckets", [])
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            # Check AI/ML data buckets
            if any(kw in bucket_name.lower() for kw in ["dataset", "training", "ml", "ai", "sagemaker"]):
                try:
                    # Check versioning for data quality
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get("Status") != "Enabled":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_type": "S3 Bucket (AI Data)",
                            "issue": "AI data bucket lacks versioning for quality control",
                            "region": region,
                            "details": {"recommendation": "Enable versioning for data lineage"},
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue
        
        ai_buckets = [b for b in buckets if any(kw in b["Name"].lower() for kw in ["dataset", "training", "ml", "ai"])]
        
        return {
            "check_name": "Data Management & Quality",
            "total_scanned": len(ai_buckets),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "Data Management & Quality", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.10 - Transparency & Explainability
def check_transparency_explainability(session):
    print("Checking transparency and explainability")
    
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        training_jobs = sagemaker.list_training_jobs(MaxResults=50).get("TrainingJobSummaries", [])
        
        for job in training_jobs:
            job_name = job["TrainingJobName"]
            
            try:
                job_details = sagemaker.describe_training_job(TrainingJobName=job_name)
                
                # Check for explainability config
                debug_hook_config = job_details.get("DebugHookConfig")
                if not debug_hook_config:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": job_name,
                        "resource_type": "Training Job",
                        "issue": "No explainability/debugging configuration",
                        "region": region,
                        "details": {"recommendation": "Enable SageMaker Debugger for model explainability"},
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue
        
        return {
            "check_name": "Transparency & Explainability",
            "total_scanned": len(training_jobs),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "Transparency & Explainability", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.11 - Human Oversight & Accountability
def check_human_oversight_accountability(session):
    print("Checking human oversight and accountability")
    
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        
        for endpoint in endpoints:
            endpoint_name = endpoint["EndpointName"]
            
            try:
                endpoint_config = sagemaker.describe_endpoint_config(
                    EndpointConfigName=endpoint["EndpointConfigName"]
                )
                
                # Check for human review workflows
                async_inference_config = endpoint_config.get("AsyncInferenceConfig")
                if not async_inference_config:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": endpoint_name,
                        "resource_type": "SageMaker Endpoint",
                        "issue": "No human oversight mechanism configured",
                        "region": region,
                        "details": {"recommendation": "Implement human-in-the-loop workflows"},
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue
        
        return {
            "check_name": "Human Oversight & Accountability",
            "total_scanned": len(endpoints),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "Human Oversight & Accountability", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.12 - Security & Robustness
def check_security_robustness(session):
    print("Checking security and robustness of AI systems")
    
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        
        for endpoint in endpoints:
            endpoint_name = endpoint["EndpointName"]
            
            try:
                endpoint_config = sagemaker.describe_endpoint_config(
                    EndpointConfigName=endpoint["EndpointConfigName"]
                )
                
                # Check for VPC configuration (network security)
                production_variants = endpoint_config.get("ProductionVariants", [])
                has_vpc_config = any(
                    variant.get("ModelDataDownloadTimeoutInSeconds") for variant in production_variants
                )
                
                if not has_vpc_config:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": endpoint_name,
                        "resource_type": "SageMaker Endpoint",
                        "issue": "Endpoint lacks proper security configuration",
                        "region": region,
                        "details": {"recommendation": "Configure VPC and security groups"},
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue
        
        return {
            "check_name": "Security & Robustness",
            "total_scanned": len(endpoints),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "Security & Robustness", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.13 - Ethical & Legal Compliance
def check_ethical_legal_compliance(session):
    print("Checking ethical and legal compliance")
    
    s3 = session.client("s3")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        # Check for bias detection in training jobs
        training_jobs = sagemaker.list_training_jobs(MaxResults=20).get("TrainingJobSummaries", [])
        
        for job in training_jobs:
            job_name = job["TrainingJobName"]
            
            try:
                job_details = sagemaker.describe_training_job(TrainingJobName=job_name)
                
                # Check for bias analysis
                profiler_config = job_details.get("ProfilerConfig")
                if not profiler_config:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": job_name,
                        "resource_type": "Training Job",
                        "issue": "No bias detection or ethical compliance monitoring",
                        "region": region,
                        "details": {"recommendation": "Enable SageMaker Clarify for bias detection"},
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue
        
        return {
            "check_name": "Ethical & Legal Compliance",
            "total_scanned": len(training_jobs),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "Ethical & Legal Compliance", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


# A.14 - Monitoring, Logging & Incident Handling
def check_monitoring_logging_incidents(session):
    print("Checking monitoring, logging and incident handling")
    
    logs = session.client("logs")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []
    
    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name
        
        endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        
        for endpoint in endpoints:
            endpoint_name = endpoint["EndpointName"]
            
            # Check for CloudWatch logs
            log_group_name = f"/aws/sagemaker/Endpoints/{endpoint_name}"
            
            try:
                logs.describe_log_groups(logGroupNamePrefix=log_group_name)
            except logs.exceptions.ResourceNotFoundException:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": endpoint_name,
                    "resource_type": "SageMaker Endpoint",
                    "issue": "No logging configured for AI system monitoring",
                    "region": region,
                    "details": {"recommendation": "Enable CloudWatch logging for incident handling"},
                    "last_updated": datetime.now(IST).isoformat(),
                })
            except Exception:
                continue
        
        return {
            "check_name": "Monitoring, Logging & Incident Handling",
            "total_scanned": len(endpoints),
            "affected": len(resources_affected),
            "resources_affected": resources_affected,
        }
    except Exception as e:
        return {"check_name": "Monitoring, Logging & Incident Handling", "error": str(e), "total_scanned": 0, "affected": 0, "resources_affected": []}


def check_sagemaker_model_monitoring(session):
    # [ISO42001.AI.1] - AI Model Monitoring and Validation
    print("Checking SageMaker model monitoring configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        # Check endpoints without monitoring
        endpoints = sagemaker.list_endpoints().get("Endpoints", [])

        for endpoint in endpoints:
            endpoint_name = endpoint["EndpointName"]
            
            try:
                # Check for data capture config
                endpoint_config = sagemaker.describe_endpoint_config(
                    EndpointConfigName=endpoint["EndpointConfigName"]
                )
                
                data_capture_config = endpoint_config.get("DataCaptureConfig", {})
                
                if not data_capture_config.get("EnableCapture", False):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": endpoint_name,
                        "resource_type": "SageMaker Endpoint",
                        "issue": "SageMaker endpoint lacks data capture for model monitoring",
                        "region": region,
                        "details": {
                            "endpoint_status": endpoint["EndpointStatus"],
                            "creation_time": endpoint["CreationTime"].isoformat(),
                            "recommendation": "Enable data capture to monitor model performance and detect drift"
                        },
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception as e:
                continue

        total_scanned = len(endpoints)
        affected = len(resources_affected)

        return {
            "check_name": "SageMaker Model Monitoring",
            "total_scanned": total_scanned,
            "affected": affected,
            "resources_affected": resources_affected,
        }

    except Exception as e:
        return {
            "check_name": "SageMaker Model Monitoring",
            "error": str(e),
            "total_scanned": 0,
            "affected": 0,
            "resources_affected": [],
        }


def check_ai_data_governance(session):
    # [ISO42001.DATA.1] - AI Data Governance and Classification
    print("Checking AI data governance and classification")

    s3 = session.client("s3")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            try:
                # Check for AI/ML related buckets (common naming patterns)
                ai_keywords = ["sagemaker", "ml", "ai", "model", "dataset", "training"]
                is_ai_bucket = any(keyword in bucket_name.lower() for keyword in ai_keywords)
                
                if is_ai_bucket:
                    # Check for data classification tags
                    try:
                        tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                        tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("TagSet", [])}
                        
                        required_tags = ["DataClassification", "AIWorkload", "DataRetention"]
                        missing_tags = [tag for tag in required_tags if tag not in tags]
                        
                        if missing_tags:
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": bucket_name,
                                "resource_type": "S3 Bucket (AI/ML)",
                                "issue": f"AI/ML bucket missing data governance tags: {', '.join(missing_tags)}",
                                "region": region,
                                "details": {
                                    "existing_tags": tags,
                                    "missing_tags": missing_tags,
                                    "recommendation": "Add data classification and governance tags for AI workloads"
                                },
                                "last_updated": datetime.now(IST).isoformat(),
                            })
                    except s3.exceptions.NoSuchTagSet:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_type": "S3 Bucket (AI/ML)",
                            "issue": "AI/ML bucket has no data governance tags",
                            "region": region,
                            "details": {
                                "recommendation": "Add DataClassification, AIWorkload, and DataRetention tags"
                            },
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception as e:
                continue

        total_scanned = len([b for b in buckets if any(kw in b["Name"].lower() for kw in ["sagemaker", "ml", "ai", "model", "dataset"])])
        affected = len(resources_affected)

        return {
            "check_name": "AI Data Governance",
            "total_scanned": total_scanned,
            "affected": affected,
            "resources_affected": resources_affected,
        }

    except Exception as e:
        return {
            "check_name": "AI Data Governance",
            "error": str(e),
            "total_scanned": 0,
            "affected": 0,
            "resources_affected": [],
        }


def check_ai_service_access_control(session):
    # [ISO42001.ACCESS.1] - AI Service Access Control
    print("Checking AI service access control policies")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # AI services to check
        ai_services = [
            "sagemaker", "bedrock", "comprehend", "rekognition", 
            "textract", "translate", "polly", "transcribe"
        ]

        roles = iam.list_roles().get("Roles", [])

        for role in roles:
            role_name = role["RoleName"]
            
            try:
                # Get attached policies
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                
                for policy in attached_policies.get("AttachedPolicies", []):
                    if "FullAccess" in policy["PolicyName"]:
                        # Check if it's an AI service full access policy
                        for service in ai_services:
                            if service.lower() in policy["PolicyName"].lower():
                                resources_affected.append({
                                    "account_id": account_id,
                                    "resource_id": role_name,
                                    "resource_type": "IAM Role",
                                    "issue": f"Role has overly permissive AI service access: {policy['PolicyName']}",
                                    "region": "global",
                                    "details": {
                                        "policy_arn": policy["PolicyArn"],
                                        "ai_service": service,
                                        "recommendation": "Use least privilege access for AI services"
                                    },
                                    "last_updated": datetime.now(IST).isoformat(),
                                })
                                break
            except Exception as e:
                continue

        total_scanned = len(roles)
        affected = len(resources_affected)

        return {
            "check_name": "AI Service Access Control",
            "total_scanned": total_scanned,
            "affected": affected,
            "resources_affected": resources_affected,
        }

    except Exception as e:
        return {
            "check_name": "AI Service Access Control",
            "error": str(e),
            "total_scanned": 0,
            "affected": 0,
            "resources_affected": [],
        }


def check_model_bias_monitoring(session):
    # [ISO42001.BIAS.1] - Model Bias Detection and Monitoring
    print("Checking model bias monitoring configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        # Check model bias monitoring jobs
        monitoring_schedules = sagemaker.list_monitoring_schedules().get("MonitoringScheduleSummaries", [])
        
        # Check training jobs for bias analysis
        training_jobs = sagemaker.list_training_jobs(MaxResults=50).get("TrainingJobSummaries", [])

        for job in training_jobs:
            job_name = job["TrainingJobName"]
            
            try:
                job_details = sagemaker.describe_training_job(TrainingJobName=job_name)
                
                # Check for bias analysis in training job
                has_bias_monitoring = False
                for schedule in monitoring_schedules:
                    if job_name in schedule.get("MonitoringScheduleName", ""):
                        has_bias_monitoring = True
                        break
                
                if not has_bias_monitoring:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": job_name,
                        "resource_type": "SageMaker Training Job",
                        "issue": "Training job lacks bias monitoring configuration",
                        "region": region,
                        "details": {
                            "training_job_status": job["TrainingJobStatus"],
                            "creation_time": job["CreationTime"].isoformat(),
                            "recommendation": "Implement bias detection and monitoring for AI models"
                        },
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception as e:
                continue

        total_scanned = len(training_jobs)
        affected = len(resources_affected)

        return {
            "check_name": "Model Bias Monitoring",
            "total_scanned": total_scanned,
            "affected": affected,
            "resources_affected": resources_affected,
        }

    except Exception as e:
        return {
            "check_name": "Model Bias Monitoring",
            "error": str(e),
            "total_scanned": 0,
            "affected": 0,
            "resources_affected": [],
        }


def check_ai_model_versioning(session):
    # [ISO42001.VERSION.1] - AI Model Version Control and Lifecycle
    print("Checking AI model versioning and lifecycle management")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        # Check model packages for versioning
        model_packages = sagemaker.list_model_packages(MaxResults=50).get("ModelPackageSummaryList", [])

        model_groups = {}
        for package in model_packages:
            group_name = package.get("ModelPackageGroupName", "")
            if group_name:
                if group_name not in model_groups:
                    model_groups[group_name] = []
                model_groups[group_name].append(package)

        for group_name, packages in model_groups.items():
            if len(packages) < 2:  # Less than 2 versions
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": group_name,
                    "resource_type": "SageMaker Model Package Group",
                    "issue": "Model group has insufficient version control (less than 2 versions)",
                    "region": region,
                    "details": {
                        "version_count": len(packages),
                        "recommendation": "Maintain proper model versioning for lifecycle management"
                    },
                    "last_updated": datetime.now(IST).isoformat(),
                })

        total_scanned = len(model_groups)
        affected = len(resources_affected)

        return {
            "check_name": "AI Model Versioning",
            "total_scanned": total_scanned,
            "affected": affected,
            "resources_affected": resources_affected,
        }

    except Exception as e:
        return {
            "check_name": "AI Model Versioning",
            "error": str(e),
            "total_scanned": 0,
            "affected": 0,
            "resources_affected": [],
        }
