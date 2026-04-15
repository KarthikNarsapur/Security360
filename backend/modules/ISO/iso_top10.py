import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_data_management(session):
    # [E2]
    print("Checking data management configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            except:
                encryption = None
            
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                versioning_enabled = versioning.get("Status") == "Enabled"
            except:
                versioning_enabled = False

            if not encryption or not versioning_enabled:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": bucket_name,
                    "resource_id_type": "BucketName",
                    "issue": "S3 bucket missing encryption or versioning",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "E2",
            "check_name": "Data Management",
            "problem_statement": "Data should be securely stored with encryption and versioning",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable encryption and versioning for all S3 buckets",
            "additional_info": {"total_scanned": len(buckets), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Navigate to S3 service in AWS Console",
                "2. Select the bucket",
                "3. Enable default encryption",
                "4. Enable versioning",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking data management: {e}")
        return None


def check_security_robustness(session):
    # [H5]
    print("Checking security and robustness configuration")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        security_groups = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in security_groups:
            sg_id = sg["GroupId"]
            
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": sg_id,
                            "resource_id_type": "SecurityGroupId",
                            "issue": "Security group allows unrestricted access",
                            "region": ec2.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break

        return {
            "id": "H5",
            "check_name": "Security and Robustness",
            "problem_statement": "AI systems should be protected from unauthorized access",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Restrict security group access to specific IP ranges",
            "additional_info": {"total_scanned": len(security_groups), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Navigate to EC2 service in AWS Console",
                "2. Select Security Groups",
                "3. Edit inbound rules",
                "4. Replace 0.0.0.0/0 with specific IP ranges",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking security robustness: {e}")
        return None


def check_privacy_data_protection(session):
    # [H7]
    print("Checking privacy and data protection configuration")

    s3 = session.client("s3")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            try:
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                block_public_acls = public_access.get("PublicAccessBlockConfiguration", {}).get("BlockPublicAcls", False)
            except:
                block_public_acls = False

            if not block_public_acls:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": bucket_name,
                    "resource_id_type": "BucketName",
                    "issue": "S3 bucket allows public access",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "H7",
            "check_name": "Privacy and Data Protection",
            "problem_statement": "Data should be protected from unauthorized public access",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Block public access for all S3 buckets",
            "additional_info": {"total_scanned": len(buckets), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Navigate to S3 service in AWS Console",
                "2. Select the bucket",
                "3. Go to Permissions tab",
                "4. Edit Block public access settings",
                "5. Enable all block public access options",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking privacy data protection: {e}")
        return None


def check_deployment_release_management(session):
    # [E5]
    print("Checking deployment and release management configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        endpoints = sagemaker.list_endpoints().get("Endpoints", [])

        for endpoint in endpoints:
            endpoint_name = endpoint["EndpointName"]
            
            try:
                endpoint_config = sagemaker.describe_endpoint_config(
                    EndpointConfigName=endpoint["EndpointConfigName"]
                )
                auto_scaling = any(variant.get("InitialInstanceCount", 0) > 1 
                                 for variant in endpoint_config.get("ProductionVariants", []))
            except:
                auto_scaling = False

            if not auto_scaling:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": endpoint_name,
                    "resource_id_type": "EndpointName",
                    "issue": "SageMaker endpoint lacks high availability configuration",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "E5",
            "check_name": "Deployment and Release Management",
            "problem_statement": "AI deployments should have proper availability and rollback mechanisms",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure high availability for SageMaker endpoints",
            "additional_info": {"total_scanned": len(endpoints), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Navigate to SageMaker service in AWS Console",
                "2. Select the endpoint",
                "3. Update endpoint configuration",
                "4. Increase instance count for high availability",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking deployment release management: {e}")
        return None


def check_monitoring_feedback(session):
    # [E6]
    print("Checking monitoring and feedback configuration")

    cloudwatch = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
        
        sagemaker_alarms = [alarm for alarm in alarms if "SageMaker" in alarm.get("Namespace", "")]

        if len(sagemaker_alarms) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudWatch",
                "resource_id_type": "Service",
                "issue": "No SageMaker monitoring alarms configured",
                "region": cloudwatch.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "E6",
            "check_name": "Monitoring and Feedback",
            "problem_statement": "AI systems should have continuous monitoring and alerting",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure CloudWatch alarms for AI services",
            "additional_info": {"total_alarms": len(alarms), "sagemaker_alarms": len(sagemaker_alarms)},
            "remediation_steps": [
                "1. Navigate to CloudWatch service in AWS Console",
                "2. Create alarms for SageMaker metrics",
                "3. Set appropriate thresholds",
                "4. Configure SNS notifications",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking monitoring feedback: {e}")
        return None


def check_data_model_governance(session):
    # [H6]
    print("Checking data and model governance configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        
        try:
            model_packages = sagemaker.list_model_packages().get("ModelPackageSummaryList", [])
        except:
            model_packages = []

        models = sagemaker.list_models().get("Models", [])

        if len(model_packages) == 0 and len(models) > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "ModelRegistry",
                "resource_id_type": "Service",
                "issue": "Models exist but no model registry usage detected",
                "region": sagemaker.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "H6",
            "check_name": "Data and Model Governance",
            "problem_statement": "Models should be version-controlled and registered",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Use SageMaker Model Registry for model governance",
            "additional_info": {"models": len(models), "registered_models": len(model_packages)},
            "remediation_steps": [
                "1. Navigate to SageMaker service in AWS Console",
                "2. Go to Model Registry",
                "3. Register existing models",
                "4. Implement version control workflow",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking data model governance: {e}")
        return None


def check_documented_information(session):
    # [D5]
    print("Checking documented information configuration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])
        
        active_trails = [trail for trail in trails if trail.get("IsLogging", False)]

        if len(active_trails) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudTrail",
                "resource_id_type": "Service",
                "issue": "No active CloudTrail logging for audit trail",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "D5",
            "check_name": "Documented Information",
            "problem_statement": "All activities should be logged for traceability and audit",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable CloudTrail logging for audit trails",
            "additional_info": {"total_trails": len(trails), "active_trails": len(active_trails)},
            "remediation_steps": [
                "1. Navigate to CloudTrail service in AWS Console",
                "2. Create a new trail",
                "3. Enable logging",
                "4. Configure S3 bucket for log storage",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking documented information: {e}")
        return None


def check_operational_planning_control(session):
    # [E1]
    print("Checking operational planning and control configuration")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])
        
        ai_roles = [role for role in roles if any(service in role.get("AssumeRolePolicyDocument", "")
                   for service in ["sagemaker", "bedrock", "comprehend"])]

        if len(ai_roles) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "IAM",
                "resource_id_type": "Service",
                "issue": "No dedicated IAM roles for AI services",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "E1",
            "check_name": "Operational Planning and Control",
            "problem_statement": "AI operations should have dedicated roles and access controls",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create dedicated IAM roles for AI services",
            "additional_info": {"total_roles": len(roles), "ai_roles": len(ai_roles)},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Create roles for AI services",
                "3. Assign appropriate policies",
                "4. Follow principle of least privilege",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking operational planning control: {e}")
        return None


def check_addressing_risks_opportunities(session):
    # [C1]
    print("Checking addressing risks and opportunities configuration")

    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        
        try:
            rules = config.describe_config_rules().get("ConfigRules", [])
        except:
            rules = []

        if len(rules) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "Config",
                "resource_id_type": "Service",
                "issue": "No AWS Config rules for compliance monitoring",
                "region": config.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "C1",
            "check_name": "Addressing Risks and Opportunities",
            "problem_statement": "Risk management should be implemented through compliance monitoring",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Implement AWS Config rules for compliance monitoring",
            "additional_info": {"config_rules": len(rules)},
            "remediation_steps": [
                "1. Navigate to AWS Config service in AWS Console",
                "2. Set up configuration recorder",
                "3. Create compliance rules",
                "4. Monitor rule compliance status",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking addressing risks opportunities: {e}")
        return None


def check_incident_management(session):
    # [E8]
    print("Checking incident management configuration")

    sns = session.client("sns")
    cloudwatch = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        topics = sns.list_topics().get("Topics", [])
        alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
        
        alarms_with_actions = [alarm for alarm in alarms if alarm.get("AlarmActions")]

        if len(topics) == 0 or len(alarms_with_actions) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "IncidentResponse",
                "resource_id_type": "Service",
                "issue": "No incident response automation configured",
                "region": sns.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "E8",
            "check_name": "Incident Management",
            "problem_statement": "Incident response should be automated with notifications",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure SNS topics and CloudWatch alarms for incident response",
            "additional_info": {"sns_topics": len(topics), "alarms_with_actions": len(alarms_with_actions)},
            "remediation_steps": [
                "1. Navigate to SNS service in AWS Console",
                "2. Create notification topics",
                "3. Configure CloudWatch alarms",
                "4. Link alarms to SNS topics for automated notifications",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking incident management: {e}")
        return None
