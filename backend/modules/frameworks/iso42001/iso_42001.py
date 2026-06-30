import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_understanding_organization_context(session):
    # [A1]
    print("Checking understanding organization context configuration")

    return {
        "id": "A1",
        "check_name": "Understanding the organization and its context",
        "problem_statement": "Not available - This is an organizational governance requirement",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires organizational assessment"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_understanding_stakeholder_needs(session):
    # [A2]
    print("Checking understanding stakeholder needs configuration")

    return {
        "id": "A2",
        "check_name": "Understanding stakeholder needs and expectations",
        "problem_statement": "Not available - This is an organizational governance requirement",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires stakeholder analysis"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_defining_scope_ai_management(session):
    # [A3]
    print("Checking defining scope AI management configuration")

    return {
        "id": "A3",
        "check_name": "Defining the scope of the AI management system",
        "problem_statement": "Not available - This is an organizational governance requirement",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires scope documentation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_establishing_ai_management_system(session):
    # [A4]
    print("Checking establishing AI management system configuration")

    return {
        "id": "A4",
        "check_name": "Establishing the AI management system",
        "problem_statement": "Not available - This is an organizational governance requirement",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires AIMS framework setup"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_leadership_commitment(session):
    # [B1]
    print("Checking leadership commitment configuration")

    return {
        "id": "B1",
        "check_name": "Leadership and commitment",
        "problem_statement": "Not available - This is an organizational governance requirement",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires management commitment assessment"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ai_policy(session):
    # [B2]
    print("Checking AI policy configuration")

    return {
        "id": "B2",
        "check_name": "AI policy",
        "problem_statement": "Not available - This is an organizational governance requirement",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires AI policy documentation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_organizational_roles_responsibilities(session):
    # [B3]
    print("Checking organizational roles responsibilities configuration")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])

        # Check for role separation: no single role should have both admin and AI permissions
        admin_ai_roles = []
        for role in roles:
            role_name = role["RoleName"]
            try:
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)[
                    "AttachedPolicies"
                ]
                policy_arns = [p["PolicyArn"] for p in attached_policies]

                has_admin = any(
                    "AdministratorAccess" in arn or "PowerUserAccess" in arn
                    for arn in policy_arns
                )
                has_ai_access = any(
                    service in role.get("AssumeRolePolicyDocument", "")
                    for service in [
                        "sagemaker",
                        "bedrock",
                        "comprehend",
                        "textract",
                        "rekognition",
                    ]
                )

                if has_admin and has_ai_access:
                    admin_ai_roles.append(role_name)
            except:
                continue

        # Check for overprivileged AI roles
        overprivileged_roles = []
        for role in roles:
            role_name = role["RoleName"]
            try:
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)[
                    "AttachedPolicies"
                ]
                ai_policies = [
                    p
                    for p in attached_policies
                    if any(
                        ai_svc in p["PolicyArn"]
                        for ai_svc in [
                            "SageMaker",
                            "Bedrock",
                            "Comprehend",
                            "Textract",
                            "Rekognition",
                        ]
                    )
                ]

                if len(ai_policies) > 0:
                    for policy in ai_policies:
                        if "FullAccess" in policy["PolicyArn"]:
                            overprivileged_roles.append(role_name)
                            break
            except:
                continue

        if admin_ai_roles:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "IAM",
                    "resource_id_type": "Service",
                    "issue": f"Roles with both admin and AI access violate separation of duties: {', '.join(admin_ai_roles)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        if overprivileged_roles:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "IAM",
                    "resource_id_type": "Service",
                    "issue": f"AI roles with excessive permissions: {', '.join(overprivileged_roles)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "B3",
            "check_name": "Organizational roles, responsibilities, and authorities",
            "problem_statement": "Roles must follow separation of duties and least privilege principles for AI governance",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Implement proper role separation and least privilege for AI operations",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(roles)),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Separate administrative and AI operational roles",
                "2. Replace FullAccess policies with specific permissions",
                "3. Implement least privilege principle",
                "4. Document role responsibilities and boundaries",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking organizational roles: {e}")
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
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "Config",
                    "resource_id_type": "Service",
                    "issue": "No AWS Config rules for compliance monitoring",
                    "region": config.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "C1",
            "check_name": "Addressing Risks and Opportunities",
            "problem_statement": "Risk management should be implemented through compliance monitoring",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Implement AWS Config rules for compliance monitoring",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(rules)),
                "affected": len(resources_affected),
            },
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


def check_ai_objectives_planning(session):
    # [C2]
    print("Checking AI objectives and planning configuration")

    cloudwatch = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check for AI service metrics (indicates objective tracking)
        ai_metrics = []
        for namespace in [
            "AWS/SageMaker",
            "AWS/Bedrock",
            "AWS/Comprehend",
            "AWS/Textract",
            "AWS/Rekognition",
        ]:
            try:
                metrics = cloudwatch.list_metrics(Namespace=namespace).get(
                    "Metrics", []
                )
                ai_metrics.extend(metrics)
            except:
                continue

        # Check for performance alarms (indicates objective thresholds)
        alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
        ai_alarms = [
            alarm
            for alarm in alarms
            if any(
                ns in alarm.get("Namespace", "")
                for ns in [
                    "AWS/SageMaker",
                    "AWS/Bedrock",
                    "AWS/Comprehend",
                    "AWS/Textract",
                    "AWS/Rekognition",
                ]
            )
        ]

        if len(ai_metrics) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudWatch",
                    "resource_id_type": "Service",
                    "issue": "No AI service metrics for objective measurement",
                    "region": cloudwatch.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        if len(ai_metrics) > 0 and len(ai_alarms) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudWatch",
                    "resource_id_type": "Service",
                    "issue": "AI metrics exist but no alarms define objective thresholds",
                    "region": cloudwatch.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "C2",
            "check_name": "AI objectives and planning to achieve them",
            "problem_statement": "AI objectives must be measurable with defined success thresholds",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Implement AI metrics collection and threshold alarms for objective tracking",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(ai_metrics)),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Enable detailed monitoring for AI services",
                "2. Create CloudWatch alarms for objective thresholds",
                "3. Document measurable success criteria",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI objectives planning: {e}")
        return None


def check_ai_risk_management_framework(session):
    # [C3]
    print("Checking AI risk management framework configuration")

    config = session.client("config")
    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check for Config rules (structured compliance assessment)
        try:
            config_rules = config.describe_config_rules().get("ConfigRules", [])
            compliance_rules = [
                rule for rule in config_rules if rule.get("ConfigRuleState") == "ACTIVE"
            ]
        except:
            compliance_rules = []

        # Check for CloudTrail logging (risk event tracking)
        trails = cloudtrail.describe_trails().get("trailList", [])
        active_trails = [
            trail
            for trail in trails
            if cloudtrail.get_trail_status(Name=trail["Name"]).get("IsLogging", False)
        ]

        if len(compliance_rules) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "Config",
                    "resource_id_type": "Service",
                    "issue": "No Config rules for continuous AI risk assessment",
                    "region": config.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        if len(active_trails) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudTrail",
                    "resource_id_type": "Service",
                    "issue": "No audit trail for AI risk event tracking",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "C3",
            "check_name": "AI risk management framework",
            "problem_statement": "Structured approach needed for continuous AI risk assessment and treatment",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Implement Config rules for compliance monitoring and CloudTrail for audit tracking",
            "additional_info": {
                "total_scanned": max(
                    len(resources_affected), len(compliance_rules) + len(trails)
                ),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Enable AWS Config with compliance rules",
                "2. Activate CloudTrail for audit logging",
                "3. Set up continuous compliance monitoring",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI risk management framework: {e}")
        return None


def check_resources(session):
    # [D1]
    print("Checking resources configuration")

    service_quotas = session.client("service-quotas")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check technical resources (service limits for AI services)
        try:
            sagemaker_limits = service_quotas.list_service_quotas(
                ServiceCode="sagemaker"
            ).get("Quotas", [])
            active_limits = [q for q in sagemaker_limits if q.get("Value", 0) > 0]
        except:
            active_limits = []

        if len(active_limits) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "ServiceQuotas",
                    "resource_id_type": "Service",
                    "issue": "No service quotas configured for AI technical resources",
                    "region": service_quotas.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "D1",
            "check_name": "Resources",
            "problem_statement": "Adequate technical resources must be allocated for AI operations",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure appropriate service quotas for AI technical capacity",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(active_limits)),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review AI service quotas in Service Quotas console",
                "2. Request quota increases for anticipated AI workloads",
                "3. Monitor resource utilization against limits",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking resources: {e}")
        return None


def check_competence(session):
    # [D2]
    print("Checking competence configuration")

    return {
        "id": "D2",
        "check_name": "Competence",
        "problem_statement": "Not available - This requires training and qualification assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires staff competency evaluation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_awareness(session):
    # [D3]
    print("Checking awareness configuration")

    return {
        "id": "D3",
        "check_name": "Awareness",
        "problem_statement": "Not available - This requires awareness program assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires awareness training evaluation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_communication(session):
    # [D4]
    print("Checking communication configuration")

    return {
        "id": "D4",
        "check_name": "Communication",
        "problem_statement": "Not available - This requires communication process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires organizational communication procedures evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


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
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudTrail",
                    "resource_id_type": "Service",
                    "issue": "No active CloudTrail logging for audit trail",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "D5",
            "check_name": "Documented Information",
            "problem_statement": "All activities should be logged for traceability and audit",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable CloudTrail logging for audit trails",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(trails)),
                "affected": len(resources_affected),
            },
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

        ai_roles = [
            role
            for role in roles
            if any(
                service in role.get("AssumeRolePolicyDocument", "")
                for service in ["sagemaker", "bedrock", "comprehend"]
            )
        ]

        if len(ai_roles) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "IAM",
                    "resource_id_type": "Service",
                    "issue": "No dedicated IAM roles for AI services",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "E1",
            "check_name": "Operational Planning and Control",
            "problem_statement": "AI operations should have dedicated roles and access controls",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create dedicated IAM roles for AI services",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(roles)),
                "affected": len(resources_affected),
            },
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
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "BucketName",
                        "issue": "S3 bucket missing encryption or versioning",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        return {
            "id": "E2",
            "check_name": "Data Management",
            "problem_statement": "Data should be securely stored with encryption and versioning",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable encryption and versioning for all S3 buckets",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(buckets)),
                "affected": len(resources_affected),
            },
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


def check_ai_system_design_development(session):
    # [E3]
    print("Checking AI system design and development configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            notebooks = sagemaker.list_notebook_instances().get("NotebookInstances", [])
            secure_notebooks = [
                nb for nb in notebooks if nb.get("DirectInternetAccess") == "Disabled"
            ]
        except:
            notebooks = []
            secure_notebooks = []

        if len(notebooks) > 0 and len(secure_notebooks) < len(notebooks):
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "SageMaker",
                    "resource_id_type": "Service",
                    "issue": "SageMaker notebooks allow direct internet access",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "E3",
            "check_name": "AI system design and development",
            "problem_statement": "AI development should integrate security considerations",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Disable direct internet access for SageMaker notebooks",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(notebooks)),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Navigate to SageMaker service in AWS Console",
                "2. Select notebook instances",
                "3. Disable direct internet access",
                "4. Use VPC endpoints for secure access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI system design development: {e}")
        return None


def check_ai_system_verification_validation(session):
    # [E4]
    print("Checking AI system verification and validation configuration")

    return {
        "id": "E4",
        "check_name": "AI system verification and validation",
        "problem_statement": "Not available - This requires testing framework assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires AI testing and validation processes"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_deployment_release_management(session):
    # [E5]
    print("Checking deployment and release management configuration")

    return {
        "id": "E5",
        "check_name": "Deployment and Release Management",
        "problem_statement": "Not available - This requires deployment process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires deployment and release management procedures evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_monitoring_feedback(session):
    # [E6]
    print("Checking monitoring and feedback configuration")

    cloudwatch = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])

        sagemaker_alarms = [
            alarm for alarm in alarms if "SageMaker" in alarm.get("Namespace", "")
        ]

        if len(sagemaker_alarms) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudWatch",
                    "resource_id_type": "Service",
                    "issue": "No SageMaker monitoring alarms configured",
                    "region": cloudwatch.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "E6",
            "check_name": "Monitoring and Feedback",
            "problem_statement": "AI systems should have continuous monitoring and alerting",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure CloudWatch alarms for AI services",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(alarms)),
                "affected": len(resources_affected),
            },
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


def check_change_management(session):
    # [E7]
    print("Checking change management configuration")

    return {
        "id": "E7",
        "check_name": "Change Management",
        "problem_statement": "Not available - This requires change management process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires change control procedures evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_incident_management(session):
    # [E8]
    print("Checking incident management configuration")

    return {
        "id": "E8",
        "check_name": "Incident Management",
        "problem_statement": "Not available - This requires incident management process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires incident response procedures evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_monitoring_measurement_analysis_evaluation(session):
    # [F1]
    print("Checking monitoring measurement analysis evaluation configuration")

    cloudwatch = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            metrics = cloudwatch.list_metrics(Namespace="AWS/SageMaker").get(
                "Metrics", []
            )
        except:
            metrics = []

        if len(metrics) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudWatch",
                    "resource_id_type": "Service",
                    "issue": "No SageMaker metrics being collected",
                    "region": cloudwatch.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "F1",
            "check_name": "Monitoring, measurement, analysis, and evaluation",
            "problem_statement": "AI systems should have comprehensive monitoring and metrics",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable comprehensive CloudWatch monitoring for AI services",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(metrics)),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Navigate to CloudWatch service in AWS Console",
                "2. Enable detailed monitoring for SageMaker",
                "3. Create custom metrics for AI performance",
                "4. Set up regular analysis and reporting",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking monitoring measurement analysis evaluation: {e}")
        return None


def check_internal_audit(session):
    # [F2]
    print("Checking internal audit configuration")

    return {
        "id": "F2",
        "check_name": "Internal audit",
        "problem_statement": "Not available - This requires audit process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires internal audit procedures"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_management_review(session):
    # [F3]
    print("Checking management review configuration")

    return {
        "id": "F3",
        "check_name": "Management review",
        "problem_statement": "Not available - This requires management review process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires management review procedures"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_nonconformity_corrective_action(session):
    # [G1]
    print("Checking nonconformity and corrective action configuration")

    return {
        "id": "G1",
        "check_name": "Nonconformity and corrective action",
        "problem_statement": "Not available - This requires nonconformity management process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires corrective action procedures evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_continuous_improvement(session):
    # [G2]
    print("Checking continuous improvement configuration")

    return {
        "id": "G2",
        "check_name": "Continuous improvement",
        "problem_statement": "Not available - This requires improvement process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires continuous improvement processes"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_transparency_explainability(session):
    # [H1]
    print("Checking transparency and explainability configuration")

    return {
        "id": "H1",
        "check_name": "Transparency and explainability",
        "problem_statement": "Not available - This requires AI explainability assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires AI model explainability evaluation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_fairness_non_discrimination(session):
    # [H2]
    print("Checking fairness and non-discrimination configuration")

    return {
        "id": "H2",
        "check_name": "Fairness and non-discrimination",
        "problem_statement": "Not available - This requires bias assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires AI bias and fairness evaluation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_human_oversight(session):
    # [H3]
    print("Checking human oversight configuration")

    return {
        "id": "H3",
        "check_name": "Human oversight",
        "problem_statement": "Not available - This requires human oversight assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {"note": "This requires human control evaluation"},
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_accountability(session):
    # [H4]
    print("Checking accountability configuration")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = cloudtrail.describe_trails().get("trailList", [])

        data_events_trails = []
        for trail in trails:
            try:
                event_selectors = cloudtrail.get_event_selectors(
                    TrailName=trail["Name"]
                )
                if event_selectors.get("EventSelectors"):
                    data_events_trails.append(trail)
            except:
                continue

        if len(data_events_trails) == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "CloudTrail",
                    "resource_id_type": "Service",
                    "issue": "No data event logging for accountability",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "H4",
            "check_name": "Accountability",
            "problem_statement": "AI decisions should have audit trails for accountability",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable CloudTrail data events for AI accountability",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(trails)),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Navigate to CloudTrail service in AWS Console",
                "2. Configure data events logging",
                "3. Enable S3 and Lambda data events",
                "4. Set up log analysis for accountability",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking accountability: {e}")
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
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": sg_id,
                                "resource_id_type": "SecurityGroupId",
                                "issue": "Security group allows unrestricted access",
                                "region": ec2.meta.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
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
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(security_groups)),
                "affected": len(resources_affected),
            },
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


def check_data_model_governance(session):
    # [H6]
    print("Checking data and model governance configuration")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            model_packages = sagemaker.list_model_packages().get(
                "ModelPackageSummaryList", []
            )
        except:
            model_packages = []

        models = sagemaker.list_models().get("Models", [])

        if len(model_packages) == 0 and len(models) > 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "ModelRegistry",
                    "resource_id_type": "Service",
                    "issue": "Models exist but no model registry usage detected",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return {
            "id": "H6",
            "check_name": "Data and Model Governance",
            "problem_statement": "Models should be version-controlled and registered",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Use SageMaker Model Registry for model governance",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(models)),
                "affected": len(resources_affected),
            },
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
                block_public_acls = public_access.get(
                    "PublicAccessBlockConfiguration", {}
                ).get("BlockPublicAcls", False)
            except:
                block_public_acls = False

            if not block_public_acls:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_id_type": "BucketName",
                        "issue": "S3 bucket allows public access",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        return {
            "id": "H7",
            "check_name": "Privacy and Data Protection",
            "problem_statement": "Data should be protected from unauthorized public access",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Block public access for all S3 buckets",
            "additional_info": {
                "total_scanned": max(len(resources_affected), len(buckets)),
                "affected": len(resources_affected),
            },
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


def check_societal_environmental_impact(session):
    # [H8]
    print("Checking societal and environmental impact configuration")

    return {
        "id": "H8",
        "check_name": "Societal and environmental impact",
        "problem_statement": "Not available - This requires impact assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires societal and environmental impact evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_lifecycle_management(session):
    # [H9]
    print("Checking lifecycle management configuration")

    return {
        "id": "H9",
        "check_name": "Lifecycle management",
        "problem_statement": "Not available - This requires lifecycle management process assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires asset lifecycle procedures evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_external_stakeholder_engagement(session):
    # [H10]
    print("Checking external stakeholder engagement configuration")

    return {
        "id": "H10",
        "check_name": "External stakeholder engagement",
        "problem_statement": "Not available - This requires stakeholder engagement assessment",
        "severity_score": 0,
        "severity_level": "Info",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": "Not available for AWS infrastructure checks",
        "additional_info": {
            "note": "This requires external stakeholder engagement evaluation"
        },
        "remediation_steps": ["Not applicable for AWS infrastructure"],
        "last_updated": datetime.now(IST).isoformat(),
    }
