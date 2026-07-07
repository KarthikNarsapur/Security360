"""
ISO 42001 Extended Checks — Miscellaneous (AI-063, AI-064, AI-066, AI-067, AI-080 to AI-083)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_config_rules_compliance(session):
    """AI-063: Compliance status of Config rules"""
    print("Checking compliance status of Config rules")

    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            compliance = config.describe_compliance_by_config_rule().get("ComplianceByConfigRules", [])
        except Exception:
            compliance = []

        total_scanned = len(compliance)
        for rule in compliance:
            rule_name = rule.get("ConfigRuleName", "")
            status = rule.get("Compliance", {}).get("ComplianceType", "")
            if status == "NON_COMPLIANT":
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": rule_name,
                    "resource_id_type": "ConfigRule",
                    "issue": f"Config rule '{rule_name}' is NON_COMPLIANT",
                    "region": config.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-063",
            "check_name": "Compliance status of Config rules",
            "problem_statement": "AWS Config rules should be in compliant state for AI governance",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Remediate non-compliant Config rules to maintain security posture",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Review non-compliant Config rules",
                "2. Identify affected resources",
                "3. Remediate configuration issues",
                "4. Re-evaluate rules after remediation",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Config rules compliance: {e}")
        return None


def check_conformance_pack_compliance(session):
    """AI-064: Conformance Pack compliance"""
    print("Checking Conformance Pack compliance")

    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            packs = config.describe_conformance_pack_status().get("ConformancePackStatusDetails", [])
        except Exception:
            packs = []

        if not packs:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "ConformancePacks",
                "resource_id_type": "Service",
                "issue": "No conformance packs configured for compliance assessment",
                "region": config.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            for pack in packs:
                pack_name = pack.get("ConformancePackName", "")
                status = pack.get("ConformancePackState", "")
                if status != "CREATE_COMPLETE":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": pack_name,
                        "resource_id_type": "ConformancePack",
                        "issue": f"Conformance pack '{pack_name}' status: {status}",
                        "region": config.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-064",
            "check_name": "Conformance Pack compliance",
            "problem_statement": "Conformance packs should be deployed for automated compliance assessment",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Deploy conformance packs for AI-related compliance frameworks",
            "additional_info": {"total_scanned": max(len(packs), 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Deploy operational best practices conformance packs",
                "2. Create custom packs for AI governance rules",
                "3. Monitor pack compliance status",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking conformance packs: {e}")
        return None


def check_backup_vault_encryption(session):
    """AI-066: Backup vault encryption"""
    print("Checking backup vault encryption")

    backup = session.client("backup")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        except Exception:
            vaults = []

        for vault in vaults:
            vault_name = vault.get("BackupVaultName", "")
            encryption_key = vault.get("EncryptionKeyArn", "")
            if not encryption_key or "alias/aws/backup" in encryption_key.lower():
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": vault_name,
                    "resource_id_type": "BackupVault",
                    "issue": f"Backup vault '{vault_name}' uses AWS-managed key instead of customer-managed KMS",
                    "region": backup.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-066",
            "check_name": "Backup vault encryption",
            "problem_statement": "Backup vaults should use customer-managed KMS keys for AI data protection",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Use customer-managed KMS keys for backup vault encryption",
            "additional_info": {"total_scanned": max(len(vaults), 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Create a customer-managed KMS key for backups",
                "2. Create new backup vault with CMK",
                "3. Migrate backup plans to new vault",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking backup vault encryption: {e}")
        return None


def check_protected_ai_resources(session):
    """AI-067: Protected AI resources"""
    print("Checking protected AI resources in Backup")

    backup = session.client("backup")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            protected = backup.list_protected_resources().get("Results", [])
        except Exception:
            protected = []

        # Check if any SageMaker/AI resources are protected
        ai_resource_types = ["EBS", "S3", "DynamoDB", "EFS"]
        protected_arns = [r.get("ResourceArn", "") for r in protected]

        # Check SageMaker related resources
        sagemaker = session.client("sagemaker")
        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
            notebooks = sagemaker.list_notebook_instances().get("NotebookInstances", [])
            ai_resources_exist = len(endpoints) > 0 or len(notebooks) > 0
        except Exception:
            ai_resources_exist = False

        if ai_resources_exist and not protected:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AWSBackup",
                "resource_id_type": "Service",
                "issue": "AI resources exist but no resources are protected by AWS Backup",
                "region": backup.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-067",
            "check_name": "Protected AI resources",
            "problem_statement": "AI-related resources (S3 data, EBS volumes) should be protected by backup plans",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Add AI resources to backup plans for disaster recovery",
            "additional_info": {"total_scanned": 1, "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Identify S3 buckets and EBS volumes used by AI workloads",
                "2. Create backup plans covering these resources",
                "3. Configure appropriate retention periods",
                "4. Test restore procedures regularly",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking protected AI resources: {e}")
        return None


def check_unused_ai_resources(session):
    """AI-080: Unused AI resources"""
    print("Checking unused AI resources")

    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        total_scanned = 0

        # Check for stopped notebook instances
        try:
            notebooks = sagemaker.list_notebook_instances().get("NotebookInstances", [])
            for nb in notebooks:
                total_scanned += 1
                if nb.get("NotebookInstanceStatus") == "Stopped":
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": nb["NotebookInstanceName"],
                        "resource_id_type": "SageMakerNotebook",
                        "issue": f"Notebook '{nb['NotebookInstanceName']}' is stopped — potential unused resource",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
        except Exception:
            pass

        # Check for endpoints with no recent invocations (OutOfService)
        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
            for ep in endpoints:
                total_scanned += 1
                if ep.get("EndpointStatus") in ("OutOfService", "Failed"):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": ep["EndpointName"],
                        "resource_id_type": "SageMakerEndpoint",
                        "issue": f"Endpoint '{ep['EndpointName']}' status: {ep.get('EndpointStatus', '')} — likely unused",
                        "region": sagemaker.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
        except Exception:
            pass

        return {
            "id": "AI-080",
            "check_name": "Unused AI resources",
            "problem_statement": "Unused AI resources waste costs and increase attack surface",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Remove or terminate unused AI resources to reduce costs and attack surface",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Identify stopped notebooks and failed endpoints",
                "2. Confirm resources are no longer needed",
                "3. Delete unused resources",
                "4. Set up auto-shutdown policies for notebooks",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking unused AI resources: {e}")
        return None


def check_ai_resources_unsupported_regions(session):
    """AI-081: AI resources in unsupported Regions"""
    print("Checking AI resources in unsupported regions")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        current_region = session.region_name

        # Regions where AI services are well-supported
        supported_ai_regions = [
            "us-east-1", "us-east-2", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            "ap-south-1",
        ]

        sagemaker = session.client("sagemaker")
        total_scanned = 0

        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
            notebooks = sagemaker.list_notebook_instances().get("NotebookInstances", [])
            total_scanned = len(endpoints) + len(notebooks)

            if (len(endpoints) > 0 or len(notebooks) > 0) and current_region not in supported_ai_regions:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": current_region,
                    "resource_id_type": "Region",
                    "issue": f"AI resources found in region '{current_region}' which may have limited AI service support",
                    "region": current_region,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            pass

        return {
            "id": "AI-081",
            "check_name": "AI resources in unsupported Regions",
            "problem_statement": "AI resources should be deployed in regions with full AI service support",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Deploy AI resources in regions with comprehensive AI/ML service availability",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Review AI resource placement across regions",
                "2. Consolidate in regions with full AI service support",
                "3. Consider data residency requirements",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI resources unsupported regions: {e}")
        return None


def check_service_quota_utilization(session):
    """AI-082: Service quota utilization"""
    print("Checking service quota utilization")

    sq = session.client("service-quotas")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        ai_services = ["sagemaker", "bedrock"]
        total_scanned = 0

        for service_code in ai_services:
            try:
                quotas = sq.list_service_quotas(ServiceCode=service_code).get("Quotas", [])
                for quota in quotas:
                    total_scanned += 1
                    quota_name = quota.get("QuotaName", "")
                    value = quota.get("Value", 0)
                    # Check if quota is very low (might limit AI operations)
                    if value is not None and value == 0:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": f"{service_code}/{quota_name}",
                            "resource_id_type": "ServiceQuota",
                            "issue": f"Service quota '{quota_name}' for {service_code} is set to 0",
                            "region": sq.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
            except Exception:
                continue

        return {
            "id": "AI-082",
            "check_name": "Service quota utilization",
            "problem_statement": "AI service quotas should be reviewed to prevent operational limitations",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Review and request increases for AI service quotas before hitting limits",
            "additional_info": {"total_scanned": max(total_scanned, 1), "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Review current quotas for SageMaker and Bedrock",
                "2. Request quota increases before reaching limits",
                "3. Set up CloudWatch alarms for quota utilization",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking service quota utilization: {e}")
        return None


def check_trusted_advisor_ai_checks(session):
    """AI-083: Trusted Advisor AI-related checks"""
    print("Checking Trusted Advisor AI-related checks")

    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            support = session.client("support", region_name="us-east-1")
            checks = support.describe_trusted_advisor_checks(language="en").get("checks", [])

            ai_keywords = ["sagemaker", "bedrock", "machine learning", "ai", "ml"]
            ai_checks = [
                c for c in checks
                if any(kw in c.get("name", "").lower() or kw in c.get("description", "").lower()
                       for kw in ai_keywords)
            ]

            for check in ai_checks:
                check_id = check.get("id", "")
                try:
                    result = support.describe_trusted_advisor_check_result(checkId=check_id).get("result", {})
                    status = result.get("status", "")
                    if status in ("warning", "error"):
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": check.get("name", check_id),
                            "resource_id_type": "TrustedAdvisorCheck",
                            "issue": f"Trusted Advisor AI check '{check.get('name', '')}' status: {status}",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue

        except Exception:
            # Support API requires Business/Enterprise support plan
            pass

        return {
            "id": "AI-083",
            "check_name": "Trusted Advisor AI-related checks",
            "problem_statement": "Trusted Advisor recommendations for AI services should be addressed",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Review and act on Trusted Advisor recommendations for AI services",
            "additional_info": {"total_scanned": 1, "affected": len(resources_affected)},
            "remediation_steps": [
                "1. Open Trusted Advisor in AWS Console",
                "2. Review AI/ML related recommendations",
                "3. Implement suggested optimizations",
                "4. Note: Requires Business or Enterprise Support plan",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking Trusted Advisor AI checks: {e}")
        return None
