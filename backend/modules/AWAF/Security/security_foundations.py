from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_sec01_bp01_iam_has_organization(session):
    # [BP01] - Separate workloads using accounts
    print("Checking if account is part of an AWS Organization")

    org = session.client("organizations")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_multi_accounts.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP01",
            "check_name": "Separate workloads using accounts (AWS Organizations)",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Use AWS Organizations to manage multiple accounts.",
                "2. Create separate accounts for production, development, testing.",
                "3. Apply Service Control Policies (SCPs).",
                "4. Use AWS Control Tower for governance.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        try:
            org_data = org.describe_organization()["Organization"]

            return build_response(
                status="passed",
                problem=(
                    "Workloads should be isolated across multiple AWS accounts "
                    "using AWS Organizations for strong security boundaries."
                ),
                recommendation="Continue managing accounts under AWS Organizations.",
                resources_affected=[],
                affected=0,
                total_scanned=1,
            )

        except org.exceptions.AWSOrganizationsNotInUseException:
            # Not part of any organization
            resources = [
                {
                    "issue": "This account is not part of an AWS Organization.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            ]

            return build_response(
                status="failed",
                problem=(
                    "AWS Organizations is not enabled. A multi-account strategy "
                    "improves isolation, governance, and security."
                ),
                recommendation="Enable AWS Organizations and adopt a multi-account structure.",
                resources_affected=resources,
                affected=1,
                total_scanned=1,
            )
    except Exception as e:
        print(f"Error checking AWS Organization membership: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred during the AWS Organizations check.",
            recommendation="Use AWS Organizations to maintain proper multi-account governance.",
        )


def check_sec01_bp02_iam_root_user_security(session):
    # [BP02] - Secure account root user and properties
    print("Checking security configuration for AWS root user")

    iam = session.client("iam")

    guardduty = session.client("guardduty")
    account = session.client("account")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_aws_account.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP02",
            "check_name": "Secure account root user and properties",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable MFA for the root user.",
                "2. Delete any existing root access keys.",
                "3. Configure an IAM account password policy.",
                "4. Enable GuardDuty for all regions.",
                "5. Add security alternate contact under Account Settings.",
                "6. Avoid root logins; use IAM roles instead.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        # Check 1 — Root MFA Enabled      
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            print("summary: ", summary)
            mfa_enabled = summary.get("AccountMFAEnabled", 0)

            if mfa_enabled == 0:
                resources_affected.append({
                    "resource_id": "root",
                    "issue": "Root account does not have MFA enabled.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print("Error checking MFA:", e)

        
        # Check 2 — Root Access Keys
        
        try:
            root_keys_present = summary.get("AccountAccessKeysPresent", 0)

            if root_keys_present > 0:
                resources_affected.append({
                    "resource_id": "root",
                    "issue": "Root account has active access keys — must be removed.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            print("Error checking root access keys:", e)

        
        # Check 3 — IAM Password Policy Exists
        
        try:
            iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntityException:
            resources_affected.append({
                "resource_id": "account_password_policy",
                "issue": "IAM password policy is not configured.",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        
        # Check 4 — GuardDuty Enabled
        
        try:
            detectors = guardduty.list_detectors()["DetectorIds"]
            if not detectors:
                resources_affected.append({
                    "resource_id": "guardduty",
                    "issue": "Amazon GuardDuty is not enabled in this AWS account.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            resources_affected.append({
                "resource_id": "guardduty",
                "issue": f"Unable to check GuardDuty status: {str(e)}",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        
        # Check 5 — Alternate Contact
        
        try:
            account.get_alternate_contact(AlternateContactType="SECURITY")
        except account.exceptions.ResourceNotFoundException:
            resources_affected.append({
                "resource_id": "alternate_contact",
                "issue": "Security alternate contact is not configured.",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        
        total_scanned = 5
        affected = len(resources_affected)
        
        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "The AWS root user has unrestricted permissions. It should be secured with MFA, "
                "no access keys, a strong password policy, configured alternate contacts, "
                "and GuardDuty enabled."
            ),
            recommendation=(
                "Secure the root user by enabling MFA, removing access keys, enforcing password policy, "
                "enabling GuardDuty, and ensuring alternate contact info is configured."
            ),
            resources_affected=resources_affected,
            affected=affected,
            total_scanned=total_scanned,
        )
    except Exception as e:
        print(f"Error checking root user security: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred during the root user security check.",
            recommendation="Secure the AWS root user by applying recommended best practices.",
        )


def check_sec01_bp03_iam_control_objectives(session):
    # [BP03] - Identify and validate control objectives
    print("Checking if Service Control Policies (SCPs) and AWS Config are enabled")

    org = session.client("organizations")
    config = session.client("config")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_control_objectives.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP03",
            "check_name": "Identify and validate control objectives (SCP & Config)",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable 'All features' in AWS Organizations to activate SCPs.",
                "2. Create and attach SCPs to organizational units (OUs).",
                "3. Enable AWS Config in all regions.",
                "4. Ensure configuration recorder is enabled.",
                "5. Apply AWS Config rules or conformance packs for compliance validation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        # ------------------ Check 1: SCPs Enabled ------------------
        try:
            org_data = org.describe_organization()["Organization"]
            feature_set = org_data.get("FeatureSet")

            if feature_set != "ALL":
                resources_affected.append(
                    {
                        "resource_id": org_data.get("Id"),
                        "issue": "Service Control Policies (SCPs) are not fully enabled in AWS Organizations.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except org.exceptions.AWSOrganizationsNotInUseException:
            resources_affected.append(
                {
                    "resource_id": "organization",
                    "issue": "AWS Organizations not in use — SCPs cannot be applied.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Check 2: AWS Config Service Enabled ------------------
        try:
            recorders = config.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )
            if not recorders:
                resources_affected.append(
                    {
                        "resource_id": "aws_config",
                        "issue": "AWS Config is not enabled to record configuration changes.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error checking AWS Config service: {e}")
            resources_affected.append(
                {
                    "resource_id": "aws_config",
                    "issue": "Unable to verify AWS Config service status.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 2
        affected = len(resources_affected)

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Control objectives must be validated using SCPs and AWS Config. "
                "These provide continuous compliance enforcement and monitoring."
            ),
            recommendation=(
                "Enable SCPs under AWS Organizations and ensure AWS Config is enabled "
                "to record configuration changes across all regions."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking control objectives: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while checking SCP and AWS Config status.",
            recommendation="Ensure AWS Organizations and AWS Config are properly configured to enforce control objectives.",
        )


def check_sec01_bp04_iam_guardduty_enabled(session):
    # [BP04] - Stay up to date with security threats and recommendations
    print("Checking if Amazon GuardDuty is enabled")

    guardduty = session.client("guardduty")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_updated_threats.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP04",
            "check_name": "Stay up to date with security threats and recommendations (GuardDuty)",
            "problem_statement": problem,
            "severity_score": 65,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Open the Amazon GuardDuty console.",
                "2. Enable GuardDuty for this AWS account.",
                "3. Enable GuardDuty in all active regions.",
                "4. (Recommended) Enable GuardDuty at the organization level using delegated admin.",
                "5. Periodically review findings and automate responses using Security Hub or EventBridge.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        # ------------------ Check: GuardDuty Detectors ------------------
        try:
            detectors = guardduty.list_detectors().get("DetectorIds", [])
            if not detectors:
                resources_affected.append(
                    {
                        "resource_id": "guardduty",
                        "issue": "Amazon GuardDuty is not enabled in this account.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error listing GuardDuty detectors: {e}")
            resources_affected.append(
                {
                    "resource_id": "guardduty",
                    "issue": "Unable to verify GuardDuty status. Check permissions or service availability.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Amazon GuardDuty provides continuous threat detection across your AWS environment. "
                "Without GuardDuty enabled, critical security threats may go unnoticed."
            ),
            recommendation=(
                "Enable Amazon GuardDuty across all AWS regions to detect, analyze, and alert on "
                "suspicious or malicious activity using AWS threat intelligence."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking GuardDuty status: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while checking GuardDuty status.",
            recommendation="Ensure GuardDuty service is accessible and try again.",
        )


def check_sec01_bp05_reduce_security_management_scope(session):
    # [BP05] - Reduce security management scope
    print("Evaluating reduction of security management scope (strategic assessment)")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_reduce_management_scope.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP05",
            "check_name": "Reduce security management scope",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Review workloads currently hosted on self-managed services such as EC2.",
                "2. Identify opportunities to migrate to AWS managed services.",
                "3. Consider services such as RDS, ECS, EKS, or Lambda.",
                "4. Align migration decisions with compliance and operational requirements.",
                "5. Periodically reassess workloads as AWS introduces new managed capabilities.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0
    try:
        return build_response(
            status="not_available",
            problem=(
                "This best practice focuses on strategic adoption of AWS managed services to reduce the "
                "security management scope"
            ),
            recommendation=(
                "Review workloads and migrate applicable components to AWS managed services like RDS, ECS, "
                "EKS, or Lambda to reduce security operations overhead."
            ),
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error evaluating BP05: {e}")
        return build_response(
            status="error",
            problem="Unable to assess security management scope.",
            recommendation="Retry this assessment and verify environment details.",
        )


def check_sec01_bp06_automate_security_controls(session):
    # [BP06] - Automate deployment of standard security controls
    print(
        "Checking usage of AWS managed services to evaluate automation of security control deployments"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_automate_security_controls.html"

    lambda_client = session.client("lambda")
    rds = session.client("rds")
    eks = session.client("eks")
    dynamodb = session.client("dynamodb")
    elasticache = session.client("elasticache")

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP06",
            "check_name": "Automate deployment of standard security controls",
            "problem_statement": problem,
            "severity_score": 55,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Use IaC tools such as AWS CloudFormation, Terraform, or CDK.",
                "2. Prefer managed services like Lambda, RDS, EKS, DynamoDB, and ElastiCache.",
                "3. Enable automated deployments via CodePipeline and CodeBuild.",
                "4. Validate templates using CloudFormation Guard.",
                "5. Maintain version control and automated rollback pipelines.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        # ------------------ Count resources across managed services ------------------
        lambda_functions = lambda_client.list_functions().get("Functions", [])
        rds_instances = rds.describe_db_instances().get("DBInstances", [])
        eks_clusters = eks.list_clusters().get("clusters", [])
        dynamodb_tables = dynamodb.list_tables().get("TableNames", [])
        elasticache_clusters = elasticache.describe_cache_clusters().get(
            "CacheClusters", []
        )

        total_resources = (
            len(lambda_functions)
            + len(rds_instances)
            + len(eks_clusters)
            + len(dynamodb_tables)
            + len(elasticache_clusters)
        )

        total_scanned = 1
        affected = 0 if total_resources > 0 else 1

        if total_resources == 0:
            resources_affected.append(
                {
                    "resource_id": "all",
                    "issue": "No managed services (Lambda, RDS, EKS, DynamoDB, ElastiCache) found — "
                    "infrastructure may not be automated or standardized.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Evaluate adoption of managed services and automation mechanisms to enforce standardized security controls."
            ),
            recommendation=(
                "Increase automation and standardize deployments using IaC and AWS managed services "
                "like Lambda, RDS, EKS, DynamoDB, and ElastiCache."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking automation of security controls: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate automation of security controls.",
            recommendation="Adopt IaC and AWS managed services to automate deployment of standard security controls.",
        )


def check_sec01_bp07_identify_threats_and_mitigations(session):
    # [BP07] - Identify threats and prioritize mitigations using a threat model
    print(
        "Checking if account is part of AWS Organization to support centralized threat modeling"
    )

    org = session.client("organizations")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_threat_model.html"
    resources_affected = []
    try:
        account_id = sts.get_caller_identity()["Account"]
    except:
        account_id = "unknown"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP07",
            "check_name": "Identify threats and prioritize mitigations using a threat model",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Define and maintain a threat model using frameworks like STRIDE or OWASP.",
                "2. Use AWS Organizations for centralized visibility and governance.",
                "3. Integrate services such as Security Hub, GuardDuty, and Config to detect threats.",
                "4. Update threat models after workload or architecture changes.",
                "5. Track threats, likelihood, impact, and mitigation status for audits.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        # ------------------ Check: Account part of AWS Organization ------------------
        try:
            org_data = org.describe_organization()["Organization"]

            total_scanned = 1
            affected = 0

            return build_response(
                status="passed",
                problem=(
                    "A structured and centrally governed threat model helps identify and mitigate evolving security risks."
                ),
                recommendation=(
                    "Maintain an up-to-date threat model and use AWS Organizations to coordinate controls across accounts."
                ),
                resources_affected=resources_affected,
                total_scanned=total_scanned,
                affected=affected,
            )

        except org.exceptions.AWSOrganizationsNotInUseException:
            # Not part of any organization
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "This account is not part of an AWS Organization, limiting centralized visibility and governance for threat modeling.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

            total_scanned = 1
            affected = 1

            return build_response(
                status="failed",
                problem=(
                    "Centralized governance is required to effectively identify threats and prioritize mitigations across workloads."
                ),
                recommendation=(
                    "Join or create an AWS Organization to centralize threat modeling and coordination of mitigations."
                ),
                resources_affected=resources_affected,
                total_scanned=total_scanned,
                affected=affected,
            )

    except Exception as e:
        print(f"Error checking AWS Organization membership for threat modeling: {e}")
        return build_response(
            status="error",
            problem="Threat modeling readiness could not be evaluated.",
            recommendation="Establish a structured threat modeling process to identify and mitigate security risks.",
        )


def check_sec01_bp08_evaluate_new_security_features(session):
    # [BP08] - Evaluate and implement new security services and features regularly
    print("Evaluating process for adopting new AWS security services and features")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_securely_operate_implement_services_features.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC01-BP08",
            "check_name": "Evaluate and implement new security services and features regularly",
            "problem_statement": problem,
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Subscribe to AWS Security Blog and AWS What's New announcements.",
                "2. Monitor AWS Security Bulletins and relevant SNS topics.",
                "3. Attend AWS re:Inforce, re:Invent and security-focused webinars.",
                "4. Periodically review new AWS and Partner security services.",
                "5. Work with AWS account teams to evaluate relevant new capabilities.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        return build_response(
            status="not_available",
            problem="New security feature adoption cannot be validated through AWS APIs.",
            recommendation="Establish a periodic review process to evaluate new AWS and Partner security features.",
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error evaluating BP08: {e}")
        return build_response(
            status="error",
            problem="Unable to assess adoption of new security features.",
            recommendation="Implement a structured process to stay updated on AWS security enhancements.",
        )
