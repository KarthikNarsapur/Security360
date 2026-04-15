from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_ops01_bp01_evaluate_external_customer_needs(session):
    print("OPS01-BP01 focuses on evaluating external customer needs.")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_priorities_ext_cust_needs.html"

    return {
        "id": "OPS01-BP01",
        "check_name": "Evaluate external customer needs",
        "problem_statement": (
            "Organizations must engage stakeholders across business, development, and operations "
            "to understand external customer needs and align operational practices with desired outcomes."
        ),
        "severity_score": 40,
        "severity_level": "Low",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Engage business, development, and operations teams regularly, gather customer feedback, "
            "and ensure operational processes support customer-focused objectives."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Establish mechanisms to collect and analyze customer feedback.",
            "2. Involve key stakeholders in operational planning and reviews.",
            "3. Align operational activities directly with customer outcomes.",
            "4. Re-evaluate feature and support decisions using customer data and experimentation.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops01_bp02_evaluate_internal_customer_needs(session):
    print("OPS01-BP02 focuses on evaluating internal customer needs.")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_priorities_int_cust_needs.html"

    return {
        "id": "OPS01-BP02",
        "check_name": "Evaluate internal customer needs",
        "problem_statement": (
            "Internal stakeholders, such as product teams, developers, and operations, must be included "
            "when determining internal customer needs to ensure operational support aligns with business outcomes."
        ),
        "severity_score": 60,
        "severity_level": "High",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Engage internal stakeholders regularly to understand their needs, validate changes, and prioritize "
            "operational improvements that support business goals."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Establish feedback loops with internal teams (dev, ops, product, support).",
            "2. Review and update internal priorities as business and team needs evolve.",
            "3. Validate planned operational changes with internal customers before implementation.",
            "4. Use internal customer data to prioritize improvements such as automation, cost reduction, "
            "performance tuning, and monitoring enhancements.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops01_bp03_evaluate_governance_requirements(session):
    print("Checking governance requirements for OPS01-BP03")

    config = session.client("config")
    orgs = session.client("organizations")
    sts = session.client("sts")

    # Control Tower may not exist in the account/region
    try:
        controltower = session.client("controltower")
    except Exception:
        controltower = None

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_priorities_governance_reqs.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # 1. Check AWS Config Conformance Packs

        try:
            conformance_packs = config.describe_conformance_packs().get(
                "ConformancePackDetails", []
            )
            if not conformance_packs:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No AWS Config Conformance Packs found. Governance rules may be missing.",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve Conformance Packs. AWS Config may not be fully configured.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 2. Check AWS Config Recorders

        try:
            recorders = config.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )
            if not recorders:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "AWS Config Recorder is not configured. Governance tracking will be incomplete.",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve Config Recorder information.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 3. Check AWS Organizations Policies (Service Control Policies)

        try:
            policies = orgs.list_policies(Filter="SERVICE_CONTROL_POLICY").get(
                "Policies", []
            )
            if not policies:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No Service Control Policies (SCPs) found. Governance enforcement may be weak.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve SCPs from AWS Organizations.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 4. Check Control Tower Enabled Controls

        if controltower:
            try:
                controls = controltower.list_enabled_controls().get(
                    "enabledControls", []
                )
                if not controls:
                    resources_affected.append(
                        {
                            "resource_id": account_id,
                            "issue": "Control Tower is available but no controls are enabled.",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "Unable to retrieve Control Tower controls. Control Tower may not be set up.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        else:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "AWS Control Tower not available in this environment.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Final result
        affected = len(resources_affected)
        total_scanned = 4

        return {
            "id": "OPS01-BP03",
            "check_name": "Evaluate governance requirements",
            "problem_statement": (
                "Governance mechanisms such as AWS Config, SCPs, and Control Tower must be implemented "
                "to ensure consistent compliance, visibility, and policy enforcement across workloads."
            ),
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Configure governance controls using AWS Config, Conformance Packs, SCPs, and Control Tower "
                "to ensure policies are consistently enforced across all environments."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Configure AWS Config Recorders in all regions.",
                "2. Deploy AWS Config Conformance Packs for compliance baselines.",
                "3. Attach Service Control Policies (SCPs) for mandatory governance rules.",
                "4. Enable AWS Control Tower controls if using Control Tower.",
                "5. Regularly review governance configuration against business requirements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OPS01-BP03: {e}")
        return None


def check_ops01_bp04_evaluate_compliance_requirements(session):
    print("Checking compliance requirements for OPS01-BP04")

    auditmanager = session.client("auditmanager")
    securityhub = session.client("securityhub")

    # AWS Artifact is a global service, may not be in all regions
    try:
        artifact = session.client("artifact")
    except Exception:
        artifact = None

    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_priorities_compliance_reqs.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # 1. Audit Manager – Check assessment frameworks

        try:
            frameworks = auditmanager.list_assessment_frameworks(
                frameworkType="Standard"
            ).get("frameworkMetadataList", [])

            if not frameworks:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No Audit Manager standard frameworks configured. Compliance tracking may be incomplete.",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve Audit Manager frameworks.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 2. AWS Artifact – Check compliance/attestation reports

        if artifact:
            try:
                reports = artifact.list_reports().get("Reports", [])
                if not reports:
                    resources_affected.append(
                        {
                            "resource_id": account_id,
                            "issue": "No AWS Artifact compliance reports found.",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "Unable to retrieve AWS Artifact reports.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        else:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "AWS Artifact service unavailable in this environment.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 3. Security Hub – Check enabled compliance standards

        try:
            standards = securityhub.get_enabled_standards().get(
                "StandardsSubscriptions", []
            )
            if not standards:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No Security Hub standards are enabled. Compliance checks may be missing.",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve enabled Security Hub standards.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Final result

        affected = len(resources_affected)
        total_scanned = 3


        return {
            "id": "OPS01-BP04",
            "check_name": "Evaluate compliance requirements",
            "problem_statement": (
                "Compliance requirements must be regularly evaluated and tracked using Audit Manager, "
                "AWS Artifact, and Security Hub standards to ensure continuous compliance posture."
            ),
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable and configure Audit Manager frameworks, review AWS Artifact compliance reports, "
                "and activate relevant Security Hub compliance standards to maintain compliance visibility."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable and configure AWS Audit Manager assessment frameworks.",
                "2. Download and review relevant AWS Artifact compliance reports.",
                "3. Enable Security Hub and activate required compliance standards (CIS, NIST, PCI, etc.).",
                "4. Map compliance requirements to operational goals.",
                "5. Continuously review and update compliance obligations as regulations change.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OPS01-BP04: {e}")
        return None


def check_ops01_bp05_evaluate_threat_landscape(session):
    print("Checking threat landscape for OPS01-BP05")

    guardduty = session.client("guardduty")
    inspector = session.client("inspector2")
    securityhub = session.client("securityhub")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_priorities_eval_threat_landscape.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        # 1. GuardDuty — Check detectors and findings

        try:
            detectors = guardduty.list_detectors().get("DetectorIds", [])
        except Exception:
            detectors = []

        if not detectors:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "No GuardDuty detector enabled. Threat detection is inactive.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
        else:
            try:
                findings = guardduty.list_findings(DetectorId=detectors[0]).get(
                    "FindingIds", []
                )
                if findings:
                    resources_affected.append(
                        {
                            "resource_id": account_id,
                            "issue": f"{len(findings)} GuardDuty security findings detected.",
                            "region": region,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "Unable to list GuardDuty findings.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # 2. Security Hub — Check threat-related findings

        try:
            sh_findings = securityhub.get_findings(
                Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
            ).get("Findings", [])

            if len(sh_findings) > 0:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": f"{len(sh_findings)} active Security Hub findings identified.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve Security Hub findings.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 3. Inspector2 — Check vulnerabilities

        try:
            inspector_findings = inspector.list_findings(
                filterCriteria={
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
                }
            ).get("findings", [])

            if inspector_findings:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": f"{len(inspector_findings)} Inspector2 vulnerability findings detected.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve Inspector2 findings.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Final evaluation

        affected = len(resources_affected)
        total_scanned = 3


        return {
            "id": "OPS01-BP05",
            "check_name": "Evaluate threat landscape",
            "problem_statement": (
                "Organizations must evaluate GuardDuty, Inspector, and Security Hub findings "
                "to understand the current threat landscape and take action on active threats."
            ),
            "severity_score": 90,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable GuardDuty and Inspector2, review active findings from Security Hub, "
                "and create workflows to triage and respond to threats in a timely manner."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable Amazon GuardDuty and ensure detectors are active in all regions.",
                "2. Enable Amazon Inspector2 for EC2, ECR, and Lambda scanning.",
                "3. Review Security Hub active findings and categorize them by severity.",
                "4. Automate alerting and remediation for recurring threat types.",
                "5. Integrate threat detection tools with incident response playbooks.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OPS01-BP05: {e}")
        return None


def check_ops01_bp06_evaluate_tradeoffs(session):
    # [BP06] - Evaluate tradeoffs while managing benefits and risks
    print("Checking OPS01-BP06: Evaluate tradeoffs while managing benefits and risks")

    support = session.client("support", region_name="us-east-1")
    sts = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_priorities_eval_tradeoffs.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS01-BP06",
            "check_name": "Evaluate tradeoffs while managing benefits and risks",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Review all flagged Trusted Advisor checks.",
                "2. Categorize findings into cost, performance, security, and fault tolerance.",
                "3. Prioritize actions based on risk vs. business value.",
                "4. Implement automation to periodically evaluate TA findings.",
                "5. Integrate TA insights into operational decision-making processes.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        try:
            total_scanned = 1
            account_id = sts.get_caller_identity()["Account"]
            region = session.region_name

            # List Trusted Advisor checks
            try:
                checks = support.describe_trusted_advisor_checks(language="en").get(
                    "checks", []
                )
            except Exception as err:
                resources = [
                    {
                        "resource_id": account_id,
                        "issue": f"Unable to list Trusted Advisor checks: {str(err)}",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                ]

                return build_response(
                    status="failed",
                    problem=(
                        "Trusted Advisor API is not accessible. This likely indicates the AWS account "
                        "does not have a Business or Enterprise support plan."
                    ),
                    recommendation=(
                        "Upgrade your AWS Support plan to Business or Enterprise to use Trusted Advisor insights."
                    ),
                    resources_affected=resources,
                    affected=1,
                    total_scanned=total_scanned,
                )

            # Process flagged items
            for check in checks:
                check_id = check.get("id")
                name = check.get("name")

                try:
                    result = support.describe_trusted_advisor_check_result(
                        checkId=check_id, language="en"
                    )
                    flagged = result.get("result", {}).get("flaggedResources", [])

                    if len(flagged) > 0:
                        resources_affected.append(
                            {
                                "resource_id": check_id,
                                "issue": f"{len(flagged)} flagged items in Trusted Advisor check '{name}'.",
                                "region": "us-east-1",
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )

                except Exception:
                    resources_affected.append(
                        {
                            "resource_id": check_id,
                            "issue": f"Unable to retrieve results for Trusted Advisor check '{name}'.",
                            "region": "us-east-1",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

            affected = len(resources_affected)

            return build_response(
                status="passed" if affected == 0 else "failed",
                problem=(
                    "Organizations must evaluate tradeoffs using Trusted Advisor insights "
                    "to balance risks, costs, and performance while making operational decisions."
                ),
                recommendation=(
                    "Review Trusted Advisor flagged items to guide cost optimization, performance improvements, "
                    "and risk reduction decisions."
                ),
                resources_affected=resources_affected,
                affected=affected,
                total_scanned=total_scanned,
            )

        except Exception:
            return build_response(
                status="error",
                problem="Unable to evaluate Trusted Advisor results.",
                recommendation="Verify IAM permissions and AWS Support plan.",
            )

    except Exception as e:
        print(f"Error checking OPS01-BP06: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while processing Trusted Advisor checks.",
            recommendation="Retry with valid AWS Support permissions.",
        )



def check_ops02_bp01_resource_owners(session):
    print("OPS02-BP01 is organizational and cannot be fully measured using API calls")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ops_model_def_resource_owners.html"

    return {
        "id": "OPS02-BP01",
        "check_name": "Resources have identified owners",
        "problem_statement": (
            "Resources must have clearly identified owners to ensure accountability, governance, "
            "and effective operational management."
        ),
        "severity_score": 70,
        "severity_level": "High",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Ensure every AWS resource is tagged with an owner using consistent tag keys such as "
            "'Owner', 'ResourceOwner', or 'CreatedBy'. Implement organization-wide tagging policies."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Define mandatory tag keys for ownership (e.g., Owner, ResourceOwner, CreatedBy).",
            "2. Enforce tagging policies using Tag Policies, SCPs, or IaC frameworks.",
            "3. Auto-tag resources during creation using CloudTrail + Lambda.",
            "4. Periodically audit resource tags using Resource Groups Tagging API.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops02_bp02_process_procedure_owners(session):
    print("OPS02-BP02 is organizational and cannot be evaluated using API calls")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ops_model_def_proc_owners.html"

    return {
        "id": "OPS02-BP02",
        "check_name": "Processes and procedures have identified owners",
        "problem_statement": (
            "Operational processes and procedures must have clearly defined owners to ensure "
            "accountability, timely maintenance, and consistent updates across the organization."
        ),
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Assign clear ownership for operational processes and procedures. Ensure each procedure "
            "has an accountable person or team responsible for updates, communication, and execution."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Define an ownership model covering all critical operational processes.",
            "2. Maintain a centralized repository documenting process owners.",
            "3. Establish periodic reviews to keep procedures updated.",
            "4. Implement RACI or similar governance models for accountability.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops02_bp03_operations_activities_have_owners(session):
    print("Checking OPS02-BP03")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ops_model_def_activity_owners.html"

    return {
        "id": "OPS02-BP03",
        "check_name": "Operations activities have identified owners responsible for their performance",
        "problem_statement": (
            "Operational activities such as deployments, patching, monitoring, and maintenance "
            "must have clearly identified owners to ensure accountability and reliability."
        ),
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Document operational activities and assign explicit owners. Maintain an operations "
            "ownership matrix and review it periodically."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. List all operational activities including deployments, backups, monitoring, and patching.",
            "2. Assign explicit owners or teams responsible for each activity.",
            "3. Maintain an ownership matrix and review it quarterly.",
            "4. Include contact details, escalation paths, and SLAs for each activity.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops02_bp04_manage_responsibilities_and_ownership(session):
    print("Checking OPS02-BP04")

    org = session.client("organizations")
    iam = session.client("iam")
    sts = session.client("sts")

    aws_doc_link = (
        "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
        "ops_ops_model_def_responsibilities_ownership.html"
    )

    resources_affected = []
    total_scanned = 0
    region = session.region_name
    account_id = sts.get_caller_identity()["Account"]

    try:

        # 1. AWS Organizations — list accounts

        try:
            accounts = org.list_accounts().get("Accounts", [])
            total_scanned += len(accounts)

            # Flag if no proper tags / ownership defined
            for acc in accounts:
                acc_id = acc.get("Id")
                acc_name = acc.get("Name")

                # No tags means ownership structure might be unclear
                if not acc.get("Arn"):
                    resources_affected.append(
                        {
                            "resource_id": acc_id,
                            "issue": f"AWS Organization account '{acc_name}' has no ARN available.",
                            "region": region,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve AWS Organizations accounts.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 2. AWS Organizations — list policies

        try:
            policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get(
                "Policies", []
            )
            total_scanned += len(policies)

            if len(policies) == 0:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No Service Control Policies (SCPs) found. Ownership/governance boundaries unclear.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve AWS Organizations policies.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 3. IAM — list customer-managed policies

        try:
            iam_policies = iam.list_policies(Scope="Local").get("Policies", [])
            total_scanned += len(iam_policies)

            if not iam_policies:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No customer-managed IAM policies found — may indicate unclear ownership permissions model.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to list IAM customer-managed policies.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # 4. IAM — Account authorization details

        try:
            auth_details = iam.get_account_authorization_details()
            total_scanned += 1

            roles = auth_details.get("RoleDetailList", [])
            policies = auth_details.get("Policies", [])

            if not roles:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No IAM roles retrieved — unclear operational responsibility boundaries.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            if not policies:
                resources_affected.append(
                    {
                        "resource_id": account_id,
                        "issue": "No IAM policies retrieved in authorization details.",
                        "region": region,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except Exception:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "Unable to retrieve IAM account authorization details.",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Final evaluation

        affected = len(resources_affected)

        return {
            "id": "OPS02-BP04",
            "check_name": "Mechanisms exist to manage responsibilities and ownership",
            "problem_statement": (
                "Organizations must have clear governance mechanisms—such as IAM roles, SCPs, "
                "and account structures—to ensure responsibilities and ownership are properly managed."
            ),
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Define and maintain governance mechanisms using AWS Organizations, SCPs, IAM roles, "
                "and customer-managed policies to enforce clear ownership boundaries."
            ),
            "additional_info": {"total_scanned": max(total_scanned,affected), "affected": affected},
            "remediation_steps": [
                "1. Implement Service Control Policies (SCPs) to enforce responsibility boundaries.",
                "2. Use IAM roles with least privilege and assign them to proper owners.",
                "3. Maintain tagging standards to map accounts and roles to owners.",
                "4. Regularly audit IAM policies and authorization details.",
                "5. Ensure organizational units (OUs) reflect ownership and responsibility structure.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking OPS02-BP04: {e}")
        return None


def check_ops02_bp05_mechanisms_for_change_requests(session):
    servicecatalog = session.client("servicecatalog")
    ssm = session.client("ssm")

    aws_doc_link = (
        "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
        "ops_ops_model_req_add_chg_exception.html"
    )

    resources_affected = []
    total_scanned = 0

    # 1. Check Service Catalog portfolios
    try:
        portfolios = servicecatalog.list_portfolios().get("PortfolioDetails", [])
        total_scanned += 1

        if len(portfolios) == 0:
            resources_affected.append(
                {
                    "resource_id": "service-catalog",
                    "issue": "No Service Catalog portfolios found for standardized request workflows.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

    except Exception as e:
        resources_affected.append(
            {
                "resource_id": "service-catalog",
                "issue": "Error fetching Service Catalog portfolios",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            }
        )

    # 2. Check SSM Change Manager templates
    try:
        change_templates = ssm.list_documents(
            Filters=[{"Key": "Owner", "Values": ["AWS"]}]
        ).get("DocumentIdentifiers", [])
        total_scanned += 1

        if len(change_templates) == 0:
            resources_affected.append(
                {
                    "resource_id": "ssm-change-manager",
                    "issue": "No SSM Change Manager templates found for controlled change workflows.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

    except Exception as e:
        resources_affected.append(
            {
                "resource_id": "ssm-change-manager",
                "issue": "Error fetching SSM change templates",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            }
        )

    affected = len(resources_affected)

    return {
        "id": "OPS02-BP05",
        "check_name": "Mechanisms exist to request additions, changes, and exceptions",
        "problem_statement": (
            "Organizations must have structured mechanisms for requesting new resources, "
            "modifications, and exceptions to maintain traceability, authorization, and compliance."
        ),
        "severity_score": 50,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "status": "passed" if affected == 0 else "failed",
        "recommendation": (
            "Establish governed workflows using AWS Service Catalog, SSM Change Manager, "
            "and documented process templates to ensure traceable and authorized changes."
        ),
        "additional_info": {"total_scanned": max(total_scanned,affected), "affected": affected},
        "remediation_steps": [
            "1. Create Service Catalog portfolios and products for standardized request workflows.",
            "2. Use AWS Systems Manager Change Manager to control and approve changes.",
            "3. Maintain SSM documents and change templates for operational tasks.",
            "4. Document workflows for requesting exceptions and ensure proper approval routing.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops02_bp06_team_responsibility_negotiation(session):
    aws_doc_link = (
        "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
        "ops_ops_model_def_neg_team_agreements.html"
    )

    resources_affected = []
    total_scanned = 0
    affected = 0

    return {
        "id": "OPS02-BP06",
        "check_name": "Responsibilities between teams are predefined or negotiated",
        "problem_statement": (
            "Teams must clearly negotiate and define responsibilities to ensure smooth "
            "operations, prevent ambiguity, and maintain accountability."
        ),
        "severity_score": 40,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "status": "not_available",
        "recommendation": (
            "Establish documented agreements (SLAs, RACI matrices, onboarding documents) "
            "to clarify responsibilities and reduce operational friction."
        ),
        "additional_info": {"total_scanned": total_scanned, "affected": affected},
        "remediation_steps": [
            "1. Define RACI matrices for operational processes.",
            "2. Create documented agreements between teams for shared responsibilities.",
            "3. Establish periodic reviews for responsibility boundaries.",
            "4. Ensure role clarity through onboarding and operational documentation.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_ops03_bp01_provide_executive_sponsorship(session):
    # [SEC03-BP01] - Provide executive sponsorship
    print("Checking executive sponsorship governance")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_define.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP01",
            "check_name": "Provide executive sponsorship",
            "problem_statement": problem,
            "severity_score": 25,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Assign an executive sponsor accountable for cloud and security initiatives.",
                "2. Ensure the sponsor reviews security strategy, KPIs, and risk posture regularly.",
                "3. Establish communication channels between leadership and technical teams.",
                "4. Align security and cloud governance with organizational objectives.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        total_scanned = 0
        affected = 0

        return build_response(
            status="not_available",
            problem=(
                "Executive sponsorship is essential to align cloud security strategy with business goals "
                "and ensure long-term support for governance initiatives."
            ),
            recommendation=(
                "Define and document an executive sponsor responsible for driving cloud security strategy, "
                "oversight, and strategic alignment across the organization."
            ),
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking SEC03-BP01: {e}")
        return build_response(
            status="error",
            problem="An error occurred while assessing executive sponsorship.",
            recommendation="Review organizational governance structures.",
        )


def check_ops03_bp02_team_empowered_to_take_action(session):
    # [SEC03-BP02] - Team members are empowered to take action when outcomes are at risk
    print("Checking if teams are empowered to take action during risk conditions")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_org_culture_team_emp_take_action.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP02",
            "check_name": "Team members are empowered to take action when outcomes are at risk",
            "problem_statement": problem,
            "severity_score": 30,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Define clear escalation paths for operational and security risks.",
                "2. Empower teams with authority to act quickly during high-risk situations.",
                "3. Provide training on identifying risks and initiating timely response actions.",
                "4. Build a culture that encourages proactive action and early escalation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        total_scanned = 0
        affected = 0

        return build_response(
            status="not_available",
            problem=(
                "Empowering team members to act during risk scenarios supports faster incident response "
                "and improves security and operational resilience."
            ),
            recommendation=(
                "Establish documented escalation paths, decision-making authority, and empowerment models "
                "that enable teams to act quickly when operational or security outcomes are at risk."
            ),
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking SEC03-BP02: {e}")
        return build_response(
            status="error",
            problem="An error occurred while assessing team empowerment.",
            recommendation="Review operational governance and empowerment practices.",
        )


def check_ops03_bp03_escalation_encouraged(session):
    # [OPS03-BP03] - Escalation is encouraged
    print("Evaluating escalation culture and practices")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_org_culture_team_enc_escalation.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP03",
            "check_name": "Escalation is encouraged",
            "problem_statement": problem,
            "severity_score": 25,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Define clear escalation paths for operational and security issues.",
                "2. Encourage team members to raise concerns early when risks increase.",
                "3. Train staff on when and how to escalate incidents or potential failures.",
                "4. Build a culture that supports proactive escalation without fear of negative consequences.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        total_scanned = 0
        affected = 0

        return build_response(
            status="not_available",
            problem=(
                "Encouraging timely escalation of issues helps prevent operational impact and enables "
                "faster decision-making during high-risk situations."
            ),
            recommendation=(
                "Document escalation paths, provide guidance on escalation triggers, and foster a culture "
                "that supports raising issues early to improve operational resilience."
            ),
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking OPS03-BP03: {e}")
        return build_response(
            status="error",
            problem="An error occurred while evaluating escalation practices.",
            recommendation="Review escalation processes and governance across teams.",
        )


def check_ops03_bp04_communications_effective(session):
    print(
        "Checking OPS03-BP04 – Timely, clear, and actionable communications (no API-based evaluation)"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_org_culture_effective_comms.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP04",
            "check_name": "Communications are timely, clear, and actionable",
            "problem_statement": problem,
            "severity_score": 20,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Establish standard operating procedures for communication during events.",
                "2. Use predefined templates for status updates and incident communications.",
                "3. Ensure communication channels are monitored and well understood by teams.",
                "4. Train teams to deliver concise, actionable information.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=("This best practice relates to communication quality."),
            recommendation=(
                "Improve communication processes by defining clear templates, timely update mechanisms, "
                "and ensuring messages are actionable and concise."
            ),
        )

    except Exception as e:
        print(f"Error evaluating OPS03-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess communication practices.",
            recommendation="Retry the assessment or review internal communication guidelines.",
        )


def check_ops03_bp05_experimentation_encouraged(session):
    print(
        "Checking OPS03-BP05 – Experimentation is encouraged (no API-based evaluation)"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_org_culture_team_enc_experiment.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP05",
            "check_name": "Experimentation is encouraged",
            "problem_statement": problem,
            "severity_score": 20,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Promote a culture that allows teams to try new ideas without fear of failure.",
                "2. Provide sandbox environments for safe experimentation.",
                "3. Encourage small, controlled experiments before implementing large changes.",
                "4. Document lessons learned from experiments and share with teams.",
                "5. Recognize and reward innovation and thoughtful experimentation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "This best practice focuses on cultural and organizational support for experimentation."
            ),
            recommendation=(
                "Encourage teams to experiment safely using sandbox environments, support innovation, "
                "and foster a culture that embraces learning through experimentation."
            ),
        )

    except Exception as e:
        print(f"Error evaluating OPS03-BP05: {e}")
        return build_response(
            status="error",
            problem="Unable to assess experimentation culture.",
            recommendation="Retry assessment or review organizational experimentation practices.",
        )


def check_ops03_bp06_team_skill_growth(session):
    print(
        "Checking OPS03-BP06 – Team members are encouraged to maintain and grow their skill sets"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_org_culture_team_enc_learn.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP06",
            "check_name": "Team members are encouraged to maintain and grow their skill sets",
            "problem_statement": problem,
            "severity_score": 25,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Provide ongoing training resources and access to AWS learning materials.",
                "2. Encourage team members to pursue certifications relevant to their roles.",
                "3. Support structured learning programs such as workshops, labs, and mentorship.",
                "4. Allocate dedicated learning time during work cycles.",
                "5. Track learning progress and celebrate completed skill development milestones.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "This best practice focuses on organizational culture and professional development."
            ),
            recommendation=(
                "Encourage continuous learning by providing access to training materials, certification "
                "paths, and dedicated time for team members to grow their skills."
            ),
        )

    except Exception as e:
        print(f"Error evaluating OPS03-BP06: {e}")
        return build_response(
            status="error",
            problem="Unable to assess team skill growth encouragement.",
            recommendation="Review organizational learning programs and retry the assessment.",
        )


def check_ops03_bp07_resource_teams_appropriately(session):
    print("Checking OPS03-BP07 – Resource teams appropriately")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_org_culture_team_res_appro.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS03-BP07",
            "check_name": "Resource teams appropriately",
            "problem_statement": problem,
            "severity_score": 30,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Evaluate whether each team has the appropriate number of members and skill sets.",
                "2. Identify workload areas where teams are overburdened or understaffed.",
                "3. Provide additional resources or redistribute responsibilities as needed.",
                "4. Align staffing levels with operational priorities and workload demands.",
                "5. Review resource allocation regularly and adjust team structures as environments evolve.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "This best practice focuses on organizational staffing and team resource allocation, "
            ),
            recommendation=(
                "Ensure teams are properly resourced by assessing workload demands, balancing responsibilities, "
                "and aligning staffing levels with operational priorities."
            ),
        )

    except Exception as e:
        print(f"Error evaluating OPS03-BP07: {e}")
        return build_response(
            status="error",
            problem="Unable to assess team resourcing.",
            recommendation="Review team resource allocation processes and retry the assessment.",
        )
