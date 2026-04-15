from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# COST 10

def check_cost10_bp01_develop_review_process(session):
    # [BP01] - Develop a workload review process
    print("Checking COST10-BP01: Workload Review Process (Service Catalog & Config)")

    sc_client = session.client("servicecatalog")
    config_client = session.client("config")
    org_client = session.client("organizations")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cost_effective_resources_review_process.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST10-BP01",
            "check_name": "Develop a workload review process",
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
                "1. Use AWS Service Catalog to standardize compliant, cost-effective infrastructure blueprints.",
                "2. Deploy AWS Config Conformance Packs to enforce architectural standards across accounts.",
                "3. Schedule regular Well-Architected Reviews (WAR) for critical workloads.",
                "4. Use AWS Organizations to centrally govern review policies.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: Service Catalog ------------------
        # Service Catalog implies a "curated" list of products, which is a strong review process.
        has_catalog = False
        try:
            if sc_client.list_portfolios(PageSize=1).get("PortfolioDetails"):
                has_catalog = True
        except Exception:
            pass

        # ------------------ Check 2: Config Conformance Packs ------------------
        # Conformance packs are literally "process as code".
        has_packs = False
        try:
            if config_client.describe_conformance_packs(Limit=1).get(
                "ConformancePackDetails"
            ):
                has_packs = True
        except Exception:
            pass

        # ------------------ Check 3: Config Recording ------------------
        # Can't review what you don't record.
        is_recording = False
        try:
            status = config_client.describe_configuration_recorders()
            for r in status.get("ConfigurationRecorders", []):
                # Check listing implies existence; 'recording' field logic varies by API version slightly
                # but existence is good enough for "Process" check.
                is_recording = True
        except Exception:
            pass

        # ------------------ Check 4: Organizations ------------------
        # Just verifying org context
        has_org = False
        try:
            org_client.list_accounts(MaxResults=1)
            has_org = True
        except Exception:
            pass

        total_scanned = 3  # Catalog, Packs, Recorder
        affected = 0

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not has_catalog and not has_packs and not is_recording:
            status = "failed"
            affected = 1
            resources_affected.append(
                {
                    "resource_id": "Review Process Tools",
                    "issue": "No standardized review tools (Service Catalog, Config Packs) detected. Infrastructure changes may be unmanaged.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            problem_text = "Workload review process is manual or non-existent."
            rec_text = "Implement AWS Config rules or Service Catalog portfolios to enforce a standard review process."
        else:
            status = "passed"
            problem_text = "Tools to support a workload review process are active."
            rec_text = "Ensure your Service Catalog portfolios are updated regularly with the latest cost-optimized instance types."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Review Process: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating process tools.",
            recommendation="Check permissions for 'servicecatalog' and 'config'.",
        )


def check_cost10_bp02_analyze_workload_regularly(session):
    # [BP02] - Review and analyze this workload regularly
    print("Checking COST10-BP02: Regular Analysis (Trusted Advisor, Pricing, CO)")

    ce_client = session.client("ce")
    co_client = session.client("compute-optimizer")
    support_client = session.client("support", region_name="us-east-1")  # TA is global
    pricing_client = session.client("pricing", region_name="us-east-1")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cost_effective_resources_analyze_workload.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST10-BP02",
            "check_name": "Review and analyze this workload regularly",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Regularly review AWS Trusted Advisor 'Cost Optimization' checks.",
                "2. Analyze Compute Optimizer recommendations weekly.",
                "3. Use Cost Explorer to identify cost trends and anomalies.",
                "4. Check the AWS Price List API for price drops or new generation instance types.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: Trusted Advisor ------------------
        # We try to get the checks. If we can, it means the user is likely utilizing Support tools.
        ta_accessible = False
        try:
            checks = support_client.describe_trusted_advisor_checks(language="en").get(
                "checks", []
            )
            if checks:
                ta_accessible = True
                # Optional: Try to get a result for a specific cost check if needed
                # But just accessing the checks proves capability.
        except Exception:
            # Often fails if no Business/Enterprise support plan
            pass

        # ------------------ Check 2: Pricing API ------------------
        # Reviewing workload implies checking current market prices.
        pricing_accessible = False
        try:
            pricing_client.get_products(ServiceCode="AmazonEC2", MaxResults=1)
            pricing_accessible = True
        except Exception:
            pass

        # ------------------ Check 3: Compute Optimizer ------------------
        co_active = False
        try:
            if co_client.get_recommendation_summaries().get("recommendationSummaries"):
                co_active = True
        except Exception:
            pass

        # ------------------ Check 4: Cost Explorer Data ------------------
        ce_active = False
        try:
            now = datetime.now()
            ce_client.get_cost_and_usage(
                TimePeriod={
                    "Start": (now - timedelta(days=2)).strftime("%Y-%m-%d"),
                    "End": (now - timedelta(days=1)).strftime("%Y-%m-%d"),
                },
                Granularity="DAILY",
                Metrics=["UnblendedCost"],
            )
            ce_active = True
        except Exception:
            pass

        total_scanned = 4
        affected = 0

        status = "passed"
        problem_text = ""
        rec_text = ""

        # Logic: If you lack TA (support plan issue) AND Compute Optimizer, you aren't analyzing much.
        if not ta_accessible and not co_active:
            status = "failed"
            affected = 1
            resources_affected.append(
                {
                    "resource_id": "Analysis Tools",
                    "issue": "Trusted Advisor and Compute Optimizer are inaccessible or inactive. Automated workload analysis is missing.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            problem_text = "Regular automated analysis tools are not being used."
            rec_text = "Enable Compute Optimizer and review Trusted Advisor (upgrade support plan if needed) to catch inefficiencies."
        elif not ce_active:
            status = "failed"
            problem_text = (
                "Cost Explorer is inaccessible. You cannot analyze usage trends."
            )
            rec_text = "Grant permissions to view Cost Explorer data."
        else:
            status = "passed"
            problem_text = "Workload analysis tools are active."
            rec_text = (
                "Set a recurring calendar invite to review these dashboards monthly."
            )

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Workload Analysis: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating analysis tools.",
            recommendation="Check permissions for 'support', 'compute-optimizer', and 'ce'.",
        )


# COST 11


def check_cost11_bp01_perform_automation(session):
    # [BP01] - Perform automation for operations
    print("Checking COST11-BP01: Operational Automation (IaC, CI/CD, SSM)")

    ssm_client = session.client("ssm")
    cf_client = session.client("cloudformation")
    cp_client = session.client("codepipeline")
    cb_client = session.client("codebuild")
    lambda_client = session.client("lambda")
    events_client = session.client("events")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cost_effective_resources_automation.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST11-BP01",
            "check_name": "Perform automation for operations",
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
                "1. Use AWS CloudFormation or Terraform (IaC) to provision infrastructure, reducing manual errors.",
                "2. Implement CI/CD pipelines (CodePipeline) to automate deployment and testing.",
                "3. Use SSM Automation Runbooks for repetitive operational tasks (e.g., patching, backups).",
                "4. Schedule maintenance scripts using EventBridge and Lambda.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        automation_score = 0

        # 1. Check Infrastructure as Code (CloudFormation)
        try:
            # If stacks exist, they are using IaC
            if cf_client.list_stacks(
                StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE"], Limit=1
            ).get("StackSummaries"):
                automation_score += 1
        except:
            pass

        # 2. Check CI/CD (CodePipeline / CodeBuild)
        try:
            if cp_client.list_pipelines(maxResults=1).get("pipelines"):
                automation_score += 1
            elif cb_client.list_projects(sortBy="NAME", sortOrder="ASCENDING").get(
                "projects"
            ):
                automation_score += 1
        except:
            pass

        # 3. Check Operational Automation (SSM)
        try:
            # Check for automation executions or custom documents
            if ssm_client.describe_automation_executions(MaxResults=1).get(
                "AutomationExecutionMetadataList"
            ):
                automation_score += 1
            # Or just check if they have documents defined
            elif ssm_client.list_documents(
                Filters=[{"Key": "Owner", "Values": ["Self"]}], MaxResults=1
            ).get("DocumentIdentifiers"):
                automation_score += 1
        except:
            pass

        # 4. Check Scripting/Event Automation (Lambda/EventBridge)
        try:
            # Check if event rules exist (scheduled tasks)
            if events_client.list_rules(Limit=1).get("Rules"):
                automation_score += 1
            # Check if Lambda functions exist (automation scripts)
            elif lambda_client.list_functions(MaxItems=1).get("Functions"):
                automation_score += 1
        except:
            pass

        total_scanned = 1
        affected = 0

        status = "passed"
        problem_text = ""
        rec_text = ""

        if automation_score == 0:
            status = "failed"
            affected = 1
            resources_affected.append(
                {
                    "resource_id": "Operational Tools",
                    "issue": "No evidence of automation found (No Stacks, Pipelines, SSM Docs, or Event Rules). Operations appear manual.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            problem_text = "Operational effort is high due to a lack of automation."
            rec_text = "Start by codifying your infrastructure using CloudFormation to eliminate manual provisioning costs."
        else:
            status = "passed"
            problem_text = f"Automation tools detected (Score: {automation_score}/4 categories active)."
            rec_text = "Review your manual runbooks and convert the most frequent tasks into SSM Automation documents."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Automation: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating operational automation.",
            recommendation="Check permissions for 'cloudformation', 'ssm', and 'codepipeline'.",
        )
