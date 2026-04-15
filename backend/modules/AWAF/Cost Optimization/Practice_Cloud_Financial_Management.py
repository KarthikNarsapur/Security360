from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

def check_cost01_bp01_cost_ownership(session):
    print("Checking COST01-BP01 – Establish ownership of cost optimization")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_function.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP01",
            "check_name": "Establish ownership of cost optimization",
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
                "1. Identify a team or individual responsible for cost management (Cloud Financial Management).",
                "2. Establish a partnership between finance and technology teams.",
                "3. Define and track cloud budgets and forecasts.",
                "4. Use AWS Cost Allocation Tags to map resources to owners.",
                "5. Regularly review cost reports (AWS Cost Explorer) with owners.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Without clear ownership, cloud costs can spiral out of control due to lack of accountability "
                "and visibility between finance and engineering teams. This is an organizational process "
                "that cannot be validated programmatically."
            ),
            recommendation=(
                "Designate a specific owner or team (Cloud Financial Management) responsible for understanding, "
                "forecasting, and optimizing cloud spend."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST01-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess cost ownership status.",
            recommendation="Review organizational cost management structure and retry the assessment.",
        )


def check_cost01_bp02_finance_tech_partnership(session):
    print(
        "Checking COST01-BP02 – Establish a partnership between finance and technology"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_partnership.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP02",
            "check_name": "Establish a partnership between finance and technology",
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
                "1. Involve finance stakeholders in cloud planning and architecture discussions.",
                "2. Establish a regular cadence (e.g., monthly) for joint cost reviews.",
                "3. Educate finance teams on cloud pricing models (On-Demand, Savings Plans, Spot).",
                "4. Educate engineering teams on budget constraints and financial goals.",
                "5. Define a common language for cost metrics (e.g., cost per transaction, unit cost).",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "A lack of communication between finance and technology teams often leads to "
                "unexpected cloud bills, inefficient spending, and friction when budgeting. "
                "This cultural alignment cannot be verified programmatically."
            ),
            recommendation=(
                "Create a culture of collaboration where finance and technology teams meet regularly "
                "to discuss cloud spend, forecast future needs, and align on unit cost metrics."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST01-BP02: {e}")
        return build_response(
            status="error",
            problem="Unable to assess finance-technology partnership status.",
            recommendation="Review internal communication channels between finance and engineering teams.",
        )


def check_cost01_bp03_cloud_budgets(session):
    # [BP03] - Establish cloud budgets and forecasts
    print("Checking for Active Cloud Budgets and Forecast Capabilities")

    budgets_client = session.client("budgets")
    ce_client = session.client("ce")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_budget_forecast.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP03",
            "check_name": "Establish cloud budgets and forecasts",
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
                "1. Open the AWS Billing and Cost Management console.",
                "2. Navigate to 'Budgets' and create a budget (Cost, Usage, or Savings Plans budget).",
                "3. Set up email or SNS alerts for when actual or forecasted spend exceeds your threshold.",
                "4. Enable AWS Cost Explorer to allow for forecasting and deep-dive analysis.",
                "5. Use the 'Forecast' feature in Cost Explorer to predict future spend based on historical trends.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # We need the Account ID for the Budgets API
        account_id = sts_client.get_caller_identity()["Account"]

        # ------------------ Check 1: AWS Budgets ------------------
        active_budgets = []
        try:
            # Listing budgets to see if any exist
            response = budgets_client.describe_budgets(
                AccountId=account_id, MaxResults=10
            )
            active_budgets = response.get("Budgets", [])

            if not active_budgets:
                resources_affected.append(
                    {
                        "resource_id": f"Account: {account_id}",
                        "issue": "No AWS Budgets found. You have no automated alerts for cost overruns.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error listing budgets: {e}")
            resources_affected.append(
                {
                    "resource_id": "AWS Budgets",
                    "issue": f"Unable to list budgets. Check permissions (budgets:DescribeBudgets). Error: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Check 2: Cost Explorer Access ------------------
        # To forecast, Cost Explorer must be enabled. We try a simple query.
        try:
            # Just checking if we can access the API without error implies CE is enabled
            now = datetime.now()
            start_date = (now - timedelta(days=2)).strftime("%Y-%m-%d")
            end_date = (now - timedelta(days=1)).strftime("%Y-%m-%d")

            ce_client.get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="DAILY",
                Metrics=["UnblendedCost"],
            )
        except Exception as e:
            # If CE is not enabled, this usually throws a specific error
            resources_affected.append(
                {
                    "resource_id": "Cost Explorer",
                    "issue": "Unable to access Cost Explorer. It may not be enabled, preventing forecasting. Error: "
                    + str(e),
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1  # Treating the "Account" as the unit of scan
        affected = len(resources_affected)

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without budgets and forecasts, you are flying blind regarding your cloud spend. "
                "You may discover cost overruns only after receiving the monthly bill."
            ),
            recommendation=(
                "Create at least one AWS Budget to track total monthly costs and alert you "
                "if you exceed your threshold. Ensure Cost Explorer is enabled for forecasting."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Cloud Budgets: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while checking for budgets and forecasts.",
            recommendation="Ensure permissions for 'budgets' and 'ce' (Cost Explorer) are granted.",
        )


def check_cost01_bp04_cost_awareness(session):
    # [BP04] - Implement cost awareness in your organizational processes
    print("Checking for Cost Awareness (Cost Allocation Tags & Org Structure)")

    ce_client = session.client("ce")
    org_client = session.client("organizations")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_cost_awareness.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP04",
            "check_name": "Implement cost awareness in your organizational processes",
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
                "1. Activate 'AWS-Generated Cost Allocation Tags' in the Billing Console.",
                "2. Activate 'User-Defined Cost Allocation Tags' for keys like 'Project', 'CostCenter', or 'Owner'.",
                "3. Use AWS Organizations to consolidate billing and view costs across all member accounts.",
                "4. Configure Cost Categories to group costs by business unit or environment.",
                "5. Schedule regular cost reports to be sent to team leaders.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: Cost Allocation Tags ------------------
        # We need to see if tags are actually being used for billing.
        active_tags_count = 0
        try:
            # Fetching both AWS generated and User defined tags
            # Note: list_cost_allocation_tags is the modern API. get_cost_allocation_tags is older/specific.
            paginator = ce_client.get_paginator("list_cost_allocation_tags")

            # We verify if we have ANY active tags.
            # If specific keys are needed, we would filter for them here.
            for page in paginator.paginate(MaxResults=50):
                for tag in page.get("CostAllocationTags", []):
                    if tag.get("Status") == "Active":
                        active_tags_count += 1

            if active_tags_count == 0:
                resources_affected.append(
                    {
                        "resource_id": "Cost Allocation Tags",
                        "issue": "No active Cost Allocation Tags found. Costs cannot be attributed to specific projects or teams.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            # AccessDenied or other errors
            print(f"Error listing cost tags: {e}")
            resources_affected.append(
                {
                    "resource_id": "Cost Allocation Tags",
                    "issue": f"Unable to verify Cost Allocation Tags. Ensure permissions (ce:ListCostAllocationTags). Error: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Check 2: Organizations Scope ------------------
        # If this is a management account, we check if they are listing accounts to ensure they see the big picture.
        is_org_management = False
        try:
            org_response = org_client.list_accounts(MaxResults=1)
            is_org_management = True
            # If we are here, we are likely the management account or a delegated admin.
            # This is just a context check; not necessarily a failure unless we found 0 accounts (impossible if we exist).
        except Exception as e:
            # Not an org error or permission error, we treat this as a single account check
            pass

        total_scanned = 1
        affected = len(resources_affected)

        # Logic: If you have 0 active cost tags, you technically fail "Cost Awareness"
        # because you can't be aware of who is spending what.
        status = "passed"
        problem_text = ""
        recommendation_text = ""

        if affected > 0:
            status = "failed"
            problem_text = (
                "Your AWS environment lacks active Cost Allocation Tags. "
                "Without these, you cannot attribute costs to specific applications, teams, or environments."
            )
            recommendation_text = (
                "Enable Cost Allocation Tags (both AWS-generated and User-defined) in the Billing Console "
                "to start tracking spend by resource metadata."
            )
        else:
            status = "passed"
            problem_text = (
                "Cost allocation tags are active, enabling granular cost tracking."
            )
            recommendation_text = "Continue refining your tagging strategy and ensure new resources are tagged compliantly."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=recommendation_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Cost Awareness: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating cost awareness configurations.",
            recommendation="Check IAM permissions for Cost Explorer and Organizations.",
        )


def check_cost01_bp05_report_cost_optimization(session):
    # [BP05] - Report and notify on cost optimization
    print("Checking COST01-BP05: Cost Notifications (Budgets & SNS)")

    budgets_client = session.client("budgets")
    sns_client = session.client("sns")
    ce_client = session.client("ce")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_usage_report.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP05",
            "check_name": "Report and notify on cost optimization",
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
                "1. Create an Amazon SNS Topic for billing alerts.",
                "2. Subscribe an endpoint (Email/SMS) to the SNS Topic and confirm the subscription.",
                "3. Open AWS Budgets and select your active budget.",
                "4. Add an 'Alert' threshold (e.g., 80% of forecasted spend).",
                "5. Link the Budget Alert to your SNS Topic to ensure notifications are delivered.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts_client.get_caller_identity()["Account"]

        # ------------------ Check 1: SNS (Topics & Subscriptions) ------------------
        # It's not enough to have a topic; it must have a confirmed subscription (someone listening).
        sns_ready = False
        try:
            topics = sns_client.list_topics().get("Topics", [])
            subs = sns_client.list_subscriptions().get("Subscriptions", [])

            if not topics:
                resources_affected.append(
                    {
                        "resource_id": "Amazon SNS",
                        "issue": "No SNS topics found. You have no channel for billing alerts.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            elif not subs:
                resources_affected.append(
                    {
                        "resource_id": "Amazon SNS",
                        "issue": "SNS topics exist, but no subscriptions found. Alerts are being sent to nowhere.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                sns_ready = True
        except Exception as e:
            print(f"Error checking SNS: {e}")
            resources_affected.append(
                {
                    "resource_id": "Amazon SNS",
                    "issue": f"Unable to verify SNS configuration. Error: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Check 2: Budget Notifications ------------------
        budgets_with_alerts = 0
        total_budgets = 0

        try:
            # We list budgets first
            budgets_resp = budgets_client.describe_budgets(
                AccountId=account_id, MaxResults=5
            )
            budget_list = budgets_resp.get("Budgets", [])
            total_budgets = len(budget_list)

            if total_budgets == 0:
                resources_affected.append(
                    {
                        "resource_id": "AWS Budgets",
                        "issue": "No budgets found. You cannot receive notifications if no budget is defined.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                # We check specific notifications for these budgets
                for budget in budget_list:
                    b_name = budget.get("BudgetName")
                    try:
                        notif_resp = budgets_client.describe_notifications_for_budget(
                            AccountId=account_id, BudgetName=b_name, MaxResults=5
                        )
                        if notif_resp.get("Notifications"):
                            budgets_with_alerts += 1
                    except Exception as inner_e:
                        # Some budgets might be auto-adjusting or have different perms
                        print(
                            f"Error checking notifications for budget {b_name}: {inner_e}"
                        )

                if total_budgets > 0 and budgets_with_alerts == 0:
                    resources_affected.append(
                        {
                            "resource_id": "AWS Budgets",
                            "issue": f"Found {total_budgets} budgets, but NONE have alerts configured.",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        except Exception as e:
            print(f"Error checking Budget Notifications: {e}")

        # ------------------ Check 3: Cost Explorer Access ------------------
        # Just ensuring we can read data (as per API list requirement)
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
        except Exception as e:
            resources_affected.append(
                {
                    "resource_id": "Cost Explorer",
                    "issue": "Unable to access Cost Explorer data via API.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Logic Synthesis
        total_scanned = 3  # SNS, Budgets, CE
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not sns_ready:
            status = "failed"
            problem_text = "The notification infrastructure (SNS) is missing or has no subscribers."
            rec_text = "Configure an SNS topic with a valid email subscription for billing alerts."
        elif total_budgets == 0:
            status = "failed"
            problem_text = "No AWS Budgets are defined, so no alerts can be triggered."
            rec_text = "Create a budget and attach your SNS topic to it."
        elif budgets_with_alerts == 0:
            status = "failed"
            problem_text = "Budgets exist but lack notification triggers."
            rec_text = "Edit your budgets to add alert thresholds (e.g., >80% spend) linked to SNS."
        else:
            status = "passed"
            problem_text = "Budgets are configured with notification alerts."
            rec_text = "Regularly test your SNS subscriptions to ensure alerts are being received."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Cost Notifications: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating cost notifications.",
            recommendation="Ensure IAM permissions for 'budgets', 'sns', and 'ce' are granted.",
        )


def check_cost01_bp06_monitor_cost_proactively(session):
    # [BP06] - Monitor cost proactively
    print("Checking for Proactive Cost Monitoring Tools (Cost Explorer & Budgets)")

    ce_client = session.client("ce")
    budgets_client = session.client("budgets")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_proactive_process.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP06",
            "check_name": "Monitor cost proactively",
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
                "1. Enable AWS Cost Explorer in the Billing Management Console.",
                "2. Create AWS Budgets for your main cost centers (e.g., total account spend, specific services).",
                "3. Set up AWS Cost Anomaly Detection to identify unusual spending patterns automatically.",
                "4. Review Cost Explorer 'Daily' granularity graphs to spot trends early.",
                "5. (Advanced) Integrate Cost & Usage Reports (CUR) with Amazon QuickSight for deep analysis.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts_client.get_caller_identity()["Account"]

        # ------------------ Check 1: Cost Explorer Accessibility ------------------
        # Proactive monitoring is impossible if Cost Explorer isn't enabled or accessible.
        ce_enabled = False
        try:
            # We try a lightweight query for the last 2 days
            now = datetime.now()
            start_date = (now - timedelta(days=2)).strftime("%Y-%m-%d")
            end_date = (now - timedelta(days=1)).strftime("%Y-%m-%d")

            ce_client.get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="DAILY",
                Metrics=["UnblendedCost"],
            )
            ce_enabled = True
        except Exception as e:
            resources_affected.append(
                {
                    "resource_id": "Cost Explorer",
                    "issue": f"Cost Explorer appears disabled or inaccessible. You cannot proactively monitor costs. Error: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Check 2: Active Budgets ------------------
        # Monitoring is manual without budgets acting as automated watchdogs.
        active_budgets_count = 0
        try:
            response = budgets_client.describe_budgets(
                AccountId=account_id, MaxResults=5
            )
            active_budgets_count = len(response.get("Budgets", []))

            if active_budgets_count == 0:
                resources_affected.append(
                    {
                        "resource_id": "AWS Budgets",
                        "issue": "No active budgets found. Proactive monitoring relies on thresholds to trigger alerts.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            # We log permission errors but don't crash the check
            print(f"Error checking budgets: {e}")

        total_scanned = 2  # Checking CE and Budgets capability
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not ce_enabled:
            status = "failed"
            problem_text = (
                "Cost Explorer is not enabled or accessible. You have no visibility into daily cost trends, "
                "making proactive monitoring impossible."
            )
            rec_text = "Enable AWS Cost Explorer immediately to visualize and analyze your spend data."
        elif active_budgets_count == 0:
            status = "failed"
            problem_text = (
                "Cost Explorer is active, but no AWS Budgets are configured. "
                "You are relying on manual checks rather than automated proactive monitoring."
            )
            rec_text = "Create at least one AWS Budget to automate the monitoring of your cloud spend."
        else:
            status = "passed"
            problem_text = (
                "Proactive monitoring tools (Cost Explorer and Budgets) are active."
            )
            rec_text = "Ensure you regularly review Cost Explorer data and refine budget thresholds."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Proactive Cost Monitoring: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while checking cost monitoring tools.",
            recommendation="Check permissions for 'ce:GetCostAndUsage' and 'budgets:DescribeBudgets'.",
        )


def check_cost01_bp07_new_service_releases(session):
    print("Checking COST01-BP07 – Keep up-to-date with new service releases")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_scheduled.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP07",
            "check_name": "Keep up-to-date with new service releases",
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
                "1. Subscribe to the AWS 'What's New' RSS feed.",
                "2. Regularly read the AWS Compute and AWS Cost Management blogs.",
                "3. Schedule quarterly architectural reviews to identify modernization opportunities.",
                "4. attend AWS Summits, re:Invent, or local user groups.",
                "5. Evaluate managed services (e.g., RDS, Lambda) to replace self-managed EC2 workloads.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Cloud technology evolves rapidly. Failing to track new releases means missing out on "
                "performance improvements, price reductions, and managed services that reduce operational overhead. "
                "This process cannot be verified via API."
            ),
            recommendation=(
                "Establish a process to review AWS release notes and blog posts regularly. "
                "Identify new features that can improve cost-efficiency or performance for your specific workloads."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST01-BP07: {e}")
        return build_response(
            status="error",
            problem="Unable to assess service release monitoring process.",
            recommendation="Review internal training and knowledge-sharing processes.",
        )


def check_cost01_bp08_cost_culture(session):
    print("Checking COST01-BP08 – Create a cost-aware culture")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_culture.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP08",
            "check_name": "Create a cost-aware culture",
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
                "1. Gamify cost optimization (e.g., leaderboards for teams who save the most).",
                "2. Recognize and reward individuals who champion cost efficiency.",
                "3. Make cost a standard agenda item in architectural reviews.",
                "4. Empower engineering teams to make their own trade-off decisions between speed and cost.",
                "5. Implement 'Showback' reports so teams can see the financial impact of their resources.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "If cost is seen solely as a 'finance problem,' engineers will prioritize speed "
                "and performance over efficiency, leading to wasteful architecture. "
                "This is a cultural metric that cannot be scraped via API."
            ),
            recommendation=(
                "Foster a culture where cost efficiency is celebrated. Treat cost as a non-functional "
                "requirement (like security or latency) and reward teams for optimizing it."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST01-BP08: {e}")
        return build_response(
            status="error",
            problem="Unable to assess organizational cost culture.",
            recommendation="Review HR or management policies regarding cloud efficiency incentives.",
        )


def check_cost01_bp09_quantify_value(session):
    print("Checking COST01-BP09 – Quantify business value from cost optimization")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_quantify_value.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST01-BP09",
            "check_name": "Quantify business value from cost optimization",
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
                "1. Define unit metrics (e.g., cost per customer, cost per transaction).",
                "2. Calculate the Return on Investment (ROI) for optimization efforts.",
                "3. Track cost avoidance (money saved by not doing something inefficient).",
                "4. Share success stories of cost reduction with the wider organization.",
                "5. Correlate AWS spend with business revenue to measure efficiency.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Reducing the bill is good, but without linking it to business outcomes (like cost per user), "
                "you can't prove if you are actually becoming more efficient or just stifling growth. "
                "This strategic metric cannot be measured via API."
            ),
            recommendation=(
                "Shift the conversation from 'Total Spend' to 'Unit Cost.' "
                "Demonstrate how technical optimizations directly contribute to higher profit margins."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST01-BP09: {e}")
        return build_response(
            status="error",
            problem="Unable to assess business value quantification processes.",
            recommendation="Review internal reporting on cloud ROI and unit economics.",
        )
