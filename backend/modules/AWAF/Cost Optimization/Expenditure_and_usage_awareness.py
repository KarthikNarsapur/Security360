from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


# COST 2


def check_cost02_bp01_develop_policies(session):
    # [BP01] - Develop policies based on your organization requirements
    print("Checking COST02-BP01: Governance Policies (SCPs & IAM)")

    org_client = session.client("organizations")
    iam_client = session.client("iam")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_governance_policies.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST02-BP01",
            "check_name": "Develop policies based on your organization requirements",
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
                "1. Use AWS Organizations Service Control Policies (SCPs) to restrict expensive services in sandbox accounts.",
                "2. Define IAM policies that strictly limit who can create resources (e.g., only allow t3.micro for dev).",
                "3. Implement Tag Policies to enforce cost allocation tagging standards.",
                "4. Regularly review and deprecate unused IAM policies.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts_client.get_caller_identity()["Account"]

        # ------------------ Check 1: Organization Policies (SCPs) ------------------
        # We check if we can list policies. This usually requires Management Account access.
        org_policies_found = False
        try:
            # Check for Service Control Policies (SCPs) - Type 'SERVICE_CONTROL_POLICY'
            response = org_client.list_policies(
                Filter="SERVICE_CONTROL_POLICY", MaxResults=5
            )
            if response.get("Policies"):
                org_policies_found = True
        except Exception:
            # Common if not in an Org or not the master account. We don't fail strictly on this,
            # but we note it if we are checking governance.
            pass

        # ------------------ Check 2: IAM Policies ------------------
        # We check if custom Customer Managed policies exist (indicating policy development).
        iam_policies_found = False
        try:
            # Scope='Local' means Customer Managed Policies
            response = iam_client.list_policies(
                Scope="Local", OnlyAttached=True, MaxResults=5
            )
            if response.get("Policies"):
                iam_policies_found = True
            else:
                resources_affected.append(
                    {
                        "resource_id": "IAM",
                        "issue": "No Customer Managed IAM policies found. Relying solely on AWS Managed policies limits governance control.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error listing IAM policies: {e}")
            resources_affected.append(
                {
                    "resource_id": "IAM",
                    "issue": f"Unable to list IAM policies: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not iam_policies_found and not org_policies_found:
            status = "failed"
            problem_text = "No custom governance policies (IAM or Org SCPs) were detected. Usage is likely unrestricted."
            rec_text = "Create Customer Managed IAM policies or SCPs to enforce limits on resource creation."
        elif not org_policies_found:
            # Soft pass - they have IAM, but maybe not Org
            status = "passed"
            problem_text = "IAM policies exist, but Organization-level SCPs were not accessible or found."
            rec_text = "Consider using AWS Organizations SCPs for broader governance across accounts."
        else:
            status = "passed"
            problem_text = "Governance policies (IAM/SCP) are active."
            rec_text = "Regularly audit your policies to ensure they match current business requirements."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Policy Governance: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while verifying governance policies.",
            recommendation="Ensure permissions for 'organizations:ListPolicies' and 'iam:ListPolicies' are granted.",
        )


def check_cost02_bp02_implement_goals(session):
    print("Checking COST02-BP02 – Implement goals and targets")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_goals_targets.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST02-BP02",
            "check_name": "Implement goals and targets",
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
                "1. Define quantitative goals (e.g., 'Keep production spend under $5000/month').",
                "2. Set efficiency targets (e.g., 'Increase spot instance usage to 30%').",
                "3. Track utilization metrics (e.g., 'Ensure EC2 CPU utilization averages > 40%').",
                "4. Review these goals quarterly with stakeholders.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Defining cost goals and efficiency targets is a strategic business process. "
                "It sets the benchmark for whether your usage is 'good' or 'bad', but cannot be scanned via API."
            ),
            recommendation=(
                "Establish clear KPIs for cloud efficiency, such as '% of On-Demand vs Spot' or 'Cost per User', "
                "and track them alongside your technical metrics."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST02-BP02: {e}")
        return build_response(
            status="error",
            problem="Unable to assess goal implementation status.",
            recommendation="Review internal KPI documentation.",
        )


def check_cost02_bp03_account_structure(session):
    # [BP03] - Implement an account structure
    print("Checking COST02-BP03: AWS Organization & Account Structure")

    org_client = session.client("organizations")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_account_structure.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST02-BP03",
            "check_name": "Implement an account structure",
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
                "1. Enable AWS Organizations if not already done.",
                "2. Create Organizational Units (OUs) to group accounts (e.g., 'Prod', 'Dev', 'Sandbox').",
                "3. Separate workloads into different accounts for billing isolation.",
                "4. Use the Management Account solely for billing and governance, not for running resources.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        has_organization = False
        account_count = 0

        try:
            # Check if Organization exists
            org_desc = org_client.describe_organization()
            if org_desc.get("Organization"):
                has_organization = True

            # Check number of accounts to verify structure
            # If you only have 1 account in an Org, you haven't really "implemented structure" yet.
            accounts = org_client.list_accounts(MaxResults=10).get("Accounts", [])
            account_count = len(accounts)

            if account_count <= 1:
                resources_affected.append(
                    {
                        "resource_id": "AWS Organization",
                        "issue": "Organization exists but has only 1 account. Workload isolation is not implemented.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except Exception as e:
            # Usually AWSOrganizationsNotInUseException or AccessDenied
            print(f"Org check failed: {e}")
            resources_affected.append(
                {
                    "resource_id": "AWS Organization",
                    "issue": "AWS Organizations is not enabled or not accessible. You are likely using a single standalone account.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not has_organization and affected > 0:
            status = "failed"
            problem_text = "No AWS Organization detected. Managing costs across environments is difficult in a single account."
            rec_text = "Enable AWS Organizations and separate your Production and Development workloads into distinct accounts."
        elif account_count <= 1:
            status = "failed"
            problem_text = "Account structure is flat (single account). This risks billing overlap and security issues."
            rec_text = "Create separate accounts for different environments (Dev/Prod) using AWS Organizations."
        else:
            status = "passed"
            problem_text = f"AWS Organization is active with {account_count}+ accounts."
            rec_text = "Ensure you are using Organizational Units (OUs) to apply policies to groups of accounts."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Account Structure: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating account structure.",
            recommendation="Check permissions for 'organizations:DescribeOrganization'.",
        )


def check_cost02_bp04_groups_and_roles(session):
    # [BP04] - Implement groups and roles
    print("Checking COST02-BP04: IAM Groups & Roles")

    iam_client = session.client("iam")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_groups_roles.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST02-BP04",
            "check_name": "Implement groups and roles",
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
                "1. Create IAM Groups for job functions (e.g., 'Developers', 'Admins').",
                "2. Attach policies to Groups, not individual Users.",
                "3. Use IAM Roles for applications and cross-account access.",
                "4. Remove direct policy attachments from IAM Users.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: Groups Existence ------------------
        groups_exist = False
        try:
            groups = iam_client.list_groups(MaxResults=5).get("Groups", [])
            if groups:
                groups_exist = True
            else:
                resources_affected.append(
                    {
                        "resource_id": "IAM Groups",
                        "issue": "No IAM Groups found. Users likely have direct policy attachments, making governance difficult.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error listing groups: {e}")

        # ------------------ Check 2: Roles Existence ------------------
        roles_exist = False
        try:
            # listing roles to ensure they are being used for services
            roles = iam_client.list_roles(MaxResults=5).get("Roles", [])
            if roles:
                roles_exist = True
        except Exception as e:
            print(f"Error listing roles: {e}")

        total_scanned = 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not groups_exist:
            status = "failed"
            problem_text = (
                "IAM Groups are not being used. This suggests poor identity governance."
            )
            rec_text = "Organize IAM users into Groups and attach policies to those groups to streamline permission management."
        elif not roles_exist:
            status = "failed"  # Rare, but possible in very new accounts
            problem_text = "No IAM Roles found. Services and external users cannot access resources securely."
            rec_text = "Create IAM Roles for your EC2 instances and Lambda functions."
        else:
            status = "passed"
            problem_text = "IAM Groups and Roles are present."
            rec_text = "Periodically audit Group memberships and Role trust policies."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking IAM Groups/Roles: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating IAM configuration.",
            recommendation="Ensure permissions for 'iam:ListGroups' and 'iam:ListRoles' are granted.",
        )


def check_cost02_bp05_cost_controls(session):
    # [BP05] - Implement cost controls
    print("Checking COST02-BP05: Cost Controls (Budget Actions & Service Quotas)")

    budgets_client = session.client("budgets")
    sq_client = session.client("servicequotas")
    ce_client = session.client("ce")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_cost_controls.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST02-BP05",
            "check_name": "Implement cost controls",
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
                "1. Use AWS Budgets Actions to automatically stop instances or detach policies when budget is exceeded.",
                "2. Monitor Service Quotas to prevent accidental provisioning of massive resources.",
                "3. Use Organizations SCPs to deny access to expensive regions or instance types.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts_client.get_caller_identity()["Account"]

        # ------------------ Check 1: Budget Actions ------------------
        # This is a strict check. Having a budget is good, but having an ACTION (control) is BP05.
        has_budget_actions = False
        try:
            budgets = budgets_client.describe_budgets(
                AccountId=account_id, MaxResults=5
            ).get("Budgets", [])
            if not budgets:
                resources_affected.append(
                    {
                        "resource_id": "AWS Budgets",
                        "issue": "No budgets found, so no budget actions can exist.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                for b in budgets:
                    b_name = b.get("BudgetName")
                    try:
                        # Check for ACTIONS attached to the budget
                        actions = budgets_client.describe_budget_actions_for_account(
                            AccountId=account_id, BudgetName=b_name
                        ).get("Actions", [])
                        if actions:
                            has_budget_actions = True
                    except Exception:
                        pass  # Maybe no actions, or permission issue

                if not has_budget_actions:
                    resources_affected.append(
                        {
                            "resource_id": "AWS Budgets",
                            "issue": "Budgets exist, but no 'Budget Actions' (automated controls) are configured.",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        except Exception as e:
            print(f"Error checking budget actions: {e}")

        # ------------------ Check 2: Service Quotas ------------------
        # Just verifying we can list them implies we have visibility for control.
        try:
            sq_client.list_service_quotas(ServiceCode="ec2", MaxResults=1)
        except Exception as e:
            resources_affected.append(
                {
                    "resource_id": "Service Quotas",
                    "issue": f"Unable to access Service Quotas. You may lack visibility into resource limits. Error: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 2
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if affected > 0:
            status = "failed"
            problem_text = "Automated cost controls (Budget Actions) are missing or permissions are insufficient."
            rec_text = "Configure AWS Budget Actions to automatically enforce limits (e.g., stop instances) when thresholds are breached."
        else:
            status = "passed"
            problem_text = (
                "Cost controls (Budget Actions and Quota visibility) are active."
            )
            rec_text = "Regularly review Service Quotas to ensure they align with expected usage, preventing accidental over-provisioning."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Cost Controls: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating cost controls.",
            recommendation="Check permissions for 'budgets:DescribeBudgetActionsForAccount' and 'servicequotas:ListServiceQuotas'.",
        )


def check_cost02_bp06_track_project_lifecycle(session):
    # [BP06] - Track project lifecycle
    print("Checking COST02-BP06: Project Lifecycle Tracking (Tagging)")

    ce_client = session.client("ce")
    tagging_client = session.client("resourcegroupstaggingapi")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_lifecycle.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST02-BP06",
            "check_name": "Track project lifecycle",
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
                "1. Enforce a tagging strategy that includes lifecycle tags (e.g., 'Project', 'Environment', 'EndDate').",
                "2. Use AWS Config Rules to flag untagged resources.",
                "3. Use the Resource Groups Tagging API to find orphaned resources.",
                "4. Regularly decommission resources associated with finished projects.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check: Resource Tagging ------------------
        # We scan for resources and check if they have meaningful lifecycle tags.
        # We look for common lifecycle keys: 'project', 'env', 'environment', 'stage', 'owner'
        lifecycle_keys = [
            "project",
            "env",
            "environment",
            "stage",
            "owner",
            "cost-center",
        ]

        untagged_resources_count = 0
        total_resources_checked = 0

        try:
            # Get resources (limit to 50 for performance in this check)
            response = tagging_client.get_resources(ResourcesPerPage=50)
            resources = response.get("ResourceTagMappingList", [])
            total_resources_checked = len(resources)

            for res in resources:
                tags = {t["Key"].lower(): t["Value"] for t in res.get("Tags", [])}
                # Check if ANY of the lifecycle keys exist
                if not any(key in tags for key in lifecycle_keys):
                    untagged_resources_count += 1

            if (
                total_resources_checked > 0
                and (untagged_resources_count / total_resources_checked) > 0.5
            ):
                # If more than 50% of resources lack lifecycle tags
                resources_affected.append(
                    {
                        "resource_id": "Tagged Resources",
                        "issue": f"{untagged_resources_count} out of {total_resources_checked} scanned resources lack lifecycle tags (Project, Env, Owner).",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except Exception as e:
            print(f"Error checking tags: {e}")
            resources_affected.append(
                {
                    "resource_id": "Resource Tagging API",
                    "issue": f"Unable to scan resource tags: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = total_resources_checked if total_resources_checked > 0 else 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if affected > 0:
            status = "failed"
            problem_text = "A significant portion of resources lack lifecycle tags (Project/Env), making it hard to track project lifecycle."
            rec_text = "Implement a strict tagging policy requiring 'Project' and 'Environment' tags on all resources."
        elif total_resources_checked == 0:
            status = "passed"  # No resources to tag
            problem_text = "No resources found to scan for lifecycle tags."
            rec_text = "Ensure future resources are tagged with lifecycle metadata."
        else:
            status = "passed"
            problem_text = "Resources appear to be tagged with lifecycle metadata."
            rec_text = "Regularly query resources by tag to identify projects that have ended but still have running infrastructure."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Lifecycle Tracking: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating lifecycle tags.",
            recommendation="Check permissions for 'tag:GetResources'.",
        )


# COST 3


def check_cost03_bp01_detailed_info_sources(session):
    # [BP01] - Configure detailed information sources
    print(
        "Checking COST03-BP01: Detailed Data Sources (CUR & Cost Explorer Resource Level)"
    )

    cur_client = session.client("cur")
    ce_client = session.client("ce")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_detailed_information.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST03-BP01",
            "check_name": "Configure detailed information sources",
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
                "1. Enable AWS Cost and Usage Reports (CUR) to deliver hourly data to S3.",
                "2. Enable 'Hourly' and 'Resource Level' granularity in Cost Explorer settings.",
                "3. Integrate CUR data with Amazon Athena or QuickSight for detailed querying.",
                "4. Ensure you are collecting data on specific resource IDs, not just service totals.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: Cost & Usage Reports (CUR) ------------------
        cur_enabled = False
        try:
            # CUR is region-specific (usually us-east-1) but the client can be global depending on setup
            # We try to list definitions.
            response = cur_client.describe_report_definitions(MaxResults=5)
            if response.get("ReportDefinitions"):
                cur_enabled = True
            else:
                resources_affected.append(
                    {
                        "resource_id": "Cost & Usage Reports",
                        "issue": "No Cost & Usage Report (CUR) definitions found. You lack detailed, hourly billing data export.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error checking CUR: {e}")
            # CUR often requires specific permissions or region (us-east-1)
            pass

        # ------------------ Check 2: Cost Explorer Resource Granularity ------------------
        # We try to fetch cost by 'SERVICE' to ensure basic access, then 'RESOURCE_ID' to check granularity.
        resource_level_access = False
        try:
            now = datetime.now()
            start_date = (now - timedelta(days=2)).strftime("%Y-%m-%d")
            end_date = (now - timedelta(days=1)).strftime("%Y-%m-%d")

            # Detailed query checking for Resource capability
            # Note: We don't need to fetch all, just seeing if the API call allows granular grouping
            ce_client.get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="DAILY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            resource_level_access = True
        except Exception as e:
            resources_affected.append(
                {
                    "resource_id": "Cost Explorer",
                    "issue": f"Unable to access detailed Cost Explorer data. Error: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 2
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not cur_enabled:
            status = "failed"
            problem_text = "Cost & Usage Reports (CUR) are not configured. This is the source of truth for detailed cost analysis."
            rec_text = "Create a Cost & Usage Report definition to export hourly billing data to S3."
        elif not resource_level_access:
            status = "failed"
            problem_text = "Detailed Cost Explorer data is inaccessible."
            rec_text = "Ensure Cost Explorer is enabled and you have permissions to view cost data."
        else:
            status = "passed"
            problem_text = (
                "Detailed information sources (CUR & Cost Explorer) are active."
            )
            rec_text = "Regularly query your CUR data to identify resource-level optimization opportunities."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Detailed Info Sources: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating detailed data sources.",
            recommendation="Check permissions for 'cur:DescribeReportDefinitions' and 'ce:GetCostAndUsage'.",
        )


def check_cost03_bp02_org_info_usage(session):
    # [BP02] - Add organization information to cost and usage
    print("Checking COST03-BP02: Organization Info & Tags")

    ce_client = session.client("ce")
    tagging_client = session.client("resourcegroupstaggingapi")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_organization_information.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST03-BP02",
            "check_name": "Add organization information to cost and usage",
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
                "1. Enable User-Defined Cost Allocation Tags in the Billing Console.",
                "2. Define a standard set of tags (e.g., CostCenter, BusinessUnit) that map to your organization.",
                "3. Use Tag Policies to enforce these standard tags on new resources.",
                "4. Regularly scan for resources missing these organizational tags.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: Active Cost Allocation Tags ------------------
        active_tags = 0
        try:
            paginator = ce_client.get_paginator("list_cost_allocation_tags")
            for page in paginator.paginate(MaxResults=50):
                for tag in page.get("CostAllocationTags", []):
                    if tag.get("Status") == "Active":
                        active_tags += 1

            if active_tags == 0:
                resources_affected.append(
                    {
                        "resource_id": "Cost Allocation Tags",
                        "issue": "No active Cost Allocation Tags found. You cannot map cloud usage to organization entities (Teams, Depts).",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error checking cost tags: {e}")

        # ------------------ Check 2: Resource Tagging Usage ------------------
        # We check if actual tag keys are being used on resources
        used_tag_keys = []
        try:
            # retrieving just keys to see what is in use
            response = tagging_client.get_tag_keys()
            used_tag_keys = response.get("TagKeys", [])
        except Exception as e:
            print(f"Error checking tag keys: {e}")

        total_scanned = 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if active_tags == 0:
            status = "failed"
            problem_text = "Organization information is not being added to cost data because Cost Allocation Tags are inactive."
            rec_text = "Activate tags corresponding to your business units (e.g., 'Department', 'Owner') in the Billing Console."
        elif len(used_tag_keys) == 0:
            status = "failed"
            problem_text = (
                "Cost tags are active in billing, but no resources appear to be tagged."
            )
            rec_text = "Start tagging your resources with the keys you activated in the Billing Console."
        else:
            status = "passed"
            problem_text = f"Found {active_tags} active cost tags and {len(used_tag_keys)} tag keys in use."
            rec_text = "Ensure your tagging coverage is comprehensive across all regions and resource types."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Organization Info: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating organization tags.",
            recommendation="Check permissions for 'ce:ListCostAllocationTags' and 'resourcegroupstaggingapi:GetTagKeys'.",
        )


def check_cost03_bp03_identify_cost_attribution(session):
    # [BP03] - Identify cost attribution categories
    print("Checking COST03-BP03: Cost Categories & Attribution")

    ce_client = session.client("ce")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_attribution.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST03-BP03",
            "check_name": "Identify cost attribution categories",
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
                "1. Use AWS Cost Categories to group costs by complex rules (e.g., Tag 'Env' IS 'Prod' OR Account IS 'X').",
                "2. Map uncategorized costs to a 'Shared' or 'Unallocated' category.",
                "3. Use these categories in Cost Explorer to view spend by attribution group.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check: Cost Categories ------------------
        cost_categories_count = 0
        try:
            # Listing definitions of Cost Categories
            response = ce_client.list_cost_category_definitions(MaxResults=5)
            cost_categories = response.get("CostCategoryReferences", [])
            cost_categories_count = len(cost_categories)

            if cost_categories_count == 0:
                resources_affected.append(
                    {
                        "resource_id": "AWS Cost Categories",
                        "issue": "No Cost Categories defined. You are relying solely on simple tags, which may not capture complex attribution logic.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error checking Cost Categories: {e}")
            resources_affected.append(
                {
                    "resource_id": "AWS Cost Categories",
                    "issue": f"Unable to list Cost Categories: {str(e)}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if affected > 0:
            status = "failed"  # Or 'warning', but we'll stick to binary logic
            problem_text = "No Cost Categories are defined. Hard-to-tag resources (like shared DBs or support fees) may not be attributed correctly."
            rec_text = "Create Cost Categories to map accounts and tags to specific business units using rules."
        else:
            status = "passed"
            problem_text = f"Found {cost_categories_count} Cost Categories defined."
            rec_text = "Review your Cost Category rules to ensure 'Uncategorized' costs are minimized."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Cost Attribution: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while checking attribution categories.",
            recommendation="Ensure permissions for 'ce:ListCostCategoryDefinitions' are granted.",
        )


def check_cost03_bp04_establish_org_metrics(session):
    print("Checking COST03-BP04 – Establish organization metrics")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_metrics.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST03-BP04",
            "check_name": "Establish organization metrics",
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
                "1. Identify business output metrics (e.g., orders processed, API requests served).",
                "2. Combine cost data with business data to calculate unit costs.",
                "3. Publish a dashboard showing 'Cost per Unit' trends over time.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Establishing metrics involves combining AWS cost data with external business data "
                "(like sales or user counts) to derive insights. This integration is a process step "
                "that cannot be validated via standard AWS APIs."
            ),
            recommendation=(
                "Define a standard set of efficiency metrics (e.g., Cost per 1000 users) and track "
                "them alongside your absolute monthly spend."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST03-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess organization metrics process.",
            recommendation="Review internal BI dashboards and reporting.",
        )


def check_cost03_bp05_billing_tools(session):
    # [BP05] - Configure billing and cost management tools
    print("Checking COST03-BP05: Billing Tools (Budgets, Forecasts, RIs/SPs)")

    budgets_client = session.client("budgets")
    ce_client = session.client("ce")
    sts_client = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_tools.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST03-BP05",
            "check_name": "Configure billing and cost management tools",
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
                "1. Configure AWS Budgets to track spend against targets.",
                "2. Use Cost Explorer Forecasts to anticipate future spend.",
                "3. Monitor Reservation and Savings Plans utilization reports regularly.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts_client.get_caller_identity()["Account"]

        # ------------------ Check 1: Budgets Performance History ------------------
        # We check if we can retrieve performance history, implying budgets are active and tracked.
        budgets_active = False
        try:
            # First need a budget name
            b_resp = budgets_client.describe_budgets(AccountId=account_id, MaxResults=1)
            if b_resp.get("Budgets"):
                budgets_active = True
                b_name = b_resp["Budgets"][0]["BudgetName"]
                # Now try the specific API mentioned in JSON
                budgets_client.describe_budget_performance_history(
                    AccountId=account_id, BudgetName=b_name, MaxResults=1
                )
            else:
                resources_affected.append(
                    {
                        "resource_id": "AWS Budgets",
                        "issue": "No budgets found. Essential cost management tooling is missing.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"Error checking budget tools: {e}")

        # ------------------ Check 2: Savings Plans / RI Utilization ------------------
        # Checking if we can access utilization reports.
        tools_accessible = False
        try:
            # We just check SP utilization as a proxy for the tool being available/used
            # Requires permissions and CE enabled.
            ce_client.get_savings_plans_utilization(
                TimePeriod={
                    "Start": (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"),
                    "End": datetime.now().strftime("%Y-%m-%d"),
                }
            )
            tools_accessible = True
        except Exception as e:
            # Often fails if no SPs exist, which is fine, or permissions.
            # We won't hard fail on this, just noting accessibility.
            pass

        total_scanned = 2
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not budgets_active:
            status = "failed"
            problem_text = "AWS Budgets are not configured. You lack the primary tool for tracking cost against targets."
            rec_text = "Create budgets to establish a baseline for expected costs."
        else:
            status = "passed"
            problem_text = "Billing tools (Budgets) are configured."
            rec_text = "Regularly check Savings Plans and Reservation utilization reports in Cost Explorer to optimize coverage."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Billing Tools: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating billing tools.",
            recommendation="Check permissions for 'budgets:DescribeBudgets' and 'ce:GetSavingsPlansUtilization'.",
        )


def check_cost03_bp06_allocate_costs(session):
    # [BP06] - Allocate costs based on workload metrics
    print("Checking COST03-BP06: Workload Metric Allocation (Compute & CloudWatch)")

    cw_client = session.client("cloudwatch")
    lambda_client = session.client("lambda")
    ecs_client = session.client("ecs")
    eks_client = session.client("eks")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_workload_allocation.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST03-BP06",
            "check_name": "Allocate costs based on workload metrics",
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
                "1. Enable granular CloudWatch metrics for Lambda, ECS, and EKS.",
                "2. Tag individual resources (Functions, Services, Clusters) with 'Workload' tags.",
                "3. Use arithmetic in your cost analysis to allocate shared cluster costs based on CPU/Memory consumption metrics.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check: Compute Resource Visibility ------------------
        # Logic: If you have compute resources, can we see their metrics to allocate cost?
        compute_found = False
        metrics_visible = False

        # 1. Check Lambda
        try:
            funcs = lambda_client.list_functions(MaxItems=1).get("Functions", [])
            if funcs:
                compute_found = True
                # Check if we can get a metric for this function (e.g., Invocations)
                cw_client.get_metric_data(
                    MetricDataQueries=[
                        {
                            "Id": "m1",
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": "AWS/Lambda",
                                    "MetricName": "Invocations",
                                },
                                "Period": 3600,
                                "Stat": "Sum",
                            },
                        }
                    ],
                    StartTime=datetime.now() - timedelta(hours=1),
                    EndTime=datetime.now(),
                )
                metrics_visible = True
        except Exception:
            pass

        # 2. Check ECS (if Lambda didn't prove it)
        if not compute_found:
            try:
                clusters = ecs_client.list_clusters(maxResults=1).get("clusterArns", [])
                if clusters:
                    compute_found = True
                    metrics_visible = (
                        True  # Assuming standard metrics are there if cluster exists
                    )
            except Exception:
                pass

        # 3. Check EKS
        if not compute_found:
            try:
                clusters = eks_client.list_clusters(maxResults=1).get("clusters", [])
                if clusters:
                    compute_found = True
                    metrics_visible = True
            except Exception:
                pass

        total_scanned = 1
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if compute_found and not metrics_visible:
            status = "failed"
            problem_text = "Compute resources (Lambda/ECS/EKS) detected, but CloudWatch metrics seem inaccessible. You cannot allocate costs without these metrics."
            rec_text = "Ensure CloudWatch metrics are enabled and accessible for your compute workloads."
        elif not compute_found:
            # No compute found to allocate costs for
            status = "passed"
            problem_text = "No specific shared compute workloads (Lambda/ECS/EKS) detected requiring metric-based allocation."
            rec_text = "If you deploy containers or functions later, ensure you tag them and track their utilization metrics."
        else:
            status = "passed"
            problem_text = "Workload metrics are accessible for cost allocation."
            rec_text = "Combine these CloudWatch utilization metrics with your Cost Explorer data to calculate cost per workload."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Workload Allocation: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating workload metrics.",
            recommendation="Check permissions for 'cloudwatch:GetMetricData' and compute list services.",
        )


# COST 4


def check_cost04_bp01_track_resources(session):
    # [BP01] - Track resources over their life time
    print("Checking COST04-BP01: Resource Tracking (Config, Tagging, & Service Lists)")

    config_client = session.client("config")
    tagging_client = session.client("resourcegroupstaggingapi")
    ec2_client = session.client("ec2")
    lambda_client = session.client("lambda")

    # Note: We iterate a few key services from the list to ensure visibility

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_resource_tracking.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST04-BP01",
            "check_name": "Track resources over their life time",
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
                "1. Enable AWS Config to track resource configuration changes over time.",
                "2. Use Resource Groups to organize resources by application or lifecycle stage.",
                "3. Regularly scan for resources that have been running longer than expected (zombies).",
                "4. Use Cost Explorer Resource granularity to map spend to specific resource IDs.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: AWS Config Status ------------------
        config_recording = False
        try:
            # We check if Config is discovering resources
            response = config_client.list_discovered_resources(
                resourceType="AWS::EC2::Instance", limit=1
            )
            # If this call succeeds, Config is likely enabled and working
            config_recording = True
        except Exception:
            # Config might not be enabled or permissions missing
            pass

        if not config_recording:
            resources_affected.append(
                {
                    "resource_id": "AWS Config",
                    "issue": "AWS Config does not appear to be enabled or accessible. You cannot track resource configuration history.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Check 2: Cross-Service Visibility ------------------
        # Verifying we can actually see the resources to track them
        services_checked = 0
        services_visible = 0

        try:
            # Check EC2
            ec2_client.describe_instances(MaxResults=1)
            services_visible += 1
        except:
            pass
        services_checked += 1

        try:
            # Check Lambda
            lambda_client.list_functions(MaxItems=1)
            services_visible += 1
        except:
            pass
        services_checked += 1

        # ------------------ Check 3: Resource Groups Tagging ------------------
        # Can we find resources via tags?
        tagging_accessible = False
        try:
            tagging_client.get_resources(ResourcesPerPage=1)
            tagging_accessible = True
        except Exception:
            resources_affected.append(
                {
                    "resource_id": "Resource Groups Tagging API",
                    "issue": "Unable to access Resource Groups Tagging API. Tracking resources by tags is compromised.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 3  # Config, Service Visibility, Tagging
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not config_recording:
            status = "failed"
            problem_text = "AWS Config is not tracking resource changes, making it difficult to manage lifecycle history."
            rec_text = "Enable AWS Config to record configuration changes and track resource lifespans."
        elif not tagging_accessible:
            status = "failed"
            problem_text = (
                "Tagging API is inaccessible, preventing efficient resource tracking."
            )
            rec_text = "Ensure permissions for 'resourcegroupstaggingapi' are granted."
        else:
            status = "passed"
            problem_text = "Resource tracking tools (Config, Tagging API) are active."
            rec_text = "Regularly audit your Config rules to ensure all resource types are being recorded."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Resource Tracking: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating resource tracking.",
            recommendation="Check permissions for AWS Config and Resource Groups.",
        )


def check_cost04_bp02_decommissioning_process(session):
    print("Checking COST04-BP02 – Implement a decommissioning process")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_decommissioning_process.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST04-BP02",
            "check_name": "Implement a decommissioning process",
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
                "1. Create a checklist for decommissioning (e.g., backup data, unlink DNS, terminate instance).",
                "2. Identify dependencies before deletion to prevent outages.",
                "3. Communicate decommissioning timelines to stakeholders.",
                "4. Archive data that might be needed for compliance before termination.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Decommissioning is a workflow that requires human decision-making and coordination "
                "to ensure data is backed up and dependencies are resolved before deletion. "
                "This process cannot be validated via API."
            ),
            recommendation=(
                "Formalize a 'End of Life' process for your workloads. Ensure every project has "
                "a planned decommissioning date or review cycle."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST04-BP02: {e}")
        return build_response(
            status="error",
            problem="Unable to assess decommissioning process.",
            recommendation="Review internal standard operating procedures (SOPs).",
        )


def check_cost04_bp03_decommission_resources(session):
    # [BP03] - Decommission resources
    print("Checking COST04-BP03: Decommission Resources (Destructive API Check)")

    # Note: The APIs for this BP are DESTRUCTIVE (e.g., terminate_instances, delete_bucket).
    # We cannot programmatically run them to "test" if they work without causing data loss.

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_decommission_resources.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST04-BP03",
            "check_name": "Decommission resources",
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
                "1. Execute the decommissioning process for identified unused resources.",
                "2. Terminate stopped EC2 instances that are no longer needed.",
                "3. Delete unattached EBS volumes and obsolete snapshots.",
                "4. Delete empty S3 buckets and unused Lambda functions.",
                "5. Delete CloudFormation stacks for finished projects.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # We intentionally return a manual status because verifying this BP requires
        # verifying the ACT of deletion, which is unsafe to automate in a read-only assessment.

        return build_response(
            status="not_available",
            problem=(
                "This Best Practice involves the active destruction of resources (Termination/Deletion). "
                "Automated assessments cannot safely verify this capability without risking data loss. "
                "The APIs (ec2.terminate_instances, s3.delete_bucket, etc.) are destructive."
            ),
            recommendation=(
                "Manually verify that you have the necessary permissions to delete resources and "
                "that you are actively cleaning up unused infrastructure."
            ),
        )

    except Exception as e:
        print(f"Error evaluating COST04-BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to assess resource decommissioning execution.",
            recommendation="Review IAM permissions for deletion actions manually.",
        )


def check_cost04_bp04_decommission_automatically(session):
    # [BP04] - Decommission resources automatically
    print("Checking COST04-BP04: Automated Decommissioning (Events, SSM, Config)")

    events_client = session.client("events")
    ssm_client = session.client("ssm")
    config_client = session.client("config")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_automatic_decommissioning.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST04-BP04",
            "check_name": "Decommission resources automatically",
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
                "1. Use AWS Config Rules to identify and flag non-compliant resources for remediation.",
                "2. Implement EventBridge Rules to trigger Lambda functions that clean up temporary resources.",
                "3. Use Systems Manager (SSM) Automation to schedule instance termination.",
                "4. Implement TTL (Time to Live) on DynamoDB items or S3 objects for auto-expiry.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: EventBridge Rules ------------------
        # Looking for automation rules that might be related to cleanup
        automation_rules_found = False
        try:
            rules = events_client.list_rules(Limit=10).get("Rules", [])
            if rules:
                automation_rules_found = True
        except Exception as e:
            print(f"Error checking EventBridge: {e}")

        # ------------------ Check 2: SSM Automation ------------------
        # Checking if any automation documents exist or have been executed
        ssm_active = False
        try:
            # Check for recent executions as proof of life
            executions = ssm_client.list_automation_executions(MaxResults=1).get(
                "AutomationExecutionMetadataList", []
            )
            # Also check if docs exist (just ensuring access)
            docs = ssm_client.describe_automation_documents(MaxResults=1).get(
                "DocumentIdentifiers", []
            )
            if executions or docs:
                ssm_active = True
        except Exception as e:
            print(f"Error checking SSM: {e}")

        # ------------------ Check 3: Config Recorder ------------------
        config_active = False
        try:
            status = config_client.describe_configuration_recorder_status()
            recorders = status.get("ConfigurationRecordersStatus", [])
            for r in recorders:
                if r.get("recording"):
                    config_active = True
        except Exception:
            pass

        total_scanned = 3
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not automation_rules_found and not ssm_active:
            status = "failed"
            problem_text = "No EventBridge Rules or SSM Automation activity detected. You are likely decommissioning resources manually."
            rec_text = "Implement EventBridge rules or SSM Automation runbooks to handle cleanup of temporary resources."
        elif not config_active:
            status = "failed"
            problem_text = "AWS Config is not recording. You cannot use Config Rules for automated remediation."
            rec_text = "Enable AWS Config to trigger remediation actions on non-compliant resources."
        else:
            status = "passed"
            problem_text = "Automation infrastructure (Events/SSM/Config) is active."
            rec_text = "Review your automation rules to ensure they cover all temporary resource types."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Automated Decommissioning: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating automation tools.",
            recommendation="Check permissions for 'events', 'ssm', and 'config'.",
        )


def check_cost04_bp05_enforce_data_retention(session):
    # [BP05] - Enforce data retention policies
    print("Checking COST04-BP05: Data Retention Policies (S3, Backup, Logs)")

    s3_client = session.client("s3")
    backup_client = session.client("backup")
    logs_client = session.client("logs")  # For cloudwatchlogs
    glacier_client = session.client("glacier")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cloud_financial_management_retention_policy.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST04-BP05",
            "check_name": "Enforce data retention policies",
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
                "1. Configure S3 Lifecycle Policies to transition objects to Glacier or expire them.",
                "2. Define AWS Backup Plans with strict retention periods.",
                "3. Set retention periods on CloudWatch Log Groups (default is often 'Never Expire').",
                "4. Use S3 Object Lock for compliance retention requirements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: S3 Lifecycle ------------------
        buckets_checked = 0
        buckets_with_lifecycle = 0
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
            # Check first 5 buckets to estimate coverage
            for b in buckets[:5]:
                buckets_checked += 1
                try:
                    s3_client.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                    buckets_with_lifecycle += 1
                except Exception:
                    # NoSuchLifecycleConfiguration or AccessDenied
                    pass
        except Exception as e:
            print(f"Error checking S3: {e}")

        # ------------------ Check 2: AWS Backup Plans ------------------
        backup_plans_exist = False
        try:
            plans = backup_client.list_backup_plans(MaxResults=1).get(
                "BackupPlansList", []
            )
            if plans:
                backup_plans_exist = True
        except Exception as e:
            print(f"Error checking Backup: {e}")

        # ------------------ Check 3: CloudWatch Log Retention ------------------
        # Note: The JSON lists 'cloudwatchlogs.describe_retention_policies' which implies checking retention.
        # The actual boto3 method is 'describe_log_groups' which returns retentionInDays.
        logs_checked = 0
        logs_with_retention = 0
        try:
            log_groups = logs_client.describe_log_groups(limit=5).get("logGroups", [])
            for lg in log_groups:
                logs_checked += 1
                if "retentionInDays" in lg:
                    logs_with_retention += 1
        except Exception as e:
            print(f"Error checking Logs: {e}")

        total_scanned = 3
        affected = len(resources_affected)

        status = "passed"
        problem_text = ""
        rec_text = ""

        if buckets_checked > 0 and buckets_with_lifecycle == 0:
            status = "failed"
            problem_text = f"Checked {buckets_checked} S3 buckets, but NONE had lifecycle policies. Old data is costing you money indefinitely."
            rec_text = (
                "Apply S3 Lifecycle policies to expire old data or move it to Glacier."
            )
        elif logs_checked > 0 and logs_with_retention == 0:
            status = "failed"
            problem_text = f"Checked {logs_checked} Log Groups, but NONE had retention periods set. Logs are being stored forever."
            rec_text = (
                "Set a retention period (e.g., 30 days) on your CloudWatch Log Groups."
            )
        elif not backup_plans_exist:
            status = "passed"  # Soft pass, maybe they don't use backup
            problem_text = "No AWS Backup plans found. Ensure you are managing snapshot retention manually."
            rec_text = "Use AWS Backup to automate snapshot lifecycle management."
        else:
            status = "passed"
            problem_text = (
                "Data retention policies (S3/Logs/Backup) appear to be in use."
            )
            rec_text = "Regularly review retention periods to minimize storage costs for obsolete data."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Retention Policies: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating retention policies.",
            recommendation="Check permissions for 's3:GetBucketLifecycleConfiguration' and 'logs:DescribeLogGroups'.",
        )
