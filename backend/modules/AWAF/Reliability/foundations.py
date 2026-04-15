from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

def check_rel01_bp01_aware_of_service_quotas(session):
    print("Checking REL01-BP01 - Aware of service quotas and constraints")

    sq = session.client("service-quotas")
    ec2 = session.client("ec2")
    org = session.client("organizations")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_manage_service_limits_aware_quotas_and_constraints.html"

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
            "id": "REL01-BP01",
            "check_name": "Aware of service quotas and constraints",
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
                "1. Review AWS service quotas in the Service Quotas console.",
                "2. Configure CloudWatch alarms or EventBridge monitoring for quota thresholds.",
                "3. Request quota increases proactively based on workload scaling needs.",
                "4. Identify critical quotas such as EC2 vCPU limits, API limits, and EIP quotas.",
                "5. For large workloads, use AWS Organizations multi-account strategy to split usage.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Service Quotas (list) ------------------------
        try:
            quotas = sq.list_service_quotas(ServiceCode="ec2")
            quotas_present = len(quotas.get("Quotas", [])) > 0
        except Exception as e:
            print(f"service-quotas.list_service_quotas error: {e}")
            quotas_present = False

        # ------------------------ Specific quota check (vCPU limit) ------------------------
        try:
            specific_quota = sq.get_service_quota(
                ServiceCode="ec2",
                QuotaCode="L-1216C47A",  # On-Demand Standard Instances vCPU Limit
            )
            specific_quota_present = bool(specific_quota.get("Quota"))
        except Exception as e:
            print(f"service-quotas.get_service_quota error: {e}")
            specific_quota_present = False

        # ------------------------ EC2 account attributes ------------------------
        try:
            account_attrs = ec2.describe_account_attributes()
            ec2_attrs_present = len(account_attrs.get("AccountAttributes", [])) > 0
        except Exception as e:
            print(f"ec2.describe_account_attributes error: {e}")
            ec2_attrs_present = False

        # ------------------------ Organizations account check ------------------------
        try:
            org_accounts = org.list_accounts()
            org_accounts_present = len(org_accounts.get("Accounts", [])) > 0
        except Exception as e:
            print(f"organizations.list_accounts error: {e}")
            org_accounts_present = False

        # ------------------------ Evaluation Logic ------------------------
        if not any(
            [
                quotas_present,
                specific_quota_present,
                ec2_attrs_present,
                org_accounts_present,
            ]
        ):
            affected = 1
            resources_affected.append(
                {
                    "resource_id": "service_quotas",
                    "issue": (
                        "Could not retrieve service quotas, EC2 attributes, or organization account data. "
                        "This indicates service quota awareness is not properly implemented."
                    ),
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without monitoring and understanding service quotas, workloads may hit AWS limits, "
                "leading to deployment failures, throttling, or service disruptions."
            ),
            recommendation=(
                "Regularly validate service quotas using Service Quotas API, EC2 account attributes, "
                "and AWS Organizations data. Implement monitoring and automate quota increase requests."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL01-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating service quota awareness.",
            recommendation="Verify IAM permissions and ensure Service Quotas, EC2, and Organizations APIs are accessible.",
        )


def check_rel01_bp02_manage_service_quotas(session):
    print("Checking REL01-BP02 - Manage service quotas across accounts and regions")

    sq = session.client("service-quotas")
    org = session.client("organizations")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_manage_service_limits_limits_considered.html"

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
            "id": "REL01-BP02",
            "check_name": "Manage service quotas across accounts and regions",
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
                "1. Use AWS Organizations to centrally manage service quotas across accounts.",
                "2. Implement automated quota monitoring using CloudWatch and Service Quotas APIs.",
                "3. Review and request quota increases proactively based on usage patterns.",
                "4. Document quota change history and maintain governance processes.",
                "5. Set up cross-region quota monitoring for critical services.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Get current account identity ------------------------
        try:
            caller_identity = sts.get_caller_identity()
            current_account = caller_identity.get("Account")
        except Exception as e:
            print(f"sts.get_caller_identity error: {e}")
            current_account = None

        # ------------------------ Check default service quotas ------------------------
        try:
            default_quotas = sq.list_aws_default_service_quotas(ServiceCode="ec2")
            default_quotas_available = len(default_quotas.get("Quotas", [])) > 0
        except Exception as e:
            print(f"service-quotas.list_aws_default_service_quotas error: {e}")
            default_quotas_available = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "default_quotas",
                    "issue": "Cannot retrieve default service quotas for quota management",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check specific default quota ------------------------
        try:
            default_quota = sq.get_aws_default_service_quota(
                ServiceCode="ec2",
                QuotaCode="L-1216C47A",  # On-Demand Standard Instances vCPU Limit
            )
            specific_default_available = bool(default_quota.get("Quota"))
        except Exception as e:
            print(f"service-quotas.get_aws_default_service_quota error: {e}")
            specific_default_available = False

        # ------------------------ Check quota change history ------------------------
        try:
            quota_history = sq.list_requested_service_quota_change_history(
                ServiceCode="ec2"
            )
            quota_management_active = len(quota_history.get("RequestedQuotas", [])) > 0
        except Exception as e:
            print(
                f"service-quotas.list_requested_service_quota_change_history error: {e}"
            )
            quota_management_active = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "quota_history",
                    "issue": "No quota change history found - indicates lack of proactive quota management",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check organization accounts ------------------------
        try:
            org_accounts = org.list_accounts()
            multi_account_setup = len(org_accounts.get("Accounts", [])) > 1
            if not multi_account_setup:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "organization",
                        "issue": "Single account setup - consider multi-account strategy for quota distribution",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"organizations.list_accounts error: {e}")
            multi_account_setup = False

        # ------------------------ Evaluation Logic ------------------------
        if not default_quotas_available and not specific_default_available:
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "quota_visibility",
                    "issue": "Cannot access service quota information for management across accounts/regions",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper service quota management across accounts and regions, "
                "workloads may face unexpected limits, leading to service disruptions and deployment failures."
            ),
            recommendation=(
                "Implement centralized quota management using AWS Organizations, monitor quota usage "
                "across regions, and maintain proactive quota increase processes."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL01-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating service quota management.",
            recommendation="Verify IAM permissions for Service Quotas, Organizations, and STS APIs.",
        )


def check_rel01_bp03_accommodate_fixed_quotas(session):
    print(
        "Checking REL01-BP03 - Accommodate fixed service quotas and constraints through architecture"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_manage_service_limits_aware_fixed_limits.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL01-BP03",
            "check_name": "Accommodate fixed service quotas and constraints through architecture",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Design architecture to work within fixed service quotas and constraints.",
                "2. Implement horizontal scaling to distribute load across resources.",
                "3. Use multi-region or multi-account deployment strategies.",
                "4. Implement graceful degradation patterns when nearing limits.",
                "5. Use rate-limiting and circuit breaker patterns in applications.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # This best practice CANNOT be validated using AWS APIs.
        # Architectural decisions such as horizontal scaling, multi-region design,
        # and quota-aware planning are based on documentation and design patterns,
        # not on programmatic inspection.

        return build_response(
            status="not_available",
            problem=(
                "AWS does not provide APIs to determine whether your architecture "
                "accommodates fixed service quotas such as multi-region design, "
                "horizontal scaling, or graceful degradation. These decisions must "
                "be documented by architects and validated during design reviews."
            ),
            recommendation=(
                "Review your workload architecture to ensure it accounts for fixed AWS service "
                "quotas. Document strategies such as multi-region failover, load distribution, "
                "rate limiting, and patterns that avoid single-region or single-resource bottlenecks."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL01-BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to assess architectural patterns for quota accommodation.",
            recommendation="Review architectural documentation and AWS Well-Architected guidance.",
        )


def check_rel01_bp04_monitor_manage_quotas(session):
    print("Checking REL01-BP04 - Monitor and manage quotas")

    cw = session.client("cloudwatch")
    sq = session.client("service-quotas")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_manage_service_limits_monitor_manage_limits.html"

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
            "id": "REL01-BP04",
            "check_name": "Monitor and manage quotas",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Set up CloudWatch alarms for service quota utilization monitoring.",
                "2. Use Service Quotas API to programmatically track quota usage.",
                "3. Implement automated alerting when approaching quota thresholds.",
                "4. Create dashboards to visualize quota utilization across services.",
                "5. Establish processes for proactive quota management and increases.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check CloudWatch metrics ------------------------
        try:
            metrics = cw.list_metrics(Namespace="AWS/Usage")
            usage_metrics_available = len(metrics.get("Metrics", [])) > 0
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")
            usage_metrics_available = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "cloudwatch_metrics",
                    "issue": "Cannot retrieve CloudWatch usage metrics for quota monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check CloudWatch alarms ------------------------
        try:
            alarms = cw.describe_alarms()
            quota_alarms = [
                alarm
                for alarm in alarms.get("MetricAlarms", [])
                if "quota" in alarm.get("AlarmName", "").lower()
                or "usage" in alarm.get("AlarmName", "").lower()
            ]
            quota_monitoring_active = len(quota_alarms) > 0
            if not quota_monitoring_active:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "quota_alarms",
                        "issue": "No CloudWatch alarms found for quota monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")
            quota_monitoring_active = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "alarm_access",
                    "issue": "Cannot access CloudWatch alarms for quota monitoring setup",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check service quotas ------------------------
        try:
            quotas = sq.list_service_quotas(ServiceCode="ec2")
            quotas_accessible = len(quotas.get("Quotas", [])) > 0
        except Exception as e:
            print(f"service-quotas.list_service_quotas error: {e}")
            quotas_accessible = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "service_quotas",
                    "issue": "Cannot access service quotas for monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check specific quota monitoring ------------------------
        try:
            specific_quota = sq.get_service_quota(
                ServiceCode="ec2",
                QuotaCode="L-1216C47A",  # On-Demand Standard Instances vCPU Limit
            )
            specific_quota_accessible = bool(specific_quota.get("Quota"))
        except Exception as e:
            print(f"service-quotas.get_service_quota error: {e}")
            specific_quota_accessible = False

        # ------------------------ Check metric data availability ------------------------
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            metric_data = cw.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "quota_usage",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Usage",
                                "MetricName": "ResourceCount",
                            },
                            "Period": 3600,
                            "Stat": "Maximum",
                        },
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            metric_data_available = len(metric_data.get("MetricDataResults", [])) > 0
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")
            metric_data_available = False

        # ------------------------ Evaluation Logic ------------------------
        if not quotas_accessible or not specific_quota_accessible:
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "quota_management",
                    "issue": "Service quota monitoring and management capabilities are not properly configured",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper quota monitoring and management, workloads may unexpectedly "
                "hit service limits, causing failures and service disruptions."
            ),
            recommendation=(
                "Implement comprehensive quota monitoring using CloudWatch metrics and alarms, "
                "Service Quotas API, and automated alerting for proactive quota management."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL01-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating quota monitoring and management.",
            recommendation="Verify IAM permissions for CloudWatch and Service Quotas APIs.",
        )


def check_rel01_bp05_automate_quota_management(session):
    print("Checking REL01-BP05 - Automate quota management")

    sq = session.client("service-quotas")
    lambda_client = session.client("lambda")
    events = session.client("events")
    ssm = session.client("ssm")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_manage_service_limits_automated_monitor_limits.html"

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
            "id": "REL01-BP05",
            "check_name": "Automate quota management",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Implement Lambda functions for automated quota increase requests.",
                "2. Set up EventBridge rules to trigger quota management workflows.",
                "3. Use Systems Manager Automation for quota management processes.",
                "4. Create automated monitoring and alerting for quota thresholds.",
                "5. Implement approval workflows for quota increase requests.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Check quota increase capability ------------------------
        try:
            # Test if we can access the quota increase API (without actually requesting)
            # This is a dry-run check to see if automation is possible
            test_quota = sq.get_service_quota(
                ServiceCode="ec2",
                QuotaCode="L-1216C47A",  # On-Demand Standard Instances vCPU Limit
            )
            quota_increase_accessible = bool(test_quota.get("Quota"))
        except Exception as e:
            print(f"service-quotas.request_service_quota_increase access error: {e}")
            quota_increase_accessible = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "quota_increase_api",
                    "issue": "Cannot access Service Quotas API for automated quota increases",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check Lambda functions ------------------------
        try:
            functions = lambda_client.list_functions()
            quota_functions = [
                func
                for func in functions.get("Functions", [])
                if "quota" in func.get("FunctionName", "").lower()
            ]
            automation_functions_exist = len(quota_functions) > 0
            if not automation_functions_exist:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_automation",
                        "issue": "No Lambda functions found for quota management automation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")
            automation_functions_exist = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "lambda_access",
                    "issue": "Cannot access Lambda service for automation setup",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check EventBridge rules ------------------------
        try:
            rules = events.list_rules()
            quota_rules = [
                rule
                for rule in rules.get("Rules", [])
                if "quota" in rule.get("Name", "").lower()
                or "usage" in rule.get("Name", "").lower()
            ]
            event_automation_exists = len(quota_rules) > 0
            if not event_automation_exists:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_rules",
                        "issue": "No EventBridge rules found for quota management automation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")
            event_automation_exists = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "events_access",
                    "issue": "Cannot access EventBridge for automation setup",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check Systems Manager Automation ------------------------
        try:
            # Check if we can access SSM automation (without starting execution)
            # This validates automation capability
            ssm.describe_automation_executions(MaxResults=1)
            ssm_automation_accessible = True
        except Exception as e:
            print(f"ssm.start_automation_execution access error: {e}")
            ssm_automation_accessible = False
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "ssm_automation",
                    "issue": "Cannot access Systems Manager Automation for quota management",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Evaluation Logic ------------------------
        if not any(
            [
                automation_functions_exist,
                event_automation_exists,
                ssm_automation_accessible,
            ]
        ):
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "automation_infrastructure",
                    "issue": "No automation infrastructure found for quota management",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated quota management, manual processes may be too slow to "
                "prevent service disruptions when approaching quota limits."
            ),
            recommendation=(
                "Implement automated quota management using Lambda functions, EventBridge rules, "
                "and Systems Manager Automation to proactively manage service quotas."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL01-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating quota automation.",
            recommendation="Verify IAM permissions for Service Quotas, Lambda, EventBridge, and SSM APIs.",
        )


def check_rel01_bp06_sufficient_quota_gap_for_failover(session):
    print("Checking REL01-BP06 - Ensure sufficient gap between current quotas and maximum usage for failover")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_manage_service_limits_suff_buffer_limits.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL01-BP06",
            "check_name": "Ensure sufficient gap between quotas and usage for failover",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Calculate maximum resource usage during normal operations across all regions.",
                "2. Ensure quotas allow for 100% failover capacity in alternate regions.",
                "3. Implement quota monitoring to maintain sufficient headroom (recommend 50%+ buffer).",
                "4. Design multi-region architecture with quota distribution planning.",
                "5. Regularly test failover scenarios to validate quota sufficiency.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # This best practice CANNOT be validated programmatically.
        
        return build_response(
            status="not_available",
            problem=(
                "Failover quota gap cannot be programmatically assessed because AWS does not "
                "expose APIs to determine disaster recovery capacity requirements or architectural "
                "failover strategies. These must be defined and documented by architects."
            ),
            recommendation=(
                "Document maximum workload usage, required failover capacity, and quota buffers. "
                "Validate that alternate regions have enough unused quota to support a full failover. "
                "Incorporate quota buffer planning into DR and HA strategies."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL01-BP06: {e}")
        return build_response(
            status="error",
            problem="Unable to assess failover quota planning requirements.",
            recommendation="Review DR documentation and AWS support quota guidance.",
        )


# REL 2. How do you plan your network topology?


def check_rel02_bp01_highly_available_network_connectivity(session):
    print(
        "Checking REL02-BP01 - Use highly available network connectivity for your workload public endpoints"
    )

    elbv2 = session.client("elbv2")
    route53 = session.client("route53")
    cloudfront = session.client("cloudfront")
    globalaccelerator = session.client("globalaccelerator")
    ec2 = session.client("ec2")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_network_topology_ha_conn_users.html"

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
            "id": "REL02-BP01",
            "check_name": "Use highly available network connectivity for workload public endpoints",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Deploy load balancers across multiple Availability Zones.",
                "2. Configure Route 53 health checks for DNS failover.",
                "3. Use CloudFront for global content delivery and availability.",
                "4. Implement AWS Global Accelerator for improved performance and availability.",
                "5. Ensure multi-AZ deployment for all public-facing services.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check Load Balancers ------------------------
        try:
            load_balancers = elbv2.describe_load_balancers()
            for lb in load_balancers.get("LoadBalancers", []):
                az_count = len(lb.get("AvailabilityZones", []))
                if az_count < 2:
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": lb["LoadBalancerArn"],
                            "issue": f"Load balancer {lb['LoadBalancerName']} is not deployed across multiple AZs",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"elbv2.describe_load_balancers error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "load_balancers",
                    "issue": "Cannot access load balancer configuration for HA assessment",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check Route 53 Health Checks ------------------------
        try:
            health_checks = route53.list_health_checks()
            if len(health_checks.get("HealthChecks", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "route53_health_checks",
                        "issue": "No Route 53 health checks configured for DNS failover",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"route53.list_health_checks error: {e}")

        # ------------------------ Check CloudFront Distributions ------------------------
        try:
            distributions = cloudfront.list_distributions()
            if len(distributions.get("DistributionList", {}).get("Items", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudfront_distributions",
                        "issue": "No CloudFront distributions found for global content delivery",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudfront.list_distributions error: {e}")

        # ------------------------ Check Global Accelerator ------------------------
        try:
            accelerators = globalaccelerator.list_accelerators()
            if len(accelerators.get("Accelerators", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "global_accelerator",
                        "issue": "No Global Accelerator configured for improved availability",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"globalaccelerator.list_accelerators error: {e}")

        # ------------------------ Check Availability Zones ------------------------
        try:
            azs = ec2.describe_availability_zones()
            available_azs = [
                az
                for az in azs.get("AvailabilityZones", [])
                if az.get("State") == "available"
            ]
            if len(available_azs) < 2:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "availability_zones",
                        "issue": "Insufficient availability zones for multi-AZ deployment",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_availability_zones error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without highly available network connectivity, public endpoints may become "
                "unavailable during AZ outages, leading to service disruptions and poor user experience."
            ),
            recommendation=(
                "Implement multi-AZ load balancers, Route 53 health checks, CloudFront distributions, "
                "and consider Global Accelerator for optimal availability and performance."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL02-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating network connectivity availability.",
            recommendation="Verify IAM permissions for ELBv2, Route 53, CloudFront, Global Accelerator, and EC2 APIs.",
        )


def check_rel02_bp02_redundant_connectivity_private_networks(session):
    print(
        "Checking REL02-BP02 - Provision redundant connectivity between private networks in cloud and on-premises"
    )

    dx = session.client("directconnect")
    ec2 = session.client("ec2")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_network_topology_ha_conn_private_networks.html"

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
            "id": "REL02-BP02",
            "check_name": "Provision redundant connectivity between private networks",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Deploy multiple Direct Connect connections in different locations.",
                "2. Configure backup VPN connections for Direct Connect redundancy.",
                "3. Use Transit Gateway for centralized connectivity management.",
                "4. Implement multiple customer gateways for VPN redundancy.",
                "5. Monitor connection health and implement automated failover.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 6
    affected = 0

    try:
        # ------------------------ Check Direct Connect Connections ------------------------
        try:
            dx_connections = dx.describe_connections()
            active_dx_connections = [
                conn
                for conn in dx_connections.get("connections", [])
                if conn.get("connectionState") == "available"
            ]
            if len(active_dx_connections) < 2:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "direct_connect",
                        "issue": f"Only {len(active_dx_connections)} Direct Connect connection(s) - recommend multiple for redundancy",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"directconnect.describe_connections error: {e}")

        # ------------------------ Check Direct Connect Virtual Interfaces ------------------------
        try:
            vifs = dx.describe_virtual_interfaces()
            active_vifs = [
                vif
                for vif in vifs.get("virtualInterfaces", [])
                if vif.get("virtualInterfaceState") == "available"
            ]
            if len(active_vifs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "virtual_interfaces",
                        "issue": "No active Direct Connect virtual interfaces found",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"directconnect.describe_virtual_interfaces error: {e}")

        # ------------------------ Check VPN Connections ------------------------
        try:
            vpn_connections = ec2.describe_vpn_connections()
            active_vpns = [
                vpn
                for vpn in vpn_connections.get("VpnConnections", [])
                if vpn.get("State") == "available"
            ]
            if len(active_vpns) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "vpn_connections",
                        "issue": "No active VPN connections found for backup connectivity",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_vpn_connections error: {e}")

        # ------------------------ Check Transit Gateways ------------------------
        try:
            transit_gateways = ec2.describe_transit_gateways()
            active_tgws = [
                tgw
                for tgw in transit_gateways.get("TransitGateways", [])
                if tgw.get("State") == "available"
            ]
            if len(active_tgws) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "transit_gateways",
                        "issue": "No Transit Gateway found for centralized connectivity management",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_transit_gateways error: {e}")

        # ------------------------ Check Customer Gateways ------------------------
        try:
            customer_gateways = ec2.describe_customer_gateways()
            active_cgws = [
                cgw
                for cgw in customer_gateways.get("CustomerGateways", [])
                if cgw.get("State") == "available"
            ]
            if len(active_cgws) < 2:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "customer_gateways",
                        "issue": f"Only {len(active_cgws)} customer gateway(s) - recommend multiple for redundancy",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_customer_gateways error: {e}")

        # ------------------------ Check VPN Gateways ------------------------
        try:
            vpn_gateways = ec2.describe_vpn_gateways()
            active_vgws = [
                vgw
                for vgw in vpn_gateways.get("VpnGateways", [])
                if vgw.get("State") == "available"
            ]
            if len(active_vgws) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "vpn_gateways",
                        "issue": "No VPN gateways found for on-premises connectivity",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_vpn_gateways error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without redundant connectivity between cloud and on-premises networks, "
                "single points of failure can cause complete loss of hybrid connectivity."
            ),
            recommendation=(
                "Implement multiple Direct Connect connections, backup VPN connections, "
                "and use Transit Gateway for centralized, redundant connectivity management."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL02-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating redundant connectivity.",
            recommendation="Verify IAM permissions for Direct Connect and EC2 APIs.",
        )


def check_rel02_bp03_ip_subnet_allocation_expansion_availability(session):
    print("Checking REL02-BP03 - Ensure IP subnet allocation accounts for expansion and availability")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_network_topology_ip_subnet_allocation.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL02-BP03",
            "check_name": "Ensure IP subnet allocation accounts for expansion and availability",
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
                "1. Plan IP address space with sufficient capacity for future growth.",
                "2. Use larger CIDR blocks (e.g., /16 or /20) to allow for expansion.",
                "3. Reserve IP ranges for multi-AZ deployments and disaster recovery.",
                "4. Implement IP address management (IPAM) for centralized planning.",
                "5. Document IP allocation strategy and maintain IP address inventory.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "IP subnet allocation planning cannot be programmatically assessed. AWS APIs do not "
                "expose whether CIDR choices allow for expansion, multi-AZ design, or future capacity."
            ),
            recommendation=(
                "Review your VPC and subnet CIDR allocation strategy to ensure sufficient room for growth, "
                "availability zone expansion, and disaster recovery. Use larger CIDR blocks and centralized "
                "IP address management where appropriate."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL02-BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to assess subnet allocation planning requirements.",
            recommendation="Review network topology documentation and IP planning strategy.",
        )


def check_rel02_bp04_prefer_hub_spoke_over_mesh(session):
    print("Checking REL02-BP04 - Prefer hub-and-spoke topologies over many-to-many mesh")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_network_topology_prefer_hub_and_spoke.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL02-BP04",
            "check_name": "Prefer hub-and-spoke topologies over many-to-many mesh",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Design network topology using hub-and-spoke architecture with Transit Gateway.",
                "2. Centralize connectivity management through a single hub.",
                "3. Avoid direct VPC-to-VPC peering connections for multiple VPCs.",
                "4. Implement centralized security and routing policies at the hub.",
                "5. Document network topology and maintain architectural standards.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Network topology design choices such as hub-and-spoke vs mesh cannot be "
                "determined through AWS APIs. These decisions must be validated through "
                "architectural documentation and design reviews."
            ),
            recommendation=(
                "Use a hub-and-spoke network topology (e.g., AWS Transit Gateway) for scalability, "
                "centralized routing, simplified management, and reduced VPC-to-VPC mesh complexity."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL02-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess network topology design requirements.",
            recommendation="Review network architecture documentation and AWS connectivity strategy.",
        )



def check_rel02_bp05_non_overlapping_ip_ranges(session):
    print(
        "Checking REL02-BP05 - Enforce non-overlapping private IP address ranges in connected private address spaces"
    )

    ec2 = session.client("ec2")
    networkmanager = session.client("networkmanager")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_network_topology_non_overlap_ip.html"

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
            "id": "REL02-BP05",
            "check_name": "Enforce non-overlapping private IP address ranges",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Audit all VPC CIDR blocks for overlapping IP ranges.",
                "2. Plan non-overlapping IP address allocation across all connected networks.",
                "3. Use AWS IPAM for centralized IP address management.",
                "4. Document IP allocation strategy and maintain IP address registry.",
                "5. Implement automated checks for IP address conflicts.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Check VPC CIDR Blocks ------------------------
        vpc_cidrs = []
        try:
            vpcs = ec2.describe_vpcs()
            for vpc in vpcs.get("Vpcs", []):
                vpc_id = vpc["VpcId"]
                cidr_block = vpc["CidrBlock"]
                vpc_cidrs.append((vpc_id, cidr_block))
        except Exception as e:
            print(f"ec2.describe_vpcs error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "vpc_access",
                    "issue": "Cannot access VPC information for IP overlap analysis",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check for Overlapping CIDR Blocks ------------------------
        import ipaddress

        overlapping_pairs = []

        for i, (vpc1_id, cidr1) in enumerate(vpc_cidrs):
            for j, (vpc2_id, cidr2) in enumerate(vpc_cidrs[i + 1 :], i + 1):
                try:
                    network1 = ipaddress.IPv4Network(cidr1, strict=False)
                    network2 = ipaddress.IPv4Network(cidr2, strict=False)

                    if network1.overlaps(network2):
                        overlapping_pairs.append((vpc1_id, cidr1, vpc2_id, cidr2))
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": f"{vpc1_id}_{vpc2_id}",
                                "issue": f"VPC {vpc1_id} ({cidr1}) overlaps with VPC {vpc2_id} ({cidr2})",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(f"Error checking CIDR overlap: {e}")

        # ------------------------ Check Transit Gateway Attachments ------------------------
        try:
            tgw_attachments = ec2.describe_transit_gateway_attachments()
            connected_vpcs = []
            for attachment in tgw_attachments.get("TransitGatewayAttachments", []):
                if (
                    attachment.get("ResourceType") == "vpc"
                    and attachment.get("State") == "available"
                ):
                    connected_vpcs.append(attachment.get("ResourceId"))

            # Check if connected VPCs have overlapping CIDRs
            for vpc1_id, cidr1 in vpc_cidrs:
                for vpc2_id, cidr2 in vpc_cidrs:
                    if (
                        vpc1_id != vpc2_id
                        and vpc1_id in connected_vpcs
                        and vpc2_id in connected_vpcs
                    ):
                        try:
                            network1 = ipaddress.IPv4Network(cidr1, strict=False)
                            network2 = ipaddress.IPv4Network(cidr2, strict=False)
                            if network1.overlaps(network2):
                                affected += 1
                                resources_affected.append(
                                    {
                                        "resource_id": f"tgw_connected_{vpc1_id}_{vpc2_id}",
                                        "issue": f"Connected VPCs have overlapping CIDRs: {vpc1_id} ({cidr1}) and {vpc2_id} ({cidr2})",
                                        "region": session.region_name,
                                        "last_updated": datetime.now(IST).isoformat(),
                                    }
                                )
                        except Exception as e:
                            print(f"Error checking connected VPC overlap: {e}")
        except Exception as e:
            print(f"ec2.describe_transit_gateway_attachments error: {e}")

        # ------------------------ Check Global Networks ------------------------
        try:
            global_networks = networkmanager.list_global_networks()
            if len(global_networks.get("GlobalNetworks", [])) > 0:
                # Global networks exist, additional validation may be needed
                pass
        except Exception as e:
            print(f"networkmanager.list_global_networks error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Overlapping IP address ranges in connected private networks can cause "
                "routing conflicts, connectivity issues, and prevent proper network communication."
            ),
            recommendation=(
                "Ensure all connected private networks use non-overlapping CIDR blocks. "
                "Implement centralized IP address management and regular auditing of IP allocations."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL02-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating IP address overlaps.",
            recommendation="Verify IAM permissions for EC2 and Network Manager APIs.",
        )
