from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_ops11_bp01_continuous_improvement(session):
    print("Checking OPS11-BP01 - Have a process for continuous improvement")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_process_cont_imp.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP01",
            "check_name": "Have a process for continuous improvement",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Establish a recurring review cycle for operational practices.",
                "2. Collect feedback from incident reviews and operational activities.",
                "3. Implement changes based on findings from retrospectives and evaluations.",
                "4. Track improvement actions and measure their effectiveness.",
                "5. Ensure teams remain aligned to the continuous improvement process.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "A continuous improvement process ensures operational maturity increases over time "
                "through feedback loops and regular evaluations."
            ),
            recommendation=(
                "Define, document, and maintain a continuous improvement process that captures lessons learned "
                "and translates them into measurable actions."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating the continuous improvement process.",
            recommendation="Review internal operational improvement workflows and supporting documentation.",
        )

def check_ops11_bp02_post_incident_analysis(session):
    print("Checking OPS11-BP02 – Perform post-incident analysis")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_perform_rca_process.html"

    resources_affected = []
    missing_items = []
    total_scanned = 0
    affected = 0

    ssm = session.client("ssm")
    ssm_incidents = session.client("ssm-incidents") 

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP02",
            "check_name": "Perform post-incident analysis",
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
                "1. Review all customer-impacting incidents and record findings.",
                "2. Perform structured root cause analysis and document contributing factors.",
                "3. Record corrective actions and track remediation progress.",
                "4. Collect metrics such as detection time, response duration, and recovery time.",
                "5. Share lessons learned and improve playbooks and procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        #  SSM OpsCenter OpsItems 
        try:
            ops_items = ssm.list_ops_items()
            summaries = ops_items.get("OpsItemSummaries", [])
            total_scanned += 1  # We attempted to scan OpsCenter

            if not summaries:
                affected += 1
                missing_items.append("No OpsCenter OpsItems found")
            else:
                total_scanned += len(summaries)
                for item in summaries:
                    if item.get("Status") != "Resolved":
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": item.get("OpsItemId"),
                                "issue": f"OpsItem unresolved - Status: {item.get('Status')}",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
        except Exception as e:
            total_scanned += 1
            affected += 1
            missing_items.append(f"Unable to query SSM OpsItems: {str(e)}")

        #  AWS Incident Manager incidents 
        try:
            inc = ssm_incidents.list_incidents()
            incident_summary = inc.get("incidentRecordSummaries", [])
            total_scanned += 1

            if not incident_summary:
                affected += 1
                missing_items.append("No Incident Manager records found")
            else:
                total_scanned += len(incident_summary)
                for i in incident_summary:
                    resources_affected.append(
                        {
                            "resource_id": i.get("arn"),
                            "issue": f"Incident requires review - Title: {i.get('title', 'N/A')}",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            total_scanned += 1
            affected += 1
            missing_items.append(f"Unable to query Incident Manager: {str(e)}")

        #  Add all missing items to resource list 
        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": item,
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        #  Final status 
        status = "passed" if affected == 0 else "failed"

        return build_response(
            status=status,
            problem=(
                "Post-incident analysis is essential to identify contributing factors, "
                "understand failure patterns, and prevent recurrence of operational issues."
            ),
            recommendation=(
                "Ensure structured post-incident reviews with documented findings, "
                "root-cause analysis, improvement tracking, and measurable remediation progress."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS11-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating post-incident analysis capability.",
            recommendation="Verify access to AWS SSM OpsCenter and AWS Incident Manager.",
        )


def check_ops11_bp03_feedback_loops(session):
    print("Checking OPS11-BP03 - Implement feedback loops")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_feedback_loops.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP03",
            "check_name": "Implement feedback loops",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Establish feedback mechanisms across development, operations, and business teams.",
                "2. Implement structured processes for collecting feedback after incidents and deployments.",
                "3. Integrate customer feedback into operational improvements.",
                "4. Track and monitor improvement actions driven by feedback.",
                "5. Review feedback loops regularly to ensure continuous improvement.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        return build_response(
            status="not_available",
            problem=(
                "Feedback loops ensure operational learning and continuous improvement across teams."
            ),
            recommendation=(
                "Define and implement structured feedback loops that support operational improvement cycles."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating feedback loop processes.",
            recommendation="Review internal feedback mechanisms and ensure continuous improvement processes are functioning.",
        )


def check_ops11_bp04_knowledge_management(session):
    print("Checking OPS11-BP04 - Perform knowledge management")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_knowledge_management.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP04",
            "check_name": "Perform knowledge management",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Establish centralized repositories to store operational knowledge.",
                "2. Maintain runbooks, playbooks, architectural diagrams, and decision logs.",
                "3. Ensure knowledge is accessible across teams and kept up to date.",
                "4. Train teams on how to contribute and consume knowledge effectively.",
                "5. Periodically review knowledge repositories for relevance, accuracy, and completeness.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        return build_response(
            status="not_available",
            problem=(
                "Knowledge management ensures that operational information is captured, shared, and reused effectively."
            ),
            recommendation=(
                "Implement structured knowledge management practices, including centralized documentation and "
                "collaboration mechanisms."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating knowledge management processes.",
            recommendation="Review documentation processes and ensure knowledge-sharing mechanisms are functioning properly.",
        )


def check_ops11_bp05_define_drivers_for_improvement(session):
    print("Checking OPS11-BP05 - Define drivers for improvement")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_drivers_for_imp.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP05",
            "check_name": "Define drivers for improvement",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Identify business, technical, and operational goals that drive improvements.",
                "2. Establish KPIs, SLIs, and SLOs for services and workloads.",
                "3. Use metrics, feedback loops, and incident learnings to guide improvement priorities.",
                "4. Align improvement drivers with organizational objectives.",
                "5. Continuously reassess improvement drivers based on evolving requirements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        return build_response(
            status="not_available",
            problem=(
                "Improvement drivers help guide operational enhancements based on business goals, metrics, and feedback."
            ),
            recommendation=(
                "Define clear drivers for operational improvement using KPIs, SLIs, incident learnings, and customer feedback."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating improvement drivers.",
            recommendation="Review operational goals, feedback loops, and metric alignment to ensure improvement criteria are well-defined.",
        )


def check_ops11_bp06_validate_insights(session):
    print("Checking OPS11-BP06 - Validate insights")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_validate_insights.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    devops = session.client("devops-guru")
    cloudwatch = session.client("cloudwatch")
    config = session.client("config")

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP06",
            "check_name": "Validate insights",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Review insights generated by DevOps Guru, CloudWatch, and AWS Config.",
                "2. Validate that insights accurately represent workload health and operational trends.",
                "3. Ensure that insights are linked to real operational data and events.",
                "4. Use validated insights to drive operational improvements.",
                "5. Periodically audit insight sources to ensure accuracy and relevance.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Step 1: DevOps Guru Insights
        try:
            insights = devops.list_insights(StatusFilter={"Ongoing": {}})
            ongoing_insights = insights.get("Insights", [])
            total_scanned += len(ongoing_insights)

            for ins in ongoing_insights:
                insight_id = ins.get("Id")
                if insight_id:
                    resources_affected.append({"insight_id": insight_id})
                    affected += 1

        except Exception as e:
            print(f"DevOps Guru insight fetch error: {e}")

        # Step 2: CloudWatch Metrics
        try:
            metrics = cloudwatch.list_metrics()
            total_scanned += len(metrics.get("Metrics", []))
        except Exception as e:
            print(f"CloudWatch metrics fetch error: {e}")

        # Step 3: AWS Config Rules
        try:
            config_rules = config.describe_config_rules()
            rules = config_rules.get("ConfigRules", [])
            total_scanned += len(rules)

            for rule in rules:
                rule_name = rule.get("ConfigRuleName")
                if rule_name:
                    resources_affected.append({"config_rule": rule_name})
                    affected += 1

        except Exception as e:
            print(f"AWS Config rules fetch error: {e}")

        status = "passed" if affected > 0 else "warning"

        return build_response(
            status=status,
            problem=(
                "Validating insights ensures that automatically generated insights such as anomalies, metric deviations, "
                "and configuration violations accurately reflect the system’s operational state."
            ),
            recommendation=(
                "Regularly review and validate insights from DevOps Guru, CloudWatch, and AWS Config to ensure they "
                "provide meaningful operational intelligence."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred during insights validation.",
            recommendation="Ensure DevOps Guru, CloudWatch metrics, and AWS Config rules are correctly configured and accessible.",
        )


def check_ops11_bp07_operations_metrics_reviews(session):
    print("Checking OPS11-BP07 - Perform operations metrics reviews")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_metrics_review.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    cloudwatch = session.client("cloudwatch")
    try:
        support = session.client("support")
    except Exception:
        support = None

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP07",
            "check_name": "Perform operations metrics reviews",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Review operational metrics dashboards on a scheduled basis.",
                "2. Use CloudWatch dashboards to monitor workload health and performance.",
                "3. Use Trusted Advisor checks to identify cost, performance, fault tolerance, and security issues.",
                "4. Ensure metrics reviewed align with KPIs and SLA objectives.",
                "5. Document findings from metric reviews and follow up with corrective actions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Step 1: CloudWatch dashboards
        try:
            dashboards = cloudwatch.list_dashboards()
            dashboard_list = dashboards.get("DashboardEntries", [])
            total_scanned += len(dashboard_list)

            for dash in dashboard_list:
                dash_name = dash.get("DashboardName")
                if dash_name:
                    resources_affected.append({"cloudwatch_dashboard": dash_name})
                    affected += 1

        except Exception as e:
            print(f"CloudWatch dashboard fetch error: {e}")

        # Step 2: AWS Trusted Advisor (requires support plan)
        if support:
            try:
                checks = support.describe_trusted_advisor_checks(language="en")
                ta_checks = checks.get("checks", [])
                total_scanned += len(ta_checks)

                for check in ta_checks:
                    check_id = check.get("id")
                    if check_id:
                        try:
                            result = support.describe_trusted_advisor_check_result(
                                checkId=check_id
                            )
                            resources_affected.append(
                                {
                                    "trusted_advisor_check": check_id,
                                    "status": result.get("result", {}).get("status"),
                                }
                            )
                            affected += 1
                        except Exception as inner_e:
                            print(f"TA check result error: {inner_e}")
            except Exception as e:
                print(f"Trusted Advisor checks fetch error: {e}")

        status = "passed" if affected == 0 else "failed"

        return build_response(
            status=status,
            problem=(
                "Regular operational metrics reviews help ensure the workload remains healthy, cost-optimized, and "
                "aligned with expected performance objectives."
            ),
            recommendation=(
                "Implement a consistent metrics review process using CloudWatch dashboards and Trusted Advisor checks "
                "to identify trends, anomalies, and optimization opportunities."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating operations metrics reviews.",
            recommendation="Ensure CloudWatch, Trusted Advisor, and monitoring systems are properly configured.",
        )


def check_ops11_bp08_document_lessons_learned(session):
    print("Checking OPS11-BP08 - Document and share lessons learned")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_share_lessons_learned.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP08",
            "check_name": "Document and share lessons learned",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Capture lessons learned after incidents, operational events, and major changes.",
                "2. Store insights in a centralized, accessible knowledge repository.",
                "3. Share findings with relevant teams to prevent recurrence of similar issues.",
                "4. Ensure lessons learned are incorporated into runbooks, playbooks, and operational procedures.",
                "5. Review documented lessons periodically to validate relevance and update processes.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        return build_response(
            status="not_available",
            problem=(
                "Documenting and sharing lessons learned helps improve operational maturity by preventing repeated "
                "failures and reinforcing best practices."
            ),
            recommendation=(
                "Implement a structured lessons-learned process that includes documenting insights, storing them "
                "centrally, and sharing them across engineering and operations teams."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP08 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating lessons learned documentation processes.",
            recommendation="Ensure lessons-learned collection and sharing workflows are well defined and followed.",
        )


def check_ops11_bp09_allocate_time_for_improvements(session):
    print("Checking OPS11-BP09 - Allocate time to make improvements")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_allocate_time_for_imp.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS11-BP09",
            "check_name": "Allocate time to make improvements",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Dedicate regular time for teams to review operations and identify improvement opportunities.",
                "2. Create structured improvement cycles (for example, weekly or monthly).",
                "3. Ensure improvements are prioritized based on impact and aligned with operational goals.",
                "4. Track progress of improvements through tickets, backlogs, or review boards.",
                "5. Continuously refine processes based on outcomes from completed improvements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        return build_response(
            status="not_available",
            problem=(
                "Allocating time to make improvements ensures operational processes evolve and prevent recurring issues."
            ),
            recommendation=(
                "Establish a consistent improvement schedule and ensure teams have dedicated time and resources "
                "to address operational enhancements."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS11-BP09 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating improvement time allocation.",
            recommendation="Review operational improvement planning processes and ensure time allocation is consistent.",
        )
