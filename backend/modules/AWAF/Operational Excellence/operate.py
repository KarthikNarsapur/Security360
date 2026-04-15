from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_ops08_bp01_analyze_workload_metrics(session):
    print("Checking OPS08-BP01 - Analyze workload metrics")

    cloudwatch = session.client("cloudwatch")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_workload_observability_analyze_workload_metrics.html"

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
            "id": "OPS08-BP01",
            "check_name": "Analyze workload metrics",
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
                "1. Collect relevant metrics for all critical workloads using CloudWatch.",
                "2. Configure CloudWatch dashboards and alarms for key metrics.",
                "3. Periodically analyze trends to detect anomalies or performance issues.",
                "4. Correlate workload metrics with other operational data for holistic insights.",
                "5. Automate reporting and alerts to support proactive operational decisions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3
    affected = 0

    try:
        #  List Metrics
        try:
            metrics = cloudwatch.list_metrics()
            metrics_present = len(metrics.get("Metrics", [])) > 0
        except Exception as e:
            print(f"CloudWatch list_metrics error: {e}")
            metrics_present = False

        #  Get Metric Data
        try:
            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                            },
                            "Period": 300,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            metric_data_present = any(
                d.get("Values") for d in metric_data.get("MetricDataResults", [])
            )
        except Exception as e:
            print(f"CloudWatch get_metric_data error: {e}")
            metric_data_present = False

        #  Get Metric Statistics
        try:
            stats = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
                Period=300,
                Statistics=["Average"],
            )
            stats_present = len(stats.get("Datapoints", [])) > 0
        except Exception as e:
            print(f"CloudWatch get_metric_statistics error: {e}")
            stats_present = False

        #  Evaluation
        missing_items = []

        if not metrics_present:
            missing_items.append("CloudWatch Metrics List")
        if not metric_data_present:
            missing_items.append("CloudWatch Metric Data")
        if not stats_present:
            missing_items.append("CloudWatch Metric Statistics")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for workload metric analysis.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Analyzing workload metrics is essential to detect performance bottlenecks and ensure operational health."
            ),
            recommendation=(
                "Collect, monitor, and analyze CloudWatch metrics for all critical workloads. "
                "Use dashboards, alarms, and automated insights to maintain workload reliability and performance."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS08-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while analyzing workload metrics.",
            recommendation="Verify CloudWatch metric collection, permissions, and metric availability.",
        )


def check_ops08_bp02_analyze_workload_logs(session):
    print("Checking OPS08-BP02 - Analyze workload logs")

    logs = session.client("logs")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_workload_observability_analyze_workload_logs.html"

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
            "id": "OPS08-BP02",
            "check_name": "Analyze workload logs",
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
                "1. Collect logs for all critical workloads using CloudWatch Logs.",
                "2. Configure log groups and log streams with appropriate retention policies.",
                "3. Use filter patterns and queries to identify anomalies and operational issues.",
                "4. Automate log analysis using CloudWatch Logs Insights and scheduled queries.",
                "5. Integrate log analysis results with dashboards and alerts to proactively respond to issues.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        #  Describe Log Groups
        try:
            log_groups = logs.describe_log_groups()
            log_groups_present = len(log_groups.get("logGroups", [])) > 0
        except Exception as e:
            print(f"CloudWatch Logs describe_log_groups error: {e}")
            log_groups_present = False

        #  Describe Log Streams
        try:
            if log_groups_present:
                log_group_name = log_groups.get("logGroups", [])[0]["logGroupName"]
                log_streams = logs.describe_log_streams(logGroupName=log_group_name)
                log_streams_present = len(log_streams.get("logStreams", [])) > 0
            else:
                log_streams_present = False
        except Exception as e:
            print(f"CloudWatch Logs describe_log_streams error: {e}")
            log_streams_present = False

        #  Filter Log Events
        try:
            if log_streams_present:
                filtered = logs.filter_log_events(logGroupName=log_group_name, limit=1)
                filter_present = len(filtered.get("events", [])) > 0
            else:
                filter_present = False
        except Exception as e:
            print(f"CloudWatch Logs filter_log_events error: {e}")
            filter_present = False

        #  Start Query
        try:
            if log_groups_present:
                query_id = logs.start_query(
                    logGroupName=log_group_name,
                    startTime=int((datetime.utcnow() - timedelta(hours=1)).timestamp()),
                    endTime=int(datetime.utcnow().timestamp()),
                    queryString="fields @timestamp, @message | limit 1",
                ).get("queryId")
                start_query_present = query_id is not None
            else:
                start_query_present = False
        except Exception as e:
            print(f"CloudWatch Logs start_query error: {e}")
            start_query_present = False

        #  Get Query Results
        try:
            if start_query_present:
                results = logs.get_query_results(queryId=query_id)
                get_results_present = len(results.get("results", [])) > 0
            else:
                get_results_present = False
        except Exception as e:
            print(f"CloudWatch Logs get_query_results error: {e}")
            get_results_present = False

        #  Evaluation
        missing_items = []

        if not log_groups_present:
            missing_items.append("CloudWatch Log Groups")
        if not log_streams_present:
            missing_items.append("CloudWatch Log Streams")
        if not filter_present:
            missing_items.append("Filtered Log Events")
        if not start_query_present:
            missing_items.append("CloudWatch Log Insights Query Start")
        if not get_results_present:
            missing_items.append("CloudWatch Log Insights Query Results")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for workload log analysis.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Analyzing workload logs is essential to identify operational issues, detect anomalies, and maintain observability."
            ),
            recommendation=(
                "Collect, monitor, and analyze CloudWatch Logs for all workloads. Use queries, filters, and automated insights "
                "to proactively detect and respond to operational issues."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS08-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while analyzing workload logs.",
            recommendation="Verify CloudWatch Logs configuration, permissions, and query setup.",
        )


def check_ops08_bp03_analyze_workload_traces(session):
    print("Checking OPS08-BP03 – Analyze workload traces")

    xray = session.client("xray")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_workload_observability_analyze_workload_traces.html"

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
            "id": "OPS08-BP03",
            "check_name": "Analyze workload traces",
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
                "1. Enable AWS X-Ray tracing across all critical workloads.",
                "2. Collect trace data for requests, dependencies, and downstream services.",
                "3. Analyze traces to identify latency issues, errors, and performance bottlenecks.",
                "4. Use batch trace analysis to review historical trace data.",
                "5. Correlate traces with logs and metrics for comprehensive observability and troubleshooting.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3
    affected = 0

    try:
        #  Get Service Graph
        try:
            service_graph = xray.get_service_graph(
                StartTime=datetime.now() - timedelta(hours=1),
                EndTime=datetime.now(),
            )
            service_graph_present = len(service_graph.get("Services", [])) > 0
        except Exception as e:
            print(f"X-Ray get_service_graph error: {e}")
            service_graph_present = False

        #  Get Trace Summaries
        try:
            summaries = xray.get_trace_summaries(
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            summaries_present = len(summaries.get("TraceSummaries", [])) > 0
        except Exception as e:
            print(f"X-Ray get_trace_summaries error: {e}")
            summaries_present = False

        #  Batch Get Traces
        try:
            if summaries_present:
                trace_ids = [t["Id"] for t in summaries.get("TraceSummaries", [])[:1]]
                batch = xray.batch_get_traces(TraceIds=trace_ids)
                batch_present = len(batch.get("Traces", [])) > 0
            else:
                batch_present = False
        except Exception as e:
            print(f"X-Ray batch_get_traces error: {e}")
            batch_present = False

        #  Evaluation
        missing_items = []

        if not service_graph_present:
            missing_items.append("X-Ray Service Graph")
        if not summaries_present:
            missing_items.append("X-Ray Trace Summaries")
        if not batch_present:
            missing_items.append("X-Ray Batch Traces")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for workload trace analysis.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )


        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Analyzing workload traces is essential to understand service interactions, "
                "detect latency and errors, and improve system performance."
            ),
            recommendation=(
                "Enable X-Ray tracing for all workloads. Collect and analyze service graphs, trace summaries, "
                "and batch traces to identify performance bottlenecks and troubleshoot issues."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS08-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while analyzing workload traces.",
            recommendation="Verify X-Ray tracing configuration, permissions, and trace collection.",
        )


def check_ops08_bp04_create_actionable_alerts(session):
    print("Checking OPS08-BP04 – Create actionable alerts")

    cloudwatch = session.client("cloudwatch")
    sns = session.client("sns")
    events = session.client("events")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_workload_observability_create_alerts.html"

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
            "id": "OPS08-BP04",
            "check_name": "Create actionable alerts",
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
                "1. Configure CloudWatch alarms for critical metrics and thresholds.",
                "2. Review alarm history to ensure alerts are actionable and timely.",
                "3. Set up SNS topics and subscriptions to notify the right teams.",
                "4. Integrate EventBridge rules for automated responses and escalation.",
                "5. Periodically test alerting mechanisms to validate operational effectiveness.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        #  CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms()
            alarms_present = len(alarms.get("MetricAlarms", [])) > 0
        except Exception as e:
            print(f"CloudWatch describe_alarms error: {e}")
            alarms_present = False

        #  CloudWatch Alarm History
        try:
            alarm_history = cloudwatch.describe_alarm_history()
            history_present = len(alarm_history.get("AlarmHistoryItems", [])) > 0
        except Exception as e:
            print(f"CloudWatch describe_alarm_history error: {e}")
            history_present = False

        #  SNS Subscriptions
        try:
            subscriptions = sns.list_subscriptions()
            subs_present = len(subscriptions.get("Subscriptions", [])) > 0
        except Exception as e:
            print(f"SNS list_subscriptions error: {e}")
            subs_present = False

        #  SNS Topics
        try:
            topics = sns.list_topics()
            topics_present = len(topics.get("Topics", [])) > 0
        except Exception as e:
            print(f"SNS list_topics error: {e}")
            topics_present = False

        #  EventBridge Rules
        try:
            rules = events.list_rules()
            rules_present = len(rules.get("Rules", [])) > 0
        except Exception as e:
            print(f"EventBridge list_rules error: {e}")
            rules_present = False

        #  Evaluation
        missing_items = []

        if not alarms_present:
            missing_items.append("CloudWatch Alarms")
        if not history_present:
            missing_items.append("CloudWatch Alarm History")
        if not subs_present:
            missing_items.append("SNS Subscriptions")
        if not topics_present:
            missing_items.append("SNS Topics")
        if not rules_present:
            missing_items.append("EventBridge Rules")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for actionable alerts and notifications.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without actionable alerts, operational teams cannot respond to critical issues promptly, "
                "increasing downtime and operational risk."
            ),
            recommendation=(
                "Implement CloudWatch alarms, SNS notifications, and EventBridge rules for critical metrics and events. "
                "Ensure alerts are actionable, targeted, and tested regularly."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS08-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while evaluating actionable alerts.",
            recommendation="Verify CloudWatch, SNS, and EventBridge configurations and permissions.",
        )


def check_ops08_bp05_create_dashboards(session):
    print("Checking OPS08-BP05 – Create dashboards")

    cloudwatch = session.client("cloudwatch")
    quicksight = session.client("quicksight")
    grafana = session.client("grafana")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_workload_observability_create_dashboards.html"

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
            "id": "OPS08-BP05",
            "check_name": "Create dashboards",
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
                "1. Create CloudWatch dashboards for key workload metrics.",
                "2. Use QuickSight dashboards for business-level metrics and visualization.",
                "3. Set up Grafana workspaces to monitor multi-source data and metrics.",
                "4. Regularly review dashboards to ensure metrics remain relevant and actionable.",
                "5. Integrate dashboards with alerting and incident response workflows.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        #  CloudWatch Dashboards
        try:
            cw_dashboards = cloudwatch.list_dashboards()
            dashboards_present = len(cw_dashboards.get("DashboardEntries", [])) > 0
        except Exception as e:
            print(f"CloudWatch list_dashboards error: {e}")
            dashboards_present = False

        try:
            if dashboards_present:
                cw_get = cloudwatch.get_dashboard(
                    DashboardName=cw_dashboards["DashboardEntries"][0]["DashboardName"]
                )
                dashboards_present = True if cw_get.get("DashboardArn") else False
        except Exception as e:
            print(f"CloudWatch get_dashboard error: {e}")
            dashboards_present = False

        #  QuickSight Dashboards
        try:
            qs_dashboards = quicksight.list_dashboards(
                AwsAccountId=session.client("sts").get_caller_identity()["Account"]
            )
            qs_present = len(qs_dashboards.get("DashboardSummaryList", [])) > 0
        except Exception as e:
            print(f"QuickSight list_dashboards error: {e}")
            qs_present = False

        #  Grafana Workspaces
        try:
            grafana_workspaces = grafana.list_workspaces()
            grafana_present = len(grafana_workspaces.get("workspaces", [])) > 0
        except Exception as e:
            print(f"Grafana list_workspaces error: {e}")
            grafana_present = False

        #  Evaluation
        missing_items = []

        if not dashboards_present:
            missing_items.append("CloudWatch Dashboards")
        if not qs_present:
            missing_items.append("QuickSight Dashboards")
        if not grafana_present:
            missing_items.append("Grafana Workspaces")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for workload visualization and dashboards.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Dashboards provide a consolidated view of workload and business metrics. "
                "Without dashboards, teams lack situational awareness to monitor performance and reliability."
            ),
            recommendation=(
                "Create and maintain CloudWatch, QuickSight, or Grafana dashboards to visualize key metrics. "
                "Ensure dashboards are actionable, relevant, and integrated with operational workflows."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS08-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing dashboards.",
            recommendation="Verify CloudWatch, QuickSight, and Grafana configurations and permissions.",
        )


def check_ops09_bp01_measure_ops_goals_kpis(session):
    print("Checking OPS09-BP01 - Measure operations goals and KPIs with metrics")

    cloudwatch = session.client("cloudwatch")
    config = session.client("config")
    devopsguru = session.client("devops-guru")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_measure_ops_goals_kpis.html"

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
            "id": "OPS09-BP01",
            "check_name": "Measure operations goals and KPIs with metrics",
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
                "1. Configure CloudWatch metrics for key operational KPIs and workload metrics.",
                "2. Review metrics with CloudWatch dashboards and alerts for visibility.",
                "3. Use AWS Config to monitor resource compliance with rules and standards.",
                "4. Leverage DevOps Guru insights to detect anomalies in operational health.",
                "5. Periodically review and refine KPIs to align with operational objectives.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        #  CloudWatch List Metrics
        try:
            metrics = cloudwatch.list_metrics()
            metrics_present = len(metrics.get("Metrics", [])) > 0
        except Exception as e:
            print(f"CloudWatch list_metrics error: {e}")
            metrics_present = False

        #  CloudWatch Get Metric Data
        try:
            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                            },
                            "Period": 300,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            metric_data_present = any(
                d.get("Values") for d in metric_data.get("MetricDataResults", [])
            )
        except Exception as e:
            print(f"CloudWatch get_metric_data error: {e}")
            metric_data_present = False

        #  CloudWatch Get Metric Statistics
        try:
            metric_stats = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
                Period=300,
                Statistics=["Average"],
            )
            metric_stats_present = len(metric_stats.get("Datapoints", [])) > 0
        except Exception as e:
            print(f"CloudWatch get_metric_statistics error: {e}")
            metric_stats_present = False

        #  AWS Config Rules
        try:
            config_rules = config.describe_config_rules()
            config_present = len(config_rules.get("ConfigRules", [])) > 0
        except Exception as e:
            print(f"AWS Config describe_config_rules error: {e}")
            config_present = False

        #  DevOps Guru Insights
        try:
            insights = devopsguru.list_insights()
            devops_present = (
                len(insights.get("ProactiveInsights", [])) > 0
                or len(insights.get("ReactiveInsights", [])) > 0
            )
        except Exception as e:
            print(f"DevOps Guru list_insights error: {e}")
            devops_present = False

        #  Evaluation
        missing_items = []

        if not metrics_present:
            missing_items.append("CloudWatch Metrics List")
        if not metric_data_present:
            missing_items.append("CloudWatch Metric Data")
        if not metric_stats_present:
            missing_items.append("CloudWatch Metric Statistics")
        if not config_present:
            missing_items.append("AWS Config Rules")
        if not devops_present:
            missing_items.append("DevOps Guru Insights")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for operational goals and KPI tracking.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without measurement of operational goals and KPIs, teams cannot effectively monitor workload performance or detect operational issues."
            ),
            recommendation=(
                "Instrument CloudWatch metrics, Config rules, and DevOps Guru insights to track and evaluate operational KPIs. "
                "Review metrics and insights regularly to ensure operational health and compliance."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS09-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while evaluating operational KPIs and metrics.",
            recommendation="Verify CloudWatch, Config, and DevOps Guru access and configurations.",
        )


def check_ops09_bp02_communicate_status(session):
    print(
        "Checking OPS09-BP02 – Communicate status and trends to ensure visibility into operation"
    )

    cloudwatch = session.client("cloudwatch")
    quicksight = session.client("quicksight")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_communicate_status_trends.html"

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
            "id": "OPS09-BP02",
            "check_name": "Communicate status and trends to ensure visibility into operation",
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
                "1. Create CloudWatch dashboards to display key operational metrics and trends.",
                "2. Use QuickSight dashboards to visualize and communicate operational insights.",
                "3. Ensure dashboards are accessible to stakeholders for timely decision-making.",
                "4. Review dashboards regularly to ensure metrics remain relevant and actionable.",
                "5. Integrate dashboards with alerts or notifications to highlight significant events.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = (
        4  # cloudwatch list/get dashboards, quicksight list/describe dashboards
    )
    affected = 0

    try:
        #  CloudWatch Dashboards
        try:
            cw_dashboards = cloudwatch.list_dashboards()
            cw_present = len(cw_dashboards.get("DashboardEntries", [])) > 0
        except Exception as e:
            print(f"CloudWatch list_dashboards error: {e}")
            cw_present = False

        try:
            if cw_present:
                cw_get = cloudwatch.get_dashboard(
                    DashboardName=cw_dashboards["DashboardEntries"][0]["DashboardName"]
                )
                cw_present = True if cw_get.get("DashboardArn") else False
        except Exception as e:
            print(f"CloudWatch get_dashboard error: {e}")
            cw_present = False

        #  QuickSight Dashboards
        try:
            qs_dashboards = quicksight.list_dashboards(
                AwsAccountId=session.client("sts").get_caller_identity()["Account"]
            )
            qs_present = len(qs_dashboards.get("DashboardSummaryList", [])) > 0
        except Exception as e:
            print(f"QuickSight list_dashboards error: {e}")
            qs_present = False

        try:
            if qs_present:
                qs_describe = quicksight.describe_dashboard(
                    AwsAccountId=session.client("sts").get_caller_identity()["Account"],
                    DashboardId=qs_dashboards["DashboardSummaryList"][0]["DashboardId"],
                )
                qs_present = True if qs_describe.get("Dashboard") else False
        except Exception as e:
            print(f"QuickSight describe_dashboard error: {e}")
            qs_present = False

        #  Evaluation
        missing_items = []

        if not cw_present:
            missing_items.append("CloudWatch Dashboards")
        if not qs_present:
            missing_items.append("QuickSight Dashboards")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for status and trend visualization.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without dashboards or visualizations, teams and stakeholders lack visibility into workload performance, trends, and operational health."
            ),
            recommendation=(
                "Use CloudWatch and QuickSight dashboards to communicate operational metrics, KPIs, and trends to stakeholders, ensuring timely visibility into system status."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS09-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while evaluating dashboards for operational visibility.",
            recommendation="Verify CloudWatch and QuickSight dashboard configurations and permissions.",
        )


def check_ops09_bp03_review_operations_metrics(session):
    print("Checking OPS09-BP03 – Review operations metrics and prioritize improvement")

    cloudwatch = session.client("cloudwatch")
    support = session.client("support")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html"

    resources_affected = []
    total_scanned = 4
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
            "id": "OPS09-BP03",
            "check_name": "Review operations metrics and prioritize improvement",
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
                "1. Regularly review operational metrics using CloudWatch dashboards.",
                "2. Analyze Trusted Advisor checks and their results for operational risks.",
                "3. Identify areas of inefficiency or failure patterns.",
                "4. Prioritize improvement actions based on operational impact.",
                "5. Continuously monitor whether implemented improvements are effective.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ---------------- CloudWatch ----------------
        dashboards_present = False

        # list_dashboards
        try:
            dboards = cloudwatch.list_dashboards()
            if len(dboards.get("DashboardEntries", [])) > 0:
                dashboards_present = True
        except Exception as e:
            print(f"Error: cloudwatch.list_dashboards — {e}")

        # get_dashboard
        try:
            if dashboards_present:
                name = dboards["DashboardEntries"][0]["DashboardName"]
                dash = cloudwatch.get_dashboard(DashboardName=name)
                if dash.get("DashboardArn"):
                    dashboards_present = True
        except Exception as e:
            print(f"Error: cloudwatch.get_dashboard — {e}")
            dashboards_present = False

        # ---------------- Trusted Advisor ----------------
        ta_present = False

        # describe_trusted_advisor_checks
        try:
            checks = support.describe_trusted_advisor_checks(language="en")
            if len(checks.get("checks", [])) > 0:
                ta_present = True
        except Exception as e:
            print(f"Error: support.describe_trusted_advisor_checks — {e}")

        # describe_trusted_advisor_check_result
        try:
            if ta_present:
                cid = checks["checks"][0]["id"]
                result = support.describe_trusted_advisor_check_result(
                    checkId=cid, language="en"
                )
                if result.get("result"):
                    ta_present = True
        except Exception as e:
            print(f"Error: support.describe_trusted_advisor_check_result — {e}")
            ta_present = False

       # ---------------- Evaluation ----------------
        missing_items = []

        if not dashboards_present:
            missing_items.append("CloudWatch Dashboards")
        if not ta_present:
            missing_items.append("Trusted Advisor Checks")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for operational metrics review.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Operational metrics and Trusted Advisor insights are not being reviewed, "
                "reducing visibility into operational health and improvement priorities."
            ),
            recommendation=(
                "Use CloudWatch dashboards and Trusted Advisor checks to regularly review "
                "operations metrics and prioritize actions that enhance operational effectiveness."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS09-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while checking operational metrics and prioritization.",
            recommendation="Validate IAM permissions and AWS service access before re-running the scan.",
        )


def check_ops10_bp01_event_incident_problem_management(session):
    print(
        "Checking OPS10-BP01 – Use a process for event, incident, and problem management"
    )

    ssm = session.client("ssm")
    incidentmanager = session.client("incidentmanager")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_event_incident_problem_process.html"

    resources_affected = []
    total_scanned = 3
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
            "id": "OPS10-BP01",
            "check_name": "Use a process for event, incident, and problem management",
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
                "1. Use SSM OpsCenter to record and manage operational issues.",
                "2. Use AWS Incident Manager for coordinated response to critical incidents.",
                "3. Implement standardized processes for event detection and response.",
                "4. Track recurring problems and perform root cause analysis.",
                "5. Continuously improve incident response based on historical data.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # -- SSM OpsItems --
        ops_items_present = False

        # list_ops_items
        try:
            ops_list = ssm.list_ops_items()
            if len(ops_list.get("OpsItemSummaries", [])) > 0:
                ops_items_present = True
        except Exception as e:
            print(f"Error: ssm.list_ops_items — {e}")

        # describe_ops_items
        try:
            if ops_items_present:
                first_id = ops_list["OpsItemSummaries"][0]["OpsItemId"]
                desc = ssm.describe_ops_items(OpsItemIds=[first_id])
                if len(desc.get("OpsItemDescriptions", [])) > 0:
                    ops_items_present = True
        except Exception as e:
            print(f"Error: ssm.describe_ops_items — {e}")
            ops_items_present = False

        # -- Incident Manager --
        incidents_present = False
        response_plans_present = False

        # list_incidents
        try:
            inc = incidentmanager.list_incidents()
            if len(inc.get("incidents", [])) > 0:
                incidents_present = True
        except Exception as e:
            print(f"Error: incidentmanager.list_incidents — {e}")

        # list_response_plans
        try:
            rp = incidentmanager.list_response_plans()
            if len(rp.get("responsePlanSummaries", [])) > 0:
                response_plans_present = True
        except Exception as e:
            print(f"Error: incidentmanager.list_response_plans — {e}")

        # -- Evaluation --
        missing_items = []

        if not ops_items_present:
            missing_items.append("SSM OpsItems")
        if not incidents_present:
            missing_items.append("AWS Incident Manager Incidents")
        if not response_plans_present:
            missing_items.append("AWS Incident Response Plans")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for event, incident, and problem management.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Event, incident, and problem management processes are not fully established, "
                "impacting the ability to respond effectively to operational issues."
            ),
            recommendation=(
                "Implement and maintain structured event, incident, and problem management processes "
                "using SSM OpsCenter and AWS Incident Manager. Review and update processes regularly."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error during event/incident/problem management evaluation.",
            recommendation="Verify IAM permissions and API access for SSM and Incident Manager.",
        )


def check_ops10_bp02_process_per_alert(session):
    print("Checking OPS10-BP02 - Have a process per alert")

    cloudwatch = session.client("cloudwatch")
    events = session.client("events")
    sns = session.client("sns")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_process_per_alert.html"

    resources_affected = []
    total_scanned = 5
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
            "id": "OPS10-BP02",
            "check_name": "Have a process per alert",
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
                "1. Ensure every CloudWatch alarm has a documented response process.",
                "2. Create routing and escalation flows using SNS and EventBridge.",
                "3. Maintain runbooks/playbooks linked to each alarm.",
                "4. Review alarm history regularly to detect noisy or ineffective alerts.",
                "5. Map alerts to incident severity and response teams.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:

        # -- CloudWatch Alarms --
        alarms_present = False
        alarm_history_present = False

        # cloudwatch.describe_alarms
        try:
            alarms = cloudwatch.describe_alarms()
            if len(alarms.get("MetricAlarms", [])) > 0:
                alarms_present = True
        except Exception as e:
            print(f"Error: cloudwatch.describe_alarms — {e}")

        # cloudwatch.describe_alarm_history
        try:
            history = cloudwatch.describe_alarm_history()
            if len(history.get("AlarmHistoryItems", [])) > 0:
                alarm_history_present = True
        except Exception as e:
            print(f"Error: cloudwatch.describe_alarm_history — {e}")

        # -- EventBridge Rules --
        rules_present = False
        try:
            rules = events.list_rules()
            if len(rules.get("Rules", [])) > 0:
                rules_present = True
        except Exception as e:
            print(f"Error: events.list_rules — {e}")

        # -- SNS Topics / Subscriptions --
        sns_topics_present = False
        sns_subscriptions_present = False

        # list_topics
        try:
            topics = sns.list_topics()
            if len(topics.get("Topics", [])) > 0:
                sns_topics_present = True
        except Exception as e:
            print(f"Error: sns.list_topics — {e}")

        # list_subscriptions
        try:
            subs = sns.list_subscriptions()
            if len(subs.get("Subscriptions", [])) > 0:
                sns_subscriptions_present = True
        except Exception as e:
            print(f"Error: sns.list_subscriptions — {e}")

        # -- Evaluation --
        missing_items = []

        if not alarms_present:
            missing_items.append("CloudWatch Alarms")
        if not alarm_history_present:
            missing_items.append("CloudWatch Alarm History")
        if not sns_topics_present:
            missing_items.append("SNS Topics")
        if not sns_subscriptions_present:
            missing_items.append("SNS Subscriptions")
        if not rules_present:
            missing_items.append("EventBridge Rules")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} missing for alert process completeness.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "One or more alerts may lack defined processes, escalation paths, or routing mechanisms, "
                "reducing the effectiveness of operational response."
            ),
            recommendation=(
                "Ensure each alert has a mapped process including SNS routing, EventBridge rules, "
                "runbooks, and defined responders. Review and optimize noisy alerts."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error during alert process evaluation.",
            recommendation="Verify IAM permissions for CloudWatch, SNS, and EventBridge APIs.",
        )


def check_ops10_bp03_prioritize_events(session):
    print(
        "Checking OPS10-BP03 – Prioritize operational events based on business impact"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_prioritize_events.html"

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
            "id": "OPS10-BP03",
            "check_name": "Prioritize operational events based on business impact",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Define clear impact levels for operational events.",
                "2. Establish prioritization criteria aligned with business importance.",
                "3. Implement escalation paths based on severity.",
                "4. Ensure teams follow the defined prioritization workflow.",
                "5. Periodically review prioritization effectiveness.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Prioritizing events based on business impact ensures appropriate response and effective handling "
                "of critical issues."
            ),
            recommendation=(
                "Establish and maintain a prioritization framework that maps operational events to business "
                "impact levels."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating event prioritization processes.",
            recommendation="Review event prioritization workflows and internal process definitions.",
        )


def check_ops10_bp04_define_escalation_paths(session):
    print("Checking OPS10-BP04 – Define escalation paths")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_define_escalation_paths.html"

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
            "id": "OPS10-BP04",
            "check_name": "Define escalation paths",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Define clear escalation paths for operational events.",
                "2. Document who should be contacted and under what conditions.",
                "3. Ensure the escalation chain reflects business priorities and response capabilities.",
                "4. Communicate escalation paths across all relevant teams.",
                "5. Periodically review and update escalation workflows.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Defined escalation paths ensure timely engagement of the right personnel during operational events."
            ),
            recommendation=(
                "Establish a documented escalation structure that aligns with business impact levels and ensures "
                "rapid response."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating escalation path definitions.",
            recommendation="Review escalation workflows and internal documentation for accuracy and completeness.",
        )


def check_ops10_bp05_customer_communication_plan(session):
    print(
        "Checking OPS10-BP05 - Define a customer communication plan for service-impacting events"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_push_notify.html"

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
            "id": "OPS10-BP05",
            "check_name": "Define a customer communication plan for service-impacting events",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Establish a communication plan for notifying customers during service-impacting events.",
                "2. Define what information must be communicated, including impact summary and expected resolution time.",
                "3. Ensure communication channels (email, status page, in-app messages) are clearly defined.",
                "4. Implement automated or manual notification workflows.",
                "5. Periodically test and update the communication plan.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "A well-defined customer communication plan ensures transparency and maintains trust during "
                "service-impacting events."
            ),
            recommendation=(
                "Create and maintain a structured customer communication plan, including message templates, "
                "communication channels, approval workflows, and event triggers."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating the customer communication plan.",
            recommendation="Review communication workflows and update documentation to reflect current processes.",
        )


def check_ops10_bp06_communicate_status_dashboards(session):
    print("Checking OPS10-BP06 - Communicate status through dashboards")

    cloudwatch = session.client("cloudwatch")
    quicksight = session.client("quicksight")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_dashboards.html"

    resources_affected = []
    total_scanned = 2
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
            "id": "OPS10-BP06",
            "check_name": "Communicate status through dashboards",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create CloudWatch dashboards to visualize operational state in real time.",
                "2. Build QuickSight dashboards for business and operational reporting.",
                "3. Review dashboards regularly to ensure relevance and accuracy.",
                "4. Update dashboards with key events and metrics based on current priorities.",
                "5. Provide access to operational and leadership teams.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ---- CloudWatch Dashboards ----
        try:
            cw_dashboards = cloudwatch.list_dashboards()
            cw_present = len(cw_dashboards.get("DashboardEntries", [])) > 0
        except Exception as e:
            print(f"CloudWatch list_dashboards error: {e}")
            cw_present = False

        # ---- QuickSight Dashboards ----
        try:
            qs_dashboards = quicksight.list_dashboards(
                AwsAccountId=sts.get_caller_identity()["Account"]
            )
            qs_present = len(qs_dashboards.get("DashboardSummaryList", [])) > 0
        except Exception as e:
            print(f"QuickSight list_dashboards error: {e}")
            qs_present = False

        # ---- Evaluation ----
        missing_items = []

        if not cw_present:
            missing_items.append("CloudWatch Dashboards")

        if not qs_present:
            missing_items.append("QuickSight Dashboards")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} missing for operational visibility.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Dashboards provide real-time visibility into operational and business status. "
                "Lack of dashboards reduces situational awareness and slows incident response."
            ),
            recommendation=(
                "Implement CloudWatch and QuickSight dashboards and keep them updated "
                "to support proactive monitoring and event response."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating dashboard visibility.",
            recommendation="Verify permissions for CloudWatch/QuickSight and retry.",
        )


def check_ops10_bp07_automate_event_responses(session):
    print("Checking OPS10-BP07 - Automate responses to events")

    events = session.client("events")
    lambda_client = session.client("lambda")
    ssm = session.client("ssm")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_event_response_auto_event_response.html"

    resources_affected = []
    total_scanned = 3
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
            "id": "OPS10-BP07",
            "check_name": "Automate responses to events",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Implement EventBridge rules that detect operational events.",
                "2. Configure targets such as Lambda, SSM Automation, or Step Functions for automated responses.",
                "3. Ensure Lambda functions used for automation are deployed and active.",
                "4. Establish SSM Automation runbooks for known event types.",
                "5. Regularly test automation workflows to ensure reliability.",
                "6. Update automation logic as systems evolve.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        missing_items = []

        # ---- EventBridge Rules ----
        try:
            rules = events.list_rules()
            rules_present = len(rules.get("Rules", [])) > 0
        except Exception as e:
            print(f"Error: events.list_rules — {e}")
            rules_present = False

        if not rules_present:
            missing_items.append("EventBridge Rules")

        # ---- Lambda Functions (Automation Targets) ----
        try:
            lambdas = lambda_client.list_functions()
            lambda_present = len(lambdas.get("Functions", [])) > 0
        except Exception as e:
            print(f"Error: lambda.list_functions — {e}")
            lambda_present = False

        if not lambda_present:
            missing_items.append("Lambda Functions")

        # ---- SSM Automation Executions ----
        try:
            execs = ssm.describe_automation_executions(MaxResults=5)
            ssm_present = len(execs.get("AutomationExecutionMetadataList", [])) > 0
        except Exception as e:
            print(f"Error: ssm.describe_automation_executions — {e}")
            ssm_present = False

        if not ssm_present:
            missing_items.append("SSM Automation Executions")

        # ---- Evaluation ----
        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} missing for automated event response readiness.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Automated responses reduce manual intervention and accelerate incident handling. "
                "Missing automation components limit operational resilience."
            ),
            recommendation=(
                "Ensure EventBridge rules, Lambda automation handlers, and SSM automation workflows "
                "are implemented to automatically react to operational events."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in OPS10-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating event automation.",
            recommendation="Verify EventBridge, Lambda, and SSM execution permissions.",
        )
