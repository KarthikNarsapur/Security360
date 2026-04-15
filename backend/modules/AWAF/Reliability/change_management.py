from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# REL 6. How do you monitor workload resources?

# REL06-BP01 Monitor all components for the workload (Generation)


def check_rel06_bp01_monitor_all_components(session):
    print("Checking REL06-BP01 - Monitor all components for the workload (Generation)")

    cloudwatch = session.client("cloudwatch")
    config = session.client("config")
    health = session.client("health")
    xray = session.client("xray")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_monitor_resources.html"

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
            "id": "REL06-BP01",
            "check_name": "Monitor all components for the workload (Generation)",
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
                "1. Enable CloudWatch metrics for all workload components.",
                "2. Configure AWS Config rules for resource monitoring.",
                "3. Set up AWS Health Dashboard for service health monitoring.",
                "4. Implement X-Ray tracing for distributed application monitoring.",
                "5. Create comprehensive monitoring dashboards and alerts.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Check CloudWatch Metrics ------------------------
        try:
            metrics = cloudwatch.list_metrics()
            if len(metrics.get("Metrics", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_metrics",
                        "issue": "No CloudWatch metrics found for workload monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "cloudwatch_access",
                    "issue": "Cannot access CloudWatch metrics for monitoring assessment",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check CloudWatch Metric Data ------------------------
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "workload_metrics",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                            },
                            "Period": 3600,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )

            if len(metric_data.get("MetricDataResults", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "metric_data",
                        "issue": "No recent metric data available for workload components",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # ------------------------ Check AWS Config Rules ------------------------
        try:
            config_rules = config.describe_config_rules()
            if len(config_rules.get("ConfigRules", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "config_rules",
                        "issue": "No AWS Config rules found for resource monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"config.describe_config_rules error: {e}")

        # ------------------------ Check AWS Health Events ------------------------
        try:
            health_events = health.describe_events()
            # Health API access indicates monitoring capability
            health_monitoring_available = True
        except Exception as e:
            print(f"health.describe_events error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "health_monitoring",
                    "issue": "Cannot access AWS Health Dashboard for service health monitoring",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check X-Ray Service Graph ------------------------
        try:
            service_graph = xray.get_service_graph(
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            if len(service_graph.get("Services", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "xray_tracing",
                        "issue": "No X-Ray service graph data found for distributed tracing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"xray.get_service_graph error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without comprehensive monitoring of all workload components, it's difficult "
                "to detect issues early, understand system behavior, and maintain reliability."
            ),
            recommendation=(
                "Implement comprehensive monitoring using CloudWatch metrics, AWS Config rules, "
                "Health Dashboard, and X-Ray tracing to ensure visibility into all workload components."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL06-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating workload component monitoring.",
            recommendation="Verify IAM permissions for CloudWatch, Config, Health, and X-Ray APIs.",
        )


def check_rel06_bp02_define_calculate_metrics(session):
    print("Checking REL06-BP02 - Define and calculate metrics (Aggregation)")

    cloudwatch = session.client("cloudwatch")
    logs = session.client("logs")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_notification_aggregation.html"

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
            "id": "REL06-BP02",
            "check_name": "Define and calculate metrics (Aggregation)",
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
                "1. Define custom CloudWatch metrics for business and technical KPIs.",
                "2. Implement metric aggregation and statistical calculations.",
                "3. Configure CloudWatch Logs for application and system logging.",
                "4. Set up metric streams for real-time data processing.",
                "5. Create composite metrics and calculated fields for insights.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Check Custom Metrics (Put Metric Data) ------------------------
        try:
            # Test if we can access put_metric_data API (without actually putting data)
            # This validates the capability to define custom metrics
            cloudwatch.list_metrics(Namespace="Custom")
            custom_metrics_capability = True
        except Exception as e:
            print(f"cloudwatch custom metrics access error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "custom_metrics",
                    "issue": "Cannot access custom metrics capability for metric definition",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check Metric Statistics ------------------------
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            metric_stats = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=["Average"],
            )

            if len(metric_stats.get("Datapoints", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "metric_statistics",
                        "issue": "No metric statistics available for aggregation calculations",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        # ------------------------ Check CloudWatch Logs ------------------------
        try:
            log_groups = logs.describe_log_groups()
            if len(log_groups.get("logGroups", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "log_groups",
                        "issue": "No CloudWatch log groups found for log-based metrics",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"logs.describe_log_groups error: {e}")

        # ------------------------ Check Metric Streams ------------------------
        try:
            metric_streams = cloudwatch.list_metric_streams()
            if len(metric_streams.get("Entries", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "metric_streams",
                        "issue": "No CloudWatch metric streams found for real-time metric processing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.list_metric_streams error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without properly defined and calculated metrics, it's difficult to "
                "measure workload performance, identify trends, and make data-driven decisions "
                "for reliability improvements."
            ),
            recommendation=(
                "Implement comprehensive metric definition and calculation using custom CloudWatch "
                "metrics, statistical aggregations, log-based metrics, and real-time metric streams."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL06-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating metric definition and calculation.",
            recommendation="Verify IAM permissions for CloudWatch and CloudWatch Logs APIs.",
        )


def check_rel06_bp03_send_notifications(session):
    print(
        "Checking REL06-BP03 - Send notifications (Real-time processing and alarming)"
    )

    sns = session.client("sns")
    cloudwatch = session.client("cloudwatch")
    events = session.client("events")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_notification_monitor.html"

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
            "id": "REL06-BP03",
            "check_name": "Send notifications (Real-time processing and alarming)",
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
                "1. Configure SNS topics for alert notifications.",
                "2. Set up CloudWatch alarms with appropriate thresholds.",
                "3. Create EventBridge rules for event-driven notifications.",
                "4. Configure alarm history tracking for incident analysis.",
                "5. Implement multi-channel notification strategies.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check SNS Topics ------------------------
        try:
            topics = sns.list_topics()
            if len(topics.get("Topics", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_topics",
                        "issue": "No SNS topics found for notification delivery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_topics error: {e}")

        # ------------------------ Check SNS Subscriptions ------------------------
        try:
            subscriptions = sns.list_subscriptions()
            if len(subscriptions.get("Subscriptions", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_subscriptions",
                        "issue": "No SNS subscriptions found for notification endpoints",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_subscriptions error: {e}")

        # ------------------------ Check CloudWatch Alarms ------------------------
        try:
            alarms = cloudwatch.describe_alarms()
            if len(alarms.get("MetricAlarms", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms found for automated alerting",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # ------------------------ Check Alarm History ------------------------
        try:
            alarm_history = cloudwatch.describe_alarm_history(MaxRecords=1)
            if len(alarm_history.get("AlarmHistoryItems", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "alarm_history",
                        "issue": "No alarm history found for incident tracking and analysis",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarm_history error: {e}")

        # ------------------------ Check EventBridge Rules ------------------------
        try:
            rules = events.list_rules()
            if len(rules.get("Rules", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_rules",
                        "issue": "No EventBridge rules found for event-driven notifications",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper notification systems, critical issues may go unnoticed, "
                "leading to delayed incident response and prolonged service disruptions."
            ),
            recommendation=(
                "Implement comprehensive notification systems using SNS topics, CloudWatch alarms, "
                "EventBridge rules, and alarm history tracking for real-time alerting and incident management."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL06-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating notification systems.",
            recommendation="Verify IAM permissions for SNS, CloudWatch, and EventBridge APIs.",
        )


def check_rel06_bp04_automate_responses(session):
    print(
        "Checking REL06-BP04 - Automate responses (Real-time processing and alarming)"
    )

    ssm = session.client("ssm")
    lambda_client = session.client("lambda")
    events = session.client("events")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_automate_response_monitor.html"

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
            "id": "REL06-BP04",
            "check_name": "Automate responses (Real-time processing and alarming)",
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
                "1. Create SSM Automation documents for incident response.",
                "2. Configure Lambda functions for automated remediation.",
                "3. Set up EventBridge rules to trigger automated responses.",
                "4. Implement automated scaling and recovery mechanisms.",
                "5. Test and validate automated response procedures regularly.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 6
    affected = 0

    try:
        # ------------------------ Check SSM Automation Executions ------------------------
        try:
            executions = ssm.describe_automation_executions(MaxResults=1)
            if len(executions.get("AutomationExecutionMetadataList", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ssm_executions",
                        "issue": "No SSM automation executions found for automated responses",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ssm.describe_automation_executions error: {e}")

        # ------------------------ Check SSM Automation Documents ------------------------
        try:
            documents = ssm.describe_automation_documents()
            if len(documents.get("DocumentIdentifiers", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ssm_documents",
                        "issue": "No SSM automation documents found for response procedures",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ssm.describe_automation_documents error: {e}")

        # ------------------------ Check SSM Automation Capability ------------------------
        try:
            # Test if we can access start_automation_execution API (without starting)
            # This validates the capability for automated responses
            ssm.describe_automation_executions(MaxResults=1)
            automation_capability = True
        except Exception as e:
            print(f"ssm automation capability error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "ssm_automation",
                    "issue": "Cannot access SSM automation capability for automated responses",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check Lambda Functions ------------------------
        try:
            functions = lambda_client.list_functions()
            if len(functions.get("Functions", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_functions",
                        "issue": "No Lambda functions found for automated response processing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # ------------------------ Check EventBridge Rules ------------------------
        try:
            rules = events.list_rules()
            automation_rules = []
            for rule in rules.get("Rules", []):
                try:
                    rule_details = events.describe_rule(Name=rule["Name"])
                    # Check if rule has targets that could trigger automation
                    targets = events.list_targets_by_rule(Rule=rule["Name"])
                    if len(targets.get("Targets", [])) > 0:
                        automation_rules.append(rule["Name"])
                except Exception as e:
                    print(f"Error checking rule {rule.get('Name', '')}: {e}")

            if len(automation_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_automation",
                        "issue": "No EventBridge rules with targets found for automated responses",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated response capabilities, incident resolution depends on manual "
                "intervention, leading to longer recovery times and potential service degradation."
            ),
            recommendation=(
                "Implement automated response systems using SSM Automation, Lambda functions, "
                "and EventBridge rules to enable rapid incident response and self-healing capabilities."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL06-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automated response systems.",
            recommendation="Verify IAM permissions for SSM, Lambda, and EventBridge APIs.",
        )


def check_rel06_bp05_analyze_logs(session):
    print("Checking REL06-BP05 - Analyze logs")

    logs = session.client("logs")
    athena = session.client("athena")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_storage_analytics.html"

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
            "id": "REL06-BP05",
            "check_name": "Analyze logs",
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
                "1. Configure CloudWatch Logs for centralized log collection.",
                "2. Set up log streams for different application components.",
                "3. Implement log filtering and search capabilities.",
                "4. Use Amazon Athena for advanced log analytics.",
                "5. Create log-based metrics and alerts for proactive monitoring.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check CloudWatch Log Groups ------------------------
        try:
            log_groups = logs.describe_log_groups()
            if len(log_groups.get("logGroups", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "log_groups",
                        "issue": "No CloudWatch log groups found for log analysis",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"logs.describe_log_groups error: {e}")

        # ------------------------ Check Log Streams ------------------------
        try:
            # Get first log group to check for streams
            log_groups = logs.describe_log_groups(limit=1)
            if len(log_groups.get("logGroups", [])) > 0:
                log_group_name = log_groups["logGroups"][0]["logGroupName"]
                log_streams = logs.describe_log_streams(
                    logGroupName=log_group_name, limit=1
                )
                if len(log_streams.get("logStreams", [])) == 0:
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": "log_streams",
                            "issue": "No log streams found in log groups for detailed analysis",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"logs.describe_log_streams error: {e}")

        # ------------------------ Check Log Event Filtering ------------------------
        try:
            # Test log filtering capability (without actually filtering large datasets)
            log_groups = logs.describe_log_groups(limit=1)
            if len(log_groups.get("logGroups", [])) > 0:
                log_group_name = log_groups["logGroups"][0]["logGroupName"]
                from datetime import datetime, timedelta

                start_time = int(
                    (datetime.utcnow() - timedelta(hours=1)).timestamp() * 1000
                )

                filtered_events = logs.filter_log_events(
                    logGroupName=log_group_name, startTime=start_time, limit=1
                )
                log_filtering_available = True
        except Exception as e:
            print(f"logs.filter_log_events error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "log_filtering",
                    "issue": "Cannot access log filtering capability for log analysis",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check Athena Query Executions ------------------------
        try:
            query_executions = athena.list_query_executions(MaxResults=1)
            if len(query_executions.get("QueryExecutionIds", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "athena_queries",
                        "issue": "No Athena query executions found for advanced log analytics",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"athena.list_query_executions error: {e}")

        # ------------------------ Check Athena Query Capability ------------------------
        try:
            # Test if we can access get_query_execution API
            # This validates the capability for advanced log analytics
            query_executions = athena.list_query_executions(MaxResults=1)
            if len(query_executions.get("QueryExecutionIds", [])) > 0:
                query_id = query_executions["QueryExecutionIds"][0]
                athena.get_query_execution(QueryExecutionId=query_id)
            athena_analytics_available = True
        except Exception as e:
            print(f"athena query capability error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "athena_analytics",
                    "issue": "Cannot access Athena analytics capability for advanced log analysis",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper log analysis capabilities, it's difficult to troubleshoot issues, "
                "identify patterns, and gain insights into system behavior and performance."
            ),
            recommendation=(
                "Implement comprehensive log analysis using CloudWatch Logs, log filtering, "
                "and Amazon Athena for advanced analytics and troubleshooting capabilities."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL06-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating log analysis capabilities.",
            recommendation="Verify IAM permissions for CloudWatch Logs and Athena APIs.",
        )


def check_rel06_bp06_regularly_review_monitoring(session):
    print("Checking REL06-BP06 - Regularly review monitoring scope and metrics")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_review_monitoring.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL06-BP06",
            "check_name": "Regularly review monitoring scope and metrics",
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
                "1. Establish regular monitoring review cycles and schedules.",
                "2. Evaluate monitoring coverage for all workload components.",
                "3. Review and update metric thresholds based on operational data.",
                "4. Assess the effectiveness of current alerting strategies.",
                "5. Document monitoring review processes and findings.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS does not expose APIs to determine whether monitoring scope and metrics "
                "are regularly reviewed. Monitoring reviews, threshold updates, and alert "
                "effectiveness must be validated through operational governance processes."
            ),
            recommendation=(
                "Establish periodic monitoring review cycles to evaluate coverage, refine "
                "thresholds, assess alerting effectiveness, and ensure monitoring strategy "
                "aligns with workload requirements."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL06-BP06: {e}")
        return build_response(
            status="error",
            problem="Unable to assess monitoring review processes.",
            recommendation="Review monitoring governance documentation and operational review procedures.",
        )


def check_rel06_bp07_monitor_end_to_end_tracing(session):
    print(
        "Checking REL06-BP07 - Monitor end-to-end tracing of requests through your system"
    )

    xray = session.client("xray")
    cloudwatch = session.client("cloudwatch")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_monitor_aws_resources_end_to_end.html"

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
            "id": "REL06-BP07",
            "check_name": "Monitor end-to-end tracing of requests through your system",
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
                "1. Enable AWS X-Ray tracing for distributed applications.",
                "2. Configure trace sampling rules for optimal performance.",
                "3. Set up service maps to visualize request flows.",
                "4. Create CloudWatch dashboards for tracing metrics.",
                "5. Implement trace analysis for performance optimization.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Check X-Ray Trace Summaries ------------------------
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            trace_summaries = xray.get_trace_summaries(
                TimeRangeType="TimeRangeByStartTime",
                StartTime=start_time,
                EndTime=end_time,
            )

            if len(trace_summaries.get("TraceSummaries", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "xray_traces",
                        "issue": "No X-Ray traces found for end-to-end request monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"xray.get_trace_summaries error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "xray_tracing",
                    "issue": "Cannot access X-Ray tracing for end-to-end monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------ Check X-Ray Service Map ------------------------
        try:
            service_statistics = xray.get_service_graph(
                StartTime=start_time, EndTime=end_time
            )

            if len(service_statistics.get("Services", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "xray_service_map",
                        "issue": "No X-Ray service map data for distributed system visualization",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"xray.get_service_graph error: {e}")

        # ------------------------ Check CloudWatch Tracing Metrics ------------------------
        try:
            metrics = cloudwatch.list_metrics(
                Namespace="AWS/X-Ray", MetricName="TracesReceived"
            )

            if len(metrics.get("Metrics", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "xray_metrics",
                        "issue": "No X-Ray metrics available for trace monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")

        # ------------------------ Check X-Ray Sampling Rules ------------------------
        try:
            sampling_rules = xray.get_sampling_rules()

            if len(sampling_rules.get("SamplingRuleRecords", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "xray_sampling",
                        "issue": "No X-Ray sampling rules configured for trace collection",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"xray.get_sampling_rules error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without end-to-end tracing, it's difficult to understand request flows, "
                "identify bottlenecks, and troubleshoot issues in distributed systems."
            ),
            recommendation=(
                "Implement AWS X-Ray tracing to monitor end-to-end request flows, "
                "configure sampling rules, and create service maps for distributed system visibility."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL06-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating end-to-end tracing capabilities.",
            recommendation="Verify IAM permissions for X-Ray and CloudWatch APIs.",
        )


def check_rel07_bp01_use_automation_scaling_resources(session):
    print("Checking REL07-BP01 - Use automation when obtaining or scaling resources")

    autoscaling = session.client("autoscaling")
    app_autoscaling = session.client("application-autoscaling")
    lambda_client = session.client("lambda")
    ec2 = session.client("ec2")
    ecs = session.client("ecs")
    eks = session.client("eks")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_adapt_to_changes_autoscale_adapt.html"

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
            "id": "REL07-BP01",
            "check_name": "Use automation when obtaining or scaling resources",
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
                "1. Configure Auto Scaling groups for EC2 instances.",
                "2. Set up Application Auto Scaling for services.",
                "3. Define scaling policies based on metrics.",
                "4. Enable Lambda concurrency controls.",
                "5. Configure EKS node group auto scaling.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 7
    affected = 0

    try:
        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            if len(asgs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "auto_scaling_groups",
                        "issue": "No Auto Scaling groups found",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Application Auto Scaling Targets
        try:
            targets = app_autoscaling.describe_scalable_targets().get(
                "ScalableTargets", []
            )
            if len(targets) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scalable_targets",
                        "issue": "No Application Auto Scaling targets configured",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"application-autoscaling.describe_scalable_targets error: {e}")

        # Check Application Auto Scaling Policies
        try:
            policies = app_autoscaling.describe_scaling_policies().get(
                "ScalingPolicies", []
            )
            if len(policies) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No Application Auto Scaling policies configured",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"application-autoscaling.describe_scaling_policies error: {e}")

        # Check Lambda Concurrency
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            has_concurrency = False
            for func in functions:
                try:
                    concurrency = lambda_client.get_function_concurrency(
                        FunctionName=func["FunctionName"]
                    )
                    if "ReservedConcurrencyLimit" in concurrency:
                        has_concurrency = True
                        break
                except Exception:
                    continue
            if not has_concurrency and len(functions) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_concurrency",
                        "issue": "No Lambda functions have reserved concurrency configured",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda concurrency check error: {e}")

        # Check EC2 Instances in ASG
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            has_asg = False
            for res in reservations:
                for inst in res.get("Instances", []):
                    if inst.get("State", {}).get("Name") == "running":
                        for tag in inst.get("Tags", []):
                            if tag.get("Key") == "aws:autoscaling:groupName":
                                has_asg = True
                                break
                    if has_asg:
                        break
                if has_asg:
                    break
            if (
                not has_asg
                and len([i for r in reservations for i in r.get("Instances", [])]) > 0
            ):
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_auto_scaling",
                        "issue": "EC2 instances found without Auto Scaling group association",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_instances error: {e}")

        # Check ECS Services
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            has_scaling = False
            for cluster in clusters:
                services = ecs.list_services(cluster=cluster).get("serviceArns", [])
                if services:
                    svc_details = ecs.describe_services(
                        cluster=cluster, services=services
                    ).get("services", [])
                    for svc in svc_details:
                        if svc.get("desiredCount", 0) > 1:
                            has_scaling = True
                            break
                if has_scaling:
                    break
            if not has_scaling and len(clusters) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ecs_auto_scaling",
                        "issue": "ECS services found without auto scaling configuration",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ecs services check error: {e}")

        # Check EKS Node Groups
        try:
            clusters = eks.list_clusters().get("clusters", [])
            has_nodegroup = False
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get(
                    "nodegroups", []
                )
                if nodegroups:
                    for ng in nodegroups:
                        ng_details = eks.describe_nodegroup(
                            clusterName=cluster, nodegroupName=ng
                        )
                        if ng_details.get("nodegroup", {}).get("scalingConfig"):
                            has_nodegroup = True
                            break
                if has_nodegroup:
                    break
            if not has_nodegroup and len(clusters) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eks_nodegroups",
                        "issue": "EKS clusters found without node group auto scaling",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"eks.describe_nodegroup error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automation for scaling resources, workloads may not respond "
                "effectively to demand changes, leading to performance issues or unnecessary costs."
            ),
            recommendation=(
                "Implement automated scaling using Auto Scaling groups, Application Auto Scaling, "
                "Lambda concurrency controls, and EKS node group auto scaling."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL07-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automation for scaling resources.",
            recommendation="Verify IAM permissions for Auto Scaling, Lambda, EC2, ECS, and EKS APIs.",
        )


def check_rel07_bp02_obtain_resources_upon_impairment(session):
    print(
        "Checking REL07-BP02 - Obtain resources upon detection of impairment to a workload"
    )

    cloudwatch = session.client("cloudwatch")
    autoscaling = session.client("autoscaling")
    ssm = session.client("ssm")
    events = session.client("events")
    lambda_client = session.client("lambda")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_adapt_to_changes_reactive_adapt_auto.html"

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
            "id": "REL07-BP02",
            "check_name": "Obtain resources upon detection of impairment to a workload",
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
                "1. Configure CloudWatch alarms for workload health monitoring.",
                "2. Set up Auto Scaling policies triggered by alarms.",
                "3. Create SSM automation for automated recovery.",
                "4. Configure EventBridge rules for impairment detection.",
                "5. Implement Lambda functions for automated remediation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 7
    affected = 0

    try:
        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            if len(alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms configured for impairment detection",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check Alarm History
        try:
            history = cloudwatch.describe_alarm_history(MaxRecords=1).get(
                "AlarmHistoryItems", []
            )
            if len(history) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "alarm_history",
                        "issue": "No alarm history found for tracking impairment events",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarm_history error: {e}")

        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            if len(asgs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "auto_scaling_groups",
                        "issue": "No Auto Scaling groups for automatic resource provisioning",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Auto Scaling Policies
        try:
            policies = autoscaling.describe_policies().get("ScalingPolicies", [])
            if len(policies) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No Auto Scaling policies configured for impairment response",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_policies error: {e}")

        # Check SSM Automation Executions
        try:
            executions = ssm.describe_automation_executions(MaxResults=1).get(
                "AutomationExecutionMetadataList", []
            )
            if len(executions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ssm_automation",
                        "issue": "No SSM automation executions for automated recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ssm.describe_automation_executions error: {e}")

        # Check EventBridge Rules
        try:
            rules = events.list_rules().get("Rules", [])
            if len(rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_rules",
                        "issue": "No EventBridge rules for event-driven resource provisioning",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # Check Lambda Functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            if len(functions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_functions",
                        "issue": "No Lambda functions for automated remediation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated resource provisioning upon impairment detection, workloads "
                "may experience prolonged degradation or outages during failure scenarios."
            ),
            recommendation=(
                "Implement automated resource provisioning using CloudWatch alarms, Auto Scaling "
                "policies, SSM automation, EventBridge rules, and Lambda functions for rapid response."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL07-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating resource provisioning upon impairment.",
            recommendation="Verify IAM permissions for CloudWatch, Auto Scaling, SSM, EventBridge, and Lambda APIs.",
        )


def check_rel07_bp03_obtain_resources_when_more_needed(session):
    print(
        "Checking REL07-BP03 - Obtain resources upon detection that more resources are needed for a workload"
    )

    app_autoscaling = session.client("application-autoscaling")
    cloudwatch = session.client("cloudwatch")
    ec2 = session.client("ec2")
    ecs = session.client("ecs")
    eks = session.client("eks")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_adapt_to_changes_proactive_adapt_auto.html"

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
            "id": "REL07-BP03",
            "check_name": "Obtain resources upon detection that more resources are needed for a workload",
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
                "1. Configure Application Auto Scaling targets for services.",
                "2. Define scaling policies based on resource utilization metrics.",
                "3. Set up CloudWatch alarms for capacity monitoring.",
                "4. Monitor EC2, ECS, and EKS resource utilization.",
                "5. Implement proactive scaling based on predictive metrics.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 7
    affected = 0

    try:
        # Check Application Auto Scaling Targets
        try:
            targets = app_autoscaling.describe_scalable_targets().get(
                "ScalableTargets", []
            )
            if len(targets) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scalable_targets",
                        "issue": "No Application Auto Scaling targets for capacity management",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"application-autoscaling.describe_scalable_targets error: {e}")

        # Check Application Auto Scaling Policies
        try:
            policies = app_autoscaling.describe_scaling_policies().get(
                "ScalingPolicies", []
            )
            if len(policies) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No Application Auto Scaling policies for resource provisioning",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"application-autoscaling.describe_scaling_policies error: {e}")

        # Check CloudWatch Metric Data
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "capacity_metrics",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                            },
                            "Period": 3600,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            if len(metric_data.get("MetricDataResults", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "metric_data",
                        "issue": "No metric data for capacity monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            if len(alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms for capacity threshold monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check EC2 Instances
        try:
            instances = ec2.describe_instances().get("Reservations", [])
            if len([i for r in instances for i in r.get("Instances", [])]) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_instances",
                        "issue": "No EC2 instances for workload capacity",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_instances error: {e}")

        # Check ECS Services
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            has_services = False
            for cluster in clusters:
                services = ecs.list_services(cluster=cluster).get("serviceArns", [])
                if services:
                    has_services = True
                    break
            if not has_services and len(clusters) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ecs_services",
                        "issue": "No ECS services for workload capacity management",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ecs.list_services error: {e}")

        # Check EKS Node Groups
        try:
            clusters = eks.list_clusters().get("clusters", [])
            has_nodegroups = False
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get(
                    "nodegroups", []
                )
                if nodegroups:
                    has_nodegroups = True
                    break
            if not has_nodegroups and len(clusters) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eks_nodegroups",
                        "issue": "No EKS node groups for workload capacity management",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"eks.list_nodegroups error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proactive resource provisioning based on capacity monitoring, workloads "
                "may experience performance degradation when demand increases."
            ),
            recommendation=(
                "Implement proactive resource provisioning using Application Auto Scaling, "
                "CloudWatch metrics and alarms, and capacity monitoring for EC2, ECS, and EKS."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL07-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating proactive resource provisioning.",
            recommendation="Verify IAM permissions for Application Auto Scaling, CloudWatch, EC2, ECS, and EKS APIs.",
        )


def check_rel07_bp04_load_test_workload(session):
    print("Checking REL07-BP04 - Load test your workload")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_adapt_to_changes_load_tested_adapt.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL07-BP04",
            "check_name": "Load test your workload",
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
                "1. Establish regular load testing schedules and procedures.",
                "2. Define realistic load test scenarios based on expected traffic.",
                "3. Use load testing tools to simulate production workloads.",
                "4. Analyze load test results to identify bottlenecks.",
                "5. Document load testing processes and findings.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS APIs cannot determine whether regular load testing is performed. "
                "Load testing frequency, scope, and results must be validated through "
                "operational and architectural documentation."
            ),
            recommendation=(
                "Establish regular load testing procedures to validate scaling behavior, "
                "identify performance bottlenecks, and ensure workloads can sustain "
                "expected production traffic levels."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL07-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess load testing practices.",
            recommendation="Review load testing documentation, governance, and validation procedures.",
        )


# REL 8. How do you implement change?


def check_rel08_bp01_use_runbooks_for_standard_activities(session):
    print(
        "Checking REL08-BP01 - Use runbooks for standard activities such as deployment"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_tracking_change_management_planned_changemgmt.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL08-BP01",
            "check_name": "Use runbooks for standard activities such as deployment",
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
                "1. Create documented runbooks for standard deployment activities.",
                "2. Define step-by-step procedures for common operational tasks.",
                "3. Implement runbook automation using AWS Systems Manager.",
                "4. Regularly review and update runbooks based on operational experience.",
                "5. Train team members on runbook usage and procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS APIs cannot determine whether runbooks exist or are regularly maintained. "
                "Runbook creation, review, and operational governance must be validated through "
                "internal documentation and processes."
            ),
            recommendation=(
                "Create and maintain detailed runbooks for deployments, scaling, and recovery. "
                "Automate runbooks where possible and ensure teams are trained in their usage."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL08-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess runbook implementation processes.",
            recommendation="Review operational documentation and runbook governance practices.",
        )


def check_rel08_bp02_integrate_functional_testing(session):
    print(
        "Checking REL08-BP02 - Integrate functional testing as part of your deployment"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_tracking_change_management_functional_testing.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL08-BP02",
            "check_name": "Integrate functional testing as part of your deployment",
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
                "1. Integrate automated functional tests into CI/CD pipelines.",
                "2. Define comprehensive test cases covering critical functionality.",
                "3. Implement pre-deployment and post-deployment testing stages.",
                "4. Use AWS CodePipeline and CodeBuild for automated testing.",
                "5. Establish rollback procedures based on test failures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Functional testing integration within CI/CD pipelines cannot be assessed using "
                "AWS APIs. Testing scope, automation, and governance must be validated through "
                "deployment process documentation and pipeline configurations."
            ),
            recommendation=(
                "Integrate automated functional tests into CI/CD workflows, covering critical "
                "business functionality, and implement rollback mechanisms triggered by test failures."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL08-BP02: {e}")
        return build_response(
            status="error",
            problem="Unable to assess functional testing implementation.",
            recommendation="Review CI/CD pipeline configurations, testing documentation, and governance practices.",
        )


def check_rel08_bp03_integrate_resiliency_testing(session):
    print(
        "Checking REL08-BP03 - Integrate resiliency testing as part of your deployment"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_tracking_change_management_resiliency_testing.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL08-BP03",
            "check_name": "Integrate resiliency testing as part of your deployment",
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
                "1. Implement chaos engineering practices using AWS Fault Injection Simulator.",
                "2. Define failure scenarios and test recovery procedures.",
                "3. Integrate resiliency tests into CI/CD pipelines.",
                "4. Validate failover mechanisms and disaster recovery procedures.",
                "5. Document and review resiliency test results regularly.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Resiliency testing practices such as chaos engineering, failover validation, "
                "and disaster recovery testing cannot be evaluated through AWS APIs. These must "
                "be verified through testing documentation and deployment pipeline configuration."
            ),
            recommendation=(
                "Integrate resiliency testing into CI/CD pipelines using AWS Fault Injection Simulator "
                "and chaos engineering principles to validate fault tolerance, failover behavior, and "
                "disaster recovery readiness."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL08-BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to assess resiliency testing processes.",
            recommendation="Review test documentation, chaos engineering procedures, and resilience validation plans.",
        )


def check_rel08_bp04_deploy_using_immutable_infrastructure(session):
    print("Checking REL08-BP04 - Deploy using immutable infrastructure")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_tracking_change_management_immutable_infrastructure.html"

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
            "id": "REL08-BP04",
            "check_name": "Deploy using immutable infrastructure",
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
                "1. Use CloudFormation or Terraform for infrastructure as code.",
                "2. Deploy EC2 instances from versioned AMIs using Image Builder.",
                "3. Use ECS/EKS with container images for immutable deployments.",
                "4. Implement blue/green or canary deployment strategies.",
                "5. Avoid manual configuration changes on running instances.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        cfn = session.client("cloudformation")
        ec2 = session.client("ec2")
        imagebuilder = session.client("imagebuilder")
        ecs = session.client("ecs")
        eks = session.client("eks")

        # Check CloudFormation stacks
        try:
            stacks = cfn.describe_stacks().get("Stacks", [])
            total_scanned += len(stacks)
            if len(stacks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudformation_stacks",
                        "issue": "No CloudFormation stacks found for infrastructure as code",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cfn.describe_stacks error: {e}")

        # Check CloudFormation StackSets
        try:
            stacksets = cfn.list_stack_sets().get("Summaries", [])
            total_scanned += 1
            if len(stacksets) > 0:
                total_scanned += len(stacksets)
        except Exception as e:
            print(f"cfn.list_stack_sets error: {e}")

        # Check EC2 AMIs
        try:
            images = ec2.describe_images(Owners=["self"]).get("Images", [])
            total_scanned += 1
            if len(images) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_amis",
                        "issue": "No custom AMIs found for immutable EC2 deployments",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_images error: {e}")

        # Check Image Builder pipelines
        try:
            pipelines = imagebuilder.list_image_pipelines().get("imagePipelineList", [])
            total_scanned += 1
            if len(pipelines) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "image_builder_pipelines",
                        "issue": "No Image Builder pipelines for automated AMI creation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"imagebuilder.list_image_pipelines error: {e}")

        # Check ECS services
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                services = ecs.list_services(cluster=cluster).get("serviceArns", [])
                if services:
                    total_scanned += len(services)
        except Exception as e:
            print(f"ecs.list_services error: {e}")

        # Check EKS node groups
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get(
                    "nodegroups", []
                )
                if nodegroups:
                    total_scanned += len(nodegroups)
        except Exception as e:
            print(f"eks.list_nodegroups error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without immutable infrastructure, manual changes can lead to configuration drift, "
                "inconsistent environments, and difficulty in rollback during failures."
            ),
            recommendation=(
                "Deploy using immutable infrastructure with CloudFormation, versioned AMIs, "
                "Image Builder pipelines, and container-based deployments with ECS/EKS."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL08-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating immutable infrastructure.",
            recommendation="Verify IAM permissions for CloudFormation, EC2, Image Builder, ECS, and EKS APIs.",
        )


def check_rel08_bp05_deploy_changes_with_automation(session):
    print("Checking REL08-BP05 - Deploy changes with automation")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_tracking_change_management_automated_changemgmt.html"

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
            "id": "REL08-BP05",
            "check_name": "Deploy changes with automation",
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
                "1. Implement CI/CD pipelines using AWS CodePipeline.",
                "2. Use CodeBuild for automated build and test processes.",
                "3. Configure CodeDeploy for automated application deployments.",
                "4. Use CloudFormation change sets for infrastructure updates.",
                "5. Implement EventBridge rules for automated deployment triggers.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        codepipeline = session.client("codepipeline")
        codebuild = session.client("codebuild")
        codedeploy = session.client("codedeploy")
        cfn = session.client("cloudformation")
        events = session.client("events")

        # Check CodePipeline pipelines
        try:
            pipelines = codepipeline.list_pipelines().get("pipelines", [])
            total_scanned += len(pipelines)
            if len(pipelines) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "codepipeline_pipelines",
                        "issue": "No CodePipeline pipelines found for automated deployments",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"codepipeline.list_pipelines error: {e}")

        # Check CodeBuild projects
        try:
            projects = codebuild.list_projects().get("projects", [])
            total_scanned += len(projects)
            if len(projects) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "codebuild_projects",
                        "issue": "No CodeBuild projects found for automated builds",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"codebuild.list_projects error: {e}")

        # Check CodeDeploy applications
        try:
            applications = codedeploy.list_applications().get("applications", [])
            total_scanned += len(applications)
            if len(applications) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "codedeploy_applications",
                        "issue": "No CodeDeploy applications found for automated deployments",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"codedeploy.list_applications error: {e}")

        # Check CloudFormation change sets
        try:
            stacks = cfn.describe_stacks().get("Stacks", [])
            for stack in stacks:
                changesets = cfn.list_change_sets(StackName=stack["StackName"]).get(
                    "Summaries", []
                )
                if changesets:
                    total_scanned += len(changesets)
        except Exception as e:
            print(f"cfn.list_change_sets error: {e}")

        # Check EventBridge rules for automation
        try:
            rules = events.list_rules().get("Rules", [])
            deployment_rules = [
                r
                for r in rules
                if "deploy" in r.get("Name", "").lower()
                or "pipeline" in r.get("Name", "").lower()
            ]
            total_scanned += len(deployment_rules)
        except Exception as e:
            print(f"events.list_rules error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated deployment processes, manual deployments increase risk of errors, "
                "inconsistencies, and longer recovery times during incidents."
            ),
            recommendation=(
                "Implement automated deployment using CodePipeline, CodeBuild, CodeDeploy, "
                "CloudFormation change sets, and EventBridge for consistent and reliable deployments."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL08-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating deployment automation.",
            recommendation="Verify IAM permissions for CodePipeline, CodeBuild, CodeDeploy, CloudFormation, and EventBridge APIs.",
        )
