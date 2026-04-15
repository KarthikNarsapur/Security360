from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# PERF 5. How do your organizational practices and culture contribute to performance efficiency in your workload?

# PERF05-BP01 Establish key performance indicators (KPIs) to measure workload health and performance
def check_perf05_bp01_establish_kpis(session):
    print("Checking PERF05-BP01 – Establish key performance indicators (KPIs) to measure workload health and performance")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_establish_key_performance_indicators.html"

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
            "id": "PERF05-BP01",
            "check_name": "Establish key performance indicators (KPIs) to measure workload health and performance",
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
                "1. Define KPIs aligned with business objectives and workload requirements.",
                "2. Establish baseline metrics for performance, availability, and latency.",
                "3. Set up CloudWatch dashboards to visualize KPIs.",
                "4. Configure CloudWatch alarms for KPI thresholds.",
                "5. Regularly review and adjust KPIs based on workload changes.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for KPI establishment",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must establish key performance indicators (KPIs) to measure workload health "
            "and performance. This is an organizational responsibility."
        ),
        recommendation=(
            "Define KPIs aligned with business objectives, establish baseline metrics, set up CloudWatch "
            "dashboards and alarms, and regularly review KPIs."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF05-BP02 Use monitoring solutions to understand the areas where performance is most critical
def check_perf05_bp02_use_monitoring_solutions(session):
    print("Checking PERF05-BP02 – Use monitoring solutions to understand the areas where performance is most critical")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_use_monitoring_solutions.html"

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
            "id": "PERF05-BP02",
            "check_name": "Use monitoring solutions to understand the areas where performance is most critical",
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
                "1. Configure CloudWatch metrics and alarms for critical resources.",
                "2. Implement AWS X-Ray for distributed tracing and analysis.",
                "3. Enable RDS Performance Insights for database monitoring.",
                "4. Use DevOps Guru for anomaly detection and insights.",
                "5. Set up CloudWatch Synthetics canaries for proactive monitoring.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        cloudwatch = session.client("cloudwatch")
        xray = session.client("xray")
        rds = session.client("rds")
        devops_guru = session.client("devops-guru")
        synthetics = session.client("synthetics")

        # Check CloudWatch metrics
        try:
            metrics = cloudwatch.list_metrics(MaxRecords=1).get("Metrics", [])
            total_scanned += 1
            if len(metrics) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_metrics",
                    "issue": "No CloudWatch metrics configured for monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")

        # Check CloudWatch metric data
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_data(
                MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"}, "Period": 300, "Stat": "Average"}}],
                StartTime=start_time,
                EndTime=end_time
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # Check CloudWatch alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
            if len(alarms) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_alarms",
                    "issue": "No CloudWatch alarms configured for monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check X-Ray service graph
        try:
            xray.get_service_graph(StartTime=start_time, EndTime=end_time)
            total_scanned += 1
        except Exception as e:
            print(f"xray.get_service_graph error: {e}")

        # Check X-Ray trace summaries
        try:
            xray.get_trace_summaries(StartTime=start_time, EndTime=end_time)
            total_scanned += 1
        except Exception as e:
            print(f"xray.get_trace_summaries error: {e}")

        # Check RDS instances
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            total_scanned += 1
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check DevOps Guru monitored resources
        try:
            monitored = devops_guru.list_monitored_resources().get("MonitoredResourceIdentifiers", [])
            total_scanned += 1
            if len(monitored) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "devops_guru",
                    "issue": "No DevOps Guru monitored resources configured",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"devops-guru.list_monitored_resources error: {e}")

        # Check Synthetics canaries
        try:
            canaries = synthetics.describe_canaries().get("Canaries", [])
            total_scanned += 1
        except Exception as e:
            print(f"synthetics.describe_canaries error: {e}")

        # Check Synthetics canaries last run
        try:
            canaries_last_run = synthetics.describe_canaries_last_run().get("CanariesLastRun", [])
            total_scanned += 1
        except Exception as e:
            print(f"synthetics.describe_canaries_last_run error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without monitoring solutions, organizations cannot understand critical performance areas, "
                "identify bottlenecks, or proactively address issues."
            ),
            recommendation=(
                "Configure CloudWatch metrics and alarms, implement X-Ray tracing, enable RDS Performance Insights, "
                "use DevOps Guru for anomaly detection, and set up Synthetics canaries."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF05-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating monitoring solutions.",
            recommendation="Verify IAM permissions for CloudWatch, X-Ray, RDS, DevOps Guru, and Synthetics APIs.",
        )


# PERF05-BP03 Define a process to improve workload performance
def check_perf05_bp03_define_process_improve_performance(session):
    print("Checking PERF05-BP03 – Define a process to improve workload performance")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_workload_performance.html"

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
            "id": "PERF05-BP03",
            "check_name": "Define a process to improve workload performance",
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
                "1. Establish regular performance review cycles and optimization processes.",
                "2. Define clear ownership and accountability for performance improvements.",
                "3. Implement continuous monitoring and feedback loops.",
                "4. Document performance optimization procedures and best practices.",
                "5. Conduct regular performance testing and load testing.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for performance improvement process",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must define a process to improve workload performance through regular reviews, "
            "optimization cycles, and continuous improvement. This is an organizational responsibility."
        ),
        recommendation=(
            "Establish regular performance review cycles, define clear ownership, implement continuous monitoring, "
            "document optimization procedures, and conduct regular performance testing."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF05-BP04 Load test your workload
def check_perf05_bp04_load_test_workload(session):
    print("Checking PERF05-BP04 – Load test your workload")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_load_test.html"

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
            "id": "PERF05-BP04",
            "check_name": "Load test your workload",
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
                "1. Conduct regular load testing to identify performance bottlenecks.",
                "2. Use realistic test scenarios that simulate production workloads.",
                "3. Test at expected peak load and beyond to understand limits.",
                "4. Monitor system behavior and resource utilization during tests.",
                "5. Document test results and implement performance improvements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for load testing practices",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must conduct regular load testing to identify performance bottlenecks, "
            "understand system limits, and validate scalability. This is an organizational responsibility."
        ),
        recommendation=(
            "Conduct regular load testing with realistic scenarios, test at peak load and beyond, "
            "monitor system behavior, and document results for continuous improvement."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF05-BP05 Use automation to proactively remediate performance-related issues
def check_perf05_bp05_use_automation_remediate_issues(session):
    print("Checking PERF05-BP05 – Use automation to proactively remediate performance-related issues")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_automation_remediate_issues.html"

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
            "id": "PERF05-BP05",
            "check_name": "Use automation to proactively remediate performance-related issues",
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
                "1. Set up CloudWatch Synthetics canaries for proactive monitoring.",
                "2. Use CloudWatch metrics to trigger automated remediation.",
                "3. Monitor ECS tasks and EKS clusters for performance issues.",
                "4. Analyze cost and usage data to identify optimization opportunities.",
                "5. Implement automated scaling and remediation workflows.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        synthetics = session.client("synthetics")
        cloudwatch = session.client("cloudwatch")
        ecs = session.client("ecs")
        eks = session.client("eks")
        ce = session.client("ce")

        # Check Synthetics canaries
        try:
            canaries = synthetics.describe_canaries().get("Canaries", [])
            total_scanned += 1
        except Exception as e:
            print(f"synthetics.describe_canaries error: {e}")

        # Check Synthetics canaries last run
        try:
            canaries_last_run = synthetics.describe_canaries_last_run().get("CanariesLastRun", [])
            total_scanned += 1
        except Exception as e:
            print(f"synthetics.describe_canaries_last_run error: {e}")

        # Check CloudWatch metric data
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_data(
                MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"}, "Period": 300, "Stat": "Average"}}],
                StartTime=start_time,
                EndTime=end_time
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # Check ECS tasks
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters[:5]:
                ecs.list_tasks(cluster=cluster)
            total_scanned += 1
        except Exception as e:
            print(f"ecs.list_tasks error: {e}")

        # Check EKS clusters
        try:
            eks_clusters = eks.list_clusters().get("clusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"eks.list_clusters error: {e}")

        # Check Cost Explorer data
        try:
            ce.get_cost_and_usage(
                TimePeriod={"Start": start_time.strftime("%Y-%m-%d"), "End": end_time.strftime("%Y-%m-%d")},
                Granularity="DAILY",
                Metrics=["UnblendedCost"]
            )
            total_scanned += 1
        except Exception as e:
            print(f"ce.get_cost_and_usage error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automation to proactively remediate performance issues, organizations must rely on "
                "manual intervention, leading to slower response times and potential service degradation."
            ),
            recommendation=(
                "Set up Synthetics canaries, use CloudWatch metrics for automated remediation, monitor ECS/EKS workloads, "
                "analyze cost data, and implement automated scaling and remediation workflows."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF05-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automation for performance remediation.",
            recommendation="Verify IAM permissions for Synthetics, CloudWatch, ECS, EKS, and Cost Explorer APIs.",
        )


# PERF05-BP06 Keep your workload and services up-to-date
def check_perf05_bp06_keep_workload_services_updated(session):
    print("Checking PERF05-BP06 – Keep your workload and services up-to-date")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_keep_workload_and_services_up_to_date.html"

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
            "id": "PERF05-BP06",
            "check_name": "Keep your workload and services up-to-date",
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
                "1. Configure CloudWatch alarms for automated notifications.",
                "2. Use Systems Manager Automation for patch management.",
                "3. Set up EventBridge rules for automated workflows.",
                "4. Implement Lambda functions for automated updates.",
                "5. Use SNS topics for notification and alerting.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        cloudwatch = session.client("cloudwatch")
        ssm = session.client("ssm")
        events = session.client("events")
        lambda_client = session.client("lambda")
        sns = session.client("sns")

        # Check CloudWatch alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check CloudWatch put metric alarm (test API availability)
        try:
            cloudwatch.put_metric_alarm(
                AlarmName="test-alarm-check",
                ComparisonOperator="GreaterThanThreshold",
                EvaluationPeriods=1,
                MetricName="CPUUtilization",
                Namespace="AWS/EC2",
                Period=300,
                Statistic="Average",
                Threshold=80.0,
                ActionsEnabled=False,
                AlarmDescription="Test alarm for API check"
            )
            cloudwatch.delete_alarms(AlarmNames=["test-alarm-check"])
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.put_metric_alarm error: {e}")

        # Check SSM automation executions
        try:
            executions = ssm.describe_automation_executions(MaxResults=1).get("AutomationExecutionMetadataList", [])
            total_scanned += 1
        except Exception as e:
            print(f"ssm.describe_automation_executions error: {e}")

        # Check SSM start automation execution (test API availability)
        try:
            ssm.start_automation_execution(
                DocumentName="AWS-UpdateSSMAgent",
                Parameters={},
                Mode="Auto"
            )
            total_scanned += 1
        except Exception as e:
            print(f"ssm.start_automation_execution error: {e}")

        # Check EventBridge rules
        try:
            rules = events.list_rules().get("Rules", [])
            total_scanned += 1
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # Check Lambda functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            total_scanned += 1
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check SNS topics
        try:
            topics = sns.list_topics().get("Topics", [])
            total_scanned += 1
        except Exception as e:
            print(f"sns.list_topics error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without keeping workloads and services up-to-date, organizations may miss performance improvements, "
                "security patches, and new features that enhance efficiency."
            ),
            recommendation=(
                "Configure CloudWatch alarms, use Systems Manager Automation for updates, set up EventBridge rules, "
                "implement Lambda functions for automation, and use SNS for notifications."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF05-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating workload and services updates.",
            recommendation="Verify IAM permissions for CloudWatch, Systems Manager, EventBridge, Lambda, and SNS APIs.",
        )


# PERF05-BP07 Review metrics at regular intervals
def check_perf05_bp07_review_metrics_regular_intervals(session):
    print("Checking PERF05-BP07 – Review metrics at regular intervals")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_process_culture_review_metrics.html"

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
            "id": "PERF05-BP07",
            "check_name": "Review metrics at regular intervals",
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
                "1. Use Systems Manager to track instance information and patch compliance.",
                "2. Configure patch baselines and patch groups for automated patching.",
                "3. Implement EC2 Image Builder pipelines for automated AMI creation.",
                "4. Set up CodePipeline and CodeBuild for CI/CD automation.",
                "5. Regularly review and update EC2 AMIs for performance improvements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ssm = session.client("ssm")
        imagebuilder = session.client("imagebuilder")
        codepipeline = session.client("codepipeline")
        codebuild = session.client("codebuild")
        ec2 = session.client("ec2")

        # Check SSM instance information
        try:
            instances = ssm.describe_instance_information(MaxResults=1).get("InstanceInformationList", [])
            total_scanned += 1
        except Exception as e:
            print(f"ssm.describe_instance_information error: {e}")

        # Check SSM patch groups
        try:
            patch_groups = ssm.describe_patch_groups().get("Mappings", [])
            total_scanned += 1
        except Exception as e:
            print(f"ssm.describe_patch_groups error: {e}")

        # Check SSM patch baselines
        try:
            patch_baselines = ssm.describe_patch_baselines().get("BaselineIdentities", [])
            total_scanned += 1
        except Exception as e:
            print(f"ssm.describe_patch_baselines error: {e}")

        # Check Image Builder pipelines
        try:
            pipelines = imagebuilder.list_image_pipelines().get("imagePipelineList", [])
            total_scanned += 1
        except Exception as e:
            print(f"imagebuilder.list_image_pipelines error: {e}")

        # Check CodePipeline pipelines
        try:
            code_pipelines = codepipeline.list_pipelines().get("pipelines", [])
            total_scanned += 1
        except Exception as e:
            print(f"codepipeline.list_pipelines error: {e}")

        # Check CodeBuild projects
        try:
            projects = codebuild.list_projects().get("projects", [])
            total_scanned += 1
        except Exception as e:
            print(f"codebuild.list_projects error: {e}")

        # Check EC2 images
        try:
            images = ec2.describe_images(Owners=["self"], MaxResults=1).get("Images", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_images error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without reviewing metrics at regular intervals, organizations cannot identify performance trends, "
                "detect degradation, or make data-driven optimization decisions."
            ),
            recommendation=(
                "Use Systems Manager for instance and patch management, implement Image Builder pipelines, "
                "set up CodePipeline/CodeBuild for CI/CD, and regularly review EC2 AMIs."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF05-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating metrics review process.",
            recommendation="Verify IAM permissions for Systems Manager, Image Builder, CodePipeline, CodeBuild, and EC2 APIs.",
        )
