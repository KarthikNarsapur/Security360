from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_ops04_bp01_identify_kpis(session):
    print("Checking OPS04-BP01 – Identify key performance indicators")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_observability_identify_kpis.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS04-BP01",
            "check_name": "Identify key performance indicators",
            "problem_statement": problem,
            "severity_score": 35,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Define KPIs aligned to workload goals, customer impact, and business outcomes.",
                "2. Establish measurable metrics such as latency, availability, error rates, or cost efficiency.",
                "3. Prioritize KPIs that directly impact user experience and operational success.",
                "4. Continuously review and refine KPIs as workloads or business priorities evolve.",
                "5. Ensure KPIs are visible and monitored through dashboards and alerts.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "This best practice focuses on defining and selecting KPIs that align with workload and "
                "business goals, which cannot be programmatically evaluated using AWS APIs."
            ),
            recommendation=(
                "Define clear and measurable KPIs that reflect workload health and operational objectives, "
                "and ensure they are continuously monitored and refined."
            ),
        )

    except Exception as e:
        print(f"Error evaluating OPS04-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess KPI identification.",
            recommendation="Review KPI determination processes and retry the assessment.",
        )


def check_ops04_bp02_application_telemetry(session):
    print("Checking OPS04-BP02 – Implement application telemetry")

    cloudwatch = session.client("cloudwatch")
    logs = session.client("logs")
    xray = session.client("xray")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_observability_application_telemetry.html"

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
            "id": "OPS04-BP02",
            "check_name": "Implement application telemetry",
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
                "1. Instrument your application with CloudWatch metrics and structured logs.",
                "2. Enable AWS X-Ray for distributed tracing.",
                "3. Ensure log groups and log streams exist for all major application components.",
                "4. Implement application-level metrics and dashboards.",
                "5. Review telemetry coverage periodically and expand instrumentation where required.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4  # metrics, logs, streams, xray
    affected = 0

    try:
        # ------------------- CloudWatch Metrics -------------------
        try:
            metrics = cloudwatch.list_metrics(MaxResults=5)
            metrics_present = len(metrics.get("Metrics", [])) > 0
        except Exception as e:
            print(f"CloudWatch metrics error: {e}")
            metrics_present = False

        # ------------------- CloudWatch Log Groups -------------------
        try:
            log_groups = logs.describe_log_groups(limit=5)
            log_groups_present = len(log_groups.get("logGroups", [])) > 0
        except Exception as e:
            print(f"CloudWatch Logs groups error: {e}")
            log_groups_present = False

        # ------------------- CloudWatch Log Streams -------------------
        try:
            log_streams_present = False
            if log_groups_present:
                first_group = log_groups["logGroups"][0]["logGroupName"]
                streams = logs.describe_log_streams(logGroupName=first_group, limit=1)
                log_streams_present = len(streams.get("logStreams", [])) > 0
        except Exception as e:
            print(f"CloudWatch log streams error: {e}")
            log_streams_present = False

        # ------------------- X-Ray Service Graph -------------------
        try:
            xray_graph = xray.get_service_graph(
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            xray_present = len(xray_graph.get("Services", [])) > 0
        except Exception as e:
            print(f"X-Ray graph error: {e}")
            xray_present = False

        # ------------------- Final Evaluation -------------------
        missing_items = []

        if not metrics_present:
            missing_items.append("Metrics")
        if not log_groups_present:
            missing_items.append("Log Groups")
        if not log_streams_present:
            missing_items.append("Log Streams")
        if not xray_present:
            missing_items.append("X-Ray Tracing")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected in application telemetry.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Application telemetry enables observability through metrics, logs, and traces. "
                "Insufficient telemetry reduces the ability to detect operational issues."
            ),
            recommendation=(
                "Implement CloudWatch metrics, structured logs, and AWS X-Ray tracing to achieve full "
                "application observability and operational visibility."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS04-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while checking application telemetry.",
            recommendation="Verify access permissions and telemetry configuration.",
        )


def check_ops04_bp03_user_experience_telemetry(session):
    print("Checking OPS04-BP03 – Implement user experience telemetry")

    rum = session.client("cloudwatchrum")
    synthetics = session.client("synthetics")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_observability_customer_telemetry.html"

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
            "id": "OPS04-BP03",
            "check_name": "Implement user experience telemetry",
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
                "1. Configure CloudWatch RUM to capture real user performance data.",
                "2. Deploy CloudWatch Synthetics canaries for proactive user journey monitoring.",
                "3. Ensure RUM applications and canaries cover key customer paths.",
                "4. Analyze user performance, latency, frontend errors, and page load metrics.",
                "5. Improve workload performance and UX based on telemetry insights.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3  # RUM monitors, Synthetics canaries, Synthetics runtime versions
    affected = 0

    try:
        # -- CloudWatch RUM --
        try:
            rum_monitors = rum.list_app_monitors(MaxResults=5)
            rum_present = len(rum_monitors.get("AppMonitorSummaries", [])) > 0
        except Exception as e:
            print(f"RUM monitor error: {e}")
            rum_present = False

        # -- Synthetics Canaries --
        try:
            canaries = synthetics.describe_canaries(maxResults=5)
            canaries_present = len(canaries.get("Canaries", [])) > 0
        except Exception as e:
            print(f"Synthetics canaries error: {e}")
            canaries_present = False

        # -- Synthetics Runtime Versions --
        try:
            runtime_versions = synthetics.describe_runtime_versions()
            runtime_present = len(runtime_versions.get("RuntimeVersions", [])) > 0
        except Exception as e:
            print(f"Synthetics runtime version error: {e}")
            runtime_present = False

        # -- Evaluation --
        missing_items = []

        if not rum_present:
            missing_items.append("CloudWatch RUM")
        if not canaries_present:
            missing_items.append("Synthetics Canaries")
        if not runtime_present:
            missing_items.append("Synthetics Runtime Versions")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected in user experience telemetry services.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            
        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "User experience telemetry provides insights into real and synthetic customer interactions. "
                "Without this telemetry, customer-impacting issues may go undetected."
            ),
            recommendation=(
                "Implement CloudWatch RUM for real user telemetry and CloudWatch Synthetics canaries "
                "for monitoring critical user workflows."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS04-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating user experience telemetry.",
            recommendation="Verify IAM permissions and telemetry service availability.",
        )


def check_ops04_bp04_dependency_telemetry(session):
    print("Checking OPS04-BP04 – Implement dependency telemetry")

    xray = session.client("xray")
    cloudwatch = session.client("cloudwatch")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_observability_dependency_telemetry.html"

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
            "id": "OPS04-BP04",
            "check_name": "Implement dependency telemetry",
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
                "1. Enable AWS X-Ray tracing across all application components.",
                "2. Ensure downstream dependencies (databases, APIs, external services) emit trace data.",
                "3. Configure X-Ray sampling rules to capture dependency interactions.",
                "4. Implement CloudWatch metrics for dependency latency, throttling, and errors.",
                "5. Continuously review dependency telemetry to identify performance bottlenecks.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = (
        4  # X-Ray summaries, batch trace results, time series stats, CloudWatch metrics
    )
    affected = 0

    try:
        #  X-Ray Trace Summaries 
        try:
            summary = xray.get_trace_summaries(
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            summaries_present = len(summary.get("TraceSummaries", [])) > 0
        except Exception as e:
            print(f"X-Ray trace summaries error: {e}")
            summaries_present = False

        #  X-Ray Batch Get Traces 
        try:
            batch = xray.batch_get_traces(
                TraceIds=summary.get("TraceSummaries", [])[:1]
            )
            batch_present = len(batch.get("Traces", [])) > 0
        except Exception as e:
            print(f"X-Ray batch traces error: {e}")
            batch_present = False

        #  X-Ray Time Series Service Stats 
        try:
            stats = xray.get_time_series_service_statistics(
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
                EntitySelectorExpression='service("*")',
            )
            stats_present = len(stats.get("TimeSeriesServiceStatistics", [])) > 0
        except Exception as e:
            print(f"X-Ray time series stats error: {e}")
            stats_present = False

        #  CloudWatch Dependency Metrics 
        try:
            metric_query = {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": "AWS/XRay", "MetricName": "ServiceFault"},
                    "Period": 300,
                    "Stat": "Sum",
                },
            }
            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[metric_query],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            cw_present = any(
                d.get("Values") for d in metric_data.get("MetricDataResults", [])
            )
        except Exception as e:
            print(f"CloudWatch metric error: {e}")
            cw_present = False

        #  Evaluation 
        missing_items = []

        if not summaries_present:
            missing_items.append("X-Ray Trace Summaries")
        if not batch_present:
            missing_items.append("X-Ray Batch Traces")
        if not stats_present:
            missing_items.append("X-Ray Time Series Stats")
        if not cw_present:
            missing_items.append("CloudWatch Dependency Metrics")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for dependency telemetry.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Dependency telemetry is required to understand how upstream and downstream services "
                "interact. Without this visibility, it becomes difficult to detect failures or latency issues "
                "originating from dependencies."
            ),
            recommendation=(
                "Enable X-Ray tracing and CloudWatch dependency metrics to capture interactions with "
                "databases, APIs, and external services."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS04-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing dependency telemetry.",
            recommendation="Review telemetry configuration and validate access permissions.",
        )


def check_ops04_bp05_distributed_tracing(session):
    print("Checking OPS04-BP05 – Implement distributed tracing")

    xray = session.client("xray")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_observability_dist_trace.html"

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
            "id": "OPS04-BP05",
            "check_name": "Implement distributed tracing",
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
                "1. Enable AWS X-Ray tracing for all application services.",
                "2. Instrument code to generate trace segments and subsegments.",
                "3. Configure X-Ray sampling rules to ensure sufficient trace coverage.",
                "4. Ensure service-to-service calls propagate tracing headers.",
                "5. Enable X-Ray encryption using KMS for trace data protection.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3  # service graph, batch traces, encryption config
    affected = 0

    try:
        #  X-Ray Service Graph 
        try:
            graph = xray.get_service_graph(
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            graph_present = len(graph.get("Services", [])) > 0
        except Exception as e:
            print(f"X-Ray service graph error: {e}")
            graph_present = False

        #  X-Ray Batch Get Traces 
        try:
            # Need at least one trace ID for batch_get_traces; attempt to fetch one from service graph edges
            trace_ids = []
            for s in graph.get("Services", []):
                for ed in s.get("Edges", []):
                    if "ReferenceId" in ed:
                        trace_ids.append(ed["ReferenceId"])
                        break
                if trace_ids:
                    break

            if trace_ids:
                batch = xray.batch_get_traces(TraceIds=trace_ids[:1])
                batch_present = len(batch.get("Traces", [])) > 0
            else:
                batch_present = False
        except Exception as e:
            print(f"X-Ray batch traces error: {e}")
            batch_present = False

        #  X-Ray Encryption Config 
        try:
            enc = xray.get_encryption_config()
            encryption_enabled = enc.get("EncryptionConfig", {}).get("Type") != "NONE"
        except Exception as e:
            print(f"X-Ray encryption config error: {e}")
            encryption_enabled = False

        #  Evaluation 
        missing_items = []

        if not graph_present:
            missing_items.append("X-Ray Service Graph")
        if not batch_present:
            missing_items.append("X-Ray Trace Data")
        if not encryption_enabled:
            missing_items.append("X-Ray Encryption Configuration")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for distributed tracing.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Distributed tracing provides end-to-end visibility across microservices, APIs, and "
                "application components. Without distributed tracing, it is difficult to isolate latency "
                "issues, failures, or service-level bottlenecks."
            ),
            recommendation=(
                "Enable AWS X-Ray service graph, generate trace data, and enforce encryption for end-to-end "
                "distributed tracing visibility."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS04-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing distributed tracing.",
            recommendation="Validate X-Ray tracing setup and ensure adequate IAM permissions.",
        )


def check_ops05_bp01_use_version_control(session):
    print("Checking OPS05-BP01 – Use version control")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_version_control.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS05-BP01",
            "check_name": "Use version control",
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
                "1. Store all application code, scripts, configuration files, and IaC templates in a version control system.",
                "2. Use services such as AWS CodeCommit, GitHub, or GitLab.",
                "3. Enforce pull requests, mandatory reviews, and commit history retention.",
                "4. Implement branching strategies (GitFlow, trunk-based development).",
                "5. Integrate version control with CI/CD pipelines for automated deployments.",
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
                "Version control is essential for maintaining code history, enabling collaboration, and "
                "supporting automation workflows across development teams."
            ),
            recommendation=(
                "Adopt a version control system such as AWS CodeCommit or GitHub and ensure all application "
                "artifacts, scripts, and configurations are tracked with appropriate branching and review controls."
            ),
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unable to assess version control practices.",
            recommendation="Review organizational development workflows and validate repository configurations.",
        )


def check_ops05_bp02_test_validate_changes(session):
    print("Checking OPS05-BP02 – Test and validate changes")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_test_val_chg.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "OPS05-BP02",
            "check_name": "Test and validate changes",
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
                "1. Implement automated tests for unit, integration, and end-to-end scenarios.",
                "2. Validate infrastructure changes using IaC test frameworks.",
                "3. Use test environments that mirror production as closely as possible.",
                "4. Incorporate automated testing into the CI/CD pipeline.",
                "5. Continuously refine test coverage to reduce deployment risks.",
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
                "Testing and validating changes is essential to ensure reliability, reduce risk, and catch "
                "issues before deployment into production environments."
            ),
            recommendation=(
                "Implement automated testing frameworks and integrate validation steps into CI/CD workflows "
                "to ensure all code and infrastructure changes are thoroughly tested."
            ),
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unable to assess testing and validation practices.",
            recommendation="Review testing frameworks and CI/CD configuration.",
        )


def check_ops05_bp03_config_management_systems(session):
    print("Checking OPS05-BP03 – Use configuration management systems")

    ssm = session.client("ssm")
    opsworks = session.client("opsworks")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_conf_mgmt_sys.html"

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
            "id": "OPS05-BP03",
            "check_name": "Use configuration management systems",
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
                "1. Use AWS Systems Manager documents and automation runbooks to standardize configuration.",
                "2. Implement configuration management tools such as OpsWorks, Ansible, Chef, or Puppet.",
                "3. Maintain a central repository of configuration definitions.",
                "4. Automate configuration drift detection using SSM and AWS Config.",
                "5. Continuously validate and update configuration management playbooks and documents.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = (
        4  # describe_document, list_documents, describe_stacks, describe_layers checks
    )
    affected = 0

    try:
        #  SSM Describe Document 
        try:
            ssm_docs = ssm.list_documents(MaxResults=5)
            ssm_present = len(ssm_docs.get("DocumentIdentifiers", [])) > 0
        except Exception as e:
            print(f"SSM list_documents error: {e}")
            ssm_present = False

        #  SSM Describe Specific Document (optional) 
        try:
            # Attempt to describe the first document if present
            if ssm_present:
                first_doc = ssm_docs["DocumentIdentifiers"][0]["Name"]
                ssm_desc = ssm.describe_document(Name=first_doc)
                ssm_desc_present = True
            else:
                ssm_desc_present = False
        except Exception as e:
            print(f"SSM describe_document error: {e}")
            ssm_desc_present = False

        #  OpsWorks Stacks 
        try:
            stacks = opsworks.describe_stacks()
            stacks_present = len(stacks.get("Stacks", [])) > 0
        except Exception as e:
            print(f"OpsWorks describe_stacks error: {e}")
            stacks_present = False

        #  OpsWorks Layers 
        try:
            if stacks_present:
                first_stack_id = stacks["Stacks"][0]["StackId"]
                layers = opsworks.describe_layers(StackId=first_stack_id)
                layers_present = len(layers.get("Layers", [])) > 0
            else:
                layers_present = False
        except Exception as e:
            print(f"OpsWorks describe_layers error: {e}")
            layers_present = False

        #  Evaluation
        missing_items = []

        if not ssm_present:
            missing_items.append("SSM Documents")
        if not ssm_desc_present:
            missing_items.append("SSM Document Details")
        if not stacks_present:
            missing_items.append("OpsWorks Stacks")
        if not layers_present:
            missing_items.append("OpsWorks Layers")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for configuration management systems.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Configuration management systems ensure consistent, automated, and controlled configuration "
                "across environments. Without these tools, configuration drift and operational inconsistencies "
                "can occur."
            ),
            recommendation=(
                "Implement AWS Systems Manager and OpsWorks or integrate external configuration management "
                "tools to automate and standardize configuration processes."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing configuration management systems.",
            recommendation="Review permissions and validate configuration management tooling.",
        )


def check_ops05_bp04_build_deployment_management(session):
    print("Checking OPS05-BP04 – Use build and deployment management systems")

    codepipeline = session.client("codepipeline")
    codebuild = session.client("codebuild")
    codedeploy = session.client("codedeploy")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_build_mgmt_sys.html"

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
            "id": "OPS05-BP04",
            "check_name": "Use build and deployment management systems",
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
                "1. Implement CI/CD pipelines using AWS CodePipeline for automated build and deployment workflows.",
                "2. Use AWS CodeBuild to compile and test application code.",
                "3. Manage deployments using AWS CodeDeploy for EC2, Lambda, and on-premise instances.",
                "4. Integrate monitoring and approvals into CI/CD pipelines.",
                "5. Continuously audit and optimize build and deployment automation for reliability and speed.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = (
        4  # pipelines, build projects, codedeploy apps, codedeploy deployments
    )
    affected = 0

    try:
        #  CodePipeline 
        try:
            pipelines = codepipeline.list_pipelines()
            pipelines_present = len(pipelines.get("pipelines", [])) > 0
        except Exception as e:
            print(f"CodePipeline list_pipelines error: {e}")
            pipelines_present = False

        #  CodeBuild 
        try:
            builds = codebuild.list_projects()
            builds_present = len(builds.get("projects", [])) > 0
        except Exception as e:
            print(f"CodeBuild list_projects error: {e}")
            builds_present = False

        #  CodeDeploy Applications 
        try:
            applications = codedeploy.list_applications()
            apps_present = len(applications.get("applications", [])) > 0
        except Exception as e:
            print(f"CodeDeploy list_applications error: {e}")
            apps_present = False

        #  CodeDeploy Deployments 
        try:
            deployments = codedeploy.list_deployments()
            deployments_present = len(deployments.get("deployments", [])) > 0
        except Exception as e:
            print(f"CodeDeploy list_deployments error: {e}")
            deployments_present = False

        #  Evaluation
        missing_items = []

        if not pipelines_present:
            missing_items.append("CodePipeline")
        if not builds_present:
            missing_items.append("CodeBuild")
        if not apps_present:
            missing_items.append("CodeDeploy Applications")
        if not deployments_present:
            missing_items.append("CodeDeploy Deployments")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for build and deployment management systems.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Automated build and deployment systems enable consistent, repeatable releases and help reduce "
                "manual deployment errors and operational risks."
            ),
            recommendation=(
                "Adopt AWS CodePipeline, CodeBuild, and CodeDeploy or equivalent CI/CD tooling to automate "
                "application build, test, and deployment workflows."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing build and deployment management systems.",
            recommendation="Review CI/CD integrations and validate access permissions.",
        )


def check_ops05_bp05_perform_patch_management(session):
    print("Checking OPS05-BP05 – Perform patch management")

    ssm = session.client("ssm")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_patch_mgmt.html"

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
            "id": "OPS05-BP05",
            "check_name": "Perform patch management",
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
                "1. Ensure patch baselines are configured for all operating systems in use.",
                "2. Assign patch groups to instances based on environment or role.",
                "3. Use Patch Manager to automate scanning and installation of patches.",
                "4. Monitor patch compliance and configure notifications for non-compliant instances.",
                "5. Enable routine patch cycles and verify all managed instances report patch states.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3 # patch baselines, patch groups, instance patch states
    affected = 0

    try:
        #  Patch Baselines 
        try:
            baselines = ssm.describe_patch_baselines()
            baselines_present = len(baselines.get("BaselineIdentities", [])) > 0
        except Exception as e:
            print(f"SSM describe_patch_baselines error: {e}")
            baselines_present = False

        #  Patch Groups 
        try:
            patch_groups = ssm.describe_patch_groups()
            patch_groups_present = len(patch_groups.get("Mappings", [])) > 0
        except Exception as e:
            print(f"SSM describe_patch_groups error: {e}")
            patch_groups_present = False

        #  Instance Patch States 
        try:
            instance_states = ssm.describe_instance_patch_states()
            instance_states_present = (
                len(instance_states.get("InstancePatchStates", [])) > 0
            )
        except Exception as e:
            print(f"SSM describe_instance_patch_states error: {e}")
            instance_states_present = False

        #  Evaluation
        missing_items = []

        if not baselines_present:
            missing_items.append("Patch Baselines")
        if not patch_groups_present:
            missing_items.append("Patch Groups")
        if not instance_states_present:
            missing_items.append("Instance Patch States")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for patch management.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Patch management is essential to keep systems up to date, secure, and compliant. "
                "A lack of patch configuration increases operational and security risks."
            ),
            recommendation=(
                "Configure SSM Patch Manager with patch baselines, patch groups, and regular patching schedules. "
                "Ensure all instances are managed and reporting patch compliance."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing patch management configuration.",
            recommendation="Verify SSM permissions, instance SSM agent status, and Patch Manager setup.",
        )


def check_ops05_bp06_share_design_standards(session):
    print("Checking OPS05-BP06 - Share design standards")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_share_design_stds.html"

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
            "id": "OPS05-BP06",
            "check_name": "Share design standards",
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
                "1. Create and document architectural and operational design standards.",
                "2. Store design standards in a central and accessible repository.",
                "3. Version-control and regularly update design standards.",
                "4. Provide guidance and training so teams understand and adopt shared standards.",
                "5. Review standards periodically to ensure relevance and organizational alignment.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        # No API checks – purely organizational requirement
        return build_response(
            status="not_available",
            problem=(
                "Sharing design standards helps ensure consistent implementation and alignment across teams."
            ),
            recommendation=(
                "Document and publish architectural and operational design standards in a central repository "
                "and ensure they are accessible across the organization."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing design standards documentation.",
            recommendation="Verify repository access and organizational documentation processes.",
        )


def check_ops05_bp07_improve_code_quality(session):
    print("Checking OPS05-BP07 – Implement practices to improve code quality")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_code_quality.html"

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
            "id": "OPS05-BP07",
            "check_name": "Implement practices to improve code quality",
            "problem_statement": problem,
            "severity_score": 45,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Establish coding standards and enforce them through code reviews.",
                "2. Use automated code analysis tools to detect issues early.",
                "3. Implement peer reviews and pair programming practices.",
                "4. Integrate automated testing into the CI/CD pipeline.",
                "5. Regularly refactor code to reduce complexity and improve maintainability.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # organisational requirement
        return build_response(
            status="not_available",
            problem=(
                "Improving code quality ensures maintainability, reduces defects, and supports long-term operational excellence."
            ),
            recommendation=(
                "Adopt automated testing, code reviews, linting, and continuous refactoring practices to "
                "ensure consistent and high-quality code across teams."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while evaluating code quality practices.",
            recommendation="Review development processes and ensure code quality tooling is functioning correctly.",
        )


def check_ops05_bp08_use_multiple_environments(session):
    print("Checking OPS05-BP08 – Use multiple environments")

    organizations = session.client("organizations")
    cloudformation = session.client("cloudformation")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_multi_env.html"

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
            "id": "OPS05-BP08",
            "check_name": "Use multiple environments",
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
                "1. Create separate environments for development, testing, staging, and production.",
                "2. Use AWS Organizations to manage accounts for isolation.",
                "3. Use CloudFormation to deploy infrastructure consistently across environments.",
                "4. Implement access controls to prevent cross-environment contamination.",
                "5. Continuously monitor and audit environment segregation and deployments.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3  # organizations accounts, CFN stacks list, CFN describe stacks
    affected = 0

    try:
        #  Organizations Accounts 
        try:
            accounts = organizations.list_accounts()
            accounts_present = (
                len(accounts.get("Accounts", [])) > 1
            )  # more than 1 indicates multiple environments
        except Exception as e:
            print(f"Organizations list_accounts error: {e}")
            accounts_present = False

        #  CloudFormation Stacks 
        try:
            stacks = cloudformation.list_stacks(
                StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE"]
            )
            stacks_present = len(stacks.get("StackSummaries", [])) > 0
        except Exception as e:
            print(f"CloudFormation list_stacks error: {e}")
            stacks_present = False

        try:
            # Describe first stack for additional validation
            if stacks_present:
                stack_detail = cloudformation.describe_stacks(
                    StackName=stacks.get("StackSummaries", [])[0]["StackName"]
                )
                stack_described = len(stack_detail.get("Stacks", [])) > 0
            else:
                stack_described = False
        except Exception as e:
            print(f"CloudFormation describe_stacks error: {e}")
            stack_described = False

        #  Evaluation
        missing_items = []

        if not accounts_present:
            missing_items.append("AWS Organizations Accounts")
        if not stacks_present:
            missing_items.append("CloudFormation Stacks")
        if not stack_described:
            missing_items.append("CloudFormation Stack Details")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for multiple environment setup.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Using multiple environments is critical to isolate development, testing, and production workloads, "
                "reducing risk of operational errors and improving governance."
            ),
            recommendation=(
                "Implement multiple AWS accounts and/or CloudFormation stacks to segregate environments. "
                "Ensure proper access controls and consistent deployments across all environments."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP08 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing multiple environment setup.",
            recommendation="Review AWS Organizations and CloudFormation setup for environment segregation.",
        )


def check_ops05_bp09_frequent_small_reversible_changes(session):
    print("Checking OPS05-BP09 – Make frequent, small, reversible changes")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_freq_sm_rev_chg.html"

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
            "id": "OPS05-BP09",
            "check_name": "Make frequent, small, reversible changes",
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
                "1. Break large changes into small, incremental updates.",
                "2. Implement automated deployment pipelines to enable quick rollbacks.",
                "3. Use feature flags or canary deployments to control release impact.",
                "4. Monitor changes for failures and performance issues in real time.",
                "5. Encourage frequent testing and validation of changes before production deployment.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # Organizational practice
        return build_response(
            status="not_available",
            problem=(
                "Making frequent, small, reversible changes reduces deployment risk, "
                "simplifies troubleshooting, and improves operational agility."
            ),
            recommendation=(
                "Adopt a process of small incremental changes with automated rollback mechanisms, "
                "feature flags, and monitoring to ensure safe and reversible deployments."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP09 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing change management practices.",
            recommendation="Review deployment pipelines and rollback procedures to ensure reliability.",
        )


def check_ops05_bp10_fully_automate_integration_deployment(session):
    print("Checking OPS05-BP10 – Fully automate integration and deployment")

    codepipeline = session.client("codepipeline")
    codebuild = session.client("codebuild")
    codedeploy = session.client("codedeploy")
    cloudformation = session.client("cloudformation")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_dev_integ_auto_integ_deploy.html"

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
            "id": "OPS05-BP10",
            "check_name": "Fully automate integration and deployment",
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
                "1. Implement CI/CD pipelines using AWS CodePipeline for fully automated integration and deployment.",
                "2. Use AWS CodeBuild for automated builds and testing.",
                "3. Use AWS CodeDeploy for automated deployments across environments.",
                "4. Employ CloudFormation change sets to manage and validate infrastructure changes.",
                "5. Continuously monitor and validate pipelines to ensure reliability and automation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4  # pipelines, build projects, deployments, change sets
    affected = 0

    try:
        #  CodePipeline 
        try:
            pipelines = codepipeline.list_pipelines()
            pipelines_present = len(pipelines.get("pipelines", [])) > 0
        except Exception as e:
            print(f"CodePipeline list_pipelines error: {e}")
            pipelines_present = False

        #  CodeBuild 
        try:
            builds = codebuild.list_projects()
            builds_present = len(builds.get("projects", [])) > 0
        except Exception as e:
            print(f"CodeBuild list_projects error: {e}")
            builds_present = False

        #  CodeDeploy 
        try:
            deployments = codedeploy.list_deployments()
            deployments_present = len(deployments.get("deployments", [])) > 0
        except Exception as e:
            print(f"CodeDeploy list_deployments error: {e}")
            deployments_present = False

        #  CloudFormation Change Sets 
        try:
            # List stacks first
            stacks = cloudformation.list_stacks(
                StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE"]
            )
            if stacks.get("StackSummaries"):
                # Describe first stack change sets
                change_sets = cloudformation.describe_change_set(
                    StackName=stacks["StackSummaries"][0]["StackName"],
                    ChangeSetName="ChangeSet1",  # placeholder; no dynamic list available programmatically
                )
                change_sets_present = bool(change_sets.get("Changes", []))
            else:
                change_sets_present = False
        except Exception as e:
            print(f"CloudFormation describe_change_set error: {e}")
            change_sets_present = False

        #  Evaluation
        missing_items = []

        if not pipelines_present:
            missing_items.append("CodePipeline")
        if not builds_present:
            missing_items.append("CodeBuild")
        if not deployments_present:
            missing_items.append("CodeDeploy Deployments")
        if not change_sets_present:
            missing_items.append("CloudFormation Change Sets")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for fully automated integration and deployment.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )


        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Fully automating integration and deployment reduces human errors, increases deployment speed, "
                "and improves reliability of software delivery."
            ),
            recommendation=(
                "Adopt AWS CodePipeline, CodeBuild, CodeDeploy, and CloudFormation change sets to automate "
                "end-to-end application integration and deployment workflows."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS05-BP10 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing automation of integration and deployment.",
            recommendation="Verify CI/CD pipelines, CodeDeploy deployments, and CloudFormation change sets.",
        )


def check_ops06_bp01_plan_for_unsuccessful_changes(session):
    print("Checking OPS06-BP01 – Plan for unsuccessful changes")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_mit_deploy_risks_plan_for_unsucessful_changes.html"

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
            "id": "OPS06-BP01",
            "check_name": "Plan for unsuccessful changes",
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
                "1. Create rollback and recovery procedures for every deployment or operational change.",
                "2. Test rollback procedures regularly to ensure effectiveness.",
                "3. Implement monitoring and alerting to detect unsuccessful changes quickly.",
                "4. Document lessons learned from unsuccessful changes and update processes accordingly.",
                "5. Ensure all teams are trained on rollback procedures and understand their responsibilities.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # Organizational practice
        return build_response(
            status="not_available",
            problem=(
                "Planning for unsuccessful changes ensures operational stability and reduces the impact of failures."
            ),
            recommendation=(
                "Establish and document rollback procedures, test them regularly, "
                "and train teams to respond effectively to unsuccessful changes."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS06-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing change rollback planning.",
            recommendation="Review rollback procedures and ensure team readiness for unsuccessful changes.",
        )


def check_ops06_bp02_test_deployments(session):
    print("Checking OPS06-BP02 – Test deployments")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_mit_deploy_risks_test_val_chg.html"

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
            "id": "OPS06-BP02",
            "check_name": "Test deployments",
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
                "1. Implement automated testing for every deployment including unit, integration, and system tests.",
                "2. Use staging or test environments to validate changes before production deployment.",
                "3. Perform rollback testing to ensure recovery procedures work as expected.",
                "4. Monitor deployments for errors and failures and validate that alerts trigger appropriately.",
                "5. Document test results and lessons learned to improve deployment reliability.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # Organizational practice
        return build_response(
            status="not_available",
            problem=(
                "Testing deployments ensures that changes are validated, reducing the risk of failures in production."
            ),
            recommendation=(
                "Adopt automated testing, use staging environments, and validate rollback procedures "
                "to ensure reliable and safe deployments."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS06-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing deployment testing practices.",
            recommendation="Review testing processes and ensure automated validation is in place for deployments.",
        )


def check_ops06_bp03_safe_deployment_strategies(session):
    print("Checking OPS06-BP03 – Employ safe deployment strategies")

    codedeploy = session.client("codedeploy")
    codepipeline = session.client("codepipeline")
    ecs = session.client("ecs")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_mit_deploy_risks_deploy_mgmt_sys.html"

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
            "id": "OPS06-BP03",
            "check_name": "Employ safe deployment strategies",
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
                "1. Implement canary, blue/green, or rolling deployment strategies to minimize impact of failures.",
                "2. Use CodeDeploy deployment groups and pipelines to manage controlled releases.",
                "3. Validate ECS service deployments with health checks and monitoring.",
                "4. Automate rollback procedures for failed deployments.",
                "5. Continuously monitor deployments and collect metrics to improve safety and reliability.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4  # codedeploy groups, deployment group details, codepipeline pipelines, ECS deployments
    affected = 0

    try:
        #  CodeDeploy Deployment Groups 
        try:
            deployment_groups = codedeploy.list_deployment_groups(applicationName="All")
            groups_present = len(deployment_groups.get("deploymentGroups", [])) > 0
        except Exception as e:
            print(f"CodeDeploy list_deployment_groups error: {e}")
            groups_present = False

        #  CodeDeploy Get Deployment Group 
        try:
            if groups_present:
                group_detail = codedeploy.get_deployment_group(
                    applicationName="All",
                    deploymentGroupName=deployment_groups.get("deploymentGroups", [])[
                        0
                    ],
                )
                group_detail_present = bool(group_detail.get("deploymentGroupInfo"))
            else:
                group_detail_present = False
        except Exception as e:
            print(f"CodeDeploy get_deployment_group error: {e}")
            group_detail_present = False

        #  CodePipeline Pipelines 
        try:
            pipelines = codepipeline.list_pipelines()
            pipelines_present = len(pipelines.get("pipelines", [])) > 0
        except Exception as e:
            print(f"CodePipeline list_pipelines error: {e}")
            pipelines_present = False

        #  ECS Deployments 
        try:
            # List services in default cluster as example
            ecs_services = ecs.list_services(cluster="default")
            if ecs_services.get("serviceArns"):
                ecs_descriptions = ecs.describe_services(
                    cluster="default", services=ecs_services.get("serviceArns", [])
                )
                ecs_present = len(ecs_descriptions.get("services", [])) > 0
            else:
                ecs_present = False
        except Exception as e:
            print(f"ECS describe_deployments error: {e}")
            ecs_present = False

        #  Evaluation
        missing_items = []

        if not groups_present:
            missing_items.append("CodeDeploy Deployment Groups")
        if not group_detail_present:
            missing_items.append("CodeDeploy Deployment Group Details")
        if not pipelines_present:
            missing_items.append("CodePipeline Pipelines")
        if not ecs_present:
            missing_items.append("ECS Deployments")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for safe deployment strategies.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Safe deployment strategies reduce the risk of production failures and service disruptions. "
                "Without controlled deployments, changes can have high operational impact."
            ),
            recommendation=(
                "Adopt canary, blue/green, or rolling deployments using CodeDeploy, CodePipeline, and ECS, "
                "and ensure automated rollback and monitoring are in place."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS06-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing safe deployment strategies.",
            recommendation="Review deployment configurations and ensure safe deployment practices are implemented.",
        )


def check_ops06_bp04_automate_testing_rollback(session):
    print("Checking OPS06-BP04 – Automate testing and rollback")

    codepipeline = session.client("codepipeline")
    cloudwatch = session.client("cloudwatch")
    codedeploy = session.client("codedeploy")
    lambda_client = session.client("lambda")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_mit_deploy_risks_auto_testing_and_rollback.html"

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
            "id": "OPS06-BP04",
            "check_name": "Automate testing and rollback",
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
                "1. Implement automated test stages in CodePipeline for every deployment.",
                "2. Configure CloudWatch alarms to detect failures and trigger automated rollback.",
                "3. Use CodeDeploy to automate rollbacks on failed deployments.",
                "4. Validate Lambda functions with automated tests before production deployment.",
                "5. Continuously monitor deployments and rollback events to improve automation reliability.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = (
        5  # pipelines, alarms, deployments, deployment details, Lambda functions
    )
    affected = 0

    try:
        #  CodePipeline 
        try:
            pipelines = codepipeline.list_pipelines()
            pipelines_present = len(pipelines.get("pipelines", [])) > 0
        except Exception as e:
            print(f"CodePipeline list_pipelines error: {e}")
            pipelines_present = False

        #  CloudWatch Alarms 
        try:
            alarms = cloudwatch.describe_alarms()
            alarms_present = len(alarms.get("MetricAlarms", [])) > 0
        except Exception as e:
            print(f"CloudWatch describe_alarms error: {e}")
            alarms_present = False

        #  CodeDeploy Deployments 
        try:
            deployments = codedeploy.list_deployments()
            deployments_present = len(deployments.get("deployments", [])) > 0
        except Exception as e:
            print(f"CodeDeploy list_deployments error: {e}")
            deployments_present = False

        #  CodeDeploy Get Deployment 
        try:
            if deployments_present:
                deployment_detail = codedeploy.get_deployment(
                    deploymentId=deployments.get("deployments", [])[0]
                )
                deployment_detail_present = bool(
                    deployment_detail.get("deploymentInfo")
                )
            else:
                deployment_detail_present = False
        except Exception as e:
            print(f"CodeDeploy get_deployment error: {e}")
            deployment_detail_present = False

        #  Lambda Functions 
        try:
            functions = lambda_client.list_functions()
            lambda_present = len(functions.get("Functions", [])) > 0
        except Exception as e:
            print(f"Lambda list_functions error: {e}")
            lambda_present = False

        #  Evaluation
        missing_items = []

        if not pipelines_present:
            missing_items.append("CodePipeline")
        if not alarms_present:
            missing_items.append("CloudWatch Alarms")
        if not deployments_present:
            missing_items.append("CodeDeploy Deployments")
        if not deployment_detail_present:
            missing_items.append("CodeDeploy Deployment Details")
        if not lambda_present:
            missing_items.append("Lambda Functions")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for automated testing and rollback.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Automating testing and rollback reduces the risk of failed deployments causing operational impact. "
                "Without automation, failures may not be detected or reverted quickly."
            ),
            recommendation=(
                "Use CodePipeline, CloudWatch alarms, CodeDeploy, and Lambda automated tests to ensure "
                "deployments are validated and automatically rolled back on failure."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS06-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing automated testing and rollback.",
            recommendation="Verify CI/CD pipelines, CloudWatch alarms, CodeDeploy deployments, and Lambda tests.",
        )


def check_ops07_bp01_personnel_capability(session):
    print("Checking OPS07-BP01 – Ensure personnel capability")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ready_to_support_personnel_capability.html"

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
            "id": "OPS07-BP01",
            "check_name": "Ensure personnel capability",
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
                "1. Identify key roles and responsibilities required to support workloads.",
                "2. Assess skill levels and provide training to fill gaps.",
                "3. Document operational procedures and ensure personnel are familiar with them.",
                "4. Implement mentoring and knowledge sharing programs.",
                "5. Periodically review and update personnel capability requirements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # Organizational practice
        return build_response(
            status="not_available",
            problem=(
                "Ensuring personnel capability is critical to maintaining operational readiness and effective workload support."
            ),
            recommendation=(
                "Evaluate team skills, provide training, document procedures, and establish knowledge sharing to ensure personnel can effectively operate and support workloads."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS07-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing personnel capability.",
            recommendation="Review training, documentation, and staffing to ensure team readiness for operations support.",
        )


def check_ops07_bp02_consistent_operational_readiness(session):
    print("Checking OPS07-BP02 – Ensure a consistent review of operational readiness")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ready_to_support_const_orr.html"

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
            "id": "OPS07-BP02",
            "check_name": "Ensure a consistent review of operational readiness",
            "problem_statement": problem,
            "severity_score": 65,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Establish a regular schedule for reviewing operational readiness across workloads.",
                "2. Define review criteria, including metrics, procedures, and personnel readiness.",
                "3. Document findings and track improvements over time.",
                "4. Engage relevant stakeholders in the review process for accountability.",
                "5. Continuously update review processes based on operational incidents and lessons learned.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # Organizational practice
        return build_response(
            status="not_available",
            problem=(
                "Consistent review of operational readiness ensures workloads are supported effectively and risks are proactively identified."
            ),
            recommendation=(
                "Implement scheduled operational readiness reviews, document findings, and update processes to maintain consistent and reliable operations."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS07-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing operational readiness review practices.",
            recommendation="Verify review procedures and stakeholder engagement to ensure operational readiness is consistently evaluated.",
        )


def check_ops07_bp03_use_runbooks(session):
    print("Checking OPS07-BP03 – Use runbooks to perform procedures")

    ssm = session.client("ssm")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ready_to_support_use_runbooks.html"

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
            "id": "OPS07-BP03",
            "check_name": "Use runbooks to perform procedures",
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
                "1. Maintain runbooks in AWS Systems Manager Documents (SSM documents) for common operational tasks.",
                "2. Use Automation Documents (SSM) to standardize and automate procedures.",
                "3. Track automation executions and validate runbook effectiveness.",
                "4. Update runbooks regularly based on operational incidents and lessons learned.",
                "5. Train personnel on the usage of runbooks and automation for consistent execution.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4  # list_documents, describe_document, describe_automation_executions, describe_automation_documents
    affected = 0

    try:
        #  List Documents 
        try:
            documents = ssm.list_documents(DocumentFilterList=[])
            docs_present = len(documents.get("DocumentIdentifiers", [])) > 0
        except Exception as e:
            print(f"SSM list_documents error: {e}")
            docs_present = False

        #  Describe Document 
        try:
            if docs_present:
                doc_detail = ssm.describe_document(
                    Name=documents.get("DocumentIdentifiers", [])[0].get("Name")
                )
                doc_detail_present = bool(doc_detail.get("Document"))
            else:
                doc_detail_present = False
        except Exception as e:
            print(f"SSM describe_document error: {e}")
            doc_detail_present = False

        #  Describe Automation Executions 
        try:
            executions = ssm.describe_automation_executions()
            executions_present = (
                len(executions.get("AutomationExecutionMetadataList", [])) > 0
            )
        except Exception as e:
            print(f"SSM describe_automation_executions error: {e}")
            executions_present = False

        #  Describe Automation Documents 
        try:
            automation_docs = ssm.describe_automation_documents()
            automation_docs_present = (
                len(automation_docs.get("DocumentIdentifiers", [])) > 0
            )
        except Exception as e:
            print(f"SSM describe_automation_documents error: {e}")
            automation_docs_present = False

        #  Evaluation
        missing_items = []

        if not docs_present:
            missing_items.append("SSM Documents")
        if not doc_detail_present:
            missing_items.append("SSM Document Details")
        if not executions_present:
            missing_items.append("SSM Automation Executions")
        if not automation_docs_present:
            missing_items.append("SSM Automation Documents")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for standardized runbook and automation usage.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Runbooks and automation documents standardize operational procedures and reduce human error. "
                "Without them, procedures may be inconsistent and slower to execute."
            ),
            recommendation=(
                "Use SSM documents and automation to create, maintain, and execute runbooks for operational tasks. "
                "Regularly review and update runbooks to reflect operational best practices."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS07-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing runbook usage.",
            recommendation="Verify SSM documents, automation executions, and IAM permissions for runbook management.",
        )


def check_ops07_bp04_use_playbooks(session):
    print("Checking OPS07-BP04 - Use playbooks to investigate issues")

    ssm = session.client("ssm")
    incidentmanager = session.client("incidentmanager")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ready_to_support_use_playbooks.html"

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
            "id": "OPS07-BP04",
            "check_name": "Use playbooks to investigate issues",
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
                "1. Maintain playbooks in SSM OpsItems for standardized issue investigation.",
                "2. Use SSM automation documents to automate common investigation procedures.",
                "3. Configure AWS Incident Manager response plans to handle incidents consistently.",
                "4. Track and analyze incidents to refine playbooks and improve response times.",
                "5. Train personnel on playbook usage and automation execution for consistent issue handling.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        #  SSM OpsItems 
        try:
            ops_items = ssm.list_ops_items()
            ops_items_present = len(ops_items.get("OpsItemSummaries", [])) > 0
        except Exception as e:
            print(f"SSM list_ops_items error: {e}")
            ops_items_present = False

        try:
            if ops_items_present:
                ops_item_detail = ssm.describe_ops_items(
                    OpsItemIds=[
                        ops_items.get("OpsItemSummaries", [])[0].get("OpsItemId")
                    ]
                )
                ops_item_detail_present = (
                    len(ops_item_detail.get("OpsItemSummaries", [])) > 0
                )
            else:
                ops_item_detail_present = False
        except Exception as e:
            print(f"SSM describe_ops_items error: {e}")
            ops_item_detail_present = False

        #  Incident Manager 
        try:
            response_plans = incidentmanager.list_response_plans()
            response_plans_present = len(response_plans.get("Items", [])) > 0
        except Exception as e:
            print(f"Incident Manager list_response_plans error: {e}")
            response_plans_present = False

        try:
            incidents = incidentmanager.list_incidents()
            incidents_present = len(incidents.get("Items", [])) > 0
        except Exception as e:
            print(f"Incident Manager list_incidents error: {e}")
            incidents_present = False

        #  Evaluation
        missing_items = []

        if not ops_items_present:
            missing_items.append("SSM OpsItems")
        if not ops_item_detail_present:
            missing_items.append("SSM OpsItem Details")
        if not response_plans_present:
            missing_items.append("Incident Manager Response Plans")
        if not incidents_present:
            missing_items.append("Incident Manager Incidents")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for playbook-based investigation processes.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Playbooks standardize incident investigation and response. Without playbooks, issue handling may be inconsistent and slower."
            ),
            recommendation=(
                "Create and maintain SSM OpsItems and Incident Manager response plans to standardize investigations. "
                "Regularly review and update playbooks to improve incident handling efficiency."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS07-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing playbook usage for investigations.",
            recommendation="Verify SSM OpsItems, automation documents, Incident Manager response plans, and IAM permissions.",
        )


def check_ops07_bp05_informed_deployments(session):
    print("Checking OPS07-BP05 – Make informed decisions to deploy systems and changes")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ready_to_support_informed_deploy_decisions.html"

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
            "id": "OPS07-BP05",
            "check_name": "Make informed decisions to deploy systems and changes",
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
                "1. Evaluate operational readiness, risks, and impact before deploying changes.",
                "2. Review testing, staging, and validation results prior to deployment.",
                "3. Consult relevant stakeholders for approval on critical changes.",
                "4. Document deployment decisions, rationale, and potential rollback plans.",
                "5. Continuously refine deployment decision-making based on post-deployment observations.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    
    total_scanned = 0
    affected = 0

    try:
        # Organizational practice
        return build_response(
            status="not_available",
            problem=(
                "Making informed deployment decisions ensures changes are safe, predictable, and aligned with operational readiness."
            ),
            recommendation=(
                "Assess operational readiness, testing results, stakeholder input, and risk before deploying systems or changes. Document decisions for accountability and continuous improvement."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS07-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing deployment decision practices.",
            recommendation="Review organizational deployment policies, approvals, and risk assessment procedures.",
        )


def check_ops07_bp06_create_support_plans(session):
    print("Checking OPS07-BP06 – Create support plans for production workloads")

    support = session.client("support")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_ready_to_support_enable_support_plans.html"

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
            "id": "OPS07-BP06",
            "check_name": "Create support plans for production workloads",
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
                "1. Define AWS Support plans (Basic, Developer, Business, or Enterprise) for production workloads.",
                "2. Configure severity levels for incidents according to business impact.",
                "3. Track and manage cases for production workloads to ensure timely resolution.",
                "4. Review support coverage periodically and adjust plans as workloads evolve.",
                "5. Train personnel to use support channels effectively and escalate critical issues.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3 
    affected = 0

    try:
        #  Describe Severity Levels 
        try:
            severity_levels = support.describe_severity_levels()
            severity_present = len(severity_levels.get("severityLevels", [])) > 0
        except Exception as e:
            print(f"Support describe_severity_levels error: {e}")
            severity_present = False

        #  Describe Services 
        try:
            services = support.describe_services()
            services_present = len(services.get("services", [])) > 0
        except Exception as e:
            print(f"Support describe_services error: {e}")
            services_present = False

        #  Describe Cases 
        try:
            cases = support.describe_cases()
            cases_present = len(cases.get("cases", [])) > 0
        except Exception as e:
            print(f"Support describe_cases error: {e}")
            cases_present = False

        #  Evaluation
        missing_items = []

        if not severity_present:
            missing_items.append("Support Severity Levels")
        if not services_present:
            missing_items.append("Support Service Details")
        if not cases_present:
            missing_items.append("Support Cases")

        affected = len(missing_items)

        for item in missing_items:
            resources_affected.append(
                {
                    "resource_id": item,
                    "issue": f"{item} not detected for AWS Support plan readiness.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Support plans for production workloads ensure timely resolution of incidents and operational issues. "
                "Without proper plans, production systems may face increased downtime or impact."
            ),
            recommendation=(
                "Establish AWS Support plans for all production workloads, configure severity levels, track cases, "
                "and review plans periodically to maintain appropriate support coverage."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during OPS07-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error while assessing support plans for production workloads.",
            recommendation="Verify AWS Support plan configuration, case tracking, and IAM permissions.",
        )
