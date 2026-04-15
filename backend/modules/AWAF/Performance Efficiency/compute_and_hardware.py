from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# PERF 2. How do you select and use compute resources in your workload?

# PERF02-BP01 Select the best compute options for your workload
def check_perf02_bp01_select_best_compute(session):
    print("Checking PERF02-BP01 – Select the best compute options for your workload")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_compute_hardware_select_best_compute_options.html"

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
            "id": "PERF02-BP01",
            "check_name": "Select the best compute options for your workload",
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
                "1. Evaluate EC2 instance types for workload requirements.",
                "2. Consider ECS/EKS for containerized workloads.",
                "3. Use Lambda for event-driven and serverless workloads.",
                "4. Review Compute Optimizer recommendations for right-sizing.",
                "5. Use AWS Batch for batch processing workloads.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ec2 = session.client("ec2")
        ecs = session.client("ecs")
        eks = session.client("eks")
        lambda_client = session.client("lambda")
        batch = session.client("batch")
        lightsail = session.client("lightsail")
        compute_optimizer = session.client("compute-optimizer")

        # Check EC2 instance type offerings
        try:
            offerings = ec2.describe_instance_type_offerings().get("InstanceTypeOfferings", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_instance_type_offerings error: {e}")

        # Check EC2 instance types
        try:
            instance_types = ec2.describe_instance_types(MaxResults=5).get("InstanceTypes", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_instance_types error: {e}")

        # Check ECS clusters
        try:
            ecs_clusters = ecs.list_clusters().get("clusterArns", [])
            total_scanned += 1
        except Exception as e:
            print(f"ecs.list_clusters error: {e}")

        # Check EKS clusters
        try:
            eks_clusters = eks.list_clusters().get("clusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"eks.list_clusters error: {e}")

        # Check Lambda functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            total_scanned += 1
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check Batch job queues
        try:
            job_queues = batch.describe_job_queues().get("jobQueues", [])
            total_scanned += 1
        except Exception as e:
            print(f"batch.describe_job_queues error: {e}")

        # Check Lightsail instances
        try:
            lightsail_instances = lightsail.get_instances().get("instances", [])
            total_scanned += 1
        except Exception as e:
            print(f"lightsail.get_instances error: {e}")

        # Check Compute Optimizer EC2 recommendations
        try:
            recommendations = compute_optimizer.get_ec2_instance_recommendations().get("instanceRecommendations", [])
            total_scanned += 1
            if len(recommendations) > 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "compute_optimizer_recommendations",
                    "issue": f"{len(recommendations)} EC2 instances have optimization recommendations",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"compute_optimizer.get_ec2_instance_recommendations error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without selecting appropriate compute options, workloads may experience suboptimal "
                "performance, higher costs, or inefficient resource utilization."
            ),
            recommendation=(
                "Evaluate and select the best compute options (EC2, ECS, EKS, Lambda, Batch) based on "
                "workload requirements and review Compute Optimizer recommendations."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF02-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating compute options.",
            recommendation="Verify IAM permissions for EC2, ECS, EKS, Lambda, Batch, Lightsail, and Compute Optimizer APIs.",
        )


# PERF02-BP02 Understand the available compute configuration and features
def check_perf02_bp02_understand_compute_config(session):
    print("Checking PERF02-BP02 – Understand the available compute configuration and features")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_compute_hardware_understand_compute_configuration_features.html"

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
            "id": "PERF02-BP02",
            "check_name": "Understand the available compute configuration and features",
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
                "1. Enable CloudWatch metrics for compute resources.",
                "2. Configure CloudWatch Logs for application and system logs.",
                "3. Implement AWS X-Ray for distributed tracing.",
                "4. Use DevOps Guru for anomaly detection and insights.",
                "5. Review metrics and logs to understand compute performance.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        cloudwatch = session.client("cloudwatch")
        logs = session.client("logs")
        xray = session.client("xray")
        devops_guru = session.client("devops-guru")

        # Check CloudWatch metrics
        try:
            metrics = cloudwatch.list_metrics(MaxRecords=1).get("Metrics", [])
            total_scanned += 1
            if len(metrics) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_metrics",
                    "issue": "No CloudWatch metrics found for monitoring compute resources",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")

        # Check CloudWatch metric data
        try:
            from datetime import timedelta
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

        # Check CloudWatch metric statistics
        try:
            cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=["Average"]
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        # Check CloudWatch log groups
        try:
            log_groups = logs.describe_log_groups(limit=1).get("logGroups", [])
            total_scanned += 1
            if len(log_groups) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_logs",
                    "issue": "No CloudWatch log groups found for application logging",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"logs.describe_log_groups error: {e}")

        # Check log events
        try:
            if len(log_groups) > 0:
                logs.filter_log_events(logGroupName=log_groups[0]["logGroupName"], limit=1)
            total_scanned += 1
        except Exception as e:
            print(f"logs.filter_log_events error: {e}")

        # Check X-Ray service graph
        try:
            xray.get_service_graph(StartTime=start_time, EndTime=end_time)
            total_scanned += 1
        except Exception as e:
            print(f"xray.get_service_graph error: {e}")

        # Check DevOps Guru monitored resources
        try:
            monitored = devops_guru.list_monitored_resources().get("MonitoredResourceIdentifiers", [])
            total_scanned += 1
            if len(monitored) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "devops_guru",
                    "issue": "No DevOps Guru monitored resources for anomaly detection",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"devops-guru.list_monitored_resources error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without understanding compute configuration and features through monitoring and observability, "
                "organizations cannot optimize performance or troubleshoot issues effectively."
            ),
            recommendation=(
                "Enable CloudWatch metrics and logs, implement X-Ray tracing, and use DevOps Guru for "
                "comprehensive monitoring and understanding of compute resources."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF02-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating compute configuration understanding.",
            recommendation="Verify IAM permissions for CloudWatch, CloudWatch Logs, X-Ray, and DevOps Guru APIs.",
        )


# PERF02-BP03 Collect compute-related metrics
def check_perf02_bp03_collect_compute_metrics(session):
    print("Checking PERF02-BP03 – Collect compute-related metrics")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_compute_hardware_collect_compute_related_metrics.html"

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
            "id": "PERF02-BP03",
            "check_name": "Collect compute-related metrics",
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
                "1. Configure Auto Scaling groups for EC2 instances.",
                "2. Set up Application Auto Scaling for ECS, DynamoDB, and other services.",
                "3. Define scaling policies based on metrics.",
                "4. Configure Lambda concurrency limits.",
                "5. Enable CloudWatch alarms for compute metrics.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        autoscaling = session.client("autoscaling")
        app_autoscaling = session.client("application-autoscaling")
        eks = session.client("eks")
        lambda_client = session.client("lambda")
        batch = session.client("batch")
        cloudwatch = session.client("cloudwatch")

        # Check Auto Scaling groups
        try:
            asg_groups = autoscaling.describe_auto_scaling_groups().get("AutoScalingGroups", [])
            total_scanned += 1
            if len(asg_groups) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "auto_scaling_groups",
                    "issue": "No Auto Scaling groups configured for EC2 scaling",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Application Auto Scaling targets
        try:
            scalable_targets = app_autoscaling.describe_scalable_targets(ServiceNamespace="ecs").get("ScalableTargets", [])
            total_scanned += 1
        except Exception as e:
            print(f"application-autoscaling.describe_scalable_targets error: {e}")

        # Check Application Auto Scaling policies
        try:
            scaling_policies = app_autoscaling.describe_scaling_policies(ServiceNamespace="ecs").get("ScalingPolicies", [])
            total_scanned += 1
            if len(scaling_policies) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "scaling_policies",
                    "issue": "No Application Auto Scaling policies configured",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"application-autoscaling.describe_scaling_policies error: {e}")

        # Check EKS clusters
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for cluster in clusters:
                eks.describe_cluster(name=cluster)
                total_scanned += 1
        except Exception as e:
            print(f"eks.describe_cluster error: {e}")

        # Check Lambda concurrency
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            for func in functions[:5]:
                lambda_client.get_function_concurrency(FunctionName=func["FunctionName"])
                total_scanned += 1
        except Exception as e:
            print(f"lambda.get_function_concurrency error: {e}")

        # Check Batch compute environments
        try:
            compute_envs = batch.describe_compute_environments().get("computeEnvironments", [])
            total_scanned += 1
        except Exception as e:
            print(f"batch.describe_compute_environments error: {e}")

        # Check CloudWatch alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
            if len(alarms) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_alarms",
                    "issue": "No CloudWatch alarms configured for compute metrics monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without collecting compute-related metrics through Auto Scaling, scaling policies, and alarms, "
                "organizations cannot respond to workload changes or optimize resource utilization."
            ),
            recommendation=(
                "Configure Auto Scaling groups, Application Auto Scaling policies, Lambda concurrency, "
                "and CloudWatch alarms to collect and act on compute metrics."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF02-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating compute metrics collection.",
            recommendation="Verify IAM permissions for Auto Scaling, Application Auto Scaling, EKS, Lambda, Batch, and CloudWatch APIs.",
        )


# PERF02-BP04 Configure and right-size compute resources
def check_perf02_bp04_rightsize_compute(session):
    print("Checking PERF02-BP04 – Configure and right-size compute resources")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_compute_hardware_configure_and_right_size_compute_resources.html"

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
            "id": "PERF02-BP04",
            "check_name": "Configure and right-size compute resources",
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
                "1. Review EC2 instance types and right-size based on workload.",
                "2. Use Compute Optimizer recommendations for right-sizing.",
                "3. Consider Reserved Instances for predictable workloads.",
                "4. Configure Lambda account settings appropriately.",
                "5. Use Pricing API to evaluate cost-effective options.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ec2 = session.client("ec2")
        compute_optimizer = session.client("compute-optimizer")
        lambda_client = session.client("lambda")
        ecs = session.client("ecs")
        eks = session.client("eks")
        pricing = session.client("pricing", region_name="us-east-1")

        # Check EC2 instance types
        try:
            instance_types = ec2.describe_instance_types(MaxResults=5).get("InstanceTypes", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_instance_types error: {e}")

        # Check Reserved Instances offerings
        try:
            ri_offerings = ec2.describe_reserved_instances_offerings(MaxResults=1).get("ReservedInstancesOfferings", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_reserved_instances_offerings error: {e}")

        # Check Compute Optimizer recommendations
        try:
            recommendations = compute_optimizer.get_ec2_instance_recommendations().get("instanceRecommendations", [])
            total_scanned += 1
            if len(recommendations) > 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "compute_optimizer_recommendations",
                    "issue": f"{len(recommendations)} EC2 instances have right-sizing recommendations",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"compute-optimizer.get_ec2_instance_recommendations error: {e}")

        # Check Lambda account settings
        try:
            lambda_client.get_account_settings()
            total_scanned += 1
        except Exception as e:
            print(f"lambda.get_account_settings error: {e}")

        # Check ECS clusters
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                ecs.describe_clusters(clusters=[cluster])
                total_scanned += 1
        except Exception as e:
            print(f"ecs.describe_clusters error: {e}")

        # Check EKS clusters
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for cluster in clusters:
                eks.describe_cluster(name=cluster)
                total_scanned += 1
        except Exception as e:
            print(f"eks.describe_cluster error: {e}")

        # Check Pricing API
        try:
            pricing.get_products(ServiceCode="AmazonEC2", MaxResults=1)
            total_scanned += 1
        except Exception as e:
            print(f"pricing.get_products error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper configuration and right-sizing of compute resources, organizations may "
                "experience over-provisioning, under-utilization, and increased costs."
            ),
            recommendation=(
                "Review EC2 instance types, use Compute Optimizer recommendations, consider Reserved Instances, "
                "and leverage Pricing API for cost-effective compute resource configuration."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF02-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating compute right-sizing.",
            recommendation="Verify IAM permissions for EC2, Compute Optimizer, Lambda, ECS, EKS, and Pricing APIs.",
        )


# PERF02-BP05 Scale your compute resources dynamically
def check_perf02_bp05_scale_dynamically(session):
    print("Checking PERF02-BP05 – Scale your compute resources dynamically")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_compute_hardware_scale_compute_resources_dynamically.html"

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
            "id": "PERF02-BP05",
            "check_name": "Scale your compute resources dynamically",
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
                "1. Review Compute Optimizer recommendations for scaling.",
                "2. Implement Auto Scaling based on CloudWatch metrics.",
                "3. Use Trusted Advisor for optimization recommendations.",
                "4. Configure EKS node groups and ECS container instances for scaling.",
                "5. Monitor EC2 instances and Lambda functions for scaling needs.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        compute_optimizer = session.client("compute-optimizer")
        support = session.client("support", region_name="us-east-1")
        cloudwatch = session.client("cloudwatch")
        ec2 = session.client("ec2")
        eks = session.client("eks")
        ecs = session.client("ecs")

        # Check Compute Optimizer recommendation summaries
        try:
            summaries = compute_optimizer.get_recommendation_summaries().get("recommendationSummaries", [])
            total_scanned += 1
        except Exception as e:
            print(f"compute-optimizer.get_recommendation_summaries error: {e}")

        # Check Compute Optimizer EC2 recommendations
        try:
            ec2_recs = compute_optimizer.get_ec2_instance_recommendations().get("instanceRecommendations", [])
            total_scanned += 1
            if len(ec2_recs) > 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "ec2_scaling_recommendations",
                    "issue": f"{len(ec2_recs)} EC2 instances have scaling recommendations",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"compute-optimizer.get_ec2_instance_recommendations error: {e}")

        # Check Compute Optimizer Lambda recommendations
        try:
            lambda_recs = compute_optimizer.get_lambda_function_recommendations().get("lambdaFunctionRecommendations", [])
            total_scanned += 1
        except Exception as e:
            print(f"compute-optimizer.get_lambda_function_recommendations error: {e}")

        # Check Trusted Advisor checks
        try:
            ta_checks = support.describe_trusted_advisor_checks(language="en").get("checks", [])
            total_scanned += 1
        except Exception as e:
            print(f"trustedadvisor.describe_trusted_advisor_checks error: {e}")

        # Check CloudWatch metric statistics
        try:
            from datetime import timedelta
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=["Average"]
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        # Check EC2 instances
        try:
            instances = ec2.describe_instances().get("Reservations", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_instances error: {e}")

        # Check EKS node groups
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get("nodegroups", [])
                total_scanned += 1
        except Exception as e:
            print(f"eks.list_nodegroups error: {e}")

        # Check ECS container instances
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                container_instances = ecs.list_container_instances(cluster=cluster).get("containerInstanceArns", [])
                total_scanned += 1
        except Exception as e:
            print(f"ecs.list_container_instances error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without dynamic scaling of compute resources, workloads may experience performance degradation "
                "during peak loads or incur unnecessary costs during low utilization periods."
            ),
            recommendation=(
                "Implement dynamic scaling using Auto Scaling, review Compute Optimizer and Trusted Advisor "
                "recommendations, and configure EKS/ECS for automatic scaling based on demand."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF02-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating dynamic compute scaling.",
            recommendation="Verify IAM permissions for Compute Optimizer, Trusted Advisor, CloudWatch, EC2, EKS, and ECS APIs.",
        )


# PERF02-BP06 Use optimized hardware-based compute accelerators
def check_perf02_bp06_hardware_accelerators(session):
    print("Checking PERF02-BP06 – Use optimized hardware-based compute accelerators")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_compute_hardware_compute_accelerators.html"

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
            "id": "PERF02-BP06",
            "check_name": "Use optimized hardware-based compute accelerators",
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
                "1. Evaluate workload requirements for GPU/FPGA acceleration.",
                "2. Consider EC2 instance types with GPUs (P, G, Inf instances).",
                "3. Use AWS Inferentia for machine learning inference workloads.",
                "4. Implement Elastic Fabric Adapter for HPC workloads.",
                "5. Review AWS Graviton processors for ARM-based workloads.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for hardware accelerator usage",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must evaluate and use optimized hardware-based compute accelerators (GPUs, FPGAs, "
            "Inferentia) for specialized workloads. This is an organizational responsibility."
        ),
        recommendation=(
            "Evaluate workload requirements for hardware acceleration, consider GPU/FPGA instance types, "
            "and use AWS Inferentia or Graviton processors for optimized performance."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )
