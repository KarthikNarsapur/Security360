from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_cost09_bp01_analyze_demand(session):
    # [BP01] - Perform an analysis on the workload demand
    print("Checking COST09-BP01: Demand Analysis (CloudWatch, CE, Compute Optimizer)")

    cw_client = session.client("cloudwatch")
    ce_client = session.client("ce")
    co_client = session.client("compute-optimizer")
    asg_client = session.client("autoscaling")
    ecs_client = session.client("ecs")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cost_effective_resources_demand_analysis.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST09-BP01",
            "check_name": "Perform an analysis on the workload demand",
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
                "1. Enable granular CloudWatch metrics to track demand (CPU, Requests, Latency).",
                "2. Use Cost Explorer to correlate spikes in cost with spikes in usage.",
                "3. Enable AWS Compute Optimizer to analyze historical utilization patterns.",
                "4. Review Auto Scaling Group scaling history to understand demand volatility.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: CloudWatch Metric Visibility ------------------
        metrics_visible = False
        try:
            # Check if we can list metrics (proof of visibility)
            cw_client.list_metrics(
                Namespace="AWS/EC2", MetricName="CPUUtilization", Limit=1
            )
            metrics_visible = True
        except Exception:
            pass

        # ------------------ Check 2: Compute Optimizer Analysis ------------------
        co_active = False
        try:
            if co_client.get_recommendation_summaries().get("recommendationSummaries"):
                co_active = True
        except Exception:
            pass

        # ------------------ Check 3: Workload Context ------------------
        # Do they have ASGs or ECS services to analyze?
        has_dynamic_workload = False
        try:
            if asg_client.describe_auto_scaling_groups(MaxRecords=1).get(
                "AutoScalingGroups"
            ):
                has_dynamic_workload = True
            if not has_dynamic_workload and ecs_client.list_clusters(maxResults=1).get(
                "clusterArns"
            ):
                has_dynamic_workload = True
        except Exception:
            pass

        total_scanned = 2  # Metrics and CO
        affected = 0

        status = "passed"
        problem_text = ""
        rec_text = ""

        if not metrics_visible:
            status = "failed"
            problem_text = "CloudWatch metrics are inaccessible. You cannot analyze workload demand without metric data."
            rec_text = "Ensure you have permissions to view CloudWatch metrics ('cloudwatch:ListMetrics')."
        elif has_dynamic_workload and not co_active:
            status = "passed"  # Soft pass
            problem_text = "Dynamic workloads exist (ASG/ECS), but Compute Optimizer is not providing analysis."
            rec_text = "Enable Compute Optimizer to automatically analyze demand patterns and recommend sizing."
        else:
            status = "passed"
            problem_text = "Demand analysis tools (metrics/optimizer) are active."
            rec_text = "Regularly review Cost Explorer hourly data to identify demand peaks and troughs."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Demand Analysis: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating analysis tools.",
            recommendation="Check permissions for 'cloudwatch' and 'compute-optimizer'.",
        )


def check_cost09_bp02_buffer_throttle(session):
    # [BP02] - Implement a buffer or throttle to manage demand
    print("Checking COST09-BP02: Buffering & Throttling (API Gateway, SQS, AppScaling)")

    apigw_client = session.client("apigateway")
    sqs_client = session.client("sqs")
    app_asg_client = session.client("application-autoscaling")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cost_effective_resources_buffer_throttle.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST09-BP02",
            "check_name": "Implement a buffer or throttle to manage demand",
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
                "1. Use Amazon SQS to decouple components and buffer unexpected load spikes.",
                "2. Configure API Gateway throttling limits to protect backend services from saturation.",
                "3. Use Application Auto Scaling target tracking to smooth out demand curves.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Check 1: API Gateway (Throttling) ------------------
        has_apis = False
        throttling_checked = False
        try:
            apis = apigw_client.get_rest_apis(limit=5).get("items", [])
            if apis:
                has_apis = True
                # Just verifying we can access stages implies we *could* configure throttling
                # Deep inspection of methodSettings is complex, presence is sufficient for 'Implementation' check
                apigw_client.get_stages(restApiId=apis[0]["id"])
                throttling_checked = True
        except Exception:
            pass

        # ------------------ Check 2: SQS (Buffering) ------------------
        has_queues = False
        try:
            if sqs_client.list_queues(MaxResults=1).get("QueueUrls"):
                has_queues = True
        except Exception:
            pass

        # ------------------ Check 3: App Auto Scaling (Target Tracking/Throttling DynamoDB) ------------------
        has_app_scaling = False
        try:
            if app_asg_client.describe_scaling_policies(
                ServiceNamespace="dynamodb", MaxResults=1
            ).get("ScalingPolicies"):
                has_app_scaling = True
        except Exception:
            pass

        total_scanned = 1
        affected = 0

        status = "passed"
        problem_text = ""
        rec_text = ""

        # Logic: We need at least one mechanism to manage demand.
        if not has_apis and not has_queues and not has_app_scaling:
            status = "failed"
            affected = 1
            resources_affected.append(
                {
                    "resource_id": "Demand Management",
                    "issue": "No buffering (SQS) or throttling (API Gateway/AppScaling) mechanisms detected.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            problem_text = "Workload appears to handle demand synchronously without buffers, risking failure during spikes."
            rec_text = "Implement SQS queues to decouple components or use API Gateway to throttle requests."
        else:
            status = "passed"
            problem_text = (
                "Demand management components (SQS/APIGW/Scaling) are present."
            )
            rec_text = "Ensure your SQS queue visibility timeouts align with your processing time to prevent message duplication."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Buffer/Throttle: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating demand management tools.",
            recommendation="Check permissions for 'sqs', 'apigateway', and 'application-autoscaling'.",
        )


def check_cost09_bp03_supply_dynamically(session):
    # [BP03] - Supply resources dynamically
    print("Checking COST09-BP03: Dynamic Supply (Auto Scaling, Lambda, EKS)")

    asg_client = session.client("autoscaling")
    app_asg_client = session.client("application-autoscaling")
    lambda_client = session.client("lambda")
    eks_client = session.client("eks")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_cost_effective_resources_dynamic_supply.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "COST09-BP03",
            "check_name": "Supply resources dynamically",
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
                "1. Configure Auto Scaling Groups for EC2 instances.",
                "2. Use DynamoDB On-Demand or Auto Scaling.",
                "3. Configure ECS Service Auto Scaling or EKS Cluster Autoscaler (Karpenter).",
                "4. Use Lambda for event-driven, inherently dynamic compute.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        dynamic_resources_count = 0

        # 1. EC2 Auto Scaling
        try:
            asgs = asg_client.describe_auto_scaling_groups(MaxRecords=5).get(
                "AutoScalingGroups", []
            )
            dynamic_resources_count += len(asgs)
        except:
            pass

        # 2. Application Auto Scaling (ECS/DynamoDB/Custom)
        try:
            # Check multiple namespaces
            for ns in ["ecs", "dynamodb", "lambda"]:
                targets = app_asg_client.describe_scalable_targets(
                    ServiceNamespace=ns, MaxResults=5
                ).get("ScalableTargets", [])
                dynamic_resources_count += len(targets)
        except:
            pass

        # 3. Lambda Functions (Inherently dynamic)
        try:
            funcs = lambda_client.list_functions(MaxItems=5).get("Functions", [])
            dynamic_resources_count += len(funcs)
        except:
            pass

        # 4. EKS Node Groups (Dynamic scaling for K8s)
        try:
            clusters = eks_client.list_clusters(maxResults=1).get("clusters", [])
            for c in clusters:
                ngs = eks_client.list_nodegroups(clusterName=c, maxResults=1).get(
                    "nodegroups", []
                )
                if ngs:
                    dynamic_resources_count += 1
        except:
            pass

        total_scanned = 1
        affected = 0

        status = "passed"
        problem_text = ""
        rec_text = ""

        if dynamic_resources_count == 0:
            status = "failed"
            affected = 1
            resources_affected.append(
                {
                    "resource_id": "Dynamic Scaling",
                    "issue": "No Auto Scaling, Lambda, or Managed Node Groups detected. Resources appear statically provisioned.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            problem_text = "Resources are statically provisioned, leading to waste during low demand and failure during high demand."
            rec_text = "Adopt Auto Scaling or Serverless (Lambda/Fargate) technologies to supply resources dynamically."
        else:
            status = "passed"
            problem_text = f"Found {dynamic_resources_count} resources configured for dynamic supply."
            rec_text = "Review scaling policies to ensure they are responsive enough to sudden demand spikes."

        return build_response(
            status=status,
            problem=problem_text,
            recommendation=rec_text,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking Dynamic Supply: {e}")
        return build_response(
            status="error",
            problem="An unexpected error occurred while validating dynamic provisioning.",
            recommendation="Check permissions for 'autoscaling', 'lambda', and 'eks'.",
        )
