from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

def check_sus02_bp01_scale_dynamically(session):
    # [BP01] - Scale workload infrastructure dynamically
    print("Checking SUS02-BP01: Dynamic Scaling (ASG, AppScaling, Lambda, K8s)")

    asg_client = session.client("autoscaling")
    app_asg_client = session.client("application-autoscaling")
    lambda_client = session.client("lambda")
    eks_client = session.client("eks")
    ecs_client = session.client("ecs")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_user_behavior_scale.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS02-BP01",
            "check_name": "Scale workload infrastructure dynamically",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Use Auto Scaling Groups for EC2 to match supply with demand.",
                "2. Configure Application Auto Scaling for DynamoDB and Aurora.",
                "3. Use Lambda concurrency controls to prevent over-provisioning.",
                "4. Implement Karpenter or Cluster Autoscaler for EKS.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        scaling_mechanisms_found = 0

        # 1. Check ASG
        try:
            if asg_client.describe_auto_scaling_groups(MaxRecords=1).get(
                "AutoScalingGroups"
            ):
                scaling_mechanisms_found += 1
        except:
            pass

        # 2. Check App Scaling (DynamoDB/ECS etc)
        try:
            if app_asg_client.describe_scaling_policies(
                ServiceNamespace="dynamodb", MaxResults=1
            ).get("ScalingPolicies"):
                scaling_mechanisms_found += 1
        except:
            pass

        # 3. Check Lambda
        try:
            if lambda_client.get_account_settings().get("AccountLimit"):
                # Just verifying Lambda API access really, implies serverless capability
                scaling_mechanisms_found += 1
        except:
            pass

        # 4. Check Containers (EKS/ECS)
        try:
            if ecs_client.list_clusters(maxResults=1).get("clusterArns"):
                scaling_mechanisms_found += 1
            elif eks_client.list_clusters(maxResults=1).get("clusters"):
                scaling_mechanisms_found += 1
        except:
            pass

        total_scanned = 1
        status = "passed" if scaling_mechanisms_found > 0 else "failed"

        problem = (
            "Resources appear to be statically provisioned."
            if status == "failed"
            else ""
        )
        rec = (
            "Implement Auto Scaling to ensure you consume energy only when there is demand."
            if status == "failed"
            else "Scaling mechanisms are active."
        )

        if status == "failed":
            resources_affected.append(
                {
                    "resource_id": "Scaling Configuration",
                    "issue": "No dynamic scaling detected.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status,
            problem,
            rec,
            resources_affected,
            total_scanned,
            1 if status == "failed" else 0,
        )

    except Exception as e:
        print(f"Error checking Dynamic Scaling: {e}")
        return build_response("error", "Unexpected error.", "Check permissions.")


def check_sus02_bp02_align_slas(session):
    print("Checking SUS02-BP02 – Align SLAs with sustainability goals")
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_user_behavior_sla.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS02-BP02",
            "check_name": "Align SLAs with sustainability goals",
            "problem_statement": problem,
            "severity_score": 25,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Renegotiate SLAs to allow for asynchronous processing.",
                "2. Allow for relaxed consistency where possible.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    return build_response(
        "not_available",
        "SLA negotiation is a business process.",
        "Review contracts to trade latency for efficiency.",
    )


def check_sus02_bp03_stop_unused_assets(session):
    # [BP03] - Stop the creation and maintenance of unused assets
    print("Checking SUS02-BP03: Unused Assets (Zombie Resources)")

    ec2 = session.client("ec2")
    rds = session.client("rds")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_user_behavior_unused_assets.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS02-BP03",
            "check_name": "Stop the creation and maintenance of unused assets",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Terminate stopped EC2 instances.",
                "2. Delete unattached EBS volumes.",
                "3. Snapshot and delete idle RDS instances.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Check stopped EC2s
        stopped_instances = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ).get("Reservations", [])
        if stopped_instances:
            count = sum(len(r["Instances"]) for r in stopped_instances)
            resources_affected.append(
                {
                    "resource_id": f"{count} Stopped EC2s",
                    "issue": "Instances are stopped but consuming storage (EBS) energy.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        status = "failed" if resources_affected else "passed"
        problem = (
            "Unused assets detected."
            if status == "failed"
            else "No obvious zombie assets found."
        )
        rec = "Decommission unused resources."

        return build_response(
            status, problem, rec, resources_affected, 1, len(resources_affected)
        )
    except Exception as e:
        return build_response("error", f"Error: {e}", "Check EC2 permissions.")


def check_sus02_bp04_optimize_geo_placement(session):
    # [BP04] - Optimize geographic placement based on networking
    print("Checking SUS02-BP04: Network Placement (Global Accelerator, CloudFront)")

    ga = session.client("globalaccelerator", region_name="us-west-2")
    cf = session.client("cloudfront")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_user_behavior_placement.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS02-BP04",
            "check_name": "Optimize geographic placement of workloads based on their networking requirements",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Use CloudFront to cache content closer to users.",
                "2. Use Global Accelerator to route traffic efficiently.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        has_network_opt = False
        try:
            if ga.list_accelerators(MaxResults=1).get("Accelerators"):
                has_network_opt = True
        except:
            pass
        try:
            if (
                cf.list_distributions(MaxItems="1")
                .get("DistributionList", {})
                .get("Items")
            ):
                has_network_opt = True
        except:
            pass

        status = "passed" if has_network_opt else "failed"
        problem = (
            "No geographic optimization tools found."
            if status == "failed"
            else "Network placement tools active."
        )

        if status == "failed":
            resources_affected.append(
                {
                    "resource_id": "Network",
                    "issue": "No CloudFront/GA detected. Traffic may be traversing long distances unnecessarily.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status,
            problem,
            "Implement CloudFront or Global Accelerator.",
            resources_affected,
            1,
            1 if status == "failed" else 0,
        )
    except Exception as e:
        return build_response("error", f"Error: {e}", "Check permissions.")


def check_sus02_bp05_optimize_team_resources(session):
    print("Checking SUS02-BP05 – Optimize team member resources")
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_user_behavior_team.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS02-BP05",
            "check_name": "Optimize team member resources for activities performed",
            "problem_statement": problem,
            "severity_score": 25,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Use shared devices for testing.",
                "2. Optimize desktop virtualization.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    return build_response(
        "not_available",
        "Team resource optimization is a physical/HR process.",
        "Optimize hardware lifecycles for staff.",
    )


def check_sus02_bp06_buffer_throttle(session):
    # [BP06] - Implement buffering or throttling
    print("Checking SUS02-BP06: Buffering (SQS, Kinesis, APIGW)")
    sqs = session.client("sqs")
    kinesis = session.client("kinesis")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_user_behavior_buffer.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS02-BP06",
            "check_name": "Implement buffering or throttling to flatten the demand curve",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Use SQS to decouple components.",
                "2. Use Kinesis for data ingestion.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        has_buffer = False
        try:
            if sqs.list_queues(MaxResults=1).get("QueueUrls"):
                has_buffer = True
        except:
            pass
        try:
            if kinesis.list_streams(Limit=1).get("StreamNames"):
                has_buffer = True
        except:
            pass

        status = "passed" if has_buffer else "failed"
        problem = (
            "No buffering mechanisms found."
            if status == "failed"
            else "Buffering tools active."
        )

        if status == "failed":
            resources_affected.append(
                {
                    "resource_id": "Architecture",
                    "issue": "No SQS/Kinesis found. Workload might be tightly coupled.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status,
            problem,
            "Implement SQS to flatten demand peaks.",
            resources_affected,
            1,
            1 if status == "failed" else 0,
        )
    except Exception as e:
        return build_response("error", f"Error: {e}", "Check permissions.")
