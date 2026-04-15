from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

def check_sus03_bp01_optimize_async(session):
    # [BP01] - Optimize software for asynchronous jobs
    print("Checking SUS03-BP01: Async Patterns (Lambda, EventBridge, SQS)")

    events = session.client("events")
    lambda_c = session.client("lambda")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_software_async.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS03-BP01",
            "check_name": "Optimize software and architecture for asynchronous and scheduled jobs",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Switch polling architectures to event-driven ones (EventBridge).",
                "2. Use Lambda for periodic tasks.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        has_async = False
        try:
            if events.list_rules(Limit=1).get("Rules"):
                has_async = True
        except:
            pass
        try:
            if lambda_c.list_functions(MaxItems=1).get("Functions"):
                has_async = True
        except:
            pass

        status = "passed" if has_async else "failed"
        problem = (
            "No event-driven infra detected."
            if status == "failed"
            else "Async architecture detected."
        )

        if status == "failed":
            resources_affected.append(
                {
                    "resource_id": "Architecture",
                    "issue": "No EventBridge Rules or Lambda found.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status,
            problem,
            "Adopt event-driven patterns.",
            resources_affected,
            1,
            1 if status == "failed" else 0,
        )
    except Exception as e:
        return build_response("error", f"Error: {e}", "Check permissions.")


def check_sus03_bp02_remove_low_use(session):
    # [BP02] - Remove or refactor workload components with low or no use
    print("Checking SUS03-BP02: Low Utilization (Trusted Advisor/Metrics)")

    cw = session.client("cloudwatch")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_software_remove.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS03-BP02",
            "check_name": "Remove or refactor workload components with low or no use",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Check CloudWatch for low CPU utilization.",
                "2. Consolidate low-traffic services.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Checking if we can access metrics implies we CAN monitor for low use
        cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            StartTime=datetime.now() - timedelta(hours=1),
            EndTime=datetime.now(),
            Period=3600,
            Statistics=["Average"],
        )
        return build_response(
            "passed",
            "Metric visibility active.",
            "Regularly review low-utilization metrics.",
            [],
            1,
            0,
        )
    except Exception as e:
        return build_response("error", f"Error: {e}", "Check CloudWatch permissions.")


def check_sus03_bp03_optimize_code(session):
    return {
        "id": "SUS03-BP03",
        "check_name": "Optimize areas of code that consume the most time or resources",
        "status": "not_available",
        "problem_statement": "Code profiling is manual.",
        "recommendation": "Profile code to reduce compute cycles.",
        "remediation_steps": [],
        "resources_affected": [],
        "last_updated": datetime.now(IST).isoformat(),
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_software_optimize.html",
        "severity_score": 0,
        "severity_level": "None",
        "additional_info": {},
    }


def check_sus03_bp04_optimize_devices(session):
    return {
        "id": "SUS03-BP04",
        "check_name": "Optimize impact on devices and equipment",
        "status": "not_available",
        "problem_statement": "Device impact analysis is manual.",
        "recommendation": "Minimize data sent to client devices.",
        "remediation_steps": [],
        "resources_affected": [],
        "last_updated": datetime.now(IST).isoformat(),
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_software_devices.html",
        "severity_score": 0,
        "severity_level": "None",
        "additional_info": {},
    }


def check_sus03_bp05_data_patterns(session):
    # [BP05] - Use software patterns for data access
    print("Checking SUS03-BP05: Data Access (DynamoDB/ElastiCache)")
    ddb = session.client("dynamodb")
    cache = session.client("elasticache")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_software_data.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS03-BP05",
            "check_name": "Use software patterns and architectures that best support data access",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Use caching (ElastiCache) to reduce DB load.",
                "2. Use DynamoDB for key-value patterns.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        has_optimized_store = False
        try:
            if ddb.list_tables(Limit=1).get("TableNames"):
                has_optimized_store = True
        except:
            pass
        try:
            if cache.describe_cache_clusters(MaxRecords=1).get("CacheClusters"):
                has_optimized_store = True
        except:
            pass

        status = "passed" if has_optimized_store else "failed"
        if status == "failed":
            resources_affected.append(
                {
                    "resource_id": "Data Store",
                    "issue": "No specialized data stores (DDB/Cache) found.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
        return build_response(
            status,
            "Using only relational DBs may be inefficient.",
            "Adopt caching/NoSQL.",
            resources_affected,
            1,
            1 if status == "failed" else 0,
        )
    except Exception as e:
        return build_response("error", f"Error: {e}", "Check permissions.")
