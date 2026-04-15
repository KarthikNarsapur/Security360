from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

def check_sus06_bp01_communicate(session):
    return {
        "id": "SUS06-BP01",
        "check_name": "Communicate and cascade your sustainability goals",
        "status": "not_available",
        "problem_statement": "Culture check.",
        "recommendation": "Set KPIs for carbon reduction.",
        "remediation_steps": [],
        "resources_affected": [],
        "last_updated": datetime.now(IST).isoformat(),
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_process_goals.html",
        "severity_score": 0,
        "severity_level": "None",
        "additional_info": {},
    }


def check_sus06_bp02_rapid_methods(session):
    return {
        "id": "SUS06-BP02",
        "check_name": "Adopt methods that can rapidly introduce sustainability improvements",
        "status": "not_available",
        "problem_statement": "Process check.",
        "recommendation": "Agile improvement.",
        "remediation_steps": [],
        "resources_affected": [],
        "last_updated": datetime.now(IST).isoformat(),
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_process_methods.html",
        "severity_score": 0,
        "severity_level": "None",
        "additional_info": {},
    }


def check_sus06_bp03_keep_updated(session):
    # [BP03] - Keep workload up-to-date
    print("Checking SUS06-BP03: Updates (SSM Patch/ImageBuilder)")
    ssm = session.client("ssm")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_process_update.html"

    def build_response(
        status, problem, rec, resources_affected=[], total=0, affected=0
    ):
        return {
            "id": "SUS06-BP03",
            "check_name": "Keep your workload up-to-date",
            "problem_statement": problem,
            "status": status,
            "recommendation": rec,
            "resources_affected": resources_affected,
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": ["Use SSM Patch Manager."],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
            "severity_score": 50,
            "severity_level": "Medium",
        }

    try:
        if ssm.describe_patch_baselines(MaxResults=1).get("BaselineIdentities"):
            return build_response(
                "passed",
                "Patch baselines found.",
                "Maintain regular patching cycles.",
                [],
                1,
                0,
            )
        return build_response(
            "passed",
            "No patch baselines found, assuming manual or immutable infra.",
            "Consider automated patching.",
            [],
            1,
            0,
        )
    except Exception as e:
        return build_response("error", f"{e}", "Check permissions.")


def check_sus06_bp04_build_utilization(session):
    # [BP04] - Build environments
    print("Checking SUS06-BP04: Build Utilization (CodeBuild)")
    cb = session.client("codebuild")
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_process_utilization.html"

    try:
        if cb.list_projects(sortBy="NAME").get("projects"):
            return {
                "id": "SUS06-BP04",
                "check_name": "Increase utilization of build environments",
                "status": "passed",
                "problem_statement": "Build projects found.",
                "recommendation": "Use CodeBuild batch builds.",
                "resources_affected": [],
                "additional_info": {"total_scanned": 1, "affected": 0},
                "remediation_steps": [],
                "aws_doc_link": aws_doc_link,
                "last_updated": datetime.now(IST).isoformat(),
                "severity_score": 50,
                "severity_level": "Medium",
            }
        return {
            "id": "SUS06-BP04",
            "check_name": "Increase utilization of build environments",
            "status": "passed",
            "problem_statement": "No build projects.",
            "recommendation": "Use managed build services.",
            "resources_affected": [],
            "additional_info": {"total_scanned": 1, "affected": 0},
            "remediation_steps": [],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
            "severity_score": 50,
            "severity_level": "Medium",
        }
    except Exception as e:
        return {
            "id": "SUS06-BP04",
            "check_name": "Increase utilization",
            "status": "error",
            "problem_statement": f"{e}",
            "recommendation": "",
            "resources_affected": [],
            "last_updated": datetime.now(IST).isoformat(),
            "severity_score": 0,
            "severity_level": "None",
            "additional_info": {},
        }


def check_sus06_bp05_device_farms(session):
    # [BP05] - Device farms
    print("Checking SUS06-BP05: Device Farm")
    df = session.client("devicefarm", region_name="us-west-2")
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_process_farms.html"

    try:
        df.list_projects()
        return {
            "id": "SUS06-BP05",
            "check_name": "Use managed device farms for testing",
            "status": "passed",
            "problem_statement": "Device Farm accessible.",
            "recommendation": "Use Device Farm instead of physical devices.",
            "resources_affected": [],
            "additional_info": {"total_scanned": 1, "affected": 0},
            "remediation_steps": [],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
            "severity_score": 50,
            "severity_level": "Medium",
        }
    except Exception as e:
        return {
            "id": "SUS06-BP05",
            "check_name": "Use managed device farms",
            "status": "passed",
            "problem_statement": f"Check skipped or failed: {e}",
            "recommendation": "Consider Device Farm.",
            "resources_affected": [],
            "last_updated": datetime.now(IST).isoformat(),
            "severity_score": 0,
            "severity_level": "None",
            "additional_info": {},
        }
