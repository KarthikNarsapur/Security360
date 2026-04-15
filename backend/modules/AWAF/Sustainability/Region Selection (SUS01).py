from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

def check_sus01_bp01_choose_region(session):
    print("Checking SUS01-BP01: Region Selection Strategy")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/sustainability-pillar/sus_sus_region_selection.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SUS01-BP01",
            "check_name": "Choose Region based on both business requirements and sustainability goals",
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
                "1. Evaluate the carbon intensity of the electricity grid in potential AWS Regions.",
                "2. Choose regions powered by renewable energy (e.g., us-west-2, eu-west-1) where latency allows.",
                "3. Balance data residency requirements with sustainability goals.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        return build_response(
            status="not_available",
            problem=(
                "Region selection is a foundational architectural decision involving grid carbon intensity "
                "and business latency requirements. This cannot be validated programmatically via API."
            ),
            recommendation=(
                "Review your active regions against the Amazon Sustainability Data methodology. "
                "Migrate workloads to regions with lower carbon intensity if business requirements permit."
            ),
        )

    except Exception as e:
        print(f"Error evaluating SUS01-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess region selection strategy.",
            recommendation="Review internal architecture decision records regarding region choice.",
        )
