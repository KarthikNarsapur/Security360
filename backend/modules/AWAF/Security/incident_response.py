from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_sec10_bp01_identify_key_personnel(session):
    print(
        "Running SEC10-BP01 identify key personnel (non-technical organizational requirement)"
    )

    return {
        "id": "SEC10-BP01",
        "check_name": "Identify key personnel and external resources",
        "problem_statement": "Key personnel and external resources must be identified in advance to enable an effective response during security incidents.",
        "severity_score": 40,
        "severity_level": "Low",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Maintain an updated roster of internal responders and external partners who support incident response activities."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Define and document roles for internal incident responders.",
            "2. Maintain up-to-date contact information for external support partners.",
            "3. Review personnel roles periodically.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_identify_personnel.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec10_bp02_incident_management_plans(session):
    print(
        "Running SEC10-BP02 develop incident management plans (organizational process requirement)"
    )

    return {
        "id": "SEC10-BP02",
        "check_name": "Develop incident management plans",
        "problem_statement": "Incident management plans must be established to ensure structured and efficient responses to security incidents.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Document incident management procedures covering preparation, detection, containment, eradication, and recovery."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Create a written incident response plan.",
            "2. Define escalation paths and communication workflows.",
            "3. Store response documentation securely and keep it updated.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_develop_management_plans.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec10_bp03_prepare_forensic_capabilities(session):
    print(
        "Running SEC10-BP03 prepare forensic capabilities (organizational requirement)"
    )

    return {
        "id": "SEC10-BP03",
        "check_name": "Prepare forensic capabilities",
        "problem_statement": "Forensic readiness must be established to support evidence collection during security investigations.",
        "severity_score": 70,
        "severity_level": "High",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Prepare mechanisms for secure evidence capture, preservation, and chain-of-custody documentation."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Define forensic evidence collection procedures.",
            "2. Ensure logs and snapshots are retained appropriately.",
            "3. Train staff on forensic handling requirements.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_prepare_forensic.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec10_bp04_develop_and_test_playbooks(session):
    print(
        "Running SEC10-BP04 develop and test response playbooks (organizational requirement)"
    )

    return {
        "id": "SEC10-BP04",
        "check_name": "Develop and test security incident response playbooks",
        "problem_statement": "Incident response playbooks must be documented and tested to ensure efficient and predictable response actions.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Develop playbooks for various incident types and regularly test them to validate their effectiveness."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Create detailed playbooks for common incident scenarios.",
            "2. Review and update playbooks regularly.",
            "3. Conduct tabletop or simulated exercises to validate them.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_playbooks.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec10_bp05_pre_provision_access(session):
    print("Running SEC10-BP05 pre-provision access (organizational requirement)")

    return {
        "id": "SEC10-BP05",
        "check_name": "Pre-provision access",
        "problem_statement": "Critical access required during security incidents must be pre-provisioned to ensure immediate response capability.",
        "severity_score": 70,
        "severity_level": "High",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Ensure emergency roles, tools, and credentials are prepared in advance for incident response activities."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Create emergency IAM roles with limited-purpose permissions.",
            "2. Securely store credentials for emergency access.",
            "3. Test emergency access paths periodically.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_pre_provision_access.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec10_bp06_pre_deploy_tools(session):
    print(
        "Running SEC10-BP06 pre-deploy incident response tools (organizational requirement)"
    )

    return {
        "id": "SEC10-BP06",
        "check_name": "Pre-deploy tools",
        "problem_statement": "Incident response tooling must be deployed in advance to avoid delays during actual security events.",
        "severity_score": 50,
        "severity_level": "Low",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Ensure monitoring, logging, evidence capture, and investigation tools are deployed before incidents occur."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Pre-deploy tools for log analysis, evidence collection, and system imaging.",
            "2. Ensure responders know how to use these tools.",
            "3. Validate tool availability across accounts and regions.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_pre_deploy_tools.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec10_bp07_run_simulations(session):
    print("Running SEC10-BP07 run simulations (organizational requirement)")

    return {
        "id": "SEC10-BP07",
        "check_name": "Run simulations",
        "problem_statement": "Regular security incident simulations ensure response teams remain prepared for real-world events.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Conduct periodic game days or simulated incident exercises to validate readiness and improve response capabilities."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Conduct game day simulations covering different incident scenarios.",
            "2. Evaluate response timelines and communication patterns.",
            "3. Update plans and playbooks based on lessons learned.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_run_game_days.html",
        "last_updated": datetime.now(IST).isoformat(),
    }
