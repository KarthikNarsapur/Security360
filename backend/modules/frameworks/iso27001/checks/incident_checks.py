"""
ISO 27001 Checks — Incident Response
Controls: A.5.24, A.5.26, A.5.35, A.6.8
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_eventbridge_rules(session):
    """A.5.24: EventBridge rules should exist for security events."""
    print("  ISO27001: Checking EventBridge rules")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        events = session.client("events")

        try:
            rules = events.list_rules().get("Rules", [])
        except Exception:
            rules = []

        if len(rules) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "EventBridge",
                "resource_id_type": "Service",
                "issue": "No EventBridge rules configured for event-driven security responses",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.24", "Info security incident management - EventBridge rules",
                      resources_affected, max(len(rules), 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking EventBridge: {e}")
        return None


def check_sns_notifications(session):
    """A.5.24/A.6.8: SNS topics with subscriptions for notifications."""
    print("  ISO27001: Checking SNS notifications")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        sns = session.client("sns")

        try:
            topics = sns.list_topics().get("Topics", [])
        except Exception:
            topics = []

        if len(topics) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "SNS",
                "resource_id_type": "Service",
                "issue": "No SNS topics configured for security notifications",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            # Check if topics have subscriptions
            empty_topics = 0
            for topic in topics[:10]:  # Limit to avoid throttling
                try:
                    subs = sns.list_subscriptions_by_topic(TopicArn=topic["TopicArn"]).get("Subscriptions", [])
                    if len(subs) == 0:
                        empty_topics += 1
                except Exception:
                    continue
            if empty_topics > 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "SNS",
                    "resource_id_type": "Service",
                    "issue": f"{empty_topics} SNS topics have no subscriptions",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.5.24", "Info security incident management - SNS notifications",
                      resources_affected, max(len(topics), 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking SNS: {e}")
        return None


def check_incident_manager_plans(session):
    """A.5.26: Incident Manager response plans should exist."""
    print("  ISO27001: Checking Incident Manager plans")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            ssm_incidents = session.client("ssm-incidents")
            plans = ssm_incidents.list_response_plans().get("responsePlanSummaries", [])
        except Exception:
            plans = []

        if len(plans) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "Incident Manager",
                "resource_id_type": "Service",
                "issue": "No Incident Manager response plans defined",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.26", "Response to info security incidents - Incident Manager",
                      resources_affected, max(len(plans), 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking Incident Manager: {e}")
        return None


def check_audit_manager(session):
    """A.5.35: Audit Manager assessments for independent review."""
    print("  ISO27001: Checking Audit Manager")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            am = session.client("auditmanager")
            assessments = am.list_assessments().get("assessmentMetadata", [])
        except Exception:
            assessments = []

        if len(assessments) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "Audit Manager",
                "resource_id_type": "Service",
                "issue": "No Audit Manager assessments configured for independent review",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.35", "Independent review of info security - Audit Manager",
                      resources_affected, max(len(assessments), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking Audit Manager: {e}")
        return None


def check_trusted_advisor(session):
    """A.10.1: Trusted Advisor checks for continual improvement."""
    print("  ISO27001: Checking Trusted Advisor")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            support = session.client("support", region_name="us-east-1")
            checks = support.describe_trusted_advisor_checks(language="en").get("checks", [])
            security_checks = [c for c in checks if c.get("category") == "security"]

            if len(security_checks) == 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "Trusted Advisor",
                    "resource_id_type": "Service",
                    "issue": "No Trusted Advisor security checks available (requires Business/Enterprise support)",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            # Trusted Advisor requires Business/Enterprise support plan
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "Trusted Advisor",
                "resource_id_type": "Service",
                "issue": "Trusted Advisor not accessible (may require Business/Enterprise support plan)",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.10.1", "Continual improvement - Trusted Advisor",
                      resources_affected, 1, 30, "Low")
    except Exception as e:
        print(f"Error checking Trusted Advisor: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Incident Response",
        "problem_statement": f"ISO 27001 {control_id}: {check_name}",
        "severity_score": severity_score if len(resources_affected) > 0 else 0,
        "severity_level": severity_level,
        "resources_affected": resources_affected,
        "status": "passed" if len(resources_affected) == 0 else "failed",
        "recommendation": f"Remediate findings for {check_name} to meet ISO 27001 requirements",
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": len(resources_affected),
        },
        "last_updated": datetime.now(IST).isoformat(),
    }
