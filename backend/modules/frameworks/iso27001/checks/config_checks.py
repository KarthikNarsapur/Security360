"""
ISO 27001 Checks — Configuration Management
Controls: A.8.9, A.8.32, A.5.36
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_config_recorder(session):
    """A.8.9: AWS Config recorder should be active."""
    print("  ISO27001: Checking Config recorder")
    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])

        if len(recorders) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AWS Config",
                "resource_id_type": "Service",
                "issue": "No AWS Config recorder configured",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            statuses = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            for status in statuses:
                if not status.get("recording", False):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": status.get("name", "Config"),
                        "resource_id_type": "Config Recorder",
                        "issue": f"Config recorder '{status.get('name')}' is not recording",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return _result("A.8.9", "Configuration management - Config recorder",
                      resources_affected, max(len(recorders), 1), 80, "High")
    except Exception as e:
        print(f"Error checking Config recorder: {e}")
        return None


def check_config_rules(session):
    """A.8.9: AWS Config rules should be deployed."""
    print("  ISO27001: Checking Config rules")
    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        rules = config.describe_config_rules().get("ConfigRules", [])

        if len(rules) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AWS Config",
                "resource_id_type": "Service",
                "issue": "No AWS Config rules deployed",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.9", "Configuration management - Config rules",
                      resources_affected, max(len(rules), 1), 70, "High")
    except Exception as e:
        print(f"Error checking Config rules: {e}")
        return None


def check_conformance_packs(session):
    """A.5.36: Conformance packs for compliance validation."""
    print("  ISO27001: Checking conformance packs")
    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            packs = config.describe_conformance_packs().get("ConformancePackDetails", [])
        except Exception:
            packs = []

        if len(packs) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AWS Config",
                "resource_id_type": "Service",
                "issue": "No conformance packs deployed for compliance validation",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.36", "Compliance with policies - Conformance packs",
                      resources_affected, max(len(packs), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking conformance packs: {e}")
        return None


def check_compliance_status(session):
    """A.5.36: Config rules should be in compliant state."""
    print("  ISO27001: Checking compliance status")
    config = session.client("config")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            results = config.describe_compliance_by_config_rule().get("ComplianceByConfigRules", [])
            non_compliant = [r for r in results if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT"]

            if len(non_compliant) > 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "AWS Config",
                    "resource_id_type": "Service",
                    "issue": f"{len(non_compliant)}/{len(results)} Config rules are NON_COMPLIANT",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            results = []

        return _result("A.5.36", "Compliance with policies - Compliance status",
                      resources_affected, max(len(results) if 'results' in dir() else 1, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking compliance status: {e}")
        return None


def check_cloudformation_stacks(session):
    """A.8.32: Infrastructure should be managed as code (CloudFormation)."""
    print("  ISO27001: Checking CloudFormation stacks")
    cfn = session.client("cloudformation")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        stacks = cfn.list_stacks(
            StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE", "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"]
        ).get("StackSummaries", [])

        healthy = [s for s in stacks if s["StackStatus"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE")]
        unhealthy = [s for s in stacks if "ROLLBACK" in s["StackStatus"]]

        if len(stacks) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudFormation",
                "resource_id_type": "Service",
                "issue": "No CloudFormation stacks — infrastructure may not be managed as code",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        elif len(unhealthy) > 0:
            for stack in unhealthy:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": stack["StackName"],
                    "resource_id_type": "CloudFormation Stack",
                    "issue": f"Stack '{stack['StackName']}' is in {stack['StackStatus']} state",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.32", "Change management - CloudFormation stack health",
                      resources_affected, max(len(stacks), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking CloudFormation: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Configuration",
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
