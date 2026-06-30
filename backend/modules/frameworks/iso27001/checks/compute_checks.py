"""
ISO 27001 Checks — Compute & Inventory
Controls: A.8.1, A.5.9, A.5.13
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_managed_ec2_ssm(session):
    """A.8.1: EC2 instances should be managed by SSM."""
    print("  ISO27001: Checking managed EC2 (SSM)")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        ec2 = session.client("ec2")
        ssm = session.client("ssm")

        instances = []
        for res in ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", []):
            instances.extend(res.get("Instances", []))

        total = len(instances)
        if total == 0:
            return _result("A.8.1", "User endpoint devices - Managed EC2 (SSM)",
                          [], 0, 0, "Low")

        try:
            managed = ssm.describe_instance_information().get("InstanceInformationList", [])
            managed_ids = set(m["InstanceId"] for m in managed)
        except Exception:
            managed_ids = set()

        for inst in instances:
            inst_id = inst["InstanceId"]
            if inst_id not in managed_ids:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": inst_id,
                    "resource_id_type": "EC2 Instance",
                    "issue": f"Instance '{inst_id}' is not managed by SSM",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.1", "User endpoint devices - Managed EC2 (SSM)",
                      resources_affected, max(total, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking managed EC2: {e}")
        return None


def check_ec2_inventory(session):
    """A.5.9: EC2 instances should be properly tagged for inventory."""
    print("  ISO27001: Checking EC2 inventory tags")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        instances = []
        for res in ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", []):
            instances.extend(res.get("Instances", []))

        total = len(instances)
        required_tags = ["name", "owner", "environment"]

        for inst in instances:
            tags = {t["Key"].lower(): t["Value"] for t in inst.get("Tags", [])}
            missing = [t for t in required_tags if t not in tags]
            if missing:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": inst["InstanceId"],
                    "resource_id_type": "EC2 Instance",
                    "issue": f"Instance '{inst['InstanceId']}' missing tags: {', '.join(missing)}",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.5.9", "Inventory of assets - EC2 inventory",
                      resources_affected, max(total, 1), 40, "Low")
    except Exception as e:
        print(f"Error checking EC2 inventory: {e}")
        return None


def check_lambda_inventory(session):
    """A.5.9: Lambda functions should be inventoried and tagged."""
    print("  ISO27001: Checking Lambda inventory")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            lam = session.client("lambda")
            functions = lam.list_functions().get("Functions", [])
            total = len(functions)

            untagged = 0
            for fn in functions:
                tags = fn.get("Tags", {}) or {}  # Can be None
                if not tags or "Owner" not in tags and "owner" not in tags:
                    untagged += 1

            if untagged > 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "Lambda",
                    "resource_id_type": "Service",
                    "issue": f"{untagged}/{total} Lambda functions are missing ownership tags",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            total = 0

        return _result("A.5.9", "Inventory of assets - Lambda inventory",
                      resources_affected, max(total, 1), 30, "Low")
    except Exception as e:
        print(f"Error checking Lambda inventory: {e}")
        return None


def check_resource_tagging(session):
    """A.5.13: Resources should have proper tagging for classification."""
    print("  ISO27001: Checking resource tagging")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        # Check EBS volumes for tagging
        volumes = ec2.describe_volumes().get("Volumes", [])
        total = len(volumes)
        untagged = 0

        for vol in volumes:
            tags = vol.get("Tags", [])
            if not tags or len(tags) == 0:
                untagged += 1

        if untagged > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "EBS",
                "resource_id_type": "Service",
                "issue": f"{untagged}/{total} EBS volumes have no tags",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.13", "Labelling of information - Resource tagging",
                      resources_affected, max(total, 1), 30, "Low")
    except Exception as e:
        print(f"Error checking resource tagging: {e}")
        return None


def check_resource_inventory(session):
    """A.5.9: Overall resource inventory via Config."""
    print("  ISO27001: Checking resource inventory")
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
                "issue": "No Config recorder for automated asset inventory",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            # Check if recorder captures all resource types
            for recorder in recorders:
                recording_group = recorder.get("recordingGroup", {})
                if not recording_group.get("allSupported", False):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": recorder.get("name", "Config"),
                        "resource_id_type": "Config Recorder",
                        "issue": "Config recorder does not capture all resource types",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return _result("A.5.9", "Inventory of assets - Resource inventory",
                      resources_affected, max(len(recorders), 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking resource inventory: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Compute & Inventory",
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
