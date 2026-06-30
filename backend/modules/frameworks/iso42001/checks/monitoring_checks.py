"""
ISO 42001 Extended Checks — Monitoring & Alarms (AI-048 to AI-052)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_missing_alarms_ai_endpoints(session):
    """AI-048: Missing alarms for AI endpoints"""
    print("Checking missing alarms for AI endpoints")

    cloudwatch = session.client("cloudwatch")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get SageMaker endpoints
        endpoints = []
        try:
            endpoints = sagemaker.list_endpoints(StatusEquals="InService").get("Endpoints", [])
        except Exception:
            pass

        total_scanned = len(endpoints)

        # Get all CloudWatch alarms for SageMaker namespace
        alarms = []
        try:
            paginator = cloudwatch.get_paginator("describe_alarms")
            for page in paginator.paginate():
                alarms.extend(page.get("MetricAlarms", []))
        except Exception:
            pass

        sagemaker_alarm_endpoints = set()
        for alarm in alarms:
            if alarm.get("Namespace") == "AWS/SageMaker":
                for dim in alarm.get("Dimensions", []):
                    if dim.get("Name") == "EndpointName":
                        sagemaker_alarm_endpoints.add(dim.get("Value"))

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "Unknown")
            if ep_name not in sagemaker_alarm_endpoints:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": ep_name,
                    "resource_id_type": "SageMakerEndpoint",
                    "issue": f"SageMaker endpoint '{ep_name}' has no CloudWatch alarms configured",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-048",
            "check_name": "Missing alarms for AI endpoints",
            "problem_statement": "All AI endpoints should have CloudWatch alarms for operational monitoring",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create CloudWatch alarms for all active SageMaker endpoints",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify SageMaker endpoints without monitoring alarms",
                "2. Create alarms for CPUUtilization, MemoryUtilization, and Invocations",
                "3. Configure SNS notifications for alarm state changes",
                "4. Set up dashboards for endpoint health visibility",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking missing alarms for AI endpoints: {e}")
        return None


def check_missing_alarms_training_failures(session):
    """AI-049: Missing alarms for training failures"""
    print("Checking missing alarms for training failures")

    cloudwatch = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check for alarms monitoring SageMaker training job metrics
        alarms = []
        try:
            paginator = cloudwatch.get_paginator("describe_alarms")
            for page in paginator.paginate():
                alarms.extend(page.get("MetricAlarms", []))
        except Exception:
            pass

        training_failure_alarms = [
            alarm for alarm in alarms
            if alarm.get("Namespace") == "AWS/SageMaker"
            and alarm.get("MetricName") in [
                "TrainingJobsFailed", "train:error", "TrainingJobError"
            ]
        ]

        total_scanned = 1  # Checking for alarm existence at account level

        if not training_failure_alarms:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "SageMaker-Training",
                "resource_id_type": "AlarmConfig",
                "issue": "No CloudWatch alarms configured for SageMaker training job failures",
                "region": cloudwatch.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return {
            "id": "AI-049",
            "check_name": "Missing alarms for training failures",
            "problem_statement": "Alarms should exist for AI training job failures to enable rapid response",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create CloudWatch alarms for SageMaker training job failure metrics",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create CloudWatch alarm for TrainingJobsFailed metric",
                "2. Set threshold to alert on any training failure (>= 1)",
                "3. Configure SNS topic for notifications",
                "4. Set up automated incident response for repeated failures",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking missing alarms for training failures: {e}")
        return None


def check_missing_alarms_invocation_failures(session):
    """AI-050: Missing alarms for invocation failures"""
    print("Checking missing alarms for invocation failures")

    cloudwatch = session.client("cloudwatch")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get active endpoints
        endpoints = []
        try:
            endpoints = sagemaker.list_endpoints(StatusEquals="InService").get("Endpoints", [])
        except Exception:
            pass

        total_scanned = len(endpoints)

        # Get alarms for invocation errors
        alarms = []
        try:
            paginator = cloudwatch.get_paginator("describe_alarms")
            for page in paginator.paginate():
                alarms.extend(page.get("MetricAlarms", []))
        except Exception:
            pass

        invocation_error_endpoints = set()
        for alarm in alarms:
            if (alarm.get("Namespace") == "AWS/SageMaker" and
                    alarm.get("MetricName") in ["Invocation4XXErrors", "Invocation5XXErrors", "InvocationErrors"]):
                for dim in alarm.get("Dimensions", []):
                    if dim.get("Name") == "EndpointName":
                        invocation_error_endpoints.add(dim.get("Value"))

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "Unknown")
            if ep_name not in invocation_error_endpoints:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": ep_name,
                    "resource_id_type": "SageMakerEndpoint",
                    "issue": f"Endpoint '{ep_name}' has no alarm for invocation errors",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-050",
            "check_name": "Missing alarms for invocation failures",
            "problem_statement": "AI endpoints should have alarms for invocation errors to detect service degradation",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create alarms for Invocation4XXErrors and Invocation5XXErrors on all endpoints",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create CloudWatch alarms for Invocation4XXErrors per endpoint",
                "2. Create CloudWatch alarms for Invocation5XXErrors per endpoint",
                "3. Set appropriate thresholds based on traffic volume",
                "4. Configure automated scaling or failover on alarm trigger",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking missing alarms for invocation failures: {e}")
        return None


def check_missing_alarms_endpoint_latency(session):
    """AI-051: Missing alarms for endpoint latency"""
    print("Checking missing alarms for endpoint latency")

    cloudwatch = session.client("cloudwatch")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get active endpoints
        endpoints = []
        try:
            endpoints = sagemaker.list_endpoints(StatusEquals="InService").get("Endpoints", [])
        except Exception:
            pass

        total_scanned = len(endpoints)

        # Get alarms for latency metrics
        alarms = []
        try:
            paginator = cloudwatch.get_paginator("describe_alarms")
            for page in paginator.paginate():
                alarms.extend(page.get("MetricAlarms", []))
        except Exception:
            pass

        latency_alarm_endpoints = set()
        for alarm in alarms:
            if (alarm.get("Namespace") == "AWS/SageMaker" and
                    alarm.get("MetricName") in ["ModelLatency", "OverheadLatency"]):
                for dim in alarm.get("Dimensions", []):
                    if dim.get("Name") == "EndpointName":
                        latency_alarm_endpoints.add(dim.get("Value"))

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "Unknown")
            if ep_name not in latency_alarm_endpoints:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": ep_name,
                    "resource_id_type": "SageMakerEndpoint",
                    "issue": f"Endpoint '{ep_name}' has no alarm for ModelLatency or OverheadLatency",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-051",
            "check_name": "Missing alarms for endpoint latency",
            "problem_statement": "AI endpoints should have latency alarms to detect performance degradation",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create CloudWatch alarms for ModelLatency and OverheadLatency metrics",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create CloudWatch alarm for ModelLatency per endpoint",
                "2. Create CloudWatch alarm for OverheadLatency per endpoint",
                "3. Set thresholds based on SLA requirements (e.g., p99 < 500ms)",
                "4. Configure auto-scaling policies triggered by latency alarms",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking missing alarms for endpoint latency: {e}")
        return None


def check_missing_alarms_model_errors(session):
    """AI-052: Missing alarms for model errors"""
    print("Checking missing alarms for model errors")

    cloudwatch = session.client("cloudwatch")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get active endpoints
        endpoints = []
        try:
            endpoints = sagemaker.list_endpoints(StatusEquals="InService").get("Endpoints", [])
        except Exception:
            pass

        total_scanned = len(endpoints)

        # Get alarms for model error metrics
        alarms = []
        try:
            paginator = cloudwatch.get_paginator("describe_alarms")
            for page in paginator.paginate():
                alarms.extend(page.get("MetricAlarms", []))
        except Exception:
            pass

        model_error_alarm_endpoints = set()
        for alarm in alarms:
            if (alarm.get("Namespace") == "AWS/SageMaker" and
                    alarm.get("MetricName") in ["ModelError", "ModelSetupError"]):
                for dim in alarm.get("Dimensions", []):
                    if dim.get("Name") == "EndpointName":
                        model_error_alarm_endpoints.add(dim.get("Value"))

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "Unknown")
            if ep_name not in model_error_alarm_endpoints:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": ep_name,
                    "resource_id_type": "SageMakerEndpoint",
                    "issue": f"Endpoint '{ep_name}' has no alarm for ModelError metrics",
                    "region": sagemaker.meta.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-052",
            "check_name": "Missing alarms for model errors",
            "problem_statement": "AI endpoints should have alarms for model errors to detect inference failures",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create CloudWatch alarms for ModelError metrics on all AI endpoints",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create CloudWatch alarm for ModelError metric per endpoint",
                "2. Set threshold to alert on any model error occurrence",
                "3. Configure SNS notifications for immediate response",
                "4. Implement automated model rollback on sustained errors",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking missing alarms for model errors: {e}")
        return None
