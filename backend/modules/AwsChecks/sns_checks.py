def check_sns_alert_integration(session, scan_meta_data):
    print("check_sns_alert_integration")
    resources = []
    total_alarms = 0

    try:
        cloudwatch = session.client("cloudwatch")
        alarms = cloudwatch.describe_alarms(StateValue="OK").get("MetricAlarms", [])
        alarms += cloudwatch.describe_alarms(StateValue="ALARM").get("MetricAlarms", [])
        alarms += cloudwatch.describe_alarms(StateValue="INSUFFICIENT_DATA").get("MetricAlarms", [])
        total_alarms = len(alarms)

        for alarm in alarms:
            actions = (
                alarm.get("AlarmActions", [])
                + alarm.get("OKActions", [])
                + alarm.get("InsufficientDataActions", [])
            )
            has_sns = any("arn:aws:sns:" in a for a in actions)
            if not has_sns:
                resources.append({
                    "resource_name": alarm.get("AlarmName"),
                    "namespace": alarm.get("Namespace", "N/A"),
                    "metric_name": alarm.get("MetricName", "N/A"),
                    "issue": "Alarm has no SNS topic action for notifications.",
                })

    except Exception as e:
        print(f"Error checking SNS alert integration: {e}")

    scan_meta_data["total_scanned"] += total_alarms
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "SNS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("SNS")

    return {
        "check_name": "SNS Alert Integration",
        "service": "SNS",
        "problem_statement": "CloudWatch alarms are not integrated with SNS topics for notifications.",
        "severity_score": 35,
        "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Configure SNS topic actions on all CloudWatch alarms to receive email/Slack/PagerDuty notifications.",
        "additional_info": {"total_scanned": total_alarms, "affected": len(resources)},
    }
