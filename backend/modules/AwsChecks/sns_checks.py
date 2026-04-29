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


import json


def check_sns_encryption(session, scan_meta_data):
    print("check_sns_encryption")
    sns = session.client("sns")
    resources = []
    topics = sns.list_topics().get("Topics", [])
    for topic in topics:
        arn = topic["TopicArn"]
        name = arn.split(":")[-1]
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            if not attrs.get("KmsMasterKeyId"):
                resources.append({"resource_name": name, "topic_arn": arn, "issue": "Topic not encrypted with KMS."})
        except Exception: pass

    scan_meta_data["total_scanned"] += len(topics)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "SNS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("SNS")
    return {"check_name": "SNS Topic Encryption", "service": "SNS", "problem_statement": "SNS topics are not encrypted with KMS.", "severity_score": 50, "severity_level": "Medium", "resources_affected": resources, "recommendation": "Enable KMS encryption on SNS topics.", "additional_info": {"total_scanned": len(topics), "affected": len(resources)}}


def check_sns_wildcard_policy(session, scan_meta_data):
    print("check_sns_wildcard_policy")
    sns = session.client("sns")
    resources = []
    topics = sns.list_topics().get("Topics", [])
    for topic in topics:
        arn = topic["TopicArn"]
        name = arn.split(":")[-1]
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            policy_str = attrs.get("Policy", "")
            if policy_str:
                policy = json.loads(policy_str)
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") != "Allow": continue
                    principal = stmt.get("Principal", {})
                    if principal == "*" or (isinstance(principal, dict) and "*" in str(principal.values())):
                        if not stmt.get("Condition"):
                            resources.append({"resource_name": name, "topic_arn": arn, "issue": "Topic policy allows Principal \"*\"."})
                            break
        except Exception: pass

    scan_meta_data["total_scanned"] += len(topics)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "SNS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("SNS")
    return {"check_name": "SNS Wildcard Principal Policy", "service": "SNS", "problem_statement": "SNS topics have policies granting access to Principal \"*\".", "severity_score": 75, "severity_level": "High", "resources_affected": resources, "recommendation": "Restrict SNS policies to specific principals.", "additional_info": {"total_scanned": len(topics), "affected": len(resources)}}
