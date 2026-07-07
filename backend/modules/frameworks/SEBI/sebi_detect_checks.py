from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def update_scan_meta(scan_meta_data, service, total, affected, severity_level):
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += affected
    scan_meta_data[severity_level] = scan_meta_data.get(severity_level, 0) + affected
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)


# --- DE.CM: Continuous Monitoring / SOC ---

def sebi_guardduty_s3_protection(session, scan_meta_data):
    print("sebi_guardduty_s3_protection")
    non_compliant = []
    total = 0
    try:
        gd = session.client("guardduty")
        detector_ids = gd.list_detectors()["DetectorIds"]
        total = len(detector_ids)
        for did in detector_ids:
            det = gd.get_detector(DetectorId=did)
            s3_status = det.get("DataSources", {}).get("S3Logs", {}).get("Status", "DISABLED")
            if s3_status != "ENABLED":
                non_compliant.append({
                    "resource_id": did,
                    "resource_type": "GuardDuty Detector",
                    "issue": "S3 Protection not enabled",
                    "region": session.region_name
                })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "GuardDuty", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "GuardDuty", total, len(non_compliant), "High")
    return {
        "check_name": "GuardDuty S3 Protection",
        "service": "GuardDuty",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-2",
        "problem_statement": "GuardDuty S3 Protection is not enabled, limiting threat detection for S3 data events.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable S3 Protection in GuardDuty to detect threats targeting S3 buckets.",
        "additional_info": f"{len(non_compliant)} detector(s) without S3 protection out of {total} scanned."
    }


def sebi_guardduty_eks_protection(session, scan_meta_data):
    print("sebi_guardduty_eks_protection")
    non_compliant = []
    total = 0
    try:
        gd = session.client("guardduty")
        detector_ids = gd.list_detectors()["DetectorIds"]
        total = len(detector_ids)
        for did in detector_ids:
            det = gd.get_detector(DetectorId=did)
            eks_status = det.get("DataSources", {}).get("Kubernetes", {}).get("AuditLogs", {}).get("Status", "DISABLED")
            if eks_status != "ENABLED":
                non_compliant.append({
                    "resource_id": did,
                    "resource_type": "GuardDuty Detector",
                    "issue": "EKS Protection not enabled",
                    "region": session.region_name
                })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "GuardDuty", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "GuardDuty", total, len(non_compliant), "High")
    return {
        "check_name": "GuardDuty EKS Protection",
        "service": "GuardDuty",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-4",
        "problem_statement": "GuardDuty EKS Audit Log Monitoring is not enabled, reducing visibility into Kubernetes threats.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable EKS Protection in GuardDuty for Kubernetes audit log monitoring.",
        "additional_info": f"{len(non_compliant)} detector(s) without EKS protection out of {total} scanned."
    }


def sebi_guardduty_malware_protection(session, scan_meta_data):
    print("sebi_guardduty_malware_protection")
    non_compliant = []
    total = 0
    try:
        gd = session.client("guardduty")
        detector_ids = gd.list_detectors()["DetectorIds"]
        total = len(detector_ids)
        for did in detector_ids:
            det = gd.get_detector(DetectorId=did)
            malware_status = det.get("DataSources", {}).get("MalwareProtection", {}).get("ScanEc2InstanceWithFindings", {}).get("EbsVolumes", {}).get("Status", "DISABLED")
            if malware_status != "ENABLED":
                non_compliant.append({
                    "resource_id": did,
                    "resource_type": "GuardDuty Detector",
                    "issue": "Malware Protection not enabled",
                    "region": session.region_name
                })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "GuardDuty", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "GuardDuty", total, len(non_compliant), "High")
    return {
        "check_name": "GuardDuty Malware Protection",
        "service": "GuardDuty",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-5",
        "problem_statement": "GuardDuty Malware Protection is not enabled, leaving EC2 instances vulnerable to undetected malware.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable Malware Protection in GuardDuty for EBS volume scanning on EC2 instances.",
        "additional_info": f"{len(non_compliant)} detector(s) without malware protection out of {total} scanned."
    }


def sebi_guardduty_unresolved_findings(session, scan_meta_data):
    print("sebi_guardduty_unresolved_findings")
    non_compliant = []
    total = 0
    try:
        gd = session.client("guardduty")
        detector_ids = gd.list_detectors()["DetectorIds"]
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        for did in detector_ids:
            paginator = gd.get_paginator("list_findings")
            finding_criteria = {
                "Criterion": {
                    "severity": {"Gte": 7},
                    "service.archived": {"Eq": ["false"]}
                }
            }
            for page in paginator.paginate(DetectorId=did, FindingCriteria=finding_criteria):
                finding_ids = page.get("FindingIds", [])
                if not finding_ids:
                    continue
                total += len(finding_ids)
                findings = gd.get_findings(DetectorId=did, FindingIds=finding_ids)["Findings"]
                for f in findings:
                    created = f.get("CreatedAt", "")
                    if isinstance(created, str):
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    else:
                        created_dt = created
                    if created_dt < cutoff:
                        non_compliant.append({
                            "resource_id": f["Id"],
                            "resource_type": "GuardDuty Finding",
                            "issue": f"High/Critical finding open > 7 days (severity: {f.get('Severity', 'N/A')}, type: {f.get('Type', 'N/A')})",
                            "region": session.region_name
                        })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "GuardDuty", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "GuardDuty", total, len(non_compliant), "Critical")
    return {
        "check_name": "GuardDuty Unresolved High/Critical Findings",
        "service": "GuardDuty",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-6",
        "problem_statement": "High or critical GuardDuty findings remain unresolved for more than 7 days, indicating inadequate incident response.",
        "severity_score": 9.5,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Investigate and remediate all high/critical GuardDuty findings within 7 days as per SEBI CSCRF timelines.",
        "additional_info": f"{len(non_compliant)} unresolved high/critical findings older than 7 days out of {total} scanned."
    }


def sebi_securityhub_enabled(session, scan_meta_data):
    print("sebi_securityhub_enabled")
    non_compliant = []
    total = 1
    try:
        sh = session.client("securityhub")
        sh.describe_hub()
    except sh.exceptions.InvalidAccessException:
        non_compliant.append({
            "resource_id": session.region_name,
            "resource_type": "SecurityHub",
            "issue": "Security Hub is not enabled",
            "region": session.region_name
        })
    except Exception as e:
        if "not subscribed" in str(e).lower() or "InvalidAccessException" in str(e):
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "SecurityHub",
                "issue": "Security Hub is not enabled",
                "region": session.region_name
            })
        else:
            non_compliant.append({"resource_id": "N/A", "resource_type": "SecurityHub", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "SecurityHub", total, len(non_compliant), "High")
    return {
        "check_name": "Security Hub Enabled",
        "service": "SecurityHub",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-7",
        "problem_statement": "AWS Security Hub is not enabled, preventing centralized security findings aggregation.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable AWS Security Hub to aggregate and prioritize security findings across AWS services.",
        "additional_info": f"{'Security Hub not enabled' if non_compliant else 'Security Hub is enabled'} in region {session.region_name}."
    }


def sebi_securityhub_standards(session, scan_meta_data):
    print("sebi_securityhub_standards")
    non_compliant = []
    total = 1
    required_standards = ["cis-aws-foundations-benchmark", "pci-dss"]
    try:
        sh = session.client("securityhub")
        standards = sh.get_enabled_standards()["StandardsSubscriptions"]
        enabled_arns = [s["StandardsArn"].lower() for s in standards if s["StandardsStatus"] == "READY"]
        for std in required_standards:
            found = any(std in arn for arn in enabled_arns)
            if not found:
                non_compliant.append({
                    "resource_id": std,
                    "resource_type": "SecurityHub Standard",
                    "issue": f"Standard '{std}' is not enabled in Security Hub",
                    "region": session.region_name
                })
        total = len(required_standards)
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "SecurityHub", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "SecurityHub", total, len(non_compliant), "Medium")
    return {
        "check_name": "Security Hub Standards (CIS/PCI-DSS)",
        "service": "SecurityHub",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-8",
        "problem_statement": "Required security standards (CIS/PCI-DSS) are not enabled in Security Hub.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable CIS AWS Foundations Benchmark and PCI-DSS standards in Security Hub for compliance monitoring.",
        "additional_info": f"{len(non_compliant)} required standard(s) not enabled out of {total} checked."
    }


def sebi_config_enabled(session, scan_meta_data):
    print("sebi_config_enabled")
    non_compliant = []
    total = 1
    try:
        config = session.client("config")
        recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
        if not recorders:
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "AWS Config",
                "issue": "No configuration recorder found",
                "region": session.region_name
            })
        else:
            status = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
            for s in status:
                if not s.get("recording", False):
                    non_compliant.append({
                        "resource_id": s["name"],
                        "resource_type": "AWS Config Recorder",
                        "issue": "Configuration recorder is not recording",
                        "region": session.region_name
                    })
            total = len(status) if status else 1
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "AWS Config", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "Config", total, len(non_compliant), "High")
    return {
        "check_name": "AWS Config Enabled",
        "service": "Config",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-9",
        "problem_statement": "AWS Config is not enabled or not recording, preventing configuration change tracking.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable AWS Config with a configuration recorder to track all resource configuration changes.",
        "additional_info": f"{len(non_compliant)} issue(s) found with AWS Config configuration."
    }


def sebi_config_all_resources(session, scan_meta_data):
    print("sebi_config_all_resources")
    non_compliant = []
    total = 1
    try:
        config = session.client("config")
        recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
        total = len(recorders) if recorders else 1
        for rec in recorders:
            recording_group = rec.get("recordingGroup", {})
            if not recording_group.get("allSupported", False):
                non_compliant.append({
                    "resource_id": rec["name"],
                    "resource_type": "AWS Config Recorder",
                    "issue": "Not recording all supported resource types",
                    "region": session.region_name
                })
            if not recording_group.get("includeGlobalResourceTypes", False):
                non_compliant.append({
                    "resource_id": rec["name"],
                    "resource_type": "AWS Config Recorder",
                    "issue": "Not recording global resource types (IAM, etc.)",
                    "region": session.region_name
                })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "AWS Config", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "Config", total, len(non_compliant), "High")
    return {
        "check_name": "AWS Config Recording All Resources",
        "service": "Config",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-10",
        "problem_statement": "AWS Config is not recording all resource types, creating blind spots in configuration monitoring.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Configure AWS Config to record all supported resource types including global resources.",
        "additional_info": f"{len(non_compliant)} issue(s) with Config recording scope."
    }


def sebi_config_delivery_channel(session, scan_meta_data):
    print("sebi_config_delivery_channel")
    non_compliant = []
    total = 1
    try:
        config = session.client("config")
        channels = config.describe_delivery_channels()["DeliveryChannels"]
        total = len(channels) if channels else 1
        if not channels:
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "AWS Config Delivery Channel",
                "issue": "No delivery channel configured",
                "region": session.region_name
            })
        else:
            statuses = config.describe_delivery_channel_status()["DeliveryChannelsStatus"]
            for s in statuses:
                last_status = s.get("configHistoryDeliveryInfo", {}).get("lastStatus", "")
                stream_status = s.get("configStreamDeliveryInfo", {}).get("lastStatus", "")
                if last_status == "FAILURE" or stream_status == "FAILURE":
                    non_compliant.append({
                        "resource_id": s["name"],
                        "resource_type": "AWS Config Delivery Channel",
                        "issue": f"Delivery failure detected (history: {last_status}, stream: {stream_status})",
                        "region": session.region_name
                    })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "AWS Config", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "Config", total, len(non_compliant), "Medium")
    return {
        "check_name": "AWS Config Delivery Channel",
        "service": "Config",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-11",
        "problem_statement": "AWS Config delivery channel is not configured or has delivery failures.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Ensure AWS Config delivery channel is properly configured and delivering configuration snapshots to S3.",
        "additional_info": f"{len(non_compliant)} issue(s) with Config delivery channel."
    }


def sebi_cloudwatch_log_retention(session, scan_meta_data):
    print("sebi_cloudwatch_log_retention")
    non_compliant = []
    total = 0
    min_retention_days = 730
    try:
        logs = session.client("logs")
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page["logGroups"]:
                total += 1
                retention = lg.get("retentionInDays")
                if retention is None or retention < min_retention_days:
                    non_compliant.append({
                        "resource_id": lg["logGroupName"],
                        "resource_type": "CloudWatch Log Group",
                        "issue": f"Retention set to {retention if retention else 'Never Expire (no explicit retention)'} days, requires >= {min_retention_days} days",
                        "region": session.region_name
                    })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "CloudWatch", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "CloudWatch", total, len(non_compliant), "High")
    return {
        "check_name": "CloudWatch Log Group Retention",
        "service": "CloudWatch",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-12",
        "problem_statement": "CloudWatch Log Groups have retention less than 730 days (2 years), violating SEBI log retention requirements.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Set retention policy to at least 730 days (2 years) for all CloudWatch Log Groups as per SEBI CSCRF requirements.",
        "additional_info": f"{len(non_compliant)} log group(s) with insufficient retention out of {total} scanned."
    }


def sebi_eventbridge_security_rules(session, scan_meta_data):
    print("sebi_eventbridge_security_rules")
    non_compliant = []
    total = 1
    required_patterns = ["aws.guardduty", "aws.securityhub", "aws.config"]
    try:
        eb = session.client("events")
        paginator = eb.get_paginator("list_rules")
        found_patterns = set()
        for page in paginator.paginate():
            for rule in page["Rules"]:
                pattern = rule.get("EventPattern", "")
                for rp in required_patterns:
                    if rp in pattern:
                        found_patterns.add(rp)
        total = len(required_patterns)
        for rp in required_patterns:
            if rp not in found_patterns:
                non_compliant.append({
                    "resource_id": rp,
                    "resource_type": "EventBridge Rule",
                    "issue": f"No EventBridge rule found for source '{rp}'",
                    "region": session.region_name
                })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "EventBridge", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "EventBridge", total, len(non_compliant), "Medium")
    return {
        "check_name": "EventBridge Security Event Rules",
        "service": "EventBridge",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-13",
        "problem_statement": "EventBridge rules for security event sources (GuardDuty, SecurityHub, Config) are missing.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Create EventBridge rules to capture and route security events from GuardDuty, Security Hub, and Config.",
        "additional_info": f"{len(non_compliant)} missing security event rule(s) out of {total} required."
    }


def sebi_cloudwatch_alarms_critical(session, scan_meta_data):
    print("sebi_cloudwatch_alarms_critical")
    non_compliant = []
    total = 0
    try:
        cw = session.client("cloudwatch")
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate(StateValue="ALARM"):
            for alarm in page["MetricAlarms"]:
                total += 1
                actions = alarm.get("AlarmActions", [])
                if not actions:
                    non_compliant.append({
                        "resource_id": alarm["AlarmName"],
                        "resource_type": "CloudWatch Alarm",
                        "issue": "Alarm in ALARM state with no actions configured",
                        "region": session.region_name
                    })
        if total == 0:
            paginator2 = cw.get_paginator("describe_alarms")
            for page in paginator2.paginate():
                total += len(page.get("MetricAlarms", []))
            if total == 0:
                non_compliant.append({
                    "resource_id": session.region_name,
                    "resource_type": "CloudWatch Alarms",
                    "issue": "No CloudWatch alarms configured for critical metrics monitoring",
                    "region": session.region_name
                })
                total = 1
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "CloudWatch", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "CloudWatch", total, len(non_compliant), "Medium")
    return {
        "check_name": "CloudWatch Critical Alarms",
        "service": "CloudWatch",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-14",
        "problem_statement": "CloudWatch alarms for critical metrics are missing or have no notification actions configured.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Configure CloudWatch alarms with SNS notification actions for all critical infrastructure metrics.",
        "additional_info": f"{len(non_compliant)} alarm issue(s) found out of {total} scanned."
    }


def sebi_config_aggregator(session, scan_meta_data):
    print("sebi_config_aggregator")
    non_compliant = []
    total = 1
    try:
        config = session.client("config")
        aggregators = config.describe_configuration_aggregators()["ConfigurationAggregators"]
        if not aggregators:
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "AWS Config Aggregator",
                "issue": "No Config aggregator configured for multi-account/region visibility",
                "region": session.region_name
            })
        else:
            total = len(aggregators)
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "AWS Config", "issue": str(e), "region": session.region_name})
    update_scan_meta(scan_meta_data, "Config", total, len(non_compliant), "Medium")
    return {
        "check_name": "AWS Config Aggregator",
        "service": "Config",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.CM-15",
        "problem_statement": "No AWS Config aggregator is configured for centralized multi-account/region compliance visibility.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Set up an AWS Config aggregator to consolidate compliance data across all accounts and regions.",
        "additional_info": f"{'No aggregator found' if non_compliant else f'{total} aggregator(s) configured'}."
    }


# --- DE.AE: Audit & Event Logging ---

def sebi_cloudtrail_log_validation(session, scan_meta_data):
    print("sebi_cloudtrail_log_validation")
    non_compliant = []
    total = 0
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        total = len(trails) if trails else 1
        for trail in trails:
            if not trail.get("LogFileValidationEnabled", False):
                non_compliant.append({
                    "resource_id": trail["Name"],
                    "resource_type": "CloudTrail",
                    "issue": "Log file validation is not enabled",
                    "region": session.region_name
                })
        if not trails:
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "CloudTrail",
                "issue": "No CloudTrail trails found",
                "region": session.region_name
            })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "CloudTrail", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "CloudTrail", total, len(non_compliant), "Critical")
    return {
        "check_name": "CloudTrail Log File Validation",
        "service": "CloudTrail",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-3",
        "problem_statement": "CloudTrail log file validation is not enabled, making it impossible to verify log integrity.",
        "severity_score": 9.5,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable log file validation on all CloudTrail trails to ensure tamper-proof audit logs.",
        "additional_info": f"{len(non_compliant)} trail(s) without log validation out of {total} scanned."
    }


def sebi_cloudtrail_kms_encryption(session, scan_meta_data):
    print("sebi_cloudtrail_kms_encryption")
    non_compliant = []
    total = 0
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        total = len(trails) if trails else 1
        for trail in trails:
            if not trail.get("KmsKeyId"):
                non_compliant.append({
                    "resource_id": trail["Name"],
                    "resource_type": "CloudTrail",
                    "issue": "Trail is not encrypted with KMS (uses default S3 encryption)",
                    "region": session.region_name
                })
        if not trails:
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "CloudTrail",
                "issue": "No CloudTrail trails found",
                "region": session.region_name
            })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "CloudTrail", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "CloudTrail", total, len(non_compliant), "High")
    return {
        "check_name": "CloudTrail KMS Encryption",
        "service": "CloudTrail",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-4",
        "problem_statement": "CloudTrail logs are not encrypted with a customer-managed KMS key, reducing data protection.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable KMS encryption with a customer-managed key for all CloudTrail trails.",
        "additional_info": f"{len(non_compliant)} trail(s) without KMS encryption out of {total} scanned."
    }


def sebi_cloudtrail_data_events(session, scan_meta_data):
    print("sebi_cloudtrail_data_events")
    non_compliant = []
    total = 0
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]
        total = len(trails) if trails else 1
        for trail in trails:
            trail_arn = trail["TrailARN"]
            selectors = ct.get_event_selectors(TrailName=trail_arn)
            event_selectors = selectors.get("EventSelectors", [])
            advanced_selectors = selectors.get("AdvancedEventSelectors", [])
            has_s3_data = False
            has_lambda_data = False
            for es in event_selectors:
                for dr in es.get("DataResources", []):
                    if dr.get("Type") == "AWS::S3::Object":
                        has_s3_data = True
                    if dr.get("Type") == "AWS::Lambda::Function":
                        has_lambda_data = True
            for aes in advanced_selectors:
                for fs in aes.get("FieldSelectors", []):
                    if "S3" in str(fs.get("Equals", [])):
                        has_s3_data = True
                    if "Lambda" in str(fs.get("Equals", [])):
                        has_lambda_data = True
            if not has_s3_data:
                non_compliant.append({
                    "resource_id": trail["Name"],
                    "resource_type": "CloudTrail",
                    "issue": "S3 data events not enabled",
                    "region": session.region_name
                })
            if not has_lambda_data:
                non_compliant.append({
                    "resource_id": trail["Name"],
                    "resource_type": "CloudTrail",
                    "issue": "Lambda data events not enabled",
                    "region": session.region_name
                })
        if not trails:
            non_compliant.append({
                "resource_id": session.region_name,
                "resource_type": "CloudTrail",
                "issue": "No CloudTrail trails found",
                "region": session.region_name
            })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "CloudTrail", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "CloudTrail", total, len(non_compliant), "Medium")
    return {
        "check_name": "CloudTrail Data Events (S3/Lambda)",
        "service": "CloudTrail",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-5",
        "problem_statement": "CloudTrail is not capturing S3 and/or Lambda data events, limiting audit visibility into data access.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable S3 and Lambda data event logging in CloudTrail for complete audit trail of data access.",
        "additional_info": f"{len(non_compliant)} data event gap(s) found across {total} trail(s)."
    }


def sebi_rds_audit_logging(session, scan_meta_data):
    print("sebi_rds_audit_logging")
    non_compliant = []
    total = 0
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                total += 1
                db_id = db["DBInstanceIdentifier"]
                engine = db.get("Engine", "")
                enabled_logs = db.get("EnabledCloudwatchLogsExports", [])
                issues = []
                if "mysql" in engine or "mariadb" in engine:
                    if "audit" not in enabled_logs:
                        issues.append("audit log not enabled")
                    if "slowquery" not in enabled_logs:
                        issues.append("slow query log not enabled")
                elif "postgres" in engine:
                    if "postgresql" not in enabled_logs:
                        issues.append("postgresql log not enabled")
                elif "oracle" in engine:
                    if "audit" not in enabled_logs:
                        issues.append("audit log not enabled")
                elif "sqlserver" in engine:
                    if "audit" not in enabled_logs:
                        issues.append("audit log not enabled")
                if issues:
                    non_compliant.append({
                        "resource_id": db_id,
                        "resource_type": "RDS Instance",
                        "issue": f"Engine: {engine}, Missing: {', '.join(issues)}",
                        "region": session.region_name
                    })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "RDS", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "RDS", total, len(non_compliant), "High")
    return {
        "check_name": "RDS Audit Logging",
        "service": "RDS",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-6",
        "problem_statement": "RDS instances do not have audit and/or slow query logging enabled to CloudWatch.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable audit logging and slow query logging for all RDS instances and export to CloudWatch Logs.",
        "additional_info": f"{len(non_compliant)} RDS instance(s) with insufficient logging out of {total} scanned."
    }


def sebi_elb_access_logging(session, scan_meta_data):
    print("sebi_elb_access_logging")
    non_compliant = []
    total = 0
    try:
        elbv2 = session.client("elbv2")
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                total += 1
                lb_arn = lb["LoadBalancerArn"]
                attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
                access_logs_enabled = False
                for attr in attrs:
                    if attr["Key"] == "access_logs.s3.enabled" and attr["Value"] == "true":
                        access_logs_enabled = True
                        break
                if not access_logs_enabled:
                    non_compliant.append({
                        "resource_id": lb.get("LoadBalancerName", lb_arn),
                        "resource_type": "ELBv2 Load Balancer",
                        "issue": "Access logging is not enabled",
                        "region": session.region_name
                    })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "ELB", "issue": str(e), "region": session.region_name})
    # Also check classic ELBs
    try:
        elb = session.client("elb")
        classic_lbs = elb.describe_load_balancers()["LoadBalancerDescriptions"]
        for clb in classic_lbs:
            total += 1
            access_log = clb.get("AccessLog", {})
            if not access_log.get("Enabled", False):
                attrs = elb.describe_load_balancer_attributes(LoadBalancerName=clb["LoadBalancerName"])
                al = attrs.get("LoadBalancerAttributes", {}).get("AccessLog", {})
                if not al.get("Enabled", False):
                    non_compliant.append({
                        "resource_id": clb["LoadBalancerName"],
                        "resource_type": "Classic Load Balancer",
                        "issue": "Access logging is not enabled",
                        "region": session.region_name
                    })
    except Exception as e:
        pass  # Classic ELB may not exist
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "ELB", total, len(non_compliant), "Medium")
    return {
        "check_name": "ELB Access Logging",
        "service": "ELB",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-7",
        "problem_statement": "Elastic Load Balancers do not have access logging enabled, limiting request-level audit visibility.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable access logging on all load balancers and store logs in a dedicated S3 bucket.",
        "additional_info": f"{len(non_compliant)} load balancer(s) without access logging out of {total} scanned."
    }


def sebi_opensearch_audit_logging(session, scan_meta_data):
    print("sebi_opensearch_audit_logging")
    non_compliant = []
    total = 0
    try:
        os_client = session.client("opensearch")
        domains = os_client.list_domain_names()["DomainNames"]
        total = len(domains) if domains else 1
        for d in domains:
            domain_name = d["DomainName"]
            desc = os_client.describe_domain(DomainName=domain_name)["DomainStatus"]
            log_options = desc.get("LogPublishingOptions", {})
            audit_log = log_options.get("AUDIT_LOGS", {})
            if not audit_log.get("Enabled", False):
                non_compliant.append({
                    "resource_id": domain_name,
                    "resource_type": "OpenSearch Domain",
                    "issue": "Audit logging is not enabled",
                    "region": session.region_name
                })
    except Exception as e:
        non_compliant.append({"resource_id": "N/A", "resource_type": "OpenSearch", "issue": str(e), "region": session.region_name})
    if total == 0:
        total = 1
    update_scan_meta(scan_meta_data, "OpenSearch", total, len(non_compliant), "Medium")
    return {
        "check_name": "OpenSearch Audit Logging",
        "service": "OpenSearch",
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DE.AE-8",
        "problem_statement": "OpenSearch domains do not have audit logging enabled, preventing access and operation tracking.",
        "severity_score": 5.5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable audit logging for all OpenSearch domains and publish logs to CloudWatch.",
        "additional_info": f"{len(non_compliant)} OpenSearch domain(s) without audit logging out of {total} scanned."
    }
