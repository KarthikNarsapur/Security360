"""
ISO 27001 Checks — Logging & Monitoring
Controls: A.8.15, A.8.16, A.5.28, A.8.17
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_cloudtrail_enabled(session):
    """A.8.15: CloudTrail must be enabled and logging."""
    print("  ISO27001: Checking CloudTrail enabled")
    ct = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = ct.describe_trails().get("trailList", [])

        if len(trails) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudTrail",
                "resource_id_type": "Service",
                "issue": "No CloudTrail trails configured",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            active_trails = 0
            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging", False):
                        active_trails += 1
                except Exception:
                    continue
            if active_trails == 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "CloudTrail",
                    "resource_id_type": "Service",
                    "issue": "No CloudTrail trails are actively logging",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.15", "Logging - CloudTrail enabled",
                      resources_affected, max(len(trails), 1), 90, "Critical")
    except Exception as e:
        print(f"Error checking CloudTrail: {e}")
        return None


def check_cloudtrail_multiregion(session):
    """A.8.15: CloudTrail should be multi-region."""
    print("  ISO27001: Checking CloudTrail multi-region")
    ct = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        has_multiregion = False

        for trail in trails:
            if trail.get("IsMultiRegionTrail", False):
                has_multiregion = True
                break

        if not has_multiregion and total > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudTrail",
                "resource_id_type": "Service",
                "issue": "No multi-region CloudTrail trail configured",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.15", "Logging - Multi-region CloudTrail",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking multi-region CloudTrail: {e}")
        return None


def check_cloudtrail_log_validation(session):
    """A.8.15: CloudTrail log file integrity validation should be enabled."""
    print("  ISO27001: Checking CloudTrail log validation")
    ct = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)

        for trail in trails:
            if not trail.get("LogFileValidationEnabled", False):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": trail.get("Name", "Unknown"),
                    "resource_id_type": "CloudTrail Trail",
                    "issue": f"Trail '{trail.get('Name')}' does not have log file validation enabled",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.15", "Logging - CloudTrail log file validation",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking CloudTrail log validation: {e}")
        return None


def check_cloudtrail_data_events(session):
    """A.5.28: Data events enabled for evidence collection."""
    print("  ISO27001: Checking CloudTrail data events")
    ct = session.client("cloudtrail")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        trails = ct.describe_trails().get("trailList", [])
        has_data_events = False

        for trail in trails:
            try:
                selectors = ct.get_event_selectors(TrailName=trail["TrailARN"])
                event_selectors = selectors.get("EventSelectors", [])
                advanced = selectors.get("AdvancedEventSelectors", [])
                if advanced:
                    has_data_events = True
                    break
                for sel in event_selectors:
                    if sel.get("DataResources"):
                        has_data_events = True
                        break
            except Exception:
                continue

        if not has_data_events:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudTrail",
                "resource_id_type": "Service",
                "issue": "No CloudTrail data events configured (S3/Lambda)",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.28", "Collection of evidence - Data events",
                      resources_affected, max(len(trails), 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking data events: {e}")
        return None


def check_cloudwatch_log_groups(session):
    """A.8.15: CloudWatch log groups should exist for key services."""
    print("  ISO27001: Checking CloudWatch log groups")
    logs = session.client("logs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        log_groups = logs.describe_log_groups().get("logGroups", [])

        if len(log_groups) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudWatch Logs",
                "resource_id_type": "Service",
                "issue": "No CloudWatch log groups configured",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.15", "Logging - CloudWatch log groups",
                      resources_affected, max(len(log_groups), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking log groups: {e}")
        return None


def check_cloudwatch_log_retention(session):
    """A.8.15: Log groups should have retention policies (not indefinite)."""
    print("  ISO27001: Checking CloudWatch log retention")
    logs = session.client("logs")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        log_groups = logs.describe_log_groups().get("logGroups", [])
        total = len(log_groups)

        for lg in log_groups:
            if "retentionInDays" not in lg:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": lg["logGroupName"],
                    "resource_id_type": "CloudWatch LogGroup",
                    "issue": f"Log group '{lg['logGroupName']}' has no retention policy (indefinite)",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.15", "Logging - Log retention policies",
                      resources_affected, max(total, 1), 40, "Low")
    except Exception as e:
        print(f"Error checking log retention: {e}")
        return None


def check_security_alarms(session):
    """A.8.16: Security-related CloudWatch alarms should exist."""
    print("  ISO27001: Checking security alarms")
    cw = session.client("cloudwatch")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        alarms = cw.describe_alarms().get("MetricAlarms", [])

        security_keywords = ["unauthorized", "root", "security", "failed", "auth", "login", "iam"]
        security_alarms = [a for a in alarms if any(kw in a.get("AlarmName", "").lower() for kw in security_keywords)]

        if len(security_alarms) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "CloudWatch",
                "resource_id_type": "Service",
                "issue": "No security-related CloudWatch alarms detected (e.g., unauthorized API, root login)",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.16", "Monitoring activities - Security alarms",
                      resources_affected, max(len(alarms), 1), 70, "High")
    except Exception as e:
        print(f"Error checking security alarms: {e}")
        return None


def check_guardduty_enabled(session):
    """A.5.7/A.8.7: GuardDuty should be enabled for threat detection."""
    print("  ISO27001: Checking GuardDuty enabled")
    gd = session.client("guardduty")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        detectors = gd.list_detectors().get("DetectorIds", [])

        if len(detectors) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "GuardDuty",
                "resource_id_type": "Service",
                "issue": "GuardDuty is not enabled in this region",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            for det_id in detectors:
                try:
                    det = gd.get_detector(DetectorId=det_id)
                    if det.get("Status") != "ENABLED":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": det_id,
                            "resource_id_type": "GuardDuty Detector",
                            "issue": f"GuardDuty detector {det_id} is not in ENABLED status",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue

        return _result("A.5.7", "Threat intelligence - GuardDuty",
                      resources_affected, max(len(detectors), 1), 90, "Critical")
    except Exception as e:
        print(f"Error checking GuardDuty: {e}")
        return None


def check_guardduty_findings(session):
    """A.5.7: GuardDuty should be actively producing/processing findings."""
    print("  ISO27001: Checking GuardDuty findings status")
    gd = session.client("guardduty")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        detectors = gd.list_detectors().get("DetectorIds", [])

        for det_id in detectors:
            try:
                stats = gd.get_findings_statistics(
                    DetectorId=det_id,
                    FindingStatisticTypes=["COUNT_BY_SEVERITY"]
                )
                counts = stats.get("FindingStatistics", {}).get("CountBySeverity", {})
                high_count = counts.get("8.0", 0) + counts.get("7.0", 0) + counts.get("8", 0) + counts.get("7", 0)
                if high_count > 0:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": det_id,
                        "resource_id_type": "GuardDuty Detector",
                        "issue": f"GuardDuty has {high_count} high-severity active findings requiring attention",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.5.7", "Threat intelligence - GuardDuty findings",
                      resources_affected, max(len(detectors), 1), 80, "High")
    except Exception as e:
        print(f"Error checking GuardDuty findings: {e}")
        return None


def check_security_hub_enabled(session):
    """A.5.25: Security Hub should be enabled for centralized finding management."""
    print("  ISO27001: Checking Security Hub enabled")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        sh = session.client("securityhub")

        try:
            hub = sh.describe_hub()
            if not hub.get("HubArn"):
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": "SecurityHub",
                    "resource_id_type": "Service",
                    "issue": "Security Hub is not enabled",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "SecurityHub",
                "resource_id_type": "Service",
                "issue": "Security Hub is not enabled in this region",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.25", "Assessment of info security events - Security Hub",
                      resources_affected, 1, 80, "High")
    except Exception as e:
        print(f"Error checking Security Hub: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Logging & Monitoring",
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
