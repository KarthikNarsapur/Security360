"""
Runtime Behavior Analysis Engine

Analyzes CloudTrail events and GuardDuty findings for anomalous patterns.
All APIs: cloudtrail:LookupEvents, guardduty:List*, guardduty:Get*,
          cloudwatch:GetMetricStatistics — all in ReadOnlyAccess.
"""

from datetime import datetime, timezone, timedelta
from collections import Counter

IST = timezone(timedelta(hours=5, minutes=30))


def analyze_runtime_behavior(session, scan_meta_data):
    """
    Analyze recent CloudTrail events and GuardDuty findings for
    suspicious runtime behavior patterns.
    """
    print("analyze_runtime_behavior")
    resources_affected = []

    resources_affected.extend(_analyze_cloudtrail_anomalies(session))
    resources_affected.extend(_analyze_guardduty_patterns(session))
    resources_affected.extend(_analyze_api_error_spikes(session))

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(resources_affected)
    critical = len([r for r in resources_affected if r.get("risk_level") == "Critical"])
    high = len([r for r in resources_affected if r.get("risk_level") == "High"])
    scan_meta_data["Critical"] += critical
    scan_meta_data["High"] += high
    scan_meta_data["Medium"] += len(resources_affected) - critical - high
    if "Runtime Analysis" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Runtime Analysis")

    severity = "Critical" if critical else "High" if high else "Medium" if resources_affected else "Low"
    score = 95 if critical else 80 if high else 50 if resources_affected else 10

    return {
        "check_name": "Runtime Behavior Analysis",
        "service": "Runtime Analysis",
        "problem_statement": "Suspicious runtime behavior patterns detected from CloudTrail events and GuardDuty findings.",
        "severity_score": score,
        "severity_level": severity,
        "resources_affected": resources_affected,
        "recommendation": "Investigate flagged activities immediately. Check for compromised credentials, unauthorized access, and data exfiltration.",
        "additional_info": {
            "total_scanned": 1,
            "affected": len(resources_affected),
            "critical_findings": critical,
            "high_findings": high,
        },
    }


def _analyze_cloudtrail_anomalies(session):
    """Analyze recent CloudTrail events for suspicious patterns."""
    findings = []

    try:
        ct = session.client("cloudtrail")
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)

        # ── Pattern 1: Root account usage ────────────────────────────────
        try:
            root_events = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "root"}],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            ).get("Events", [])

            if root_events:
                event_names = Counter(e.get("EventName", "") for e in root_events)
                findings.append({
                    "resource_name": "Root Account Activity",
                    "risk_level": "Critical",
                    "pattern": "Root Account Usage",
                    "event_count": len(root_events),
                    "top_actions": dict(event_names.most_common(5)),
                    "time_range": f"{start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}",
                    "issue": f"Root account performed {len(root_events)} API call(s) in the last 7 days.",
                })
        except Exception as e:
            print(f"Error checking root CloudTrail events: {e}")

        # ── Pattern 2: Console logins from unusual sources ───────────────
        try:
            login_events = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            ).get("Events", [])

            failed_logins = []
            for event in login_events:
                try:
                    import json
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    if detail.get("responseElements", {}).get("ConsoleLogin") == "Failure":
                        failed_logins.append({
                            "user": detail.get("userIdentity", {}).get("userName", "Unknown"),
                            "source_ip": detail.get("sourceIPAddress", "Unknown"),
                            "time": event.get("EventTime", "").isoformat() if hasattr(event.get("EventTime", ""), "isoformat") else str(event.get("EventTime", "")),
                        })
                except Exception:
                    continue

            if len(failed_logins) >= 3:
                findings.append({
                    "resource_name": "Console Login Failures",
                    "risk_level": "High",
                    "pattern": "Brute Force Attempt",
                    "event_count": len(failed_logins),
                    "sample_events": failed_logins[:5],
                    "time_range": f"{start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}",
                    "issue": f"{len(failed_logins)} failed console login(s) detected — possible brute force.",
                })
        except Exception as e:
            print(f"Error checking login events: {e}")

        # ── Pattern 3: Suspicious IAM changes ────────────────────────────
        suspicious_iam_events = [
            "CreateUser", "CreateAccessKey", "AttachUserPolicy",
            "AttachRolePolicy", "PutUserPolicy", "CreateLoginProfile",
            "UpdateAssumeRolePolicy", "CreateRole",
        ]

        iam_changes = []
        for event_name in suspicious_iam_events:
            try:
                events = ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=10,
                ).get("Events", [])
                for e in events:
                    iam_changes.append({
                        "event": event_name,
                        "user": e.get("Username", "Unknown"),
                        "time": e.get("EventTime", "").isoformat() if hasattr(e.get("EventTime", ""), "isoformat") else str(e.get("EventTime", "")),
                    })
            except Exception:
                continue

        if len(iam_changes) >= 5:
            findings.append({
                "resource_name": "IAM Configuration Changes",
                "risk_level": "High",
                "pattern": "Rapid IAM Changes",
                "event_count": len(iam_changes),
                "sample_events": iam_changes[:10],
                "time_range": f"{start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}",
                "issue": f"{len(iam_changes)} IAM modification event(s) in 7 days — review for unauthorized changes.",
            })

        # ── Pattern 4: Data exfiltration indicators ──────────────────────
        exfil_events = ["GetObject", "CopyObject", "PutBucketPolicy"]
        exfil_count = 0
        for event_name in exfil_events:
            try:
                events = ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                    StartTime=end_time - timedelta(days=1),
                    EndTime=end_time,
                    MaxResults=50,
                ).get("Events", [])
                exfil_count += len(events)
            except Exception:
                continue

        if exfil_count > 100:
            findings.append({
                "resource_name": "S3 Data Access Spike",
                "risk_level": "High",
                "pattern": "Potential Data Exfiltration",
                "event_count": exfil_count,
                "time_range": "Last 24 hours",
                "issue": f"{exfil_count} S3 data access events in 24 hours — unusually high volume.",
            })

    except Exception as e:
        print(f"Error in CloudTrail anomaly analysis: {e}")

    return findings


def _analyze_guardduty_patterns(session):
    """Analyze GuardDuty findings for active threat patterns."""
    findings = []

    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])

        if not detectors:
            return findings

        detector_id = detectors[0]

        # Get recent HIGH/CRITICAL findings
        finding_ids = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "severity": {"Gte": 7},
                    "service.archived": {"Eq": ["false"]},
                }
            },
            MaxResults=50,
        ).get("FindingIds", [])

        if not finding_ids:
            return findings

        details = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids[:20],
        ).get("Findings", [])

        # Group by finding type
        type_groups = {}
        for f in details:
            ftype = f.get("Type", "Unknown")
            type_groups.setdefault(ftype, []).append(f)

        # Detect patterns
        for ftype, group in type_groups.items():
            risk_level = "Critical" if any(f.get("Severity", 0) >= 8 for f in group) else "High"

            # Crypto mining detection
            if "CryptoCurrency" in ftype:
                findings.append({
                    "resource_name": "Crypto Mining Detection",
                    "risk_level": "Critical",
                    "pattern": "Cryptocurrency Mining",
                    "event_count": len(group),
                    "finding_type": ftype,
                    "issue": f"GuardDuty detected {len(group)} crypto mining indicator(s). Instances may be compromised.",
                })
            # Unauthorized access
            elif "UnauthorizedAccess" in ftype:
                findings.append({
                    "resource_name": "Unauthorized Access",
                    "risk_level": risk_level,
                    "pattern": "Unauthorized Access",
                    "event_count": len(group),
                    "finding_type": ftype,
                    "issue": f"{len(group)} unauthorized access finding(s) detected.",
                })
            # Recon activity
            elif "Recon" in ftype or "Discovery" in ftype:
                findings.append({
                    "resource_name": "Reconnaissance Activity",
                    "risk_level": "High",
                    "pattern": "Reconnaissance",
                    "event_count": len(group),
                    "finding_type": ftype,
                    "issue": f"{len(group)} reconnaissance/discovery finding(s) — possible attack preparation.",
                })
            # Exfiltration
            elif "Exfiltration" in ftype or "Trojan" in ftype:
                findings.append({
                    "resource_name": "Data Exfiltration / Trojan",
                    "risk_level": "Critical",
                    "pattern": "Data Exfiltration",
                    "event_count": len(group),
                    "finding_type": ftype,
                    "issue": f"{len(group)} exfiltration/trojan finding(s) — active data theft suspected.",
                })
            else:
                if len(group) >= 3:
                    findings.append({
                        "resource_name": f"GuardDuty: {ftype}",
                        "risk_level": risk_level,
                        "pattern": ftype.split("/")[0] if "/" in ftype else ftype,
                        "event_count": len(group),
                        "finding_type": ftype,
                        "issue": f"{len(group)} finding(s) of type {ftype}.",
                    })

    except Exception as e:
        print(f"Error in GuardDuty pattern analysis: {e}")

    return findings


def _analyze_api_error_spikes(session):
    """Check CloudWatch for unusual API error rates."""
    findings = []

    try:
        cw = session.client("cloudwatch")
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=24)

        # Check for AccessDenied errors spike via CloudTrail metrics
        try:
            ct = session.client("cloudtrail")
            denied_events = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": ""}],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            ).get("Events", [])

            # Count AccessDenied errors
            import json
            denied_count = 0
            denied_users = Counter()
            for event in denied_events:
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    error_code = detail.get("errorCode", "")
                    if "AccessDenied" in error_code or "UnauthorizedAccess" in error_code:
                        denied_count += 1
                        user = detail.get("userIdentity", {}).get("userName", detail.get("userIdentity", {}).get("arn", "Unknown"))
                        denied_users[user] += 1
                except Exception:
                    continue

            if denied_count >= 10:
                findings.append({
                    "resource_name": "API Access Denied Spike",
                    "risk_level": "High",
                    "pattern": "Permission Enumeration",
                    "event_count": denied_count,
                    "top_users": dict(denied_users.most_common(5)),
                    "time_range": "Last 24 hours",
                    "issue": f"{denied_count} AccessDenied errors in 24 hours — possible permission enumeration or compromised credentials.",
                })

        except Exception:
            pass

    except Exception as e:
        print(f"Error in API error analysis: {e}")

    return findings
