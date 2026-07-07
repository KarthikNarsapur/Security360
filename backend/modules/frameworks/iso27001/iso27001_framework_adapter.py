"""
Adapter to plug ISO 27001 checks into the unified framework_scan.py registry.
Runs all 72 active checks and returns normalized findings.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def run_iso27001_checks_sync(session, scan_meta_data, progress_callback=None):
    """
    Synchronous wrapper for ISO 27001 checks compatible with framework_scan.py.
    Runs all 72 active checks across 9 domains.
    progress_callback: optional fn(percent) to update scan progress.
    """
    from modules.frameworks.iso27001.iso27001_run_checks import get_iso27001_checks

    checks = get_iso27001_checks()
    results = []
    total_checks = len(checks)
    completed = 0

    def _update_percent():
        nonlocal completed
        completed += 1
        if progress_callback:
            percent = 2 + int((completed / total_checks) * 93)
            progress_callback(percent)

    for check_id, check_function in checks.items():
        try:
            print(f"  ISO 27001 check: {check_id}")
            check_result = check_function(session)

            if check_result is None:
                _update_percent()
                continue

            if isinstance(check_result, dict):
                finding = _normalize_finding(check_id, check_result, scan_meta_data)
                results.append(finding)
            elif isinstance(check_result, list):
                for item in check_result:
                    finding = _normalize_finding(check_id, item, scan_meta_data)
                    results.append(finding)
        except Exception as e:
            print(f"  ISO 27001 check {check_id} error: {e}")
        _update_percent()

    return results


def _normalize_finding(check_id, raw, scan_meta_data):
    """Convert a raw ISO 27001 check result dict into the standard finding format."""
    severity = raw.get("severity_level", raw.get("severity", "Medium"))

    additional_info = raw.get("additional_info", {})
    affected = additional_info.get("affected", raw.get("affected", 0))
    total_scanned = additional_info.get("total_scanned", raw.get("total_scanned", 0))

    if total_scanned == 0 and affected == 0:
        result = "NOT_APPLICABLE"
    elif affected > 0:
        result = "FAIL"
    else:
        result = "PASS"

    # Update scan_meta_data counters
    scan_meta_data["total_scanned"] += total_scanned
    scan_meta_data["affected"] += affected
    if severity in scan_meta_data:
        scan_meta_data[severity] += (1 if affected > 0 else 0)

    service = raw.get("service", "Information Security")
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)

    return {
        "control_id": check_id,
        "check_name": raw.get("check_name", raw.get("title", check_id)),
        "service": service,
        "severity_level": severity,
        "severity_score": raw.get("severity_score", _severity_to_score(severity)),
        "affected": affected,
        "total_scanned": total_scanned,
        "result": result,
        "region": raw.get("region", "global"),
        "problem_statement": raw.get("problem_statement", raw.get("description", "")),
        "description": raw.get("description", raw.get("problem_statement", "")),
        "remediation": raw.get("remediation", raw.get("recommendation", "")),
        "frameworks": ["iso27001"],
        "additional_info": additional_info,
    }


def _severity_to_score(severity):
    return {"Critical": 10, "High": 8, "Medium": 5, "Low": 2}.get(severity, 3)
