"""
Adapter to plug ISO 42001 checks into the unified framework_scan.py registry.
Converts the existing async ISO check dict into the standard (session, scan_meta_data) -> list format.
"""
from modules.ISO.iso_run_checks import iso_checks


def run_iso42001_checks_sync(session, scan_meta_data):
    """
    Synchronous wrapper for ISO 42001 checks compatible with framework_scan.py.
    Runs all ISO checks and returns results as a list of dicts.
    """
    results = []

    for check_id, check_function in iso_checks.items():
        try:
            print(f"  ISO 42001 check: {check_id}")
            check_result = check_function(session)

            # Normalize result into the standard finding format
            if isinstance(check_result, dict):
                finding = _normalize_iso_finding(check_id, check_result, scan_meta_data)
                results.append(finding)
            elif isinstance(check_result, list):
                for item in check_result:
                    finding = _normalize_iso_finding(check_id, item, scan_meta_data)
                    results.append(finding)
        except Exception as e:
            print(f"  ISO 42001 check {check_id} error: {e}")

    return results


def _normalize_iso_finding(check_id, raw, scan_meta_data):
    """Convert a raw ISO check result dict into the standard finding format."""
    severity = raw.get("severity_level", raw.get("severity", "Medium"))
    
    # Read from additional_info first (where check functions actually put them), fallback to top-level
    additional_info = raw.get("additional_info", {})
    affected = additional_info.get("affected", raw.get("affected", 0))
    total_scanned = additional_info.get("total_scanned", raw.get("total_scanned", 0))

    # Determine result: if no resources were scanned at all, mark as Not Applicable
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

    service = raw.get("service", "AI Management")
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
        "frameworks": ["iso42001"],
        "additional_info": additional_info,
    }


def _severity_to_score(severity):
    return {"Critical": 10, "High": 8, "Medium": 5, "Low": 2}.get(severity, 3)
