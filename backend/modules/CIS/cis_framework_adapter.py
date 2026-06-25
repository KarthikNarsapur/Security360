"""
Adapter to plug CIS checks into the unified framework_scan.py registry.
Converts the existing async CIS check dict into the standard (session, scan_meta_data) -> list format.
"""
from modules.CIS.cis_run_checks import cis_checks


def run_cis_checks_sync(session, scan_meta_data):
    """
    Synchronous wrapper for CIS checks compatible with framework_scan.py.
    Runs all CIS checks and returns results as a list of dicts.
    """
    results = []

    for check_id, check_function in cis_checks.items():
        try:
            print(f"  CIS check: {check_id}")
            check_result = check_function(session)

            # Normalize result into the standard finding format
            if isinstance(check_result, dict):
                finding = _normalize_cis_finding(check_id, check_result, scan_meta_data)
                results.append(finding)
            elif isinstance(check_result, list):
                for item in check_result:
                    finding = _normalize_cis_finding(check_id, item, scan_meta_data)
                    results.append(finding)
        except Exception as e:
            print(f"  CIS check {check_id} error: {e}")

    return results


def _normalize_cis_finding(check_id, raw, scan_meta_data):
    """Convert a raw CIS check result dict into the standard finding format."""
    severity = raw.get("severity_level", raw.get("severity", "Medium"))
    affected = raw.get("affected", 0)
    total_scanned = raw.get("total_scanned", 0)

    # Update scan_meta_data counters
    scan_meta_data["total_scanned"] += total_scanned
    scan_meta_data["affected"] += affected
    if severity in scan_meta_data:
        scan_meta_data[severity] += (1 if affected > 0 else 0)

    service = raw.get("service", check_id.split(".")[0])
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)

    return {
        "control_id": f"CIS-{check_id}",
        "check_name": raw.get("check_name", raw.get("title", check_id)),
        "service": service,
        "severity_level": severity,
        "severity_score": raw.get("severity_score", _severity_to_score(severity)),
        "affected": affected,
        "total_scanned": total_scanned,
        "region": raw.get("region", "global"),
        "description": raw.get("description", raw.get("problem_statement", "")),
        "remediation": raw.get("remediation", raw.get("recommendation", "")),
        "frameworks": ["cis"],
        "additional_info": raw.get("additional_info", {}),
    }


def _severity_to_score(severity):
    return {"Critical": 10, "High": 8, "Medium": 5, "Low": 2}.get(severity, 3)
