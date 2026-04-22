def check_guardduty_enabled(session, scan_meta_data):
    print("check_guardduty_enabled and its findings")
    gd = session.client("guardduty")

    detectors = gd.list_detectors().get("DetectorIds", [])
    findings_list = []

    if not detectors:
        # GuardDuty NOT enabled
        return {
            "check_name": "GuardDuty Enabled Check",
            "service": "GuardDuty",
            "problem_statement": "Amazon GuardDuty is not enabled in this region.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": [],
            "recommendation": "Enable Amazon GuardDuty to detect suspicious activities.",
            "additional_info": {
                "total_scanned": 1,
                "affected": 0,
            },
        }

    # If GuardDuty is enabled
    detector_id = detectors[0]

    findings = gd.list_findings(DetectorId=detector_id).get("FindingIds", [])

    if findings:
        # Fetch actual finding details
        finding_details = gd.get_findings(DetectorId=detector_id, FindingIds=findings)[
            "Findings"
        ]
        print("findings: ", finding_details)

        for f in finding_details:
            findings_list.append(
                {
                    "resource_name": f.get("Title"),
                    "finding_id": f.get("Id"),
                    "severity": f.get("Severity"),
                    "type": f.get("Type"),
                    "description": f.get("Description"),
                }
            )

    return {
        "check_name": "GuardDuty Enabled & Findings Check",
        "service": "GuardDuty",
        "problem_statement": "GuardDuty findings detected in the account.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": findings_list,
        "recommendation": (
            "Review GuardDuty findings and remediate any malicious or suspicious activities."
        ),
        "additional_info": {
            "total_scanned": 1,
            "affected": 0,
        },
    }
