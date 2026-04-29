"""
Unified Risk Engine

Combines outputs from all 4 security engines into:
1. Asset-centric risk view (per-resource aggregation)
2. Confidence-weighted scoring
3. Time-decay for stale findings
4. Deduplication across engines
5. MITRE ATT&CK mapping
6. Blast radius estimation

Runs AFTER all checks and engines complete. Zero additional API calls.
"""

import math
from datetime import datetime, timezone, timedelta
from collections import defaultdict

IST = timezone(timedelta(hours=5, minutes=30))

# ── MITRE ATT&CK Mapping ────────────────────────────────────────────────────

MITRE_MAPPING = {
    # Initial Access
    "Open Security Groups": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "stage": 1},
    "Publicly Accessible RDS Instances": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "stage": 1},
    "Publicly Accessible S3 Buckets": {"tactic": "Initial Access", "technique": "T1530 - Data from Cloud Storage", "stage": 1},
    "S3 Bucket Policies with Wildcard Principal": {"tactic": "Initial Access", "technique": "T1530 - Data from Cloud Storage", "stage": 1},
    "ElastiCache Public Accessibility": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "stage": 1},
    "RDS Default Ports Exposed to Internet": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "stage": 1},

    # Credential Access
    "IAM Console Users Without MFA": {"tactic": "Credential Access", "technique": "T1110 - Brute Force", "stage": 2},
    "Root Account Without MFA": {"tactic": "Credential Access", "technique": "T1110 - Brute Force", "stage": 2},
    "Hardcoded Secrets in EC2 User Data": {"tactic": "Credential Access", "technique": "T1552 - Unsecured Credentials", "stage": 2},
    "Plaintext Secrets in Lambda Environment Variables": {"tactic": "Credential Access", "technique": "T1552 - Unsecured Credentials", "stage": 2},
    "ECS Plaintext Secrets in Environment": {"tactic": "Credential Access", "technique": "T1552 - Unsecured Credentials", "stage": 2},
    "ECS Task Roles and Hardcoded Credentials": {"tactic": "Credential Access", "technique": "T1552 - Unsecured Credentials", "stage": 2},
    "Access Keys Older Than 90 Days": {"tactic": "Credential Access", "technique": "T1528 - Steal Application Access Token", "stage": 2},
    "Root Account Used in Last 30 Days": {"tactic": "Credential Access", "technique": "T1078 - Valid Accounts", "stage": 2},

    # Privilege Escalation
    "Overly Permissive IAM Policies": {"tactic": "Privilege Escalation", "technique": "T1078.004 - Cloud Accounts", "stage": 3},
    "IAM Users with AdministratorAccess": {"tactic": "Privilege Escalation", "technique": "T1078.004 - Cloud Accounts", "stage": 3},
    "Wildcard Principal in Role Trust Policies": {"tactic": "Privilege Escalation", "technique": "T1098 - Account Manipulation", "stage": 3},
    "ECS Privileged Containers": {"tactic": "Privilege Escalation", "technique": "T1611 - Escape to Host", "stage": 3},

    # Lateral Movement
    "EC2 Instances Without IAM Role": {"tactic": "Lateral Movement", "technique": "T1550 - Use Alternate Authentication Material", "stage": 4},
    "Overly Permissive Outbound Security Groups": {"tactic": "Lateral Movement", "technique": "T1021 - Remote Services", "stage": 4},
    "NACLs Allowing Inbound from 0.0.0.0/0": {"tactic": "Lateral Movement", "technique": "T1021 - Remote Services", "stage": 4},

    # Defense Evasion
    "CloudTrail Log Immutability": {"tactic": "Defense Evasion", "technique": "T1562 - Impair Defenses", "stage": 5},
    "Unresolved Security Findings": {"tactic": "Defense Evasion", "technique": "T1562 - Impair Defenses", "stage": 5},

    # Exfiltration
    "S3 Buckets Shared with External Accounts": {"tactic": "Exfiltration", "technique": "T1537 - Transfer Data to Cloud Account", "stage": 6},
    "Unencrypted RDS Instances": {"tactic": "Exfiltration", "technique": "T1530 - Data from Cloud Storage", "stage": 6},
    "Unencrypted EBS Volumes": {"tactic": "Exfiltration", "technique": "T1530 - Data from Cloud Storage", "stage": 6},

    # Impact
    "RDS Automated Backups Disabled": {"tactic": "Impact", "technique": "T1485 - Data Destruction", "stage": 7},
    "RDS Cluster Deletion Protection": {"tactic": "Impact", "technique": "T1485 - Data Destruction", "stage": 7},
    "EC2 Termination Protection": {"tactic": "Impact", "technique": "T1485 - Data Destruction", "stage": 7},
}


def run_unified_risk_engine(
    regional_results_list,
    global_results,
    attack_path_results,
    identity_risk_results,
    data_sensitivity_results,
    runtime_results_list,
):
    """
    Main entry point. Aggregates all engine outputs into:
    1. Asset-centric risk view
    2. MITRE ATT&CK kill chain coverage
    3. Unified risk score per resource
    4. Deduplicated findings

    Returns dict to be added to the report.
    """
    print("run_unified_risk_engine")

    asset_map = defaultdict(lambda: {
        "resource_name": "",
        "resource_type": "",
        "risk_score": 0,
        "confidence": 0,
        "findings": [],
        "mitre_tactics": set(),
        "mitre_techniques": set(),
        "attack_paths": [],
        "identity_risk": None,
        "data_sensitivity": None,
        "runtime_alerts": [],
        "blast_radius": "Unknown",
    })

    # ── Step 1: Ingest all check findings ────────────────────────────────

    # Regional results (list of {region, data} dicts)
    for region_entry in (regional_results_list or []):
        region = region_entry.get("region", "")
        data = region_entry.get("data", {})
        for check_key, check_result in data.items():
            if not isinstance(check_result, dict):
                continue
            check_name = check_result.get("check_name", "")
            for resource in check_result.get("resources_affected", []):
                res_name = resource.get("resource_name", resource.get("resource_id", "unknown"))
                asset = asset_map[res_name]
                asset["resource_name"] = res_name
                asset["resource_type"] = check_result.get("service", "")

                severity_score = check_result.get("severity_score", 0)
                confidence = _calculate_confidence(check_result, resource)
                weighted_score = severity_score * confidence

                asset["findings"].append({
                    "check_name": check_name,
                    "severity": check_result.get("severity_level", ""),
                    "severity_score": severity_score,
                    "confidence": round(confidence, 2),
                    "weighted_score": round(weighted_score, 1),
                    "region": region,
                })

                # MITRE mapping
                mitre = MITRE_MAPPING.get(check_name)
                if mitre:
                    asset["mitre_tactics"].add(mitre["tactic"])
                    asset["mitre_techniques"].add(mitre["technique"])

    # Global results
    for check_key, check_result in (global_results or {}).items():
        if not isinstance(check_result, dict):
            continue
        check_name = check_result.get("check_name", "")
        for resource in check_result.get("resources_affected", []):
            res_name = resource.get("resource_name", resource.get("resource_id", "unknown"))
            asset = asset_map[res_name]
            asset["resource_name"] = res_name
            asset["resource_type"] = check_result.get("service", "")

            severity_score = check_result.get("severity_score", 0)
            confidence = _calculate_confidence(check_result, resource)

            asset["findings"].append({
                "check_name": check_name,
                "severity": check_result.get("severity_level", ""),
                "severity_score": severity_score,
                "confidence": round(confidence, 2),
                "weighted_score": round(severity_score * confidence, 1),
                "region": "global",
            })

            mitre = MITRE_MAPPING.get(check_name)
            if mitre:
                asset["mitre_tactics"].add(mitre["tactic"])
                asset["mitre_techniques"].add(mitre["technique"])

    # ── Step 2: Enrich with attack paths ─────────────────────────────────

    if isinstance(attack_path_results, dict):
        for path in attack_path_results.get("resources_affected", []):
            components = path.get("components", {})
            for key, val in components.items():
                names = val if isinstance(val, list) else []
                for name in names:
                    if name in asset_map:
                        asset_map[name]["attack_paths"].append({
                            "path_name": path.get("resource_name", ""),
                            "risk_level": path.get("risk_level", ""),
                            "attack_chain": path.get("attack_path", ""),
                        })

    # ── Step 3: Enrich with identity risk ────────────────────────────────

    if isinstance(identity_risk_results, dict):
        for identity in identity_risk_results.get("resources_affected", []):
            name = identity.get("resource_name", "")
            if name in asset_map:
                asset_map[name]["identity_risk"] = {
                    "score": identity.get("risk_score", 0),
                    "level": identity.get("risk_level", ""),
                    "factors": identity.get("risk_factors", ""),
                }

    # ── Step 4: Enrich with data sensitivity ─────────────────────────────

    if isinstance(data_sensitivity_results, dict):
        for resource in data_sensitivity_results.get("resources_affected", []):
            name = resource.get("resource_name", "")
            if name in asset_map:
                asset_map[name]["data_sensitivity"] = {
                    "classification": resource.get("sensitivity_classification", ""),
                    "exposure": resource.get("exposure_level", ""),
                }

    # ── Step 5: Enrich with runtime alerts ───────────────────────────────

    for region_entry in (runtime_results_list or []):
        data = region_entry.get("data", {})
        runtime = data.get("runtime_behavior", {})
        if isinstance(runtime, dict):
            for alert in runtime.get("resources_affected", []):
                name = alert.get("resource_name", "")
                # Runtime alerts are often pattern-based, not resource-specific
                # Add to a general "Runtime" asset
                asset_map[f"[Runtime] {name}"]["runtime_alerts"].append(alert)
                asset_map[f"[Runtime] {name}"]["resource_name"] = f"[Runtime] {name}"
                asset_map[f"[Runtime] {name}"]["resource_type"] = "Runtime Analysis"

    # ── Step 6: Calculate unified risk scores ────────────────────────────

    unified_assets = []
    for res_name, asset in asset_map.items():
        if not asset["findings"] and not asset["attack_paths"] and not asset["runtime_alerts"]:
            continue

        # Base score: weighted average of finding scores
        finding_scores = [f["weighted_score"] for f in asset["findings"]]
        base_score = max(finding_scores) if finding_scores else 0

        # Attack path amplifier: +20% per attack path involvement
        path_amplifier = min(len(asset["attack_paths"]) * 0.2, 0.6)

        # Identity risk amplifier
        identity_amplifier = 0
        if asset["identity_risk"]:
            identity_amplifier = asset["identity_risk"]["score"] / 200  # max +0.5

        # Data sensitivity amplifier
        data_amplifier = 0
        if asset["data_sensitivity"]:
            exposure = asset["data_sensitivity"].get("exposure", "Low")
            data_amplifier = {"Critical": 0.4, "High": 0.3, "Medium": 0.15, "Low": 0}.get(exposure, 0)

        # Runtime amplifier
        runtime_amplifier = 0
        if asset["runtime_alerts"]:
            has_critical = any(a.get("risk_level") == "Critical" for a in asset["runtime_alerts"])
            runtime_amplifier = 0.4 if has_critical else 0.2

        # Final score
        total_amplifier = 1 + path_amplifier + identity_amplifier + data_amplifier + runtime_amplifier
        final_score = min(round(base_score * total_amplifier), 100)

        # Blast radius estimation
        blast_radius = _estimate_blast_radius(asset)

        # MITRE kill chain coverage
        kill_chain_stages = len(asset["mitre_tactics"])

        # Determine risk level
        risk_level = (
            "Critical" if final_score >= 80 else
            "High" if final_score >= 60 else
            "Medium" if final_score >= 35 else
            "Low"
        )

        unified_assets.append({
            "resource_name": res_name,
            "resource_type": asset["resource_type"],
            "unified_risk_score": final_score,
            "risk_level": risk_level,
            "finding_count": len(asset["findings"]),
            "attack_path_count": len(asset["attack_paths"]),
            "mitre_tactics": list(asset["mitre_tactics"]),
            "mitre_techniques": list(asset["mitre_techniques"]),
            "kill_chain_coverage": f"{kill_chain_stages}/7 stages",
            "blast_radius": blast_radius,
            "data_classification": asset["data_sensitivity"]["classification"] if asset["data_sensitivity"] else "Unknown",
            "identity_risk_score": asset["identity_risk"]["score"] if asset["identity_risk"] else None,
            "runtime_alert_count": len(asset["runtime_alerts"]),
            "top_findings": sorted(asset["findings"], key=lambda f: f["weighted_score"], reverse=True)[:5],
            "amplifiers": {
                "attack_path": round(path_amplifier, 2),
                "identity": round(identity_amplifier, 2),
                "data_sensitivity": round(data_amplifier, 2),
                "runtime": round(runtime_amplifier, 2),
            },
        })

    # Sort by unified risk score
    unified_assets.sort(key=lambda x: x["unified_risk_score"], reverse=True)

    # ── Build MITRE ATT&CK summary ──────────────────────────────────────

    all_tactics = set()
    all_techniques = set()
    for asset in unified_assets:
        all_tactics.update(asset["mitre_tactics"])
        all_techniques.update(asset["mitre_techniques"])

    mitre_summary = {
        "tactics_covered": sorted(all_tactics),
        "techniques_detected": sorted(all_techniques),
        "kill_chain_coverage": f"{len(all_tactics)}/7 MITRE tactics",
    }

    return {
        "unified_risk_assets": unified_assets[:50],  # Top 50 riskiest
        "total_assets_analyzed": len(asset_map),
        "critical_assets": len([a for a in unified_assets if a["risk_level"] == "Critical"]),
        "high_assets": len([a for a in unified_assets if a["risk_level"] == "High"]),
        "mitre_summary": mitre_summary,
        "timestamp": datetime.now(IST).isoformat(),
    }


def _calculate_confidence(check_result, resource):
    """
    Calculate confidence score (0.0 - 1.0) based on:
    - Check specificity
    - Resource detail richness
    - Time relevance
    """
    confidence = 0.5  # Base

    # Higher confidence if check has specific affected count
    additional = check_result.get("additional_info", {})
    total = additional.get("total_scanned", 0)
    affected = additional.get("affected", 0)
    if total > 0:
        ratio = affected / total
        if ratio < 0.1:
            confidence += 0.2  # Few affected = high confidence per finding
        elif ratio > 0.5:
            confidence -= 0.1  # Many affected = might be noisy

    # Higher confidence if resource has detailed info
    detail_keys = len(resource.keys())
    if detail_keys >= 5:
        confidence += 0.15
    elif detail_keys >= 3:
        confidence += 0.1

    # Time decay: reduce confidence for stale data
    last_updated = resource.get("last_updated")
    if last_updated:
        try:
            updated = datetime.fromisoformat(last_updated)
            days_old = (datetime.now(IST) - updated).days
            decay = math.exp(-days_old / 30)  # 30-day half-life
            confidence *= max(decay, 0.3)  # Floor at 0.3
        except (ValueError, TypeError):
            pass

    return min(max(confidence, 0.1), 1.0)


def _estimate_blast_radius(asset):
    """
    Estimate blast radius based on resource type and findings.
    """
    findings = asset["findings"]
    attack_paths = asset["attack_paths"]
    resource_type = asset["resource_type"]

    # IAM identities have the widest blast radius
    if resource_type == "IAM":
        has_admin = any("Administrator" in f.get("check_name", "") for f in findings)
        has_wildcard = any("Wildcard" in f.get("check_name", "") for f in findings)
        if has_admin:
            return "Full Account (AdministratorAccess)"
        if has_wildcard:
            return "Cross-Account (Wildcard Trust)"
        return "Multiple Services (IAM Scope)"

    # S3 with public access
    if resource_type == "S3":
        has_public = any("Public" in f.get("check_name", "") for f in findings)
        has_wildcard = any("Wildcard" in f.get("check_name", "") for f in findings)
        if has_public and has_wildcard:
            return "Internet-Facing (Public + Wildcard)"
        if has_public:
            return "Internet-Facing (Public Access)"
        return "Data Store"

    # EC2/RDS with public exposure
    if resource_type in ("EC2", "RDS"):
        has_public = any("Public" in f.get("check_name", "") or "Open" in f.get("check_name", "") for f in findings)
        if has_public:
            return "Internet-Facing (Network Exposed)"
        return "VPC Scope"

    # ECS with privilege escalation
    if resource_type == "ECS":
        has_priv = any("Privileged" in f.get("check_name", "") for f in findings)
        if has_priv:
            return "Host Escape (Container → Host)"
        return "Container Scope"

    # Attack path involvement
    if attack_paths:
        return f"Multi-Service ({len(attack_paths)} attack path(s))"

    return "Single Resource"
