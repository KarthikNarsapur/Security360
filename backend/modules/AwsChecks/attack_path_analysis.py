"""
Cross-Service Correlation & Attack Path Analysis Engine

Analyzes scan results post-collection to identify toxic combinations
of findings that together create high-risk attack paths.
No additional AWS API calls needed — works entirely on already-collected data.
"""


def analyze_attack_paths(session, regional_results, global_results, scan_meta_data):
    """
    Main entry point. Runs after all individual checks complete.
    Correlates findings across services to identify attack paths.

    Args:
        session: boto3 session (for account context only)
        regional_results: dict of regional check results from run_checks()
        global_results: dict of global check results from run_global_services_checks()
        scan_meta_data: scan metadata dict

    Returns:
        dict with check_name, resources_affected (attack paths found)
    """
    print("analyze_attack_paths")

    attack_paths = []

    # Collect all findings into a normalized structure for correlation
    context = _build_context(regional_results, global_results)

    # Run each correlation rule
    attack_paths.extend(_check_public_ec2_with_admin_role(context))
    attack_paths.extend(_check_public_rds_with_weak_sg(context))
    attack_paths.extend(_check_public_s3_with_sensitive_data_indicators(context))
    attack_paths.extend(_check_ec2_no_role_with_userdata_secrets(context))
    attack_paths.extend(_check_lambda_secrets_no_vpc(context))
    attack_paths.extend(_check_ecs_privileged_with_hardcoded_creds(context))
    attack_paths.extend(_check_public_ec2_no_mfa_users(context))
    attack_paths.extend(_check_unmonitored_public_resources(context))
    attack_paths.extend(_check_lateral_movement_risk(context))
    attack_paths.extend(_check_data_exfiltration_path(context))

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(attack_paths)
    if attack_paths:
        scan_meta_data["Critical"] += len([p for p in attack_paths if p.get("risk_level") == "Critical"])
        scan_meta_data["High"] += len([p for p in attack_paths if p.get("risk_level") == "High"])
    if "Attack Path Analysis" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Attack Path Analysis")

    severity = "Critical" if any(p["risk_level"] == "Critical" for p in attack_paths) else \
               "High" if attack_paths else "Low"
    score = 95 if severity == "Critical" else 85 if severity == "High" else 10

    return {
        "check_name": "Cross-Service Attack Path Analysis",
        "service": "Attack Path Analysis",
        "problem_statement": "Multiple findings across services combine to create exploitable attack paths.",
        "severity_score": score,
        "severity_level": severity,
        "resources_affected": attack_paths,
        "recommendation": "Address the highest-risk attack paths first — fixing any single link in the chain breaks the path.",
        "additional_info": {
            "total_scanned": 1,
            "affected": len(attack_paths),
            "critical_paths": len([p for p in attack_paths if p.get("risk_level") == "Critical"]),
            "high_paths": len([p for p in attack_paths if p.get("risk_level") == "High"]),
        },
    }


def _build_context(regional_results, global_results):
    """Build a normalized context from all check results for correlation."""
    ctx = {
        "public_ec2_instances": [],
        "ec2_without_iam_role": [],
        "ec2_with_userdata_secrets": [],
        "open_security_groups": [],
        "public_rds_instances": [],
        "rds_weak_security_groups": [],
        "public_s3_buckets": [],
        "s3_wildcard_policies": [],
        "users_without_mfa": [],
        "admin_users": [],
        "overly_permissive_policies": [],
        "wildcard_trust_roles": [],
        "lambda_secrets": [],
        "lambda_no_vpc": [],
        "ecs_privileged": [],
        "ecs_hardcoded_creds": [],
        "guardduty_disabled": False,
        "cloudtrail_issues": [],
        "no_waf": False,
        "unresolved_findings": [],
        "permissive_outbound_sg": [],
    }

    # Extract from regional results
    r = regional_results or {}

    if r.get("open_security_groups", {}).get("resources_affected"):
        ctx["open_security_groups"] = r["open_security_groups"]["resources_affected"]

    if r.get("ec2_without_iam_role", {}).get("resources_affected"):
        ctx["ec2_without_iam_role"] = r["ec2_without_iam_role"]["resources_affected"]

    if r.get("ec2_userdata_secrets", {}).get("resources_affected"):
        ctx["ec2_with_userdata_secrets"] = r["ec2_userdata_secrets"]["resources_affected"]

    if r.get("rds_public", {}).get("resources_affected"):
        ctx["public_rds_instances"] = r["rds_public"]["resources_affected"]

    if r.get("rds_security_groups_restricted", {}).get("resources_affected"):
        ctx["rds_weak_security_groups"] = r["rds_security_groups_restricted"]["resources_affected"]

    if r.get("lambda_env_secrets", {}).get("resources_affected"):
        ctx["lambda_secrets"] = r["lambda_env_secrets"]["resources_affected"]

    if r.get("lambda_vpc_enabled", {}).get("resources_affected"):
        ctx["lambda_no_vpc"] = r["lambda_vpc_enabled"]["resources_affected"]

    if r.get("ecs_privileged_containers", {}).get("resources_affected"):
        ctx["ecs_privileged"] = r["ecs_privileged_containers"]["resources_affected"]

    if r.get("ecs_task_role_credentials", {}).get("resources_affected"):
        ctx["ecs_hardcoded_creds"] = r["ecs_task_role_credentials"]["resources_affected"]

    if r.get("overly_permissive_outbound_sg", {}).get("resources_affected"):
        ctx["permissive_outbound_sg"] = r["overly_permissive_outbound_sg"]["resources_affected"]

    gd = r.get("guardduty_findings", {})
    if gd and not gd.get("resources_affected") and "not enabled" in gd.get("problem_statement", "").lower():
        ctx["guardduty_disabled"] = True

    # Extract from global results
    g = global_results or {}

    if g.get("public_s3_buckets", {}).get("resources_affected"):
        ctx["public_s3_buckets"] = g["public_s3_buckets"]["resources_affected"]

    if g.get("wildcard_principal_bucket_policies", {}).get("resources_affected"):
        ctx["s3_wildcard_policies"] = g["wildcard_principal_bucket_policies"]["resources_affected"]

    if g.get("users_without_mfa", {}).get("resources_affected"):
        ctx["users_without_mfa"] = g["users_without_mfa"]["resources_affected"]

    if g.get("users_with_administrator_access", {}).get("resources_affected"):
        ctx["admin_users"] = g["users_with_administrator_access"]["resources_affected"]

    if g.get("overly_permissive_policies", {}).get("resources_affected"):
        ctx["overly_permissive_policies"] = g["overly_permissive_policies"]["resources_affected"]

    if g.get("wildcard_principal_in_trust_policies", {}).get("resources_affected"):
        ctx["wildcard_trust_roles"] = g["wildcard_principal_in_trust_policies"]["resources_affected"]

    if g.get("cloudtrail_and_logging", {}).get("resources_affected"):
        ct_findings = g["cloudtrail_and_logging"]["resources_affected"]
        ctx["cloudtrail_issues"] = [f for f in ct_findings if f.get("status") == "Not Enabled"]

    return ctx


# ── Correlation Rules ──────────────────────────────────────────────────────


def _check_public_ec2_with_admin_role(ctx):
    """Public EC2 + open SG + admin IAM users = full account compromise risk."""
    paths = []
    if ctx["open_security_groups"] and ctx["admin_users"]:
        # Confidence: high if admin users have no MFA, lower if they do
        admin_no_mfa = [u for u in ctx["admin_users"] if u.get("resource_name") in 
                        {m.get("resource_id") for m in ctx["users_without_mfa"]}]
        confidence = 0.9 if admin_no_mfa else 0.6

        paths.append({
            "resource_name": "Public EC2 + Admin Users",
            "risk_level": "Critical",
            "confidence": confidence,
            "mitre_tactics": ["Initial Access", "Privilege Escalation"],
            "mitre_technique": "T1190 → T1078.004",
            "attack_path": "Open Security Group → EC2 Instance → Admin IAM User → Full Account Access",
            "components": {
                "open_security_groups": len(ctx["open_security_groups"]),
                "admin_users": [u.get("resource_name") for u in ctx["admin_users"][:5]],
            },
            "impact": "An attacker exploiting an EC2 instance behind an open security group could leverage admin credentials for full account takeover.",
            "remediation": "1) Restrict security groups 2) Remove AdministratorAccess from users 3) Use least-privilege roles",
        })
    return paths


def _check_public_rds_with_weak_sg(ctx):
    """Public RDS + permissive SG = database breach."""
    paths = []
    if ctx["public_rds_instances"] and ctx["rds_weak_security_groups"]:
        affected_dbs = [r.get("resource_name") for r in ctx["public_rds_instances"][:5]]
        paths.append({
            "resource_name": "Public RDS + Open Security Groups",
            "risk_level": "Critical",
            "confidence": 0.85,
            "mitre_tactics": ["Initial Access", "Exfiltration"],
            "mitre_technique": "T1190 → T1530",
            "attack_path": "Internet → Open Security Group → Publicly Accessible RDS → Data Breach",
            "components": {
                "public_rds": affected_dbs,
                "weak_security_groups": len(ctx["rds_weak_security_groups"]),
            },
            "impact": "Databases are directly reachable from the internet with no network restriction, enabling brute-force or exploit-based data theft.",
            "remediation": "1) Disable public accessibility 2) Restrict SGs to app subnets only 3) Enable IAM authentication",
        })
    return paths


def _check_public_s3_with_sensitive_data_indicators(ctx):
    """Public S3 + wildcard policy = data exposure."""
    paths = []
    if ctx["public_s3_buckets"] and ctx["s3_wildcard_policies"]:
        paths.append({
            "resource_name": "Public S3 + Wildcard Policies",
            "risk_level": "Critical",
            "confidence": 0.95,
            "mitre_tactics": ["Initial Access", "Exfiltration"],
            "mitre_technique": "T1530",
            "attack_path": "Internet → S3 Wildcard Policy → Public Bucket → Data Exfiltration",
            "components": {
                "public_buckets": [b.get("resource_name") for b in ctx["public_s3_buckets"][:5]],
                "wildcard_policies": [b.get("resource_name") for b in ctx["s3_wildcard_policies"][:5]],
            },
            "impact": "S3 buckets are publicly accessible AND have wildcard principal policies, allowing anyone to read/write data.",
            "remediation": "1) Enable Block Public Access 2) Remove Principal:* from policies 3) Enable access logging",
        })
    elif ctx["public_s3_buckets"]:
        paths.append({
            "resource_name": "Public S3 Buckets",
            "risk_level": "High",
            "confidence": 0.7,
            "mitre_tactics": ["Initial Access"],
            "mitre_technique": "T1530",
            "attack_path": "Internet → Public S3 Bucket → Data Exposure",
            "components": {
                "public_buckets": [b.get("resource_name") for b in ctx["public_s3_buckets"][:5]],
            },
            "impact": "S3 buckets lack public access blocks, potentially exposing data to the internet.",
            "remediation": "1) Enable Block Public Access at account and bucket level 2) Audit bucket policies",
        })
    return paths


def _check_ec2_no_role_with_userdata_secrets(ctx):
    """EC2 without IAM role + secrets in userdata = credential theft."""
    paths = []
    if ctx["ec2_without_iam_role"] and ctx["ec2_with_userdata_secrets"]:
        # Find instances that appear in both lists
        no_role_ids = {r.get("resource_name") for r in ctx["ec2_without_iam_role"]}
        secrets_ids = {r.get("resource_name") for r in ctx["ec2_with_userdata_secrets"]}
        overlap = no_role_ids & secrets_ids

        if overlap:
            paths.append({
                "resource_name": "EC2 No IAM Role + UserData Secrets",
                "risk_level": "Critical",
                "confidence": 0.9,
                "mitre_tactics": ["Credential Access", "Lateral Movement"],
                "mitre_technique": "T1552 → T1550",
                "attack_path": "EC2 Instance → No IAM Role → Hardcoded Secrets in UserData → Credential Theft",
                "components": {
                    "instances_with_both_issues": list(overlap)[:5],
                },
                "impact": "Instances without IAM roles rely on hardcoded credentials in UserData, which are retrievable via IMDS.",
                "remediation": "1) Attach IAM instance profiles 2) Remove secrets from UserData 3) Use Secrets Manager",
            })
        elif ctx["ec2_with_userdata_secrets"]:
            paths.append({
                "resource_name": "EC2 UserData Secrets Exposure",
                "risk_level": "High",
                "confidence": 0.75,
                "mitre_tactics": ["Credential Access"],
                "mitre_technique": "T1552",
                "attack_path": "EC2 Instance → Hardcoded Secrets in UserData → Credential Theft",
                "components": {
                    "instances_with_secrets": len(ctx["ec2_with_userdata_secrets"]),
                },
                "impact": "EC2 instances have hardcoded secrets in UserData, retrievable by anyone with instance access.",
                "remediation": "1) Remove secrets from UserData 2) Use IAM roles + Secrets Manager",
            })
    return paths


def _check_lambda_secrets_no_vpc(ctx):
    """Lambda with plaintext secrets + no VPC = exposed secrets over internet."""
    paths = []
    if ctx["lambda_secrets"] and ctx["lambda_no_vpc"]:
        secrets_fns = {r.get("resource_name") for r in ctx["lambda_secrets"]}
        no_vpc_fns = {r.get("resource_name") for r in ctx["lambda_no_vpc"]}
        overlap = secrets_fns & no_vpc_fns

        if overlap:
            paths.append({
                "resource_name": "Lambda Secrets + No VPC",
                "risk_level": "High",
                "confidence": 0.7,
                "mitre_tactics": ["Credential Access"],
                "mitre_technique": "T1552",
                "attack_path": "Lambda (No VPC) → Plaintext Secrets → External Network Exposure",
                "components": {
                    "functions_with_both": list(overlap)[:5],
                },
                "impact": "Lambda functions with plaintext secrets and no VPC isolation can leak credentials over the public internet.",
                "remediation": "1) Move secrets to Secrets Manager 2) Attach Lambda to VPC for sensitive workloads",
            })
    return paths


def _check_ecs_privileged_with_hardcoded_creds(ctx):
    """ECS privileged containers + hardcoded creds = container escape + credential theft."""
    paths = []
    if ctx["ecs_privileged"] and ctx["ecs_hardcoded_creds"]:
        paths.append({
            "resource_name": "ECS Privileged + Hardcoded Credentials",
            "risk_level": "Critical",
            "confidence": 0.85,
            "mitre_tactics": ["Privilege Escalation", "Credential Access"],
            "mitre_technique": "T1611 → T1552",
            "attack_path": "Privileged Container → Host Escape → Hardcoded AWS Credentials → Account Compromise",
            "components": {
                "privileged_containers": len(ctx["ecs_privileged"]),
                "hardcoded_creds": len(ctx["ecs_hardcoded_creds"]),
            },
            "impact": "Privileged containers can escape to the host, and hardcoded credentials enable lateral movement to AWS services.",
            "remediation": "1) Remove privileged flag 2) Use taskRoleArn 3) Remove hardcoded credentials",
        })
    return paths


def _check_public_ec2_no_mfa_users(ctx):
    """Open SGs + users without MFA = easy initial access."""
    paths = []
    if ctx["open_security_groups"] and ctx["users_without_mfa"]:
        paths.append({
            "resource_name": "Open SGs + No MFA Users",
            "risk_level": "High",
            "confidence": 0.65,
            "mitre_tactics": ["Credential Access", "Initial Access"],
            "mitre_technique": "T1110 → T1190",
            "attack_path": "Compromised Password (No MFA) → Console/API Access → Open Security Groups → Lateral Movement",
            "components": {
                "users_without_mfa": [u.get("resource_id") for u in ctx["users_without_mfa"][:5]],
                "open_security_groups": len(ctx["open_security_groups"]),
            },
            "impact": "Users without MFA are vulnerable to credential theft. Combined with open security groups, an attacker gains network access.",
            "remediation": "1) Enforce MFA for all console users 2) Restrict security group inbound rules",
        })
    return paths


def _check_unmonitored_public_resources(ctx):
    """Public resources + GuardDuty disabled + CloudTrail gaps = blind spot."""
    paths = []
    has_public = ctx["open_security_groups"] or ctx["public_rds_instances"] or ctx["public_s3_buckets"]
    has_monitoring_gap = ctx["guardduty_disabled"] or ctx["cloudtrail_issues"]

    if has_public and has_monitoring_gap:
        paths.append({
            "resource_name": "Public Resources + Monitoring Gaps",
            "risk_level": "High",
            "confidence": 0.8,
            "mitre_tactics": ["Defense Evasion"],
            "mitre_technique": "T1562",
            "attack_path": "Internet → Public Resources → No GuardDuty/CloudTrail → Undetected Breach",
            "components": {
                "guardduty_disabled": ctx["guardduty_disabled"],
                "cloudtrail_issues": len(ctx["cloudtrail_issues"]),
                "public_resources": {
                    "open_sgs": len(ctx["open_security_groups"]),
                    "public_rds": len(ctx["public_rds_instances"]),
                    "public_s3": len(ctx["public_s3_buckets"]),
                },
            },
            "impact": "Public-facing resources exist but threat detection and logging are incomplete, allowing attacks to go undetected.",
            "remediation": "1) Enable GuardDuty 2) Fix CloudTrail configuration 3) Restrict public access",
        })
    return paths


def _check_lateral_movement_risk(ctx):
    """Wildcard trust policies + permissive outbound = lateral movement."""
    paths = []
    if ctx["wildcard_trust_roles"] and ctx["permissive_outbound_sg"]:
        paths.append({
            "resource_name": "Wildcard Trust + Permissive Outbound",
            "risk_level": "High",
            "confidence": 0.7,
            "mitre_tactics": ["Lateral Movement", "Exfiltration"],
            "mitre_technique": "T1550 → T1537",
            "attack_path": "Compromised Resource → Assume Wildcard Role → Unrestricted Outbound → Data Exfiltration",
            "components": {
                "wildcard_trust_roles": [r.get("resource_name") for r in ctx["wildcard_trust_roles"][:5]],
                "permissive_outbound_sgs": len(ctx["permissive_outbound_sg"]),
            },
            "impact": "Roles with wildcard trust policies can be assumed by any principal. Combined with unrestricted outbound, stolen data can be exfiltrated.",
            "remediation": "1) Add conditions to trust policies 2) Restrict outbound SG rules 3) Use VPC endpoints",
        })
    return paths


def _check_data_exfiltration_path(ctx):
    """Overly permissive policies + permissive outbound + public S3 = data exfil."""
    paths = []
    if ctx["overly_permissive_policies"] and ctx["permissive_outbound_sg"] and ctx["public_s3_buckets"]:
        paths.append({
            "resource_name": "Data Exfiltration Path",
            "risk_level": "Critical",
            "confidence": 0.85,
            "mitre_tactics": ["Privilege Escalation", "Exfiltration"],
            "mitre_technique": "T1078 → T1530 → T1537",
            "attack_path": "Overly Permissive IAM → S3 Full Access → Public Bucket → Unrestricted Outbound → Data Exfiltration",
            "components": {
                "permissive_policies": len(ctx["overly_permissive_policies"]),
                "public_s3_buckets": [b.get("resource_name") for b in ctx["public_s3_buckets"][:5]],
                "permissive_outbound": len(ctx["permissive_outbound_sg"]),
            },
            "impact": "Full chain: overly permissive IAM policies grant S3 access, public buckets allow external reads, and unrestricted outbound enables exfiltration.",
            "remediation": "1) Apply least-privilege IAM 2) Block public S3 access 3) Restrict outbound traffic 4) Enable S3 access logging",
        })
    return paths
