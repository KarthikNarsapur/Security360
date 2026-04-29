"""
Identity Risk Scoring Engine

Analyzes IAM users, roles, and policies to compute a risk score per identity.
Detects privilege escalation paths using read-only API calls.
All APIs used: iam:List*, iam:Get*, iam:SimulatePrincipalPolicy (all in ReadOnlyAccess).
"""

import json
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

# Actions that enable privilege escalation
PRIV_ESC_ACTIONS = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
]


def analyze_identity_risks(session, scan_meta_data_global_services):
    """
    Compute risk scores for IAM users and roles.
    Uses iam:SimulatePrincipalPolicy to check effective permissions.
    """
    print("analyze_identity_risks")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        current_account = sts.get_caller_identity()["Account"]
    except Exception:
        current_account = ""

    # ── Score IAM Users ──────────────────────────────────────────────────
    users = iam.list_users().get("Users", [])

    for user in users:
        user_name = user["UserName"]
        risk_score = 0
        risk_factors = []

        try:
            # Factor 1: Console access without MFA
            try:
                iam.get_login_profile(UserName=user_name)
                has_console = True
            except iam.exceptions.NoSuchEntityException:
                has_console = False

            if has_console:
                mfa_devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                if not mfa_devices:
                    risk_score += 25
                    risk_factors.append("Console access without MFA")

            # Factor 2: Direct policy attachments (should use groups)
            attached = iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
            inline = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])

            if attached or inline:
                risk_score += 10
                risk_factors.append(f"{len(attached)} attached + {len(inline)} inline policies directly on user")

            # Factor 3: AdministratorAccess
            for p in attached:
                if p.get("PolicyName") == "AdministratorAccess":
                    risk_score += 30
                    risk_factors.append("Has AdministratorAccess policy")
                    break

            # Factor 4: Old access keys
            access_keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            for key in access_keys:
                if key["Status"] == "Active" and key["CreateDate"] < threshold:
                    age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                    risk_score += 15
                    risk_factors.append(f"Active access key {key['AccessKeyId']} is {age_days} days old")
                    break

            # Factor 5: Inactivity (stale identity)
            password_last_used = user.get("PasswordLastUsed")
            if password_last_used:
                inactive_threshold = datetime.now(timezone.utc) - timedelta(days=90)
                if password_last_used < inactive_threshold:
                    risk_score += 10
                    risk_factors.append("No console activity in 90+ days")

            # Factor 6: Privilege escalation potential via SimulatePrincipalPolicy
            priv_esc_found = _check_priv_esc_actions(iam, user["Arn"])
            if priv_esc_found:
                risk_score += 20
                risk_factors.append(f"Can perform privilege escalation: {', '.join(priv_esc_found[:3])}")

            # Only report users with meaningful risk
            if risk_score >= 20:
                risk_level = "Critical" if risk_score >= 60 else "High" if risk_score >= 40 else "Medium"
                resources_affected.append({
                    "resource_name": user_name,
                    "identity_type": "IAM User",
                    "risk_score": min(risk_score, 100),
                    "risk_level": risk_level,
                    "risk_factors": "; ".join(risk_factors),
                    "factor_count": len(risk_factors),
                    "last_updated": datetime.now(IST).isoformat(),
                })

        except Exception as e:
            print(f"Error scoring user {user_name}: {e}")

    # ── Score IAM Roles ──────────────────────────────────────────────────
    roles = iam.list_roles().get("Roles", [])

    for role in roles:
        role_name = role["RoleName"]
        # Skip AWS service-linked roles
        if role.get("Path", "").startswith("/aws-service-role/"):
            continue

        risk_score = 0
        risk_factors = []

        try:
            # Factor 1: Wildcard trust policy
            trust = role.get("AssumeRolePolicyDocument", {})
            for stmt in trust.get("Statement", []):
                principal = stmt.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and "*" in str(principal.values())):
                    if not stmt.get("Condition"):
                        risk_score += 30
                        risk_factors.append("Wildcard principal in trust policy without conditions")
                        break

            # Factor 2: Cross-account trust without ExternalId
            for stmt in trust.get("Statement", []):
                principal = stmt.get("Principal", {})
                if isinstance(principal, dict):
                    aws_principals = principal.get("AWS", [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if current_account and current_account not in str(p) and p != "*":
                            condition = stmt.get("Condition", {})
                            has_external_id = "sts:ExternalId" in str(condition)
                            if not has_external_id:
                                risk_score += 15
                                risk_factors.append("Cross-account trust without ExternalId condition")
                                break

            # Factor 3: Overly permissive attached policies
            attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
            for p in attached:
                if p.get("PolicyName") in ("AdministratorAccess", "PowerUserAccess"):
                    risk_score += 25
                    risk_factors.append(f"Has {p['PolicyName']} policy")
                    break

            # Factor 4: Not used recently
            role_detail = iam.get_role(RoleName=role_name)["Role"]
            last_used = role_detail.get("RoleLastUsed", {}).get("LastUsedDate")
            if not last_used:
                risk_score += 5
                risk_factors.append("Role never used")
            else:
                inactive_threshold = datetime.now(timezone.utc) - timedelta(days=90)
                if last_used < inactive_threshold:
                    risk_score += 5
                    risk_factors.append("Role not used in 90+ days")

            if risk_score >= 20:
                risk_level = "Critical" if risk_score >= 60 else "High" if risk_score >= 40 else "Medium"
                resources_affected.append({
                    "resource_name": role_name,
                    "identity_type": "IAM Role",
                    "risk_score": min(risk_score, 100),
                    "risk_level": risk_level,
                    "risk_factors": "; ".join(risk_factors),
                    "factor_count": len(risk_factors),
                    "last_updated": datetime.now(IST).isoformat(),
                })

        except Exception as e:
            print(f"Error scoring role {role_name}: {e}")

    # Sort by risk score descending
    resources_affected.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    scan_meta_data_global_services["total_scanned"] += len(users) + len(roles)
    scan_meta_data_global_services["affected"] += len(resources_affected)
    critical_count = len([r for r in resources_affected if r["risk_level"] == "Critical"])
    high_count = len([r for r in resources_affected if r["risk_level"] == "High"])
    scan_meta_data_global_services["Critical"] += critical_count
    scan_meta_data_global_services["High"] += high_count
    scan_meta_data_global_services["Medium"] += len(resources_affected) - critical_count - high_count
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    top_severity = "Critical" if critical_count else "High" if high_count else "Medium" if resources_affected else "Low"
    top_score = resources_affected[0]["risk_score"] if resources_affected else 0

    return {
        "check_name": "Identity Risk Scoring",
        "service": "IAM",
        "problem_statement": "IAM identities have been scored based on multiple risk factors including permissions, MFA, key age, activity, and privilege escalation potential.",
        "severity_score": top_score,
        "severity_level": top_severity,
        "resources_affected": resources_affected,
        "recommendation": "Address Critical and High risk identities first. Enforce MFA, rotate keys, remove admin access, and restrict trust policies.",
        "additional_info": {
            "total_scanned": len(users) + len(roles),
            "affected": len(resources_affected),
            "users_scored": len(users),
            "roles_scored": len([r for r in roles if not r.get("Path", "").startswith("/aws-service-role/")]),
            "critical_identities": critical_count,
            "high_identities": high_count,
        },
    }


def _check_priv_esc_actions(iam, principal_arn):
    """
    Check if a principal can perform privilege escalation actions.
    Uses iam:SimulatePrincipalPolicy (included in ReadOnlyAccess).
    Returns list of allowed escalation actions.
    """
    allowed = []
    try:
        # Check in batches to avoid throttling
        for i in range(0, len(PRIV_ESC_ACTIONS), 5):
            batch = PRIV_ESC_ACTIONS[i:i + 5]
            result = iam.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=batch,
            )
            for eval_result in result.get("EvaluationResults", []):
                if eval_result.get("EvalDecision") == "allowed":
                    allowed.append(eval_result["EvalActionName"])
    except Exception as e:
        # SimulatePrincipalPolicy may fail for some principals
        pass
    return allowed
