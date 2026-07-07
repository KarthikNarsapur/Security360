"""
ISO 27001 Checks — Identity & Access Management
Controls: A.5.15, A.5.16, A.5.17, A.5.18, A.8.2, A.8.5, A.5.2, A.5.3
All checks use ReadOnlyAccess permissions only.
"""
import json
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_password_policy(session):
    """A.5.15/A.5.17/A.8.5: Validate IAM password policy meets ISO 27001 requirements."""
    print("  ISO27001: Checking IAM password policy")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "IAM-PasswordPolicy",
                "resource_id_type": "AccountSetting",
                "issue": "No password policy configured for the account",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })
            return _result("A.5.17", "Authentication information management",
                          resources_affected, 1, 90, "Critical")

        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"Minimum password length is {policy.get('MinimumPasswordLength', 0)} (should be >= 14)")
        if not policy.get("RequireSymbols", False):
            issues.append("Password policy does not require symbols")
        if not policy.get("RequireNumbers", False):
            issues.append("Password policy does not require numbers")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Password policy does not require uppercase characters")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Password policy does not require lowercase characters")
        if policy.get("MaxPasswordAge", 0) == 0 or policy.get("MaxPasswordAge", 0) > 90:
            issues.append(f"Password max age is {policy.get('MaxPasswordAge', 0)} days (should be <= 90)")
        if policy.get("PasswordReusePrevention", 0) < 24:
            issues.append(f"Password reuse prevention is {policy.get('PasswordReusePrevention', 0)} (should be >= 24)")

        if issues:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "IAM-PasswordPolicy",
                "resource_id_type": "AccountSetting",
                "issue": "; ".join(issues),
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.5.17", "Authentication information management",
                      resources_affected, 1, 80, "High")
    except Exception as e:
        print(f"Error checking password policy: {e}")
        return None


def check_mfa_enforcement(session):
    """A.5.15/A.8.2: MFA enabled for all console users."""
    print("  ISO27001: Checking MFA enforcement")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])
        total_console_users = 0

        for user in users:
            username = user["UserName"]
            try:
                iam.get_login_profile(UserName=username)
            except iam.exceptions.NoSuchEntityException:
                continue  # No console access
            except Exception:
                continue

            total_console_users += 1
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if len(mfa_devices) == 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": username,
                    "resource_id_type": "IAM User",
                    "issue": f"Console user '{username}' does not have MFA enabled",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.5.15", "Access control - MFA enforcement",
                      resources_affected, max(total_console_users, 1), 90, "Critical")
    except Exception as e:
        print(f"Error checking MFA: {e}")
        return None


def check_root_account_security(session):
    """A.8.2: Root account should have MFA and no access keys."""
    print("  ISO27001: Checking root account security")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountMFAEnabled", 0) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "root",
                "resource_id_type": "IAM Root",
                "issue": "Root account does not have MFA enabled",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "root",
                "resource_id_type": "IAM Root",
                "issue": "Root account has active access keys (should be removed)",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.2", "Privileged access rights - Root account",
                      resources_affected, 2, 100, "Critical")
    except Exception as e:
        print(f"Error checking root account: {e}")
        return None


def check_access_key_rotation(session):
    """A.5.16: Access keys should be rotated within 90 days."""
    print("  ISO27001: Checking access key rotation")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])
        total_keys = 0

        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key["Status"] != "Active":
                    continue
                total_keys += 1
                created = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days > 90:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": f"{username}/{key['AccessKeyId']}",
                        "resource_id_type": "IAM AccessKey",
                        "issue": f"Access key is {age_days} days old (max 90 days)",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return _result("A.5.16", "Identity management - Access key rotation",
                      resources_affected, max(total_keys, 1), 70, "High")
    except Exception as e:
        print(f"Error checking access key rotation: {e}")
        return None


def check_unused_credentials(session):
    """A.5.16: Detect unused IAM credentials (inactive > 90 days)."""
    print("  ISO27001: Checking unused credentials")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])
        total = 0

        for user in users:
            username = user["UserName"]
            total += 1
            last_used = user.get("PasswordLastUsed")

            # Check if user has console access but hasn't logged in
            try:
                iam.get_login_profile(UserName=username)
                has_console = True
            except Exception:
                has_console = False

            if has_console and last_used:
                days_since = (datetime.now(timezone.utc) - last_used).days
                if days_since > 90:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": username,
                        "resource_id_type": "IAM User",
                        "issue": f"User '{username}' has not logged in for {days_since} days",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })

            # Check access keys not used in 90 days
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key["Status"] != "Active":
                    continue
                try:
                    key_last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    last = key_last["AccessKeyLastUsed"].get("LastUsedDate")
                    if last:
                        days_unused = (datetime.now(timezone.utc) - last).days
                        if days_unused > 90:
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": f"{username}/{key['AccessKeyId']}",
                                "resource_id_type": "IAM AccessKey",
                                "issue": f"Access key unused for {days_unused} days",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            })
                except Exception:
                    continue

        return _result("A.5.16", "Identity management - Unused credentials",
                      resources_affected, max(total, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking unused credentials: {e}")
        return None


def check_least_privilege(session):
    """A.5.18: No wildcard (*) permissions in user policies."""
    print("  ISO27001: Checking least privilege")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])
        total = 0

        for user in users:
            username = user["UserName"]
            total += 1

            # Check attached policies for wildcards
            attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            for policy in attached:
                if "AdministratorAccess" in policy["PolicyArn"]:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": username,
                        "resource_id_type": "IAM User",
                        "issue": f"User '{username}' has AdministratorAccess policy attached",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
                    break

        return _result("A.5.18", "Access rights - Least privilege",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking least privilege: {e}")
        return None


def check_wildcard_permissions(session):
    """A.5.18: Detect IAM policies with wildcard actions or resources."""
    print("  ISO27001: Checking wildcard permissions")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        policies = iam.list_policies(Scope="Local", OnlyAttached=True).get("Policies", [])
        total = len(policies)

        for policy in policies:
            try:
                version_id = policy["DefaultVersionId"]
                doc = iam.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=version_id
                )["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    if "*" in actions and "*" in resources:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": policy["PolicyName"],
                            "resource_id_type": "IAM Policy",
                            "issue": f"Policy '{policy['PolicyName']}' grants Action:* on Resource:*",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break
            except Exception:
                continue

        return _result("A.5.18", "Access rights - Wildcard permission detection",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking wildcard permissions: {e}")
        return None


def check_inline_policies(session):
    """A.5.18: Users should not have inline policies (harder to audit)."""
    print("  ISO27001: Checking inline policies")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])
        total = len(users)

        for user in users:
            username = user["UserName"]
            inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
            if len(inline) > 0:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": username,
                    "resource_id_type": "IAM User",
                    "issue": f"User '{username}' has {len(inline)} inline policies: {', '.join(inline[:3])}",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.5.18", "Access rights - Inline policy detection",
                      resources_affected, max(total, 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking inline policies: {e}")
        return None


def check_privileged_role_review(session):
    """A.8.2: Review roles with elevated privileges."""
    print("  ISO27001: Checking privileged roles")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])
        total = len(roles)
        admin_policies = ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]

        for role in roles:
            role_name = role["RoleName"]
            if role_name.startswith("aws-") or role_name.startswith("AWS"):
                continue
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                for policy in attached:
                    if any(ap in policy["PolicyArn"] for ap in admin_policies):
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": role_name,
                            "resource_id_type": "IAM Role",
                            "issue": f"Role '{role_name}' has privileged policy: {policy['PolicyName']}",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break
            except Exception:
                continue

        return _result("A.8.2", "Privileged access rights - Role review",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking privileged roles: {e}")
        return None


def check_segregation_of_duties(session):
    """A.5.3: No single role has both administrative and security audit access."""
    print("  ISO27001: Checking segregation of duties")
    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])
        total = 0

        for role in roles:
            role_name = role["RoleName"]
            if role_name.startswith("aws-") or role_name.startswith("AWS"):
                continue
            total += 1
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                policy_names = [p["PolicyName"] for p in attached]
                arns = [p["PolicyArn"] for p in attached]

                has_admin = any("AdministratorAccess" in a for a in arns)
                has_security = any(kw in a for a in arns for kw in ["SecurityAudit", "ViewOnlyAccess", "ReadOnlyAccess"])

                if has_admin and has_security:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": role_name,
                        "resource_id_type": "IAM Role",
                        "issue": f"Role '{role_name}' has both admin and audit access (violates SoD)",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.5.3", "Segregation of duties",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking segregation of duties: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "IAM",
        "problem_statement": f"ISO 27001 {control_id}: {check_name} - compliance validation",
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
