import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_iam_full_admin_access(session):
    # [IAM.1]
    print("Checking IAM full admin access policies")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check users with AdministratorAccess
        users = iam.list_users().get("Users", [])
        for user in users:
            user_name = user["UserName"]
            attached_policies = iam.list_attached_user_policies(UserName=user_name).get(
                "AttachedPolicies", []
            )
            if any(
                policy["PolicyName"] == "AdministratorAccess"
                for policy in attached_policies
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": user_name,
                        "resource_id_type": "UserName",
                        "issue": "User has AdministratorAccess policy attached",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # Check roles with AdministratorAccess
        roles = iam.list_roles().get("Roles", [])
        for role in roles:
            role_name = role["RoleName"]
            attached_policies = iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
            if any(
                policy["PolicyName"] == "AdministratorAccess"
                for policy in attached_policies
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": role_name,
                        "resource_id_type": "RoleName",
                        "issue": "Role has AdministratorAccess policy attached",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(users) + len(roles)
        affected = len(resources_affected)

        return {
            "id": "IAM.1",
            "check_name": "IAM Full Admin Access",
            "problem_statement": "IAM identities should not have the AdministratorAccess policy attached",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove AdministratorAccess policy and use least privilege permissions",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the affected user/role",
                "3. Detach the AdministratorAccess policy",
                "4. Attach specific policies based on required permissions",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM full admin access: {e}")
        return None


def check_iam_user_policies(session):
    # [IAM.2]
    print("Checking IAM user policies configuration")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])

        for user in users:
            user_name = user["UserName"]

            # Check attached policies
            attached_policies = iam.list_attached_user_policies(UserName=user_name).get(
                "AttachedPolicies", []
            )

            # Check inline policies
            inline_policies = iam.list_user_policies(UserName=user_name).get(
                "PolicyNames", []
            )

            if attached_policies or inline_policies:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": user_name,
                        "resource_id_type": "UserName",
                        "issue": "IAM user has policies directly attached",
                        "attached_policy_count": len(attached_policies),
                        "inline_policy_count": len(inline_policies),
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(users)
        affected = len(resources_affected)

        return {
            "id": "IAM.2",
            "check_name": "IAM User Direct Policies",
            "problem_statement": "IAM users should not have IAM policies attached directly",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Move policies from IAM users to groups or roles",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the problematic user",
                "3. Remove any attached policies",
                "4. Add user to appropriate IAM groups with needed permissions",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM user policies: {e}")
        return None


def check_iam_access_key_rotation(session):
    # [IAM.3]
    print("Checking IAM access key rotation")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []
    total_scanned = 0

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])

        for user in users:
            user_name = user["UserName"]
            access_keys = iam.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata", []
            )

            for key in access_keys:
                if key["Status"] == "Active":
                    total_scanned += 1
                    key_age = (datetime.now(IST) - key["CreateDate"]).days

                    if key_age > 90:
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": f"{user_name}/{key['AccessKeyId']}",
                                "resource_id_type": "UserName/AccessKeyId",
                                "access_key_age_days": key_age,
                                "issue": f"Access key not rotated for {key_age} days",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )

        affected = len(resources_affected)

        return {
            "id": "IAM.3",
            "check_name": "IAM Access Key Rotation",
            "problem_statement": "IAM users' access keys should be rotated every 90 days or less",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Rotate access keys older than 90 days",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the problematic user",
                "3. Create new access key",
                "4. Update applications with new key",
                "5. Deactivate old access key",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM access keys: {e}")
        return None


def check_root_access_key(session):
    # [IAM.4]
    print("Checking root user access key")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        account_summary = iam.get_account_summary()
        summary_map = account_summary.get("SummaryMap", {})
        access_keys_present = summary_map.get("AccountAccessKeysPresent", 0)

        if access_keys_present:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "issue": "Root user has active access key",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "IAM.4",
            "check_name": "Root Access Key",
            "problem_statement": "IAM root user access key should not exist",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Immediately remove all access keys for the root user",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Sign in to AWS as root user",
                "2. Navigate to IAM service",
                "3. Go to 'My Security Credentials'",
                "4. Delete all access keys under 'Access keys' section",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking root access keys: {e}")
        return None


def check_iam_mfa_enabled(session):
    # [IAM.5, IAM.19]
    print("Checking IAM MFA configuration")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])

        for user in users:
            user_name = user["UserName"]

            try:
                login_profile = iam.get_login_profile(UserName=user_name)
            except iam.exceptions.NoSuchEntityException:
                login_profile = None

            if login_profile:
                mfa_devices = iam.list_mfa_devices(UserName=user_name).get(
                    "MFADevices", []
                )
                if not mfa_devices:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": user_name,
                            "resource_id_type": "UserName",
                            "issue": "Console user without MFA enabled",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(users)
        affected = len(resources_affected)

        return {
            "id": "IAM.5",
            "check_name": "IAM MFA Enforcement",
            "problem_statement": "MFA should be enabled for all IAM users that have a console password",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable MFA for all IAM users with console access",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the problematic user",
                "3. Go to 'Security credentials' tab",
                "4. Under 'Assigned MFA device', click 'Manage'",
                "5. Follow prompts to enable MFA device",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM MFA: {e}")
        return None


def check_iam_password_policy(session):
    # [IAM.7]
    print("Checking IAM password policy")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})

            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append(
                    f"Minimum length is {policy.get('MinimumPasswordLength', 0)} (should be 14+)"
                )
            if not policy.get("RequireUppercaseCharacters", False):
                issues.append("Uppercase characters not required")
            if not policy.get("RequireLowercaseCharacters", False):
                issues.append("Lowercase characters not required")
            if not policy.get("RequireNumbers", False):
                issues.append("Numbers not required")
            if not policy.get("RequireSymbols", False):
                issues.append("Symbols not required")

            if issues:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": "account_password_policy",
                        "issue": "; ".join(issues),
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        except iam.exceptions.NoSuchEntityException:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "account_password_policy",
                    "issue": "No IAM password policy exists",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "IAM.7",
            "check_name": "IAM Password Policy",
            "problem_statement": "IAM password policy should enforce strong password requirements",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Configure strong IAM password policy",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Go to 'Account settings'",
                "3. Click 'Edit' on Password policy",
                "4. Enable all password complexity requirements",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM password policy: {e}")
        return None


def check_iam_console_access(session):
    # [IAM.8]
    print("Checking IAM console access")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])
        cutoff_date = datetime.now(IST) - timedelta(days=90)

        for user in users:
            user_name = user["UserName"]
            password_last_used = user.get("PasswordLastUsed")

            if password_last_used and password_last_used < cutoff_date:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": user_name,
                        "resource_id_type": "UserName",
                        "issue": f"Console password unused since {password_last_used}",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(users)
        affected = len(resources_affected)

        return {
            "id": "IAM.8",
            "check_name": "IAM Console Access",
            "problem_statement": "IAM user credentials unused for 90 days should be removed",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove or deactivate unused IAM credentials",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Review users with reported issues",
                "3. For unused console passwords: Delete login profile",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM console access: {e}")
        return None


def check_root_mfa_enabled(session):
    # [IAM.9]
    print("Checking root user MFA configuration")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        summary = iam.get_account_summary()
        mfa_enabled = summary["SummaryMap"].get("AccountMFAEnabled", 0)

        if mfa_enabled == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "root",
                    "issue": "Root user does not have MFA enabled",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "IAM.9",
            "check_name": "Root MFA Enforcement",
            "problem_statement": "MFA should be enabled for the root user",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable MFA for the root user immediately",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Sign in to AWS as root user",
                "2. Navigate to IAM service",
                "3. Go to 'My Security Credentials'",
                "4. Under 'Multi-factor authentication (MFA)', click 'Activate MFA'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking root MFA: {e}")
        return None


def check_iam_managed_policy_full_access(session):
    # [IAM.21]
    print("Checking IAM managed policy full access")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Check users with service-specific full access policies
        users = iam.list_users().get("Users", [])
        for user in users:
            user_name = user["UserName"]
            attached_policies = iam.list_attached_user_policies(UserName=user_name).get(
                "AttachedPolicies", []
            )

            for policy in attached_policies:
                if (
                    "FullAccess" in policy["PolicyName"]
                    and policy["PolicyName"] != "AdministratorAccess"
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": user_name,
                            "resource_id_type": "UserName",
                            "policy_name": policy["PolicyName"],
                            "issue": f"User has {policy['PolicyName']} policy attached",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(users)
        affected = len(resources_affected)

        return {
            "id": "IAM.21",
            "check_name": "IAM Managed Policy Full Access",
            "problem_statement": "IAM identities should not have service-specific full access policies",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Replace full access policies with least privilege permissions",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the affected user",
                "3. Detach the full access policy",
                "4. Attach specific policies based on required permissions",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM managed policy full access: {e}")
        return None
