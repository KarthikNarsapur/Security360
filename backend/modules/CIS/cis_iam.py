import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


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
            user_id = user["UserId"]
            user_arn = user["Arn"]
            create_date = (
                user["CreateDate"].isoformat() if "CreateDate" in user else None
            )

            policies = iam.list_attached_user_policies(UserName=user_name).get(
                "AttachedPolicies", []
            )

            if policies:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": user_name,
                        "resource_id_type": "UserName",
                        "user_id": user_id,
                        "user_arn": user_arn,
                        "create_date": create_date,
                        "attached_policy_count": len(policies),
                        "issue": "IAM user has policies directly attached",
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
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the problematic user",
                "3. Remove any attached policies",
                "4. Add user to appropriate IAM groups with needed permissions",
                "5. Or configure role assumption for the user",
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
            user_id = user["UserId"]
            user_arn = user["Arn"]
            user_create_date = (
                user["CreateDate"].isoformat() if "CreateDate" in user else None
            )

            access_keys = iam.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata", []
            )

            for key in access_keys:
                if key["Status"] == "Active":
                    total_scanned = total_scanned + 1
                    key_id = key["AccessKeyId"]
                    key_create_date = key["CreateDate"]
                    key_age = (datetime.now(IST) - key_create_date).days

                    if key_age > 90:
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": f"{user_name}/{key_id}",
                                "resource_id_type": "UserName/AccessKeyId",
                                "user_id": user_id,
                                "user_arn": user_arn,
                                "user_create_date": user_create_date,
                                "access_key_id": key_id,
                                "access_key_status": key["Status"],
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
            "recommendation": "Rotate access keys older than 90 days or use IAM roles/federation instead",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the problematic user",
                "3. Under 'Security credentials', create new access key",
                "4. Update applications with new key",
                "5. Deactivate old access key",
                "6. Consider using IAM roles or federation instead of access keys",
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

        account_summary = iam.get_account_summary()
        summary_map = account_summary.get("SummaryMap", {})
        access_keys_present = summary_map.get("AccountAccessKeysPresent", 0)

        account_id = sts.get_caller_identity()["Account"]

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
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Sign in to AWS as root user",
                "2. Navigate to IAM service",
                "3. Go to 'My Security Credentials'",
                "4. Delete all access keys under 'Access keys' section",
                "5. Never create root access keys again",
                "6. Use IAM users/roles for programmatic access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking root access keys: {e}")
        return None


def check_iam_mfa_enabled(session):
    # [IAM.5]
    print("Checking IAM MFA configuration")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        users = iam.list_users().get("Users", [])

        for user in users:
            try:
                user_name = user["UserName"]
                user_id = user.get("UserId")
                user_arn = user.get("Arn")
                password_last_used = (
                    user.get("PasswordLastUsed").isoformat()
                    if user.get("PasswordLastUsed")
                    else "Never"
                )

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
                                "user_id": user_id,
                                "user_arn": user_arn,
                                "password_last_used": password_last_used,
                                "issue": "Console user without MFA enabled",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
            except Exception as e:
                print(f"Error checking IAM MFA for user {user_name}: {e}")

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
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Select the problematic user",
                "3. Go to 'Security credentials' tab",
                "4. Under 'Assigned MFA device', click 'Manage'",
                "5. Follow prompts to enable virtual or hardware MFA device",
                "6. Require MFA for all console users",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM MFA: {e}")
        return None


def check_root_hardware_mfa(session):
    # [IAM.6]
    print("Checking root user hardware MFA configuration")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        summary = iam.get_account_summary()
        mfa_enabled = summary["SummaryMap"].get("AccountMFAEnabled", 0)
        print("mfa: ", mfa_enabled)
        if mfa_enabled == 0:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "root",
                    "issue": "Root user does not have MFA enabled",
                    "mfa_enabled": False,
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
        else:
            virtual_mfas = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")[
                "VirtualMFADevices"
            ]
            print(virtual_mfas)
            

            if virtual_mfas:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": "root",
                        "issue": "Root user have Virtual MFA enabled",
                        "mfa_enabled": True,
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "IAM.6",
            "check_name": "Root Hardware MFA",
            "problem_statement": "Hardware MFA should be enabled for the root user",
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable hardware MFA for root user and remove any virtual MFA",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Sign in to AWS as root user",
                "2. Navigate to IAM service",
                "3. Go to 'My Security Credentials'",
                "4. Remove any virtual MFA device",
                "5. Register a hardware MFA device (YubiKey, etc.)",
                "6. Never use virtual MFA for root account",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking root MFA: {e}")
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
                    "mfa_enabled": False,
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
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Sign in to AWS as root user",
                "2. Navigate to IAM service",
                "3. Go to 'My Security Credentials'",
                "4. Under 'Multi-factor authentication (MFA)', click 'Activate MFA'",
                "5. Follow prompts to enable either virtual or hardware MFA device",
                "6. Complete the MFA setup process",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking root MFA: {e}")
        return None


def check_iam_password_policy_length(session):
    # [IAM.15]
    print("Checking IAM password policy minimum length")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            min_length = policy.get("MinimumPasswordLength", 0)

            if min_length < 14:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": "account_password_policy",
                        "issue": f"Password policy minimum length is {min_length} (less than 14)",
                        "min_length": min_length,
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
            "id": "IAM.15",
            "check_name": "IAM Password Policy Length",
            "problem_statement": "IAM password policy should require minimum password length of 14 or greater",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Set IAM password policy minimum length to at least 14 characters",
            "additional_info": {
                "total_scanned": 1,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Go to 'Account settings'",
                "3. Click 'Edit' on Password policy",
                "4. Set 'Minimum password length' to 14 or higher",
                "5. Enable other recommended password complexity options",
                "6. Click 'Save changes'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM password policy: {e}")
        return None


def check_iam_password_reuse_prevention(session):
    # [IAM.16]
    print("Checking IAM password policy password reuse prevention")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            password_reuse_prevention = policy.get("PasswordReusePrevention", 0)

            if password_reuse_prevention != 24:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": "account_password_policy",
                        "issue": f"Password reuse prevention is set to {password_reuse_prevention} (should be 24)",
                        "password_reuse_prevention": password_reuse_prevention,
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
            "id": "IAM.16",
            "check_name": "IAM Password Reuse Prevention",
            "problem_statement": "IAM password policy should prevent password reuse (24 passwords remembered)",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Set IAM password policy to remember 24 previous passwords",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Go to 'Account settings'",
                "3. Click 'Edit' on Password policy",
                "4. Set 'Password reuse prevention' to 24",
                "5. Click 'Save changes'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM password reuse prevention: {e}")
        return None


def check_support_role_exists(session):
    # [IAM.18]
    print("Checking for AWS Support role existence")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        roles = iam.list_roles().get("Roles", [])
        has_support_role = False

        for role in roles:
            role_name = role.get("RoleName")
            attached_policies = iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
            for policy in attached_policies:
                if policy.get("PolicyName") == "AWSSupportAccess":
                    has_support_role = True
                    break
            if has_support_role:
                break

        if not has_support_role:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": "NoSupportRole",
                    "issue": "No IAM role with AWSSupportAccess policy attached exists",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = len(roles)
        affected = len(resources_affected)

        return {
            "id": "IAM.18",
            "check_name": "AWS Support Role",
            "problem_statement": "A support role should be created to manage incidents with AWS Support",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Create an IAM role with the AWSSupportAccess managed policy attached",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Go to 'Roles' and click 'Create role'",
                "3. Select 'AWS account' as trusted entity",
                "4. Attach the 'AWSSupportAccess' managed policy",
                "5. Name the role (e.g., 'AWSSupportRole')",
                "6. Create the role",
                "7. Provide role ARN to AWS Support team when needed",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking support role: {e}")
        return None


def check_unused_iam_credentials(session):
    # [IAM.22]
    print("Checking for unused IAM credentials")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        cutoff_date = datetime.now(IST) - timedelta(days=45)

        users = iam.list_users().get("Users", [])

        for user in users:
            user_name = user["UserName"]
            issues = []

            try:
                login_profile = iam.get_login_profile(UserName=user_name)
                password_last_used = user.get("PasswordLastUsed")
                if password_last_used and password_last_used < cutoff_date:
                    issues.append(f"Console password unused since {password_last_used}")
            except iam.exceptions.NoSuchEntityException:
                pass

            access_keys = iam.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata", []
            )
            for key in access_keys:
                if key["Status"] == "Active":
                    last_used = iam.get_access_key_last_used(
                        AccessKeyId=key["AccessKeyId"]
                    ).get("AccessKeyLastUsed", {})
                    if (
                        "LastUsedDate" not in last_used
                        or last_used["LastUsedDate"] < cutoff_date
                    ):
                        issues.append(
                            f"Access key {key['AccessKeyId']} unused since {last_used.get('LastUsedDate', 'never')}"
                        )

            if issues:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": user_name,
                        "issue": ", ".join(issues),
                        "region": "global",
                        "user_arn": user.get("Arn", ""),
                        "password_last_used": (
                            str(password_last_used) if password_last_used else None
                        ),
                        "unused_access_key_ids": [
                            key["AccessKeyId"]
                            for key in access_keys
                            if key["Status"] == "Active"
                            and (
                                "LastUsedDate"
                                not in iam.get_access_key_last_used(
                                    AccessKeyId=key["AccessKeyId"]
                                ).get("AccessKeyLastUsed", {})
                                or iam.get_access_key_last_used(
                                    AccessKeyId=key["AccessKeyId"]
                                )["AccessKeyLastUsed"]["LastUsedDate"]
                                < cutoff_date
                            )
                        ],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(users)
        affected = len(resources_affected)
        return {
            "id": "IAM.22",
            "check_name": "Unused IAM Credentials",
            "problem_statement": "IAM user credentials unused for 45 days should be removed",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove or deactivate unused IAM credentials older than 45 days",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Review users with reported issues",
                "3. For unused console passwords: Delete login profile",
                "4. For unused access keys: Deactivate and remove",
                "5. Consider implementing credential rotation policy",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking unused IAM credentials: {e}")
        return None


def check_expired_iam_certificates(session):
    # [IAM.26]
    print("Checking for expired IAM SSL/TLS certificates")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        current_time = datetime.now(IST)
        # print("current_time: ", current_time)

        server_certs = iam.list_server_certificates().get(
            "ServerCertificateMetadataList", []
        )

        for cert in server_certs:
            expiration = cert["Expiration"]
            if expiration < current_time:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cert["ServerCertificateName"],
                        "arn": cert["Arn"],
                        "issue": f"Certificate expired on {expiration.isoformat()}",
                        "region": "global",
                        "expiration_date": expiration.isoformat(),
                        "upload_date": (
                            cert.get("UploadDate", "").isoformat()
                            if cert.get("UploadDate")
                            else None
                        ),
                        "path": cert.get("Path", ""),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(server_certs)
        affected = len(resources_affected)
        return {
            "id": "IAM.26",
            "check_name": "Expired IAM Certificates",
            "problem_statement": "Expired SSL/TLS certificates managed in IAM should be removed",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove expired SSL/TLS certificates from IAM",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. Go to 'SSL/TLS certificates' section",
                "3. Identify expired certificates",
                "4. Select the expired certificate and click 'Delete'",
                "5. Confirm deletion",
                "6. Update any services referencing the deleted certificate",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM certificates: {e}")
        return None


def check_cloudshell_full_access_policy(session):
    print("Checking for AWSCloudShellFullAccess policy attachments")

    iam = session.client("iam")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        users = iam.list_users().get("Users", [])
        for user in users:
            user_name = user["UserName"]
            attached_policies = iam.list_attached_user_policies(UserName=user_name).get(
                "AttachedPolicies", []
            )
            if any(
                policy["PolicyName"] == "AWSCloudShellFullAccess"
                for policy in attached_policies
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_type": "IAM User",
                        "resource_id": user_name,
                        "issue": "Has AWSCloudShellFullAccess policy attached",
                        "region": "global",
                        "user_create_date": (
                            user.get("CreateDate").strftime("%Y-%m-%d %H:%M:%S")
                            if user.get("CreateDate")
                            else "N/A"
                        ),
                        "user_arn": user.get("Arn", "N/A"),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        roles = iam.list_roles().get("Roles", [])
        for role in roles:
            role_name = role["RoleName"]
            attached_policies = iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            )
            if any(
                policy["PolicyName"] == "AWSCloudShellFullAccess"
                for policy in attached_policies
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_type": "IAM Role",
                        "resource_id": role_name,
                        "issue": "Has AWSCloudShellFullAccess policy attached",
                        "region": "global",
                        "role_create_date": (
                            role.get("CreateDate").strftime("%Y-%m-%d %H:%M:%S")
                            if role.get("CreateDate")
                            else "N/A"
                        ),
                        "role_arn": role.get("Arn", "N/A"),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        groups = iam.list_groups().get("Groups", [])
        for group in groups:
            group_name = group["GroupName"]
            attached_policies = iam.list_attached_group_policies(
                GroupName=group_name
            ).get("AttachedPolicies", [])
            if any(
                policy["PolicyName"] == "AWSCloudShellFullAccess"
                for policy in attached_policies
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_type": "IAM Group",
                        "resource_id": group_name,
                        "issue": "Has AWSCloudShellFullAccess policy attached",
                        "region": "global",
                        "group_create_date": (
                            group.get("CreateDate").strftime("%Y-%m-%d %H:%M:%S")
                            if group.get("CreateDate")
                            else "N/A"
                        ),
                        "group_arn": group.get("Arn", "N/A"),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(users) + len(roles) + len(groups)
        affected = len(resources_affected)
        return {
            "id": "IAM.27",
            "check_name": "AWSCloudShellFullAccess Policy Check",
            "problem_statement": "IAM identities should not have the AWSCloudShellFullAccess policy attached",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Remove AWSCloudShellFullAccess policy from all IAM identities",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM service in AWS Console",
                "2. For each affected identity (user/role/group):",
                "3. Select the identity and go to 'Permissions' tab",
                "4. Locate the AWSCloudShellFullAccess policy",
                "5. Click 'Detach' or 'Remove'",
                "6. Apply least privilege permissions instead",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking AWSCloudShellFullAccess policy: {e}")
        return None


def check_access_analyzer_enabled(session):
    print("Checking IAM Access Analyzer configuration")

    accessanalyzer = session.client("accessanalyzer")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        analyzers = accessanalyzer.list_analyzers().get("analyzers", [])

        active_external_analyzers = [
            analyzer
            for analyzer in analyzers
            if analyzer.get("type") == "EXTERNAL" and analyzer.get("status") == "ACTIVE"
        ]

        if not active_external_analyzers:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "issue": "No active external IAM Access Analyzer enabled",
                    "region": region,
                    "analyzers_found": len(analyzers),
                    "analyzer_details": [
                        {
                            "name": analyzer.get("name", "N/A"),
                            "type": analyzer.get("type", "N/A"),
                            "status": analyzer.get("status", "N/A"),
                            "created_at": (
                                analyzer.get("createdAt").strftime("%Y-%m-%d %H:%M:%S")
                                if analyzer.get("createdAt")
                                else "N/A"
                            ),
                        }
                        for analyzer in analyzers
                    ],
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "IAM.28",
            "check_name": "IAM Access Analyzer External",
            "problem_statement": "IAM Access Analyzer external access analyzer should be enabled",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable an external IAM Access Analyzer in the region",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to IAM Access Analyzer service",
                "2. Click 'Create analyzer'",
                "3. Select 'External' as analyzer type",
                "4. Choose an appropriate name",
                "5. Optionally add tags",
                "6. Click 'Create analyzer'",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking IAM Access Analyzer: {e}")
        return None
