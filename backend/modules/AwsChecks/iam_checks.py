from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def users_without_mfa(iam, scan_meta_data_global_services, users):
    print("users_without_mfa")
    no_mfa = []

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
                    no_mfa.append(
                        {
                            "resource_id": user_name,
                            "resource_id_type": "UserName",
                            "user_id": user_id,
                            "password_last_used": password_last_used,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"Error checking IAM MFA for user {user_name}: {e}")

    scan_meta_data_global_services["total_scanned"] += len(users)
    scan_meta_data_global_services["affected"] += len(no_mfa)
    scan_meta_data_global_services["High"] += len(no_mfa)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "IAM Console Users Without MFA",
        "service": "IAM",
        "problem_statement": "Some IAM users with console access do not have Multi-Factor Authentication (MFA) enabled.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": no_mfa,
        "recommendation": "Enable MFA for all IAM users who have console access.",
        "additional_info": {"total_scanned": len(users), "affected": len(no_mfa)},
    }


def overly_permissive_policies(iam, scan_meta_data_global_services, policies):
    print("overly_permissive_policies")
    risky = []

    for policy in policies:
        doc = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )["PolicyVersion"]["Document"]

        statements = doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            if (
                stmt.get("Effect") == "Allow"
                and stmt.get("Action") == "*"
                and stmt.get("Resource") == "*"
            ):
                risky.append(
                    {
                        "resource_name": policy["PolicyName"],
                        # "arn": policy.get("Arn"),
                        "policy_id": policy.get("PolicyId"),
                        "create_date": str(policy.get("CreateDate")),
                        "default_version_id": policy.get("DefaultVersionId"),
                    }
                )
                break
    scan_meta_data_global_services["total_scanned"] += len(policies)
    scan_meta_data_global_services["affected"] += len(risky)
    scan_meta_data_global_services["Critical"] += len(risky)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Overly Permissive IAM Policies",
        "service": "IAM",
        "problem_statement": "IAM policies granting full access to all actions and resources detected.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": risky,
        "recommendation": "Restrict IAM policies to only required actions and resources.",
        "additional_info": {"total_scanned": len(policies), "affected": len(risky)},
    }


def root_account_without_mfa(iam, scan_meta_data_global_services, account_summary):
    print("root_account_without_mfa")

    mfa_enabled = account_summary.get("AccountMFAEnabled", 0)

    resources_affected = []
    if mfa_enabled == 0:
        resources_affected.append(
            {
                "resource_name": "Root Account",
                "note": "Root account does not have MFA enabled. This is a critical security risk.",
            }
        )
        scan_meta_data_global_services["affected"] += 1
        scan_meta_data_global_services["High"] += 1

    scan_meta_data_global_services["total_scanned"] += 1
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Root Account Without MFA",
        "service": "IAM",
        "problem_statement": "The root account does not have Multi-Factor Authentication (MFA) enabled.",
        "severity_score": 95,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "recommendation": "Enable MFA for the root account immediately to secure your AWS environment.",
        "additional_info": {"total_scanned": 1, "affected": len(resources_affected)},
    }


def access_keys_older_than_90_days(
    users, iam, scan_meta_data_global_services, access_keys_map
):
    print("access_keys_older_than_90_days")
    old_keys = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=90)
    total_scanned = 0

    for user in users:
        access_keys = access_keys_map[user["UserName"]]
        # iam.list_access_keys(UserName=user["UserName"])[
        #     "AccessKeyMetadata"
        # ]
        total_scanned += len(access_keys)
        for key in access_keys:
            if key["CreateDate"] < threshold_date:
                old_keys.append(
                    {
                        "resource_name": user["UserName"],
                        "access_key_id": key["AccessKeyId"],
                        "create_date": str(key["CreateDate"]),
                        "status": key["Status"],
                    }
                )

    scan_meta_data_global_services["total_scanned"] += total_scanned
    scan_meta_data_global_services["affected"] += len(old_keys)
    scan_meta_data_global_services["Medium"] += len(old_keys)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Access Keys Older Than 90 Days",
        "service": "IAM",
        "problem_statement": "Some IAM users have access keys older than 90 days, which is a security risk.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": old_keys,
        "recommendation": "Rotate or deactivate old access keys to maintain security best practices.",
        "additional_info": {"total_scanned": len(users), "affected": len(old_keys)},
    }


def active_access_keys_with_high_age(
    users, iam, scan_meta_data_global_services, access_keys_map, age_threshold_days=180
):
    print("active_access_keys_with_high_age")
    old_active_keys = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=age_threshold_days)
    total_scanned = 0

    for user in users:
        access_keys = access_keys_map[user["UserName"]]
        # iam.list_access_keys(UserName=user["UserName"])[
        #     "AccessKeyMetadata"
        # ]
        total_scanned += len(access_keys)
        for key in access_keys:
            if key["Status"] == "Active" and key["CreateDate"] < threshold_date:
                old_active_keys.append(
                    {
                        "resource_name": user["UserName"],
                        "access_key_id": key["AccessKeyId"],
                        "create_date": str(key["CreateDate"]),
                        "status": key["Status"],
                    }
                )

    scan_meta_data_global_services["total_scanned"] += total_scanned
    scan_meta_data_global_services["affected"] += len(old_active_keys)
    scan_meta_data_global_services["Medium"] += len(old_active_keys)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Active Access Keys with High Age",
        "service": "IAM",
        "problem_statement": "Users are actively using access keys that are several hundred days old.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": old_active_keys,
        "recommendation": "Enforce access key rotation policy and set up alerts for key age thresholds.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(old_active_keys),
        },
    }


def iam_users_with_no_recent_activity(
    users, iam, scan_meta_data_global_services, access_keys_map, inactivity_days=90
):
    print("iam_users_with_no_recent_activity")
    inactive_users = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=inactivity_days)

    for user in users:
        user_name = user["UserName"]
        last_used_date = None

        # 1. Password usage (for console access)
        password_last_used = user.get("PasswordLastUsed")

        if password_last_used and password_last_used > threshold_date:
            continue  # user is active via console

        # 2. Access key usage (for programmatic access)
        access_keys = access_keys_map[user_name]
        for key in access_keys:
            last_used_info = iam.get_access_key_last_used(
                AccessKeyId=key["AccessKeyId"]
            )
            key_last_used = last_used_info.get("AccessKeyLastUsed", {}).get(
                "LastUsedDate"
            )

            if key_last_used and key_last_used > threshold_date:
                break  # user is active via API
        else:
            # No recent activity
            inactive_users.append(
                {
                    "resource_name": user_name,
                    "user_id": user.get("UserId"),
                    "create_date": str(user.get("CreateDate")),
                    "password_last_used": (
                        str(password_last_used) if password_last_used else "Never"
                    ),
                    "note": "No console or access key activity in the last 90+ days",
                }
            )

    scan_meta_data_global_services["total_scanned"] += len(users)
    scan_meta_data_global_services["affected"] += len(inactive_users)
    scan_meta_data_global_services["Low"] += len(inactive_users)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "IAM Users with No Recent Activity",
        "service": "IAM",
        "problem_statement": "Users did not record any activity in the last 90+ days.",
        "severity_score": 50,
        "severity_level": "Low",
        "resources_affected": inactive_users,
        "recommendation": "Review and remove inactive IAM users to reduce the attack surface.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(inactive_users),
        },
    }


def passwords_older_than_90_days(
    users, iam, scan_meta_data_global_services, max_password_age_days=90
):
    print("passwords_older_than_90_days")
    old_password_users = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=max_password_age_days)

    for user in users:
        user_name = user["UserName"]
        try:
            login_profile = iam.get_login_profile(UserName=user_name)
            # If user has a console password, check password last used or fallback to create date
            password_last_used = user.get("PasswordLastUsed")
            if password_last_used:
                if password_last_used < threshold_date:
                    old_password_users.append(
                        {
                            "resource_name": user_name,
                            "user_id": user.get("UserId"),
                            "password_last_used": str(password_last_used),
                            "note": "Password used, but not changed in the last 90+ days.",
                        }
                    )
            else:
                # No recorded password usage, but has login profile
                old_password_users.append(
                    {
                        "resource_name": user_name,
                        "user_id": user.get("UserId"),
                        "password_last_used": "Never Used",
                        "note": "Console password exists and might be stale.",
                    }
                )
        except iam.exceptions.NoSuchEntityException:
            # User doesn't have a console password; ignore
            continue

    scan_meta_data_global_services["total_scanned"] += len(users)
    scan_meta_data_global_services["affected"] += len(old_password_users)
    scan_meta_data_global_services["Medium"] += len(old_password_users)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Passwords Older Than 90 Days",
        "service": "IAM",
        "problem_statement": "Several users have passwords exceeding 90 days.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": old_password_users,
        "recommendation": "Implement and enforce a password rotation policy.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(old_password_users),
        },
    }


def multiple_active_access_keys(
    users, iam, scan_meta_data_global_services, access_keys_map
):
    print("multiple_active_access_keys")
    users_with_multiple_keys = []

    for user in users:
        user_name = user["UserName"]
        access_keys = access_keys_map[user_name]
        # iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

        # Filter active keys
        active_keys = [key for key in access_keys if key["Status"] == "Active"]
        if len(active_keys) > 1:
            users_with_multiple_keys.append(
                {
                    "resource_name": user_name,
                    "user_id": user.get("UserId"),
                    "active_keys_count": len(active_keys),
                    "access_key_ids": [k["AccessKeyId"] for k in active_keys],
                    "note": "More than one active access key detected.",
                }
            )

    scan_meta_data_global_services["total_scanned"] += len(users)
    scan_meta_data_global_services["affected"] += len(users_with_multiple_keys)
    scan_meta_data_global_services["Medium"] += len(users_with_multiple_keys)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Multiple Active Access Keys",
        "service": "IAM",
        "problem_statement": "Some users have more than one active access key.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": users_with_multiple_keys,
        "recommendation": "Limit each IAM user to a single active access key to reduce exposure risk.",
        "additional_info": {
            "total_scanned": len(users),
            "affected": len(users_with_multiple_keys),
        },
    }


def iam_roles_without_recent_use(
    roles, iam, scan_meta_data_global_services, inactivity_days=90
):
    print("iam_roles_without_recent_use")
    unused_roles = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=inactivity_days)
    for role in roles:
        role_name = role["RoleName"]
        role_info = iam.get_role(RoleName=role_name)
        role_last_used = role_info["Role"].get("RoleLastUsed", {})
        last_used_date = role_last_used.get("LastUsedDate")

        if not last_used_date or last_used_date < threshold_date:
            unused_roles.append(
                {
                    "resource_name": role_name,
                    "role_id": role.get("RoleId"),
                    "create_date": str(role.get("CreateDate")),
                    "last_used_date": (
                        str(last_used_date) if last_used_date else "Never Used"
                    ),
                    "note": "Role not used in the last 90+ days or never used.",
                }
            )

    scan_meta_data_global_services["total_scanned"] += len(roles)
    scan_meta_data_global_services["affected"] += len(unused_roles)
    scan_meta_data_global_services["Low"] += len(unused_roles)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "IAM Roles Without Recent Use",
        "service": "IAM",
        "problem_statement": "Some IAM roles have not been used in the last 90+ days or never used at all.",
        "severity_score": 45,
        "severity_level": "Low",
        "resources_affected": unused_roles,
        "recommendation": "Review and delete unused IAM roles after confirming they are no longer needed.",
        "additional_info": {"total_scanned": len(roles), "affected": len(unused_roles)},
    }


def access_keys_last_used_over_90_days_ago(
    users, iam, scan_meta_data_global_services, access_keys_map, inactive_days=90
):
    print("access_keys_last_used_over_90_days_ago")
    stale_keys = []
    threshold_date = datetime.now(timezone.utc) - timedelta(days=inactive_days)

    for user in users:
        user_name = user["UserName"]
        access_keys = access_keys_map[user_name]
        # iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

        for key in access_keys:
            if key["Status"] != "Active":
                continue

            last_used_info = iam.get_access_key_last_used(
                AccessKeyId=key["AccessKeyId"]
            )
            last_used_date = last_used_info.get("AccessKeyLastUsed", {}).get(
                "LastUsedDate"
            )

            if not last_used_date or last_used_date < threshold_date:
                stale_keys.append(
                    {
                        "resource_name": user_name,
                        "access_key_id": key["AccessKeyId"],
                        "last_used_date": (
                            str(last_used_date) if last_used_date else "Never Used"
                        ),
                        "create_date": str(key["CreateDate"]),
                        "note": "Active key not used in the last 90+ days",
                    }
                )

    scan_meta_data_global_services["total_scanned"] += len(users)
    scan_meta_data_global_services["affected"] += len(stale_keys)
    scan_meta_data_global_services["Medium"] += len(stale_keys)
    if "IAM" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("IAM")

    return {
        "check_name": "Access Key Last Used > 90 Days Ago",
        "service": "IAM",
        "problem_statement": "Some access keys are active but were last used more than 90 days ago.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": stale_keys,
        "recommendation": "Disable or rotate keys not recently used to follow security best practices.",
        "additional_info": {"total_scanned": len(users), "affected": len(stale_keys)},
    }


def check_iam_access_analyzer(session, scan_meta_data):
    print("check_iam_access_analyzer")
    analyzer_client = session.client("accessanalyzer")

    analyzers = analyzer_client.list_analyzers()["analyzers"]
    findings_list = []

    if not analyzers:
        # Access Analyzer NOT enabled

        return {
            "check_name": "IAM Access Analyzer Check",
            "service": "IAM",
            "problem_statement": "IAM Access Analyzer is not enabled in this region.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": [],
            "recommendation": "Enable IAM Access Analyzer to detect resources shared with external entities.",
            "additional_info": {
                "total_scanned": 1,
                "affected": 0,
            },
        }

    # If analyzer is enabled
    analyzer_arn = analyzers[0]["arn"]

    findings = analyzer_client.list_findings(analyzerArn=analyzer_arn).get(
        "findings", []
    )

    for f in findings:
        findings_list.append(
            {
                "resource_name": f.get("resource"),
                "finding_id": f.get("id"),
                "principal": f.get("principal"),
                "isPublic": f.get("isPublic"),
                "condition": f.get("condition"),
                "status": f.get("status"),
                "description": (
                    f.get("createdAt").isoformat() if f.get("createdAt") else "N/A"
                ),
            }
        )

    return {
        "check_name": "IAM Access Analyzer Findings Check",
        "service": "IAM",
        "problem_statement": "IAM Access Analyzer findings detected.",
        "severity_score": 50,
        "severity_level": "Medium",
        "resources_affected": findings_list,
        "recommendation": "Review Access Analyzer findings and remediate resources shared with external principals if unintended.",
        "additional_info": {
            "total_scanned": 1,
            "affected": 0,
        },
    }
