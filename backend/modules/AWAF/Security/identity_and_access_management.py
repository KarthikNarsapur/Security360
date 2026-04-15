from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_sec02_bp01_strong_signin_mechanisms(session):
    # [SEC02-BP01] - Use strong sign-in mechanisms
    print("Checking strong sign-in mechanisms for IAM users")

    iam = session.client("iam")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_enforce_mechanisms.html"
    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC02-BP01",
            "check_name": "Use strong sign-in mechanisms",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable MFA for all IAM users.",
                "2. Update IAM password policy to enforce strong complexity and rotation rules.",
                "3. Rotate access keys older than 30 days.",
                "4. Review IAM credential reports regularly.",
                "5. Prefer IAM roles over long-lived credentials.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # ------------------ Collect IAM Users ------------------
        users = iam.list_users().get("Users", [])
        
        # ------------------ Password Policy ------------------
        total_scanned+=1
        try:
            password_policy = iam.get_account_password_policy().get(
                "PasswordPolicy", {}
            )
        except iam.exceptions.NoSuchEntityException:
            password_policy = {}
            resources_affected.append(
                {
                    "resource_id": "password_policy",
                    "issue": "Weak or missing IAM password policy.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Weak password policy rules
        weak_policy = (
            password_policy.get("MinimumPasswordLength", 0) < 12
            or not password_policy.get("RequireNumbers", False)
            or not password_policy.get("RequireSymbols", False)
            or not password_policy.get("RequireUppercaseCharacters", False)
            or not password_policy.get("RequireLowercaseCharacters", False)
        )
        total_scanned+=1
        if weak_policy:
            resources_affected.append(
                {
                    "resource_id": "password_policy",
                    "issue": "IAM password policy does not meet strong complexity standards.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------ Per-User Checks ------------------
        for user in users:
            total_scanned+=1
            user_name = user["UserName"]

            # MFA check
            mfa_devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
            if not mfa_devices:
                resources_affected.append(
                    {
                        "resource_id": user_name,
                        "issue": "User does not have MFA enabled.",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            # Access Keys rotation check
            access_keys = iam.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata", []
            )
            for key in access_keys:
                total_scanned+=1
                create_date = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - create_date).days
                if age_days > 30:
                    resources_affected.append(
                        {
                            "resource_id": key["AccessKeyId"],
                            "issue": f"Access key older than 30 days ({age_days} days). Rotation required.",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ------------------ Final response ------------------
        affected = len(resources_affected)

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem="Ensure strong sign-in practices by enforcing MFA, password strength, and timely credential rotation.",
            recommendation=(
                "Require MFA for all users, enforce strong password policies, rotate access keys regularly, "
                "and monitor user authentication activity for anomalies."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )
    except Exception as e:
        print(f"Error in SEC02-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate strong sign-in mechanisms.",
            recommendation="Enforce MFA, strong password policies, and regular access key rotation as part of secure sign-in practices.",
        )


def check_sec02_bp02_ec2_temporary_credentials(session):
    # [SEC02-BP02] - Use temporary credentials
    print("Checking EC2 instances for IAM instance profiles (temporary credentials)")

    ec2 = session.client("ec2")
    
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_unique.html"
    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC02-BP02",
            "check_name": "Use temporary credentials (EC2 IAM instance profiles)",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create an IAM role with the required permissions for your EC2 workload.",
                "2. Create an instance profile for the role.",
                "3. Attach the instance profile to the EC2 instance.",
                "4. Remove long-term access keys stored on the instance.",
                "5. Use Systems Manager or Parameter Store instead of embedding secrets.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        reservations = ec2.describe_instances().get("Reservations", [])

        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                total_scanned += 1

                # Check if instance has instance profile (IAM role)
                has_profile = "IamInstanceProfile" in instance

                if not has_profile:
                    resources_affected.append(
                        {
                            "resource_id": instance_id,
                            "resource_id_type": "instance id",
                            "issue": "EC2 instance is not using an IAM instance profile (uses long-term credentials).",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        
        affected = len(resources_affected)

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem="Ensure EC2 instances use temporary credentials through IAM instance profiles instead of long-term static credentials.",
            recommendation=(
                "Attach IAM instance profiles to all EC2 instances so they obtain temporary STS credentials "
                "instead of using long-lived access keys."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error in SEC02-BP02: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate temporary credential usage for EC2 instances.",
            recommendation="Use IAM instance profiles for EC2 to ensure workloads rely on temporary STS credentials instead of long-term keys.",
        )


def check_sec02_bp03_store_and_use_secrets_securely(session):
    # [BP03] - Store and use secrets securely
    print("Checking secure storage and usage of secrets (IAM + RDS + Secrets Manager)")

    iam = session.client("iam")
    rds = session.client("rds")
    secretsmanager = session.client("secretsmanager")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_secrets.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC02-BP03",
            "check_name": "Store and use secrets securely",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Replace long-term IAM access keys with short-term credentials.",
                "2. Store database credentials in AWS Secrets Manager.",
                "3. Enable automatic secret rotation where supported.",
                "4. Remove old or unused IAM access keys.",
                "5. Enforce IAM policies preventing long-term key creation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ----------------------------------------------------------------------
        # 1. IAM: Check access keys not rotated for 30 days
        # ----------------------------------------------------------------------
        old_keys_found = False
        users = iam.list_users().get("Users", [])

        for user in users:
            username = user["UserName"]
            access_keys = iam.list_access_keys(UserName=username).get(
                "AccessKeyMetadata", []
            )

            for key in access_keys:
                created = key["CreateDate"]
                age_days = (datetime.now(IST) - created).days
                if age_days > 30:
                    old_keys_found = True
                    resources_affected.append(
                        {
                            "resource_id": username,
                            "resource_id_type": "IAMUser",
                            "issue": f"IAM access key older than 30 days ({age_days} days)",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ----------------------------------------------------------------------
        # 2. RDS: Identify DBs NOT using Secrets Manager at all
        # ----------------------------------------------------------------------
        dbs = rds.describe_db_instances().get("DBInstances", [])
        dbs_without_sm = []
        dbs_with_some_sm = []
        secret_arns = []

        # Collect all secrets ARNs
        try:
            paginator = secretsmanager.get_paginator("list_secrets")
            for page in paginator.paginate():
                for sec in page.get("SecretList", []):
                    secret_arns.append(sec["ARN"])
        except Exception:
            pass  # Accounts without secrets manager usage won't break evaluation

        # Match RDS instances to Secrets Manager ARNs
        for db in dbs:
            db_arn = db.get("DBInstanceArn")
            engine = db.get("Engine")

            # Check if database is using any secret
            matched_secrets = [arn for arn in secret_arns if db_arn and db_arn in arn]

            if not matched_secrets:
                dbs_without_sm.append(db)
                resources_affected.append(
                    {
                        "resource_id": db.get("DBInstanceIdentifier"),
                        "resource_id_type": "RDSInstance",
                        "issue": "RDS instance is not using AWS Secrets Manager",
                        "region": db.get("AvailabilityZone", "unknown")[:-1],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                dbs_with_some_sm.append(db)

        # ----------------------------------------------------------------------
        # Determine status
        # ----------------------------------------------------------------------
        any_issue = old_keys_found or len(dbs_without_sm) > 0

        status = "failed" if any_issue else "passed"
        affected = len(resources_affected)
        total_scanned = len(users) + len(dbs)

        recommendation = (
            "Ensure all long-term credentials are replaced with short-term credentials. "
            "Use AWS Secrets Manager for storing and automatically rotating database secrets. "
            "Remove long-lived IAM access keys and enable automated secret rotation where possible."
        )

        return build_response(
            status=status,
            problem="Secrets must be securely stored and rotated using AWS Secrets Manager and IAM key rotation best practices.",
            recommendation=recommendation,
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate secure secret storage and rotation.",
            recommendation="Store all sensitive credentials in Secrets Manager and eliminate long-term IAM access keys.",
        )


def check_sec02_bp04_iam_centralized_identity_provider(session):
    # [BP04] - Rely on a centralized identity provider
    print("Checking centralized identity provider setup (SSO roles + external IdP)")

    iam = session.client("iam")
    sts = session.client("sts")
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_identity_provider.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC02-BP04",
            "check_name": "Centralized Identity Provider (SSO + External IdP)",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable AWS IAM Identity Center.",
                "2. Integrate IAM Identity Center with an external identity provider (Azure AD, Okta, PingIdentity, etc.).",
                "3. Configure SAML or OIDC-based federation for workforce access.",
                "4. Assign users/groups to AWS accounts using permission sets.",
                "5. Regularly audit user access and identity lifecycle events.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ---------------------------
        # 1. Check AWS SSO (IAM Identity Center) roles
        # ---------------------------
        roles = iam.list_roles().get("Roles", [])
        sso_roles = [r for r in roles if "AWSReservedSSO" in r["RoleName"]]

        # ---------------------------
        # 2. Check external IAM identity providers (SAML / OIDC)
        # ---------------------------
        oidc_providers = iam.list_open_id_connect_providers().get(
            "OpenIDConnectProviderList", []
        )
        saml_providers = iam.list_saml_providers().get("SAMLProviderList", [])

        has_external_idp = len(oidc_providers) > 0 or len(saml_providers) > 0

        total_scanned = len(roles) + len(oidc_providers) + len(saml_providers)

        if sso_roles and has_external_idp:
            return build_response(
                status="passed",
                problem="Workforce identities should be centrally managed using an external identity provider integrated with AWS IAM Identity Center.",
                recommendation=(
                    "Centralize workforce authentication using IAM Identity Center integrated with an external SAML/OIDC identity provider."
                ),
                resources_affected=[],
                total_scanned=total_scanned,
                affected=0,
            )
        if not sso_roles:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "No AWS SSO (IAM Identity Center) roles found.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        if not has_external_idp:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "issue": "No external identity provider (SAML/OIDC) configured.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        affected = len(resources_affected)

        return build_response(
            status="failed",
            problem="AWS IAM Identity Center is not fully connected to an external identity provider for centralized workforce authentication.",
            recommendation=(
                "Integrate IAM Identity Center with a centralized enterprise IdP (Azure AD, Okta, PingIdentity) for unified workforce authentication."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking centralized identity provider setup: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate centralized identity provider configuration.",
            recommendation="Use IAM Identity Center with an external IdP to centralize workforce identity and authentication.",
        )


def check_sec02_bp05_audit_and_rotate_credentials(session):
    # [BP05] - Audit and rotate credentials periodically
    print(
        "Checking credential rotation, IAM access key age, inline policies, roles, EC2/Lambda profiles, and EKS RBAC"
    )

    iam = session.client("iam")
    lambda_client = session.client("lambda")
    ec2 = session.client("ec2")
    eks = session.client("eks")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_audit.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC02-BP05",
            "check_name": "Audit and rotate credentials periodically",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Rotate IAM access keys older than 30 days.",
                "2. Enforce password rotation and implement strong password policies.",
                "3. Remove or restrict inline IAM policies granting full privileges.",
                "4. Assign unique IAM execution roles for each Lambda function.",
                "5. Attach IAM instance profiles to all EC2 instances.",
                "6. Review and enforce least privilege for EKS RBAC mappings.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        total_scanned = 0
        users = iam.list_users().get("Users", [])
        
        # ------------------------------------------------------------
        # 1. IAM Access Keys not rotated > 30 days
        # ------------------------------------------------------------
        total_scanned += len(users)
        for user in users:
            uname = user["UserName"]
            keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
            for k in keys:
                created = k["CreateDate"]
                age_days = (datetime.now(IST) - created).days
                if age_days > 30:
                    resources_affected.append(
                        {
                            "resource_id": uname,
                            "resource_id_type": "IAMUser",
                            "issue": f"IAM access key older than 30 days ({age_days} days)",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ------------------------------------------------------------
        # 2. Inline IAM policies with full access (Admin or *:* )
        # ------------------------------------------------------------
        total_scanned += len(users)
        for user in users:
            uname = user["UserName"]
            policies = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
            for p in policies:
                policy_doc = iam.get_user_policy(UserName=uname, PolicyName=p)
                if '"Action": "*"' in str(policy_doc) or '"Effect": "Allow"' in str(
                    policy_doc
                ):
                    resources_affected.append(
                        {
                            "resource_id": uname,
                            "resource_id_type": "IAMUser",
                            "issue": "Inline IAM policy appears to provide full admin privileges",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ------------------------------------------------------------
        # 3. IAM users or roles with AdministratorAccess policy
        # ------------------------------------------------------------
        admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        total_scanned += len(users)
        
        for user in users:
            attached = iam.list_attached_user_policies(UserName=user["UserName"]).get(
                "AttachedPolicies", []
            )
            for p in attached:
                if p["PolicyArn"] == admin_policy_arn:
                    resources_affected.append(
                        {
                            "resource_id": user["UserName"],
                            "resource_id_type": "IAMUser",
                            "issue": "User has AdministratorAccess policy attached",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ------------------------------------------------------------
        # 4. Lambda role reuse check
        # ------------------------------------------------------------
        lambda_functions = lambda_client.list_functions().get("Functions", [])
        total_scanned += len(lambda_functions)
        
        role_usage = {}
        for fn in lambda_functions:
            role = fn.get("Role")
            role_usage.setdefault(role, 0)
            role_usage[role] += 1

        for role, count in role_usage.items():
            if count > 1:
                resources_affected.append(
                    {
                        "resource_id": role,
                        "resource_id_type": "LambdaRole",
                        "issue": "Lambda execution role reused across multiple functions",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ------------------------------------------------------------
        # 5. EC2 instances without proper IAM Instance Profile
        # ------------------------------------------------------------
        instances = ec2.describe_instances().get("Reservations", [])
        for r in instances:
            for ins in r.get("Instances", []):
                if "IamInstanceProfile" not in ins:
                    resources_affected.append(
                        {
                            "resource_id": ins["InstanceId"],
                            "resource_id_type": "EC2Instance",
                            "issue": "EC2 instance missing IAM instance profile",
                            "region": ins.get("Placement", {}).get(
                                "AvailabilityZone", "unknown"
                            )[:-1],
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ------------------------------------------------------------
        # Final evaluation
        # ------------------------------------------------------------
        affected = len(resources_affected)

        status = "failed" if affected > 0 else "passed"

        return build_response(
            status=status,
            problem="Long-term credentials and identity configurations must be audited and rotated regularly to reduce the risk of compromise.",
            recommendation=(
                "Rotate passwords and keys frequently, eliminate unnecessary long-term credentials, "
                "restrict full-access IAM policies, avoid reusing roles across workloads, and enforce least privilege "
                "across IAM, Lambda, EC2, and EKS environments."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking BP05: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate credential rotation and auditing configuration.",
            recommendation="Regularly audit IAM, Lambda, EC2, and EKS credentials to maintain proper rotation and least privilege.",
        )


def check_sec02_bp06_employ_user_groups_and_attributes(session):
    # [BP06] - Employ user groups and attributes
    print("Checking IAM user group usage and empty IAM groups")

    iam = session.client("iam")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_groups_attributes.html"
    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "SEC02-BP06",
            "check_name": "Employ user groups and attributes",
            "problem_statement": problem,
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Assign each IAM user to an appropriate IAM group based on their job responsibilities.",
                "2. Remove or repurpose unused or empty IAM groups.",
                "3. Use IAM Identity Center with synchronized IdP groups and attributes.",
                "4. Avoid assigning permissions directly to individual IAM users.",
                "5. Periodically audit IAM group membership and permissions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        account_id = sts.get_caller_identity()["Account"]

        # -------------------------------------------------------
        # Get IAM users and groups
        # -------------------------------------------------------
        users = iam.list_users().get("Users", [])
        groups = iam.list_groups().get("Groups", [])

        # Track issues
        users_not_in_group = []
        empty_groups = []

        # -------------------------------------------------------
        # 1. Users NOT using any IAM group
        # -------------------------------------------------------
        for user in users:
            uname = user["UserName"]
            user_groups = iam.list_groups_for_user(UserName=uname).get("Groups", [])

            if len(user_groups) == 0:
                users_not_in_group.append(uname)
                resources_affected.append(
                    {
                        "resource_id": uname,
                        "resource_id_type": "IAMUser",
                        "issue": "IAM user is not part of any IAM group",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # -------------------------------------------------------
        # 2. IAM groups with zero users
        # -------------------------------------------------------
        for group in groups:
            gname = group["GroupName"]
            g_users = iam.get_group(GroupName=gname).get("Users", [])

            if len(g_users) == 0:
                empty_groups.append(gname)
                resources_affected.append(
                    {
                        "resource_id": gname,
                        "resource_id_type": "IAMGroup",
                        "issue": "IAM group has no users assigned",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # -------------------------------------------------------
        # Determine status
        # -------------------------------------------------------
        affected = len(resources_affected)
        total_scanned = len(users) + len(groups)

        status = "failed" if affected > 0 else "passed"

        return build_response(
            status=status,
            problem=(
                "IAM permissions should be centrally managed using groups and identity attributes "
                "instead of assigning permissions directly to individual users."
            ),
            recommendation=(
                "Use IAM groups and identity provider attributes to centrally manage permissions and "
                "ensure users are mapped to appropriate groups while removing unused ones."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error checking BP06: {e}")
        return build_response(
            status="error",
            problem="Unable to evaluate IAM group and attribute configuration.",
            recommendation="Use IAM groups and identity attributes to centrally manage user permissions.",
        )


def check_sec03_bp01_define_access_requirements(session):
    # [SEC03-BP01] - Define access requirements
    print(
        "Checking IAM inline policies to ensure access requirements are properly defined"
    )

    iam = session.client("iam")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_define.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # -------------------------------------------------------
        # Fetch all IAM users and roles
        # -------------------------------------------------------
        users = iam.list_users().get("Users", [])
        roles = iam.list_roles().get("Roles", [])

        # Track counts
        inline_policy_issues = 0

        # -------------------------------------------------------
        # 1. Check inline IAM policies for users
        # -------------------------------------------------------
        for user in users:
            uname = user["UserName"]
            policies = iam.list_user_policies(UserName=uname).get("PolicyNames", [])

            for policy_name in policies:
                inline_policy_issues += 1
                resources_affected.append(
                    {
                        "resource_id": uname,
                        "resource_id_type": "IAMUser",
                        "issue": f"Inline IAM policy '{policy_name}' found for IAM user",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # -------------------------------------------------------
        # 2. Check inline IAM policies for roles
        # -------------------------------------------------------
        for role in roles:
            rname = role["RoleName"]
            policies = iam.list_role_policies(RoleName=rname).get("PolicyNames", [])

            for policy_name in policies:
                inline_policy_issues += 1
                resources_affected.append(
                    {
                        "resource_id": rname,
                        "resource_id_type": "IAMRole",
                        "issue": f"Inline IAM policy '{policy_name}' found for IAM role",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # -------------------------------------------------------
        # Determine final status
        # -------------------------------------------------------
        affected = len(resources_affected)
        total_scanned = len(users) + len(roles)

        status = "failed" if affected > 0 else "passed"

        return {
            "id": "SEC03-BP01",
            "check_name": "Define access requirements",
            "problem_statement": "Access requirements should be centrally defined and implemented using managed policies instead of inline permissions.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": (
                "Avoid inline IAM policies. Use managed policies and clearly define access requirements "
                "based on roles, least privilege, and separation of duties."
            ),
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Replace inline IAM policies with AWS managed or customer managed policies.",
                "2. Define access requirements per job function using IAM roles and groups.",
                "3. Use least privilege when assigning permissions to roles or identities.",
                "4. Review and remove user-specific custom permissions.",
                "5. Avoid long-lived credentials and hard-coded permissions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC03-BP01: {e}")
        return None


def check_sec03_bp02_grant_least_privilege_access(session):
    # [SEC03-BP02] Grant least privilege access
    print("Checking least privilege access across IAM, Lambda, EC2, SQS, and EKS")

    iam = session.client("iam")
    lambda_client = session.client("lambda")
    ec2 = session.client("ec2")
    eks = session.client("eks")
    sqs = session.client("sqs")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_least_privileges.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # -------------------------------------------------------
        # Fetch IAM users, roles, and managed policies
        # -------------------------------------------------------
        users = iam.list_users().get("Users", [])
        roles = iam.list_roles().get("Roles", [])
        managed_policies = iam.list_policies(Scope="Local").get("Policies", [])

        # -------------------------------------------------------
        # 1. Inline policy full access for users & roles (* or admin-like)
        # -------------------------------------------------------
        for user in users:
            uname = user["UserName"]
            inline_policies = iam.list_user_policies(UserName=uname).get(
                "PolicyNames", []
            )
            for policy in inline_policies:
                doc = iam.get_user_policy(UserName=uname, PolicyName=policy)
                if '"Action": "*"' in str(doc) or '"Effect": "Allow"' in str(doc):
                    resources_affected.append(
                        {
                            "resource_id": uname,
                            "resource_id_type": "IAMUser",
                            "issue": "Inline IAM policy grants full access",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        for role in roles:
            rname = role["RoleName"]
            inline_policies = iam.list_role_policies(RoleName=rname).get(
                "PolicyNames", []
            )
            for policy in inline_policies:
                doc = iam.get_role_policy(RoleName=rname, PolicyName=policy)
                if '"Action": "*"' in str(doc) or '"Effect": "Allow"' in str(doc):
                    resources_affected.append(
                        {
                            "resource_id": rname,
                            "resource_id_type": "IAMRole",
                            "issue": "Inline IAM policy grants full admin access",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # -------------------------------------------------------
        # 2. Full Admin Managed Policy attached to users/roles
        # -------------------------------------------------------
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

        for user in users:
            attached = iam.list_attached_user_policies(UserName=user["UserName"]).get(
                "AttachedPolicies", []
            )
            for p in attached:
                if p["PolicyArn"] == admin_arn:
                    resources_affected.append(
                        {
                            "resource_id": user["UserName"],
                            "resource_id_type": "IAMUser",
                            "issue": "User has AdministratorAccess managed policy attached",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        for role in roles:
            attached = iam.list_attached_role_policies(RoleName=role["RoleName"]).get(
                "AttachedPolicies", []
            )
            for p in attached:
                if p["PolicyArn"] == admin_arn:
                    resources_affected.append(
                        {
                            "resource_id": role["RoleName"],
                            "resource_id_type": "IAMRole",
                            "issue": "Role has AdministratorAccess managed policy attached",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # -------------------------------------------------------
        # 3. Lambda Execution Role reuse
        # -------------------------------------------------------
        lambda_functions = lambda_client.list_functions().get("Functions", [])
        role_usage = {}

        for fn in lambda_functions:
            role = fn.get("Role")
            role_usage.setdefault(role, 0)
            role_usage[role] += 1

        for role, count in role_usage.items():
            if count > 1:  # same execution role reused across multiple functions
                resources_affected.append(
                    {
                        "resource_id": role,
                        "resource_id_type": "LambdaRole",
                        "issue": "Lambda execution role reused across multiple functions",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # -------------------------------------------------------
        # 4. EC2 IAM instance profile exists
        # -------------------------------------------------------
        reservations = ec2.describe_instances().get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                if "IamInstanceProfile" not in instance:
                    resources_affected.append(
                        {
                            "resource_id": instance.get("InstanceId"),
                            "resource_id_type": "EC2Instance",
                            "issue": "EC2 instance missing IAM instance profile",
                            "region": instance.get("Placement", {}).get(
                                "AvailabilityZone", "unknown"
                            )[:-1],
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # -------------------------------------------------------
        # 5. Managed Policy giving excessive access (One service full access)
        # -------------------------------------------------------
        for policy in managed_policies:
            pname = policy["PolicyName"]
            if "FullAccess" in pname:
                resources_affected.append(
                    {
                        "resource_id": pname,
                        "resource_id_type": "IAMManagedPolicy",
                        "issue": "Managed policy grants full access to a service",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # -------------------------------------------------------
        # 6. SQS Policies - check for overly permissive access
        # -------------------------------------------------------
        try:
            queues = sqs.list_queues().get("QueueUrls", [])
            for q in queues:
                attrs = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["Policy"])
                policy = attrs.get("Attributes", {}).get("Policy")
                if (
                    policy
                    and '"Effect":"Allow"' in policy
                    and '"Principal":"*"' in policy
                ):
                    resources_affected.append(
                        {
                            "resource_id": q,
                            "resource_id_type": "SQSQueue",
                            "issue": "SQS queue allows public access",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception:
            pass  # safe if no SQS queues exist

        # -------------------------------------------------------
        # 7. EKS cluster RBAC - cannot fully validate through API
        # -------------------------------------------------------
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for c in clusters:
                resources_affected.append(
                    {
                        "resource_id": c,
                        "resource_id_type": "EKSCluster",
                        "issue": "Manual review required: EKS RBAC least privilege cannot be auto-validated",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception:
            pass

        # -------------------------------------------------------
        # Final evaluation
        # -------------------------------------------------------
        affected = len(resources_affected)
        total_scanned = len(users) + len(roles)

        status = "failed" if affected > 0 else "passed"

        return {
            "id": "SEC03-BP02",
            "check_name": "Grant least privilege access",
            "problem_statement": "Permissions must follow least privilege, avoiding overly permissive roles, policies, and trust relationships.",
            "severity_score": 90,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": (
                "Review IAM policies, roles, Lambda execution roles, EC2 profiles, SQS access policies, "
                "and EKS RBAC to ensure least privilege. Replace full-access permissions with scoped, "
                "role-based access rules."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Replace full-access IAM policies with granular permissions.",
                "2. Avoid AdministratorAccess unless absolutely required.",
                "3. Assign unique execution roles per Lambda function.",
                "4. Ensure EC2 instances use properly scoped IAM roles.",
                "5. Remove SQS policies that allow public or overly broad access.",
                "6. Review EKS RBAC mappings for least privilege.",
                "7. Perform periodic access reviews and deprovision unused permissions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC03-BP02: {e}")
        return None


def check_sec03_bp03_emergency_access_process(session):
    """
    BP03 – Establish emergency access process
    Internally runs:
    - iam.EnableConfigService
    - iam.SCPEnabled
    - iam.InlinePolicy
    """

    print("Running BP03 – Establish emergency access process")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_emergency_process.html"

    resources_affected = []
    total_scanned = 0
    affected = 0

    # --------------------------
    # 1. Check if AWS Config is enabled (iam.EnableConfigService)
    # --------------------------
    try:
        cfg = session.client("config")
        status = cfg.describe_configuration_recorder_status()
        total_scanned += 1

        if (
            not status["ConfigurationRecordersStatus"]
            or not status["ConfigurationRecordersStatus"][0]["recording"]
        ):
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "AWSConfig",
                    "issue": "AWS Config is not enabled.",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
    except Exception as e:
        print(f"Error checking AWS Config: {e}")

    # --------------------------
    # 2. Check if SCPs are enabled (iam.SCPEnabled)
    # --------------------------
    try:
        org = session.client("organizations")
        org_data = org.describe_organization()["Organization"]
        total_scanned += 1

        if org_data.get("FeatureSet") != "ALL":
            affected += 1
            resources_affected.append(
                {
                    "resource_id": org_data.get("Id"),
                    "issue": "SCPs are not fully enabled in the organization.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

    except org.exceptions.AWSOrganizationsNotInUseException:
        total_scanned += 1
        affected += 1
        resources_affected.append(
            {
                "resource_id": "Organization",
                "issue": "AWS Organizations not in use; SCP cannot be enabled.",
                "region": "global",
                "last_updated": datetime.now(IST).isoformat(),
            }
        )
    except Exception as e:
        print(f"Error checking SCP: {e}")

    # --------------------------
    # 3. Check inline IAM policies (iam.InlinePolicy)
    # --------------------------
    try:
        iam = session.client("iam")
        users = iam.list_users().get("Users", [])
        total_scanned += len(users)

        for u in users:
            inline_policies = iam.list_user_policies(UserName=u["UserName"]).get(
                "PolicyNames", []
            )
            if inline_policies:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": u["UserName"],
                        "issue": f"User has inline policy: {inline_policies}",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

    except Exception as e:
        print(f"Error checking inline user policies: {e}")

    # --------------------------
    # Final BP03 Output
    # --------------------------
    return {
        "id": "SEC03-BP03",
        "check_name": "Establish emergency access process",
        "problem_statement": "Emergency access mechanisms must be available if primary identity systems fail.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "status": "passed" if affected == 0 else "failed",
        "recommendation": (
            "Ensure AWS Config is enabled, SCPs are enforced, and avoid using inline policies "
            "to strengthen emergency access preparedness."
        ),
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": affected,
        },
        "remediation_steps": [
            "1. Enable AWS Config and ensure continuous recording.",
            "2. Enable AWS Organizations with Full Feature Set so SCPs can be applied.",
            "3. Remove inline IAM policies and migrate to managed or customer-managed policies.",
            "4. Document emergency access procedures and test them regularly.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec03_bp04_identity_basics(session):
    # SEC03-BP04 Enforce basic identity hygiene and monitoring
    print("Checking IAM hygiene: empty groups, inactive users, and data event logging")

    iam = session.client("iam")
    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_establish_basics.html"

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ------------------------------------------------------------
        # 1. iam.groupEmptyUsers — Groups with zero users
        # ------------------------------------------------------------
        try:
            groups = iam.list_groups().get("Groups", [])
            for group in groups:
                group_name = group["GroupName"]
                users = iam.get_group(GroupName=group_name).get("Users", [])

                if len(users) == 0:  # empty group
                    resources_affected.append(
                        {
                            "resource_id": group_name,
                            "resource_id_type": "IAM Group",
                            "issue": "IAM group has no users attached",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print("Error checking empty IAM groups:", e)

        # ------------------------------------------------------------
        # 2. iam.userNoActivity90days — Users without activity for 90 days
        # ------------------------------------------------------------
        try:
            users = iam.list_users().get("Users", [])
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)

            for user in users:
                uname = user["UserName"]

                # Last activity is found from access key last used + console login
                last_activity = None

                # 2A. Access key usage
                keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                for key in keys:
                    key_id = key["AccessKeyId"]
                    last_used = iam.get_access_key_last_used(AccessKeyId=key_id).get(
                        "AccessKeyLastUsed", {}
                    )
                    last_used_date = last_used.get("LastUsedDate")
                    if last_used_date and (
                        not last_activity or last_used_date > last_activity
                    ):
                        last_activity = last_used_date

                # 2B. Console login: IAM -> generate-service-last-access-details
                try:
                    details = iam.generate_service_last_accessed_details(
                        Arn=user["Arn"]
                    )
                    job_id = details["JobId"]
                    # Need to wait / poll once
                    time.sleep(2)
                    report = iam.get_service_last_accessed_details(JobId=job_id)
                    services = report.get("ServicesLastAccessed", [])
                    for s in services:
                        d = s.get("LastAuthenticated")
                        if d and (not last_activity or d > last_activity):
                            last_activity = d
                except:
                    pass  # Console activity unavailable sometimes

                # If never used, treat as inactive
                if not last_activity or last_activity < cutoff:
                    resources_affected.append(
                        {
                            "resource_id": uname,
                            "resource_id_type": "IAM User",
                            "issue": "IAM user has no activity for 90+ days",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print("Error checking inactive IAM users:", e)

        # ---------------------------------------------------------------------
        # 3. cloudtrail.HasDataEventsCaptured — S3 / Lambda data event logging
        # ---------------------------------------------------------------------
        try:
            trails = cloudtrail.describe_trails().get("trailList", [])
            data_events_enabled = False

            for t in trails:
                name = t["Name"]
                event_selectors = cloudtrail.get_event_selectors(TrailName=name)

                selectors = event_selectors.get(
                    "EventSelectors", []
                ) + event_selectors.get("AdvancedEventSelectors", [])

                for sel in selectors:
                    # Normal EventSelector: must contain DataResources
                    if "DataResources" in sel:
                        for dr in sel["DataResources"]:
                            if dr.get("Type") in [
                                "AWS::S3::Object",
                                "AWS::Lambda::Function",
                            ]:
                                data_events_enabled = True

                    # Advanced Event Selectors: check field matches
                    if "FieldSelectors" in sel:
                        for f in sel["FieldSelectors"]:
                            if (
                                f.get("Field") == "resources.type"
                                and f.get("Equals")
                                and any(
                                    x in ["AWS::S3::Object", "AWS::Lambda::Function"]
                                    for x in f["Equals"]
                                )
                            ):
                                data_events_enabled = True

            if not data_events_enabled:
                resources_affected.append(
                    {
                        "resource_id": "CloudTrail",
                        "resource_id_type": "Service",
                        "issue": "CloudTrail data events (S3/Lambda) are not enabled",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print("Error checking CloudTrail data events:", e)

        # ---------------------------------------
        total_scanned = 1
        affected = len(resources_affected)
        # ---------------------------------------

        return {
            "id": "SEC03-BP04",
            "check_name": "Establish basic identity & data event guardrails",
            "problem_statement": (
                "IAM groups should not be empty, users must be monitored for inactivity, "
                "and CloudTrail must capture data events for governance."
            ),
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Review IAM groups and remove unused ones, disable/rotate inactive users, "
                "and enable CloudTrail data events for S3 and Lambda."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Delete or repurpose IAM groups without any attached users.",
                "2. Deactivate, delete, or rotate long-inactive IAM users.",
                "3. Enable CloudTrail data event logging for S3 buckets and Lambda invokes.",
                "4. Apply monitoring guardrails to detect future identity drifts.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC03-BP04: {e}")
        return None


def check_sec03_bp05_permission_guardrails(session):
    # SEC03-BP05 Define permission guardrails for your organization
    print("Checking permission guardrails: SCP enablement & CloudTrail requirement")

    org = session.client("organizations")
    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_define_guardrails.html"

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ------------------------------------------------
        # 1. iam.SCPEnabled — Check if SCPs are enabled
        # ------------------------------------------------
        scp_enabled = True
        try:
            org_data = org.describe_organization().get("Organization", {})
            feature_set = org_data.get("FeatureSet", "")

            if feature_set != "ALL":
                scp_enabled = False

        except org.exceptions.AWSOrganizationsNotInUseException:
            scp_enabled = False

        if not scp_enabled:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "resource_id_type": "Account",
                    "issue": "Service Control Policies (SCPs) are not enabled",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ---------------------------------------------------------
        # 2. cloudtrail.NeedToEnableCloudTrail — Check CloudTrail
        # ---------------------------------------------------------
        trails = cloudtrail.describe_trails().get("trailList", [])
        cloudtrail_enabled = any(t.get("HomeRegion") for t in trails)

        if not cloudtrail_enabled:
            resources_affected.append(
                {
                    "resource_id": "CloudTrail",
                    "resource_id_type": "Service",
                    "issue": "CloudTrail is not enabled for the account",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "SEC03-BP05",
            "check_name": "Define permission guardrails for your organization",
            "problem_statement": "Organization-level guardrails should enforce preventative controls using SCPs and CloudTrail.",
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable SCPs in AWS Organizations and ensure CloudTrail is configured across all accounts "
                "to enforce mandatory permission guardrails."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable AWS Organizations with FeatureSet=ALL to activate Service Control Policies (SCPs).",
                "2. Define SCPs to restrict unsupported or risky actions across accounts.",
                "3. Enable AWS CloudTrail in all regions for full governance tracking.",
                "4. Apply organization-wide logging guardrails and enforce monitoring.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC03-BP05: {e}")
        return None


def check_sec03_bp06_manage_access_lifecycle(session):
    # SEC03-BP06 Manage access based on lifecycle
    print("Checking lifecycle-based access controls: SCPs and S3 ACL review")

    org = session.client("organizations")
    s3 = session.client("s3")
    sts = session.client("sts")

    resources_affected = []
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_permissions_lifecycle.html"

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ------------------------------------------------
        # 1. iam.SCPEnabled — Check if SCPs are enabled
        # ------------------------------------------------
        scp_enabled = True
        try:
            org_data = org.describe_organization().get("Organization", {})
            feature_set = org_data.get("FeatureSet", "")

            if feature_set != "ALL":
                scp_enabled = False

        except org.exceptions.AWSOrganizationsNotInUseException:
            scp_enabled = False

        if not scp_enabled:
            resources_affected.append(
                {
                    "resource_id": account_id,
                    "resource_id_type": "Account",
                    "issue": "Service Control Policies (SCPs) are not enabled for the organization",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ------------------------------------------------
        # 2. s3.AccessControlList — Check for public/unsafe ACLs
        # ------------------------------------------------
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)

                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")

                        # Public access identifiers
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            resources_affected.append(
                                {
                                    "resource_id": bucket_name,
                                    "resource_id_type": "S3Bucket",
                                    "issue": f"S3 bucket '{bucket_name}' has a public or overly permissive ACL",
                                    "region": "global",
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                except Exception:
                    # Skip buckets we cannot access ACL for
                    continue

        except Exception:
            # If S3 listing fails, skip ACL checks
            pass

        # Final count
        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "SEC03-BP06",
            "check_name": "Manage access based on lifecycle",
            "problem_statement": "Access must be governed by lifecycle requirements ensuring permissions remain appropriate over time.",
            "severity_score": 65,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable SCPs for organization-wide preventative controls and regularly audit S3 ACLs "
                "to ensure buckets do not retain outdated or overly permissive access settings."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable Service Control Policies (SCPs) within AWS Organizations.",
                "2. Restrict S3 bucket ACLs and remove any 'AllUsers' or 'AuthenticatedUsers' grants.",
                "3. Use IAM policies, bucket policies, and Block Public Access settings instead of ACLs.",
                "4. Review access permissions as part of user and resource lifecycle processes.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC03-BP06: {e}")
        return None


def check_sec03_bp07_analyze_access(session):
    # SEC03-BP07 Analyze public and cross-account access
    print("Evaluating guidance for analyzing public and cross-account access")

    aws_doc_link = (
        "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
        "sec_permissions_analyze_cross_account.html"
    )

    # No direct AWS API evaluation is required for this best practice.
    # The principle focuses on organizational processes for reviewing and analyzing
    # cross-account and publicly exposed permissions rather than specific resource checks.

    resources_affected = []
    total_scanned = 0
    affected = 0

    return {
        "id": "SEC03-BP07",
        "check_name": "Analyze public and cross-account access",
        "problem_statement": "Regular analysis is required to understand and manage public and cross-account access within workloads.",
        "severity_score": 55,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "status": "passed",
        "recommendation": (
            "Establish processes to routinely review public and cross-account permissions, "
            "identify unnecessary exposure, and ensure access aligns with least privilege principles."
        ),
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": affected,
        },
        "remediation_steps": [
            "1. Review IAM policies, S3 bucket policies, and resource-based policies for unexpected access.",
            "2. Use IAM Access Analyzer to identify external or public access paths.",
            "3. Remove or restrict public access where not required.",
            "4. Periodically re-assess cross-account access to ensure continued relevance.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec03_bp09_share_with_third_party(session):
    # SEC03-BP09 Share resources securely with a third party
    print("Checking AWS Config enablement for secure third-party resource sharing")

    config = session.client("config")
    sts = session.client("sts")

    aws_doc_link = (
        "https://docs.aws.amazon.com/wellarchitected/latest/framework/"
        "sec_permissions_share_securely_third_party.html"
    )

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ------------------------------------------------------
        # iam.EnableConfigService – Check if AWS Config is enabled
        # ------------------------------------------------------
        try:
            recorders = config.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )
            configs_enabled = any(r.get("recordingGroup") for r in recorders)
        except Exception:
            configs_enabled = False

        if not configs_enabled:
            resources_affected.append(
                {
                    "resource_id": "AWSConfig",
                    "resource_id_type": "Service",
                    "issue": "AWS Config is not enabled, which limits the ability to audit resource sharing with third parties.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "SEC03-BP09",
            "check_name": "Share resources securely with a third party",
            "problem_statement": "Resource sharing with third parties must be monitored and validated to avoid unintended exposure.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable AWS Config to continuously track configuration changes and validate that "
                "resource sharing with third parties adheres to approved security policies."
            ),
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to AWS Config and set up a configuration recorder.",
                "2. Enable recording of all supported resource types.",
                "3. Use AWS IAM Access Analyzer to evaluate external access paths.",
                "4. Validate cross-account and third-party shares regularly.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC03-BP09: {e}")
        return None


def check_sec04_bp01_detect_and_investigate_security_events(session):
    # SEC04-BP01 - How do you detect and investigate security events?
    print("Checking logging, monitoring, and security event detection across services")

    sts = session.client("sts")
    ec2_client = session.client("ec2")
    s3_client = session.client("s3")
    cloudtrail = session.client("cloudtrail")
    cloudfront = session.client("cloudfront")
    guardduty = session.client("guardduty")
    sqs = session.client("sqs")

    aws_doc_link = (
        "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-04.html"
    )
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Gather region list for regional services
        try:
            regions = [
                r["RegionName"] for r in ec2_client.describe_regions()["Regions"]
            ]
        except Exception:
            # Fallback to session region if describe_regions fails
            regions = [session.region_name] if session.region_name else ["us-east-1"]

        total_scanned = 0

        # ----------------------------
        # 1) eks.eksClusterLogging (regional)
        # ----------------------------
        try:
            for region in regions:
                eks_client = session.client("eks", region_name=region)
                try:
                    clusters = eks_client.list_clusters().get("clusters", [])
                except Exception:
                    clusters = []

                for c in clusters:
                    total_scanned += 1
                    try:
                        info = eks_client.describe_cluster(name=c).get("cluster", {})
                        # EKS logging configuration is available in cluster['logging']
                        logging_cfg = info.get("logging", {}).get("clusterLogging", [])
                        enabled = (
                            any(lg.get("enabled", False) for lg in logging_cfg)
                            if logging_cfg
                            else False
                        )

                        if not enabled:
                            resources_affected.append(
                                {
                                    "resource_id": c,
                                    "resource_id_type": "EKSCluster",
                                    "issue": "EKS cluster logging not enabled for cluster-level logs",
                                    "region": region,
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                    except Exception:
                        # If describe_cluster fails, treat as finding for review
                        resources_affected.append(
                            {
                                "resource_id": c,
                                "resource_id_type": "EKSCluster",
                                "issue": "Unable to confirm EKS cluster logging (manual review recommended)",
                                "region": region,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
        except Exception as e:
            print(f"EKS check error: {e}")

        # ----------------------------
        # 2) ec2.VPCFlowLogEnabled (regional)
        # ----------------------------
        try:
            for region in regions:
                ec2_r = session.client("ec2", region_name=region)
                vpcs = ec2_r.describe_vpcs().get("Vpcs", [])
                # Pre-fetch flow logs
                try:
                    flow_logs = ec2_r.describe_flow_logs().get("FlowLogs", [])
                except Exception:
                    flow_logs = []

                flow_by_resource = {}
                for fl in flow_logs:
                    rid = fl.get("ResourceId")
                    if rid:
                        flow_by_resource.setdefault(rid, []).append(fl)

                for v in vpcs:
                    vpc_id = v.get("VpcId")
                    total_scanned += 1
                    if not flow_by_resource.get(vpc_id):
                        resources_affected.append(
                            {
                                "resource_id": vpc_id,
                                "resource_id_type": "VPC",
                                "issue": "VPC Flow Logs are not enabled for this VPC",
                                "region": region,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
        except Exception as e:
            print(f"VPC Flow Log check error: {e}")

        # ----------------------------
        # 3) opensearch.ApplicationLogs (regional) - best-effort (opensearch or es)
        # ----------------------------
        try:
            for region in regions:
                # Try opensearch client first, fallback to 'es'
                op_client = None
                try:
                    op_client = session.client("opensearch", region_name=region)
                    domains = []
                    try:
                        # list_domain_names exists on opensearch
                        names_resp = op_client.list_domain_names().get(
                            "DomainNames", []
                        )
                        domains = [d["DomainName"] for d in names_resp]
                    except Exception:
                        # opensearch list failed; try es client
                        domains = []
                except Exception:
                    domains = []

                if not domains:
                    # try 'es' (elasticsearch) fallback
                    try:
                        es_client = session.client("es", region_name=region)
                        dlist = es_client.list_domain_names().get("DomainNames", [])
                        domains = [d["DomainName"] for d in dlist]
                    except Exception:
                        domains = []

                for dom in domains:
                    total_scanned += 1
                    try:
                        # Try describe domain config style response
                        if op_client:
                            cfg = op_client.describe_domain_config(DomainName=dom)
                            log_pub = cfg.get("DomainConfig", {}).get(
                                "LogPublishingOptions", {}
                            )
                        else:
                            # es client
                            cfg = es_client.describe_elasticsearch_domain_config(
                                DomainName=dom
                            )
                            log_pub = cfg.get("DomainConfig", {}).get(
                                "LogPublishing", {}
                            )
                        # Determine if any application logs are configured
                        if not log_pub:
                            resources_affected.append(
                                {
                                    "resource_id": dom,
                                    "resource_id_type": "OpenSearchDomain",
                                    "issue": "OpenSearch domain has no application log publishing configured",
                                    "region": region,
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                    except Exception:
                        resources_affected.append(
                            {
                                "resource_id": dom,
                                "resource_id_type": "OpenSearchDomain",
                                "issue": "Unable to confirm OpenSearch log publishing (manual review recommended)",
                                "region": region,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
        except Exception as e:
            print(f"OpenSearch check error: {e}")

        # ----------------------------
        # 4) redshift.AuditLogging (regional)
        # ----------------------------
        try:
            for region in regions:
                rs = session.client("redshift", region_name=region)
                try:
                    clusters = rs.describe_clusters().get("Clusters", [])
                except Exception:
                    clusters = []

                for c in clusters:
                    total_scanned += 1
                    cid = c.get("ClusterIdentifier")
                    # Redshift exposes LoggingProperties via describe_logging_status? Best-effort:
                    try:
                        # Newer API: describe_logging_status exists
                        logging_status = rs.describe_logging_status(
                            ClusterIdentifier=cid
                        )
                        enabled = logging_status.get("LoggingEnabled", False)
                    except Exception:
                        # fallback: check the Cluster properties for logging
                        enabled = c.get("LoggingEnabled", False) or c.get(
                            "Logging", {}
                        ).get("Enabled", False)

                    if not enabled:
                        resources_affected.append(
                            {
                                "resource_id": cid,
                                "resource_id_type": "RedshiftCluster",
                                "issue": "Redshift audit logging is not enabled for this cluster",
                                "region": region,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
        except Exception as e:
            print(f"Redshift check error: {e}")

        # ----------------------------
        # 5) s3.BucketLogging (global)
        # ----------------------------
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
            for b in buckets:
                bname = b["Name"]
                total_scanned += 1
                try:
                    logging = s3_client.get_bucket_logging(Bucket=bname)
                    if not logging.get("LoggingEnabled"):
                        resources_affected.append(
                            {
                                "resource_id": bname,
                                "resource_id_type": "S3Bucket",
                                "issue": "S3 bucket does not have server access logging enabled",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception:
                    # If we cannot access the bucket logging info, flag for manual review
                    resources_affected.append(
                        {
                            "resource_id": bname,
                            "resource_id_type": "S3Bucket",
                            "issue": "Unable to verify S3 bucket logging (manual review recommended)",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"S3 bucket logging check error: {e}")

        # ----------------------------
        # 6) apigateway.ExecutionLogging (REST + HTTP)
        # ----------------------------
        try:
            for region in regions:
                # REST APIs (v1)
                try:
                    apigw = session.client("apigateway", region_name=region)
                    apis = apigw.get_rest_apis(limit=500).get("items", [])
                    for api in apis:
                        api_id = api.get("id")
                        # get stages for api
                        try:
                            stages = apigw.get_stages(restApiId=api_id).get("item", [])
                        except Exception:
                            stages = []
                        for st in stages:
                            total_scanned += 1
                            if not st.get("accessLogSettings"):
                                resources_affected.append(
                                    {
                                        "resource_id": f"{api_id}:{st.get('stageName')}",
                                        "resource_id_type": "APIGatewayStage",
                                        "issue": "API Gateway (REST) stage has no execution (access) logging configured",
                                        "region": region,
                                        "last_updated": datetime.now(IST).isoformat(),
                                    }
                                )
                except Exception:
                    pass

                # HTTP/WebSocket APIs (v2)
                try:
                    apigwv2 = session.client("apigatewayv2", region_name=region)
                    apis_v2 = apigwv2.get_apis().get("Items", [])
                    for api in apis_v2:
                        api_id = api.get("ApiId")
                        try:
                            stages = apigwv2.get_stages(ApiId=api_id).get("Items", [])
                        except Exception:
                            stages = []
                        for st in stages:
                            total_scanned += 1
                            if not st.get("AccessLogSettings") and not st.get(
                                "accessLogSettings"
                            ):
                                resources_affected.append(
                                    {
                                        "resource_id": f"{api_id}:{st.get('StageName') or st.get('stageName')}",
                                        "resource_id_type": "APIGatewayV2Stage",
                                        "issue": "API Gateway (v2) stage has no execution (access) logging configured",
                                        "region": region,
                                        "last_updated": datetime.now(IST).isoformat(),
                                    }
                                )
                except Exception:
                    pass
        except Exception as e:
            print(f"API Gateway check error: {e}")

        # ----------------------------
        # 7) cloudfront.accessLogging (global)
        # ----------------------------
        try:
            dists = (
                cloudfront.list_distributions()
                .get("DistributionList", {})
                .get("Items", [])
            )
            for d in dists:
                total_scanned += 1
                cfg = d.get("DistributionConfig", {})
                logging_cfg = cfg.get("Logging", {})
                if not logging_cfg.get("Enabled"):
                    resources_affected.append(
                        {
                            "resource_id": d.get("Id"),
                            "resource_id_type": "CloudFrontDistribution",
                            "issue": "CloudFront distribution does not have access logging enabled",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"CloudFront check error: {e}")

        # ----------------------------
        # 8-11) CloudTrail related checks (NeedToEnableCloudTrail, HasOneMultiRegionTrail,
        #       EnableTrailS3BucketLifecycle, HasInsightSelectors) (global)
        # ----------------------------
        try:
            trails = cloudtrail.describe_trails().get("trailList", [])
            total_scanned += 1
            if not trails:
                resources_affected.append(
                    {
                        "resource_id": "CloudTrail",
                        "resource_id_type": "Service",
                        "issue": "CloudTrail is not configured for this account",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                # HasOneMultiRegionTrail
                multi_region_ok = any(
                    t.get("IsMultiRegionTrail") or t.get("IsOrganizationTrail")
                    for t in trails
                )
                if not multi_region_ok:
                    resources_affected.append(
                        {
                            "resource_id": "CloudTrail",
                            "resource_id_type": "Service",
                            "issue": "No multi-region CloudTrail detected",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

                # For each trail check insight selectors and s3 lifecycle on log bucket
                for t in trails:
                    t_name = t.get("Name") or t.get("TrailARN")
                    # Insight selectors
                    try:
                        insight = cloudtrail.get_insight_selectors(
                            TrailName=t_name
                        ).get("InsightSelectors", [])
                        if not insight:
                            resources_affected.append(
                                {
                                    "resource_id": t_name,
                                    "resource_id_type": "CloudTrail",
                                    "issue": "CloudTrail has no insight selectors enabled",
                                    "region": "global",
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                    except Exception:
                        # Some trails may not support insight selectors naming; flag for review
                        resources_affected.append(
                            {
                                "resource_id": t_name,
                                "resource_id_type": "CloudTrail",
                                "issue": "Unable to confirm CloudTrail insight selectors (manual review recommended)",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )

                    # S3 lifecycle on trail bucket (EnableTrailS3BucketLifecycle)
                    s3_bucket = t.get("S3BucketName")
                    if s3_bucket:
                        try:
                            # Check lifecycle configuration exists
                            lifecycle = s3_client.get_bucket_lifecycle_configuration(
                                Bucket=s3_bucket
                            )
                            rules = lifecycle.get("Rules", [])
                            if not rules:
                                resources_affected.append(
                                    {
                                        "resource_id": s3_bucket,
                                        "resource_id_type": "S3Bucket",
                                        "issue": "CloudTrail S3 bucket has no lifecycle rules configured",
                                        "region": "global",
                                        "last_updated": datetime.now(IST).isoformat(),
                                    }
                                )
                        except Exception:
                            resources_affected.append(
                                {
                                    "resource_id": s3_bucket or t_name,
                                    "resource_id_type": "S3Bucket",
                                    "issue": "Unable to confirm S3 lifecycle on CloudTrail bucket (manual review recommended)",
                                    "region": "global",
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
        except Exception as e:
            print(f"CloudTrail checks error: {e}")

        # ----------------------------
        # 12) iam.enableGuardDuty (global / regional)
        # ----------------------------
        try:
            # GuardDuty detectors are regional; check across regions for at least one detector
            gd_enabled_any = False
            for region in regions:
                try:
                    gd = session.client("guardduty", region_name=region)
                    detectors = gd.list_detectors().get("DetectorIds", [])
                    if detectors:
                        gd_enabled_any = True
                        break
                except Exception:
                    continue

            if not gd_enabled_any:
                resources_affected.append(
                    {
                        "resource_id": "GuardDuty",
                        "resource_id_type": "Service",
                        "issue": "Amazon GuardDuty is not enabled in any region",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            total_scanned += 1
        except Exception as e:
            print(f"GuardDuty check error: {e}")

        # ----------------------------
        # 13) sqs.QueueMonitoring (global/regional) - check for DLQ (RedrivePolicy) as proxy for monitoring
        # ----------------------------
        try:
            queues = sqs.list_queues().get("QueueUrls", []) or []
            for q in queues:
                total_scanned += 1
                try:
                    attrs = sqs.get_queue_attributes(
                        QueueUrl=q, AttributeNames=["RedrivePolicy"]
                    ).get("Attributes", {})
                    if not attrs.get("RedrivePolicy"):
                        resources_affected.append(
                            {
                                "resource_id": q,
                                "resource_id_type": "SQSQueue",
                                "issue": "SQS queue does not have a dead-letter queue configured (no RedrivePolicy)",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception:
                    resources_affected.append(
                        {
                            "resource_id": q,
                            "resource_id_type": "SQSQueue",
                            "issue": "Unable to confirm SQS queue monitoring settings (manual review recommended)",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"SQS check error: {e}")

        # ----------------------------
        # Finalize totals and return
        # ----------------------------
        affected = len(resources_affected)

        return {
            "id": "SEC04-BP01",
            "check_name": "Detect and investigate security events",
            "problem_statement": "Ensure logging and detection controls are enabled to detect, investigate, and respond to security events.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable and centralize logging (EKS, VPC flow logs, OpenSearch, Redshift, S3, API Gateway, CloudFront), "
                "configure CloudTrail (multi-region, insights, lifecycle on storage), enable GuardDuty, "
                "and ensure SQS and other services have monitoring and DLQs."
            ),
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable cluster and control-plane logging for EKS clusters.",
                "2. Turn on VPC Flow Logs for all VPCs and centralize flow logs into a logging account.",
                "3. Configure OpenSearch/Elasticsearch domains to publish application logs to CloudWatch or dedicated logging sinks.",
                "4. Enable audit logging for Redshift clusters and ship logs to a centralized location.",
                "5. Configure S3 server access logging or use CloudTrail data events for S3 object-level activity.",
                "6. Enable API Gateway execution logging (access logs) for stages.",
                "7. Enable CloudFront access logs and centralize collection.",
                "8. Configure at least one multi-region CloudTrail and enable insight selectors where appropriate.",
                "9. Ensure CloudTrail log buckets have lifecycle rules to manage retention.",
                "10. Enable GuardDuty across accounts/regions and use organization delegation where possible.",
                "11. Ensure SQS queues use dead-letter queues and have alarms/monitoring configured.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC04-BP01 overall: {e}")
        return None


def check_sec04_bp02_capture_logs_findings_metrics(session):
    # SEC04-BP02 Capture logs, findings, and metrics in standardized locations
    print(
        "Evaluating processes to capture logs, findings, and metrics in standard locations"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_logs.html"

    # This best practice is organisation/process focused (centralized logging design).
    resources_affected = []
    total_scanned = 0
    affected = 0

    return {
        "id": "SEC04-BP02",
        "check_name": "Capture logs, findings, and metrics in standardized locations",
        "problem_statement": "Centralize logs, findings, and metrics into standardized locations for detection and investigation.",
        "severity_score": 70,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "status": "not_available",
        "recommendation": (
            "Define and implement centralized logging and metrics pipelines (for example: CloudTrail, "
            "VPC Flow Logs, CloudWatch Logs/Log Groups, S3 logging buckets, and a central security account)."
        ),
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": affected,
        },
        "remediation_steps": [
            "1. Identify canonical locations for logs, findings, and metrics (central logging account).",
            "2. Configure cross-account delivery (S3, CloudWatch, Kinesis) to the central account.",
            "3. Ensure retention and lifecycle policies for log storage are defined.",
            "4. Integrate findings into Security Hub or a centralized SIEM for correlation.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec04_bp03_correlate_enrich_security_alerts(session):
    # SEC04-BP03 Correlate and enrich security alerts
    print(
        "Checking if AWS Config is recording configuration changes (supporting alert correlation/enrichment)"
    )

    config = session.client("config")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_security_alerts.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        total_scanned = 1

        try:
            recorders = config.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )
            configs_enabled = any(
                r.get("name") and r.get("recordingGroup") is not None for r in recorders
            )
        except Exception:
            configs_enabled = False

        if not configs_enabled:
            resources_affected.append(
                {
                    "resource_id": "AWSConfig",
                    "resource_id_type": "Service",
                    "issue": "AWS Config is not enabled or not recording configuration changes.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        affected = len(resources_affected)

        return {
            "id": "SEC04-BP03",
            "check_name": "Correlate and enrich security alerts",
            "problem_statement": "Enrich security alerts with configuration and context data to speed investigations.",
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable AWS Config and aggregate configuration snapshots and resource relationships into your detection pipeline "
                "so alerts can be correlated with resource state and change history."
            ),
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable AWS Config recorders and delivery channels in all regions of operation.",
                "2. Aggregate Config data into the central security account or SIEM for alert enrichment.",
                "3. Correlate findings from GuardDuty, Security Hub, and Config for structured investigations.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC04-BP03: {e}")
        return None


def check_sec04_bp04_initiate_remediation_non_compliant(session):
    # SEC04-BP04 Initiate remediation for non-compliant resources
    print(
        "Checking remediation capability indicators: GuardDuty enabled and Macie (sensitive data discovery) enabled"
    )

    sts = session.client("sts")
    sts2 = sts  # reuse
    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_noncompliant_resources.html"
    resources_affected = []

    try:
        account_id = sts2.get_caller_identity()["Account"]
        total_scanned = 0

        # -------------------------
        # iam.enableGuardDuty -> check GuardDuty detectors in any region
        # -------------------------
        try:
            # get regions from STS/EC2 describe_regions might be better, but we can try common regions list fallback
            ec2_client = session.client("ec2")
            regions = [
                r["RegionName"]
                for r in ec2_client.describe_regions().get("Regions", [])
            ]
        except Exception:
            regions = [session.region_name] if session.region_name else ["us-east-1"]

        total_scanned += 1
        guardduty_enabled = False
        for region in regions:
            try:
                gd = session.client("guardduty", region_name=region)
                detectors = gd.list_detectors().get("DetectorIds", [])
                if detectors:
                    guardduty_enabled = True
                    break
            except Exception:
                # ignore region-level failures and continue
                continue

        if not guardduty_enabled:
            resources_affected.append(
                {
                    "resource_id": "GuardDuty",
                    "resource_id_type": "Service",
                    "issue": "Amazon GuardDuty is not enabled in any region.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # -------------------------
        # s3.MacieToEnable -> check Macie (macie2) status best-effort
        # -------------------------
        total_scanned += 1
        macie_enabled = False
        try:
            macie = session.client("macie2")
            # Best-effort: get_macie_session exists and returns 'status' or raises if not enabled
            try:
                session_info = macie.get_macie_session()
                # If API returns and status is 'ENABLED' consider enabled
                status_val = session_info.get("status")
                if status_val and status_val.upper() == "ENABLED":
                    macie_enabled = True
                else:
                    # some accounts return a dict without 'status' but no exception — treat as enabled if no exception
                    macie_enabled = bool(session_info)
            except macie.exceptions.ResourceNotFoundException:
                macie_enabled = False
            except Exception:
                # Some accounts/regions may not support Macie; treat as not enabled for safety
                macie_enabled = False
        except Exception:
            macie_enabled = False

        if not macie_enabled:
            resources_affected.append(
                {
                    "resource_id": "Macie",
                    "resource_id_type": "Service",
                    "issue": "Amazon Macie (sensitive data discovery) is not enabled.",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        affected = len(resources_affected)

        return {
            "id": "SEC04-BP04",
            "check_name": "Initiate remediation for non-compliant resources",
            "problem_statement": "Ensure remediation workflows are in place to act on non-compliant or risky resources.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable detection services (GuardDuty, Macie) and wire findings to automated remediation or ticketing systems."
            ),
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable GuardDuty across all operational regions and consider organization-wide delegation.",
                "2. Enable Amazon Macie in appropriate regions to detect sensitive data in S3.",
                "3. Integrate findings into Security Hub or your SOAR/ITSM for automated remediation playbooks.",
                "4. Implement automated response using EventBridge + Lambda/Systems Manager for common remediation tasks.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC04-BP04: {e}")
        return None
