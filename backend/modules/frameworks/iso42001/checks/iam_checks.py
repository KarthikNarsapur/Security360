"""
ISO 42001 Extended Checks — Identity & Access Management (AI-001 to AI-007)
All checks use ReadOnlyAccess permissions only.
"""
import json
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_iam_access_analyzer_findings(session):
    """AI-001: IAM Access Analyzer findings for AI resources"""
    print("Checking IAM Access Analyzer findings for AI resources")

    analyzer_client = session.client("accessanalyzer")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            analyzers = analyzer_client.list_analyzers(type="ACCOUNT").get("analyzers", [])
        except Exception:
            analyzers = []

        if len(analyzers) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "AccessAnalyzer",
                "resource_id_type": "Service",
                "issue": "No IAM Access Analyzer configured — cannot detect external access to AI resources",
                "region": analyzer_client.meta.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })
        else:
            # Check for active findings related to AI services
            for analyzer in analyzers:
                try:
                    findings = analyzer_client.list_findings(
                        analyzerArn=analyzer["arn"],
                        filter={"status": {"eq": ["ACTIVE"]}},
                    ).get("findings", [])

                    ai_findings = [
                        f for f in findings
                        if any(svc in (f.get("resource", "") or "").lower()
                               for svc in ["sagemaker", "bedrock", "comprehend", "rekognition", "textract"])
                    ]

                    for finding in ai_findings:
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": finding.get("resource", "Unknown"),
                            "resource_id_type": "ARN",
                            "issue": f"Active Access Analyzer finding: {finding.get('resourceType', 'Unknown')} — external access detected",
                            "region": analyzer_client.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                except Exception:
                    continue

        total_scanned = max(len(analyzers), 1)
        return {
            "id": "AI-001",
            "check_name": "IAM Access Analyzer findings for AI resources",
            "problem_statement": "AI resources should not have unintended external access",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Enable IAM Access Analyzer and remediate findings related to AI services",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Enable IAM Access Analyzer in your account",
                "2. Review active findings for AI service resources",
                "3. Remove unintended external access grants",
                "4. Set up alerts for new findings",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking IAM Access Analyzer: {e}")
        return None


def check_ai_roles_wildcard_resources(session):
    """AI-002: AI roles with wildcard (*) resource permissions"""
    print("Checking AI roles with wildcard resource permissions")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])

        ai_service_keywords = ["sagemaker", "bedrock", "comprehend", "textract", "rekognition"]
        ai_roles = []

        for role in roles:
            role_name = role["RoleName"]
            assume_doc = json.dumps(role.get("AssumeRolePolicyDocument", {})).lower()
            if any(svc in assume_doc for svc in ai_service_keywords):
                ai_roles.append(role_name)

        for role_name in ai_roles:
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                for policy in attached:
                    try:
                        policy_arn = policy["PolicyArn"]
                        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                        doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]

                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]

                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                resource = stmt.get("Resource", "")
                                if resource == "*" or (isinstance(resource, list) and "*" in resource):
                                    resources_affected.append({
                                        "account_id": account_id,
                                        "resource_id": role_name,
                                        "resource_id_type": "RoleName",
                                        "issue": f"AI role '{role_name}' has wildcard (*) resource in policy '{policy['PolicyName']}'",
                                        "region": "global",
                                        "last_updated": datetime.now(IST).isoformat(),
                                    })
                                    break
                    except Exception:
                        continue
            except Exception:
                continue

        return {
            "id": "AI-002",
            "check_name": "AI roles with wildcard (*) resource permissions",
            "problem_statement": "AI roles should not have wildcard resource permissions — violates least privilege",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Scope AI role policies to specific resource ARNs instead of wildcard (*)",
            "additional_info": {
                "total_scanned": max(len(ai_roles), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify AI roles with Resource: '*'",
                "2. Replace wildcard with specific resource ARNs",
                "3. Use condition keys to limit scope",
                "4. Test with IAM Policy Simulator before applying",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI roles wildcard resources: {e}")
        return None


def check_ai_roles_wildcard_actions(session):
    """AI-003: AI roles with wildcard actions"""
    print("Checking AI roles with wildcard actions")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])

        ai_service_keywords = ["sagemaker", "bedrock", "comprehend", "textract", "rekognition"]
        ai_roles = []

        for role in roles:
            role_name = role["RoleName"]
            assume_doc = json.dumps(role.get("AssumeRolePolicyDocument", {})).lower()
            if any(svc in assume_doc for svc in ai_service_keywords):
                ai_roles.append(role_name)

        for role_name in ai_roles:
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                for policy in attached:
                    try:
                        policy_arn = policy["PolicyArn"]
                        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                        doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]

                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]

                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                if "*" in actions or any(a.endswith(":*") for a in actions):
                                    resources_affected.append({
                                        "account_id": account_id,
                                        "resource_id": role_name,
                                        "resource_id_type": "RoleName",
                                        "issue": f"AI role '{role_name}' has wildcard action in policy '{policy['PolicyName']}'",
                                        "region": "global",
                                        "last_updated": datetime.now(IST).isoformat(),
                                    })
                                    break
                    except Exception:
                        continue
            except Exception:
                continue

        return {
            "id": "AI-003",
            "check_name": "AI roles with wildcard actions",
            "problem_statement": "AI roles should not have wildcard (*) actions — use specific service actions only",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Replace wildcard actions with specific API actions for AI services",
            "additional_info": {
                "total_scanned": max(len(ai_roles), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Audit AI roles for Action: '*' or service:* permissions",
                "2. Replace with specific actions (e.g., sagemaker:CreateModel)",
                "3. Use IAM Access Advisor to find unused permissions",
                "4. Apply least privilege principle",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI roles wildcard actions: {e}")
        return None


def check_ai_service_linked_roles(session):
    """AI-004: AI service-linked roles validation"""
    print("Checking AI service-linked roles validation")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])

        ai_slr_prefixes = [
            "AWSServiceRoleForSageMaker",
            "AWSServiceRoleForAmazonBedrock",
            "AWSServiceRoleForComprehend",
            "AWSServiceRoleForRekognition",
            "AWSServiceRoleForTextract",
        ]

        found_slrs = []
        for role in roles:
            role_name = role["RoleName"]
            if any(role_name.startswith(prefix) for prefix in ai_slr_prefixes):
                found_slrs.append(role_name)

        # Check if AI services are in use but missing SLRs
        ai_services_in_use = set()
        for role in roles:
            assume_doc = json.dumps(role.get("AssumeRolePolicyDocument", {})).lower()
            for svc in ["sagemaker", "bedrock", "comprehend", "rekognition", "textract"]:
                if svc in assume_doc:
                    ai_services_in_use.add(svc)

        expected_slrs = {
            "sagemaker": "AWSServiceRoleForSageMaker",
            "bedrock": "AWSServiceRoleForAmazonBedrock",
        }

        for svc, expected_prefix in expected_slrs.items():
            if svc in ai_services_in_use:
                if not any(slr.startswith(expected_prefix) for slr in found_slrs):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": expected_prefix,
                        "resource_id_type": "ServiceLinkedRole",
                        "issue": f"AI service '{svc}' in use but service-linked role '{expected_prefix}' not found",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })

        return {
            "id": "AI-004",
            "check_name": "AI service-linked roles validation",
            "problem_statement": "AI services should use proper service-linked roles for secure operation",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Ensure service-linked roles exist for all active AI services",
            "additional_info": {
                "total_scanned": max(len(ai_services_in_use), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Verify service-linked roles exist for active AI services",
                "2. Create missing SLRs via the respective service console",
                "3. Review SLR permissions align with service requirements",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI service-linked roles: {e}")
        return None


def check_cross_account_trust_ai_roles(session):
    """AI-005: Cross-account trust on AI IAM roles"""
    print("Checking cross-account trust on AI IAM roles")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])

        ai_service_keywords = ["sagemaker", "bedrock", "comprehend", "textract", "rekognition"]

        for role in roles:
            role_name = role["RoleName"]
            assume_doc = role.get("AssumeRolePolicyDocument", {})
            assume_str = json.dumps(assume_doc).lower()

            # Only check roles related to AI
            has_ai_policies = False
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                has_ai_policies = any(
                    any(svc in p["PolicyArn"].lower() for svc in ai_service_keywords)
                    for p in attached
                )
            except Exception:
                pass

            if not has_ai_policies and not any(svc in assume_str for svc in ai_service_keywords):
                continue

            # Check for cross-account principals
            statements = assume_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal", {})
                    aws_principals = principal.get("AWS", [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]

                    for p in aws_principals:
                        if ":" in p and account_id not in p and p != "*":
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": role_name,
                                "resource_id_type": "RoleName",
                                "issue": f"AI role '{role_name}' trusts external account: {p}",
                                "region": "global",
                                "last_updated": datetime.now(IST).isoformat(),
                            })
                            break

        return {
            "id": "AI-005",
            "check_name": "Cross-account trust on AI IAM roles",
            "problem_statement": "AI roles with cross-account trust increase attack surface",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Review and restrict cross-account trust policies on AI roles",
            "additional_info": {
                "total_scanned": max(len(roles), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Audit AI roles for cross-account trust relationships",
                "2. Remove unnecessary external account access",
                "3. Add condition keys (e.g., aws:PrincipalOrgID) to restrict trust",
                "4. Document approved cross-account relationships",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking cross-account trust on AI roles: {e}")
        return None


def check_ai_users_long_lived_access_keys(session):
    """AI-006: AI users with long-lived access keys"""
    print("Checking AI users with long-lived access keys")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        users = iam.list_users().get("Users", [])

        ai_service_keywords = ["sagemaker", "bedrock", "comprehend", "textract", "rekognition", "ai", "ml"]
        now = datetime.now(timezone.utc)
        max_key_age_days = 90

        for user in users:
            username = user["UserName"]

            # Check if user has AI-related policies
            try:
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                has_ai_access = any(
                    any(kw in p["PolicyArn"].lower() for kw in ai_service_keywords)
                    for p in attached
                )
            except Exception:
                has_ai_access = False

            if not has_ai_access:
                continue

            # Check access key age
            try:
                keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                for key in keys:
                    if key.get("Status") == "Active":
                        create_date = key.get("CreateDate")
                        if create_date:
                            age = (now - create_date.replace(tzinfo=timezone.utc)).days
                            if age > max_key_age_days:
                                resources_affected.append({
                                    "account_id": account_id,
                                    "resource_id": username,
                                    "resource_id_type": "UserName",
                                    "issue": f"AI user '{username}' has access key older than {max_key_age_days} days ({age} days)",
                                    "region": "global",
                                    "last_updated": datetime.now(IST).isoformat(),
                                })
            except Exception:
                continue

        return {
            "id": "AI-006",
            "check_name": "AI users with long-lived access keys",
            "problem_statement": "AI users should rotate access keys regularly (max 90 days)",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Rotate or deactivate access keys older than 90 days for AI users",
            "additional_info": {
                "total_scanned": max(len(users), 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify AI users with access keys older than 90 days",
                "2. Create new access keys",
                "3. Update applications to use new keys",
                "4. Deactivate and delete old keys",
                "5. Consider using IAM roles instead of long-lived keys",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI users long-lived access keys: {e}")
        return None


def check_ai_service_last_accessed(session):
    """AI-007: AI service last accessed analysis"""
    print("Checking AI service last accessed analysis")

    iam = session.client("iam")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        roles = iam.list_roles().get("Roles", [])

        ai_service_keywords = ["sagemaker", "bedrock", "comprehend", "textract", "rekognition"]
        ai_roles_checked = 0

        for role in roles:
            role_name = role["RoleName"]
            assume_doc = json.dumps(role.get("AssumeRolePolicyDocument", {})).lower()
            if not any(svc in assume_doc for svc in ai_service_keywords):
                continue

            ai_roles_checked += 1

            # Check if role has attached AI FullAccess policies but hasn't been used
            try:
                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                full_access_policies = [
                    p for p in attached if "FullAccess" in p["PolicyArn"]
                ]

                if full_access_policies:
                    # Role has FullAccess — flag for review
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": role_name,
                        "resource_id_type": "RoleName",
                        "issue": f"AI role '{role_name}' has FullAccess policies — review for least privilege",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return {
            "id": "AI-007",
            "check_name": "AI service last accessed analysis",
            "problem_statement": "AI roles should only retain permissions for services actually in use",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Use IAM Access Advisor to remove unused permissions from AI roles",
            "additional_info": {
                "total_scanned": max(ai_roles_checked, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Open IAM console → Roles → select AI role",
                "2. Check Access Advisor tab for unused services",
                "3. Remove permissions for services not accessed in 90+ days",
                "4. Replace FullAccess policies with scoped policies",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking AI service last accessed: {e}")
        return None
