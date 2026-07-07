from datetime import datetime, timezone, timedelta
import json
import csv
import io
import re
import time

IST = timezone(timedelta(hours=5, minutes=30))

FRAMEWORK = "SEBI CSCRF 2024"
SECRET_PATTERNS = re.compile(r'(password|secret|key|token|api_key|apikey|conn.*string)', re.IGNORECASE)


def _update_meta(scan_meta_data, service, total, affected, severity_level):
    scan_meta_data["total_scanned"] = scan_meta_data.get("total_scanned", 0) + total
    scan_meta_data["affected"] = scan_meta_data.get("affected", 0) + affected
    sev_key = severity_level
    scan_meta_data[sev_key] = scan_meta_data.get(sev_key, 0) + affected
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)


def _result(check_name, service, control_id, problem, severity_score, severity_level, resources, recommendation, total, affected):
    return {
        "check_name": check_name,
        "service": service,
        "framework": FRAMEWORK,
        "control_id": control_id,
        "problem_statement": problem,
        "severity_score": severity_score,
        "severity_level": severity_level,
        "resources_affected": resources,
        "recommendation": recommendation,
        "additional_info": {"total_scanned": total, "affected": affected}
    }


# ===================== PR.AA: Identity & Access Control =====================

def sebi_root_access_keys_present(session, scan_meta_data):
    print("sebi_root_access_keys_present")
    resources = []
    total = 1
    try:
        iam = session.client("iam")
        try:
            iam.generate_credential_report()
            time.sleep(2)
        except Exception:
            pass
        resp = iam.get_credential_report()
        content = resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            if row["user"] == "<root_account>":
                if row.get("access_key_1_active", "false") == "true" or row.get("access_key_2_active", "false") == "true":
                    resources.append({"resource_name": "root_account", "note": "Root account has active access keys"})
                break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "Critical")
    return _result("sebi_root_access_keys_present", "IAM", "SEBI-CSCRF-PR.AA-4",
                   "Root account has active access keys which poses critical security risk",
                   9.5, "Critical", resources, "Remove root access keys and use IAM users/roles instead", total, affected)


def sebi_inactive_iam_users(session, scan_meta_data):
    print("sebi_inactive_iam_users")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        users = iam.list_users()["Users"]
        total = len(users)
        now = datetime.now(timezone.utc)
        for user in users:
            last_used = user.get("PasswordLastUsed")
            if last_used and (now - last_used).days > 90:
                resources.append({"resource_name": user["UserName"], "note": f"Inactive for {(now - last_used).days} days"})
            elif not last_used:
                create_date = user["CreateDate"]
                if (now - create_date).days > 90:
                    resources.append({"resource_name": user["UserName"], "note": f"Never logged in, created {(now - create_date).days} days ago"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "High")
    return _result("sebi_inactive_iam_users", "IAM", "SEBI-CSCRF-PR.AA-5",
                   "IAM users inactive for 90+ days increase attack surface",
                   7.0, "High", resources, "Remove or disable IAM users inactive for more than 90 days", total, affected)


def sebi_unused_access_keys(session, scan_meta_data):
    print("sebi_unused_access_keys")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        users = iam.list_users()["Users"]
        now = datetime.now(timezone.utc)
        for user in users:
            try:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] == "Active":
                        total += 1
                        try:
                            last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                            last_date = last_used["AccessKeyLastUsed"].get("LastUsedDate")
                            if last_date and (now - last_date).days > 90:
                                resources.append({"resource_name": f"{user['UserName']}/{key['AccessKeyId']}", "note": f"Unused for {(now - last_date).days} days"})
                            elif not last_date and (now - key["CreateDate"]).days > 90:
                                resources.append({"resource_name": f"{user['UserName']}/{key['AccessKeyId']}", "note": "Never used"})
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "High")
    return _result("sebi_unused_access_keys", "IAM", "SEBI-CSCRF-PR.AA-6",
                   "Access keys unused for 90+ days should be removed",
                   7.0, "High", resources, "Deactivate or delete access keys not used in 90+ days", total, affected)


def sebi_iam_admin_access_users(session, scan_meta_data):
    print("sebi_iam_admin_access_users")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        users = iam.list_users()["Users"]
        total = len(users)
        for user in users:
            try:
                attached = iam.list_attached_user_policies(UserName=user["UserName"])["AttachedPolicies"]
                for p in attached:
                    if p["PolicyName"] == "AdministratorAccess":
                        resources.append({"resource_name": user["UserName"], "note": "Has AdministratorAccess attached directly"})
                        break
            except Exception:
                pass
            try:
                groups = iam.list_groups_for_user(UserName=user["UserName"])["Groups"]
                for g in groups:
                    gp = iam.list_attached_group_policies(GroupName=g["GroupName"])["AttachedPolicies"]
                    for p in gp:
                        if p["PolicyName"] == "AdministratorAccess":
                            resources.append({"resource_name": user["UserName"], "note": f"Has AdministratorAccess via group {g['GroupName']}"})
                            break
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    # deduplicate
    seen = set()
    deduped = []
    for r in resources:
        if r["resource_name"] not in seen:
            seen.add(r["resource_name"])
            deduped.append(r)
    resources = deduped
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "High")
    return _result("sebi_iam_admin_access_users", "IAM", "SEBI-CSCRF-PR.AA-7",
                   "Users with AdministratorAccess violate least-privilege principle",
                   7.5, "High", resources, "Replace AdministratorAccess with granular policies following least privilege", total, affected)


def sebi_wildcard_iam_policies(session, scan_meta_data):
    print("sebi_wildcard_iam_policies")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                total += 1
                try:
                    version = iam.get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])
                    doc = version["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            res = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(res, str):
                                res = [res]
                            if "*" in actions and "*" in res:
                                resources.append({"resource_name": policy["PolicyName"], "note": f"ARN: {policy['Arn']} has Action:* Resource:*"})
                                break
                except Exception:
                    pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "Critical")
    return _result("sebi_wildcard_iam_policies", "IAM", "SEBI-CSCRF-PR.AA-8",
                   "IAM policies with Action:* and Resource:* grant unrestricted access",
                   9.5, "Critical", resources, "Scope down policies to specific actions and resources", total, affected)


def sebi_console_without_mfa_enforcement(session, scan_meta_data):
    print("sebi_console_without_mfa_enforcement")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        users = iam.list_users()["Users"]
        for user in users:
            try:
                login_profile = iam.get_login_profile(UserName=user["UserName"])
                total += 1
                mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                if not mfa_devices:
                    resources.append({"resource_name": user["UserName"], "note": "Console access without MFA enabled"})
            except iam.exceptions.NoSuchEntityException:
                pass
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "High")
    return _result("sebi_console_without_mfa_enforcement", "IAM", "SEBI-CSCRF-PR.AA-9",
                   "Console users without MFA are vulnerable to credential theft",
                   7.5, "High", resources, "Enforce MFA for all console users via IAM policy", total, affected)


def sebi_access_key_rotation(session, scan_meta_data):
    print("sebi_access_key_rotation")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        users = iam.list_users()["Users"]
        now = datetime.now(timezone.utc)
        for user in users:
            try:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] == "Active":
                        total += 1
                        age = (now - key["CreateDate"]).days
                        if age > 90:
                            resources.append({"resource_name": f"{user['UserName']}/{key['AccessKeyId']}", "note": f"Key age: {age} days"})
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "High")
    return _result("sebi_access_key_rotation", "IAM", "SEBI-CSCRF-PR.AA-10",
                   "Access keys older than 90 days should be rotated",
                   7.0, "High", resources, "Rotate access keys every 90 days or less", total, affected)


def sebi_iam_roles_external_trust(session, scan_meta_data):
    print("sebi_iam_roles_external_trust")
    resources = []
    total = 0
    try:
        iam = session.client("iam")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                total += 1
                doc = role["AssumeRolePolicyDocument"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    if principal == "*":
                        resources.append({"resource_name": role["RoleName"], "note": "Trusts anonymous principal (*)"})
                        break
                    aws_principals = principal.get("AWS", [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if p == "*":
                            resources.append({"resource_name": role["RoleName"], "note": "Trusts anonymous AWS principal"})
                            break
                        if account_id not in p:
                            resources.append({"resource_name": role["RoleName"], "note": f"Trusts external principal: {p}"})
                            break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "IAM", total, affected, "Critical")
    return _result("sebi_iam_roles_external_trust", "IAM", "SEBI-CSCRF-PR.AA-11",
                   "IAM roles with external or anonymous trust relationships pose privilege escalation risk",
                   9.0, "Critical", resources, "Review and restrict trust policies to internal accounts only", total, affected)


def sebi_cognito_mfa_config(session, scan_meta_data):
    print("sebi_cognito_mfa_config")
    resources = []
    total = 0
    try:
        cognito = session.client("cognito-idp")
        pools = cognito.list_user_pools(MaxResults=60).get("UserPools", [])
        total = len(pools)
        for pool in pools:
            try:
                detail = cognito.describe_user_pool(UserPoolId=pool["Id"])["UserPool"]
                mfa = detail.get("MfaConfiguration", "OFF")
                if mfa == "OFF":
                    resources.append({"resource_name": pool["Name"], "note": f"MFA is {mfa}"})
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "Cognito", total, affected, "High")
    return _result("sebi_cognito_mfa_config", "Cognito", "SEBI-CSCRF-PR.AA-12",
                   "Cognito user pools without MFA weaken authentication controls",
                   7.0, "High", resources, "Enable MFA (OPTIONAL or REQUIRED) on all Cognito user pools", total, affected)


def sebi_api_gateway_no_auth(session, scan_meta_data):
    print("sebi_api_gateway_no_auth")
    resources = []
    total = 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            try:
                api_resources = apigw.get_resources(restApiId=api["id"])["items"]
                for r in api_resources:
                    methods = r.get("resourceMethods", {})
                    for method_name in methods:
                        total += 1
                        try:
                            method = apigw.get_method(restApiId=api["id"], resourceId=r["id"], httpMethod=method_name)
                            if method.get("authorizationType", "NONE") == "NONE" and not method.get("apiKeyRequired", False):
                                resources.append({"resource_name": f"{api['name']}{r['path']}:{method_name}", "note": "No authorization configured"})
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "API Gateway", total, affected, "High")
    return _result("sebi_api_gateway_no_auth", "API Gateway", "SEBI-CSCRF-PR.AA-13",
                   "API Gateway methods without authorization allow unauthenticated access",
                   7.5, "High", resources, "Add IAM, Cognito, or Lambda authorizer to all API methods", total, affected)


def sebi_cloudfront_oai(session, scan_meta_data):
    print("sebi_cloudfront_oai")
    resources = []
    total = 0
    try:
        cf = session.client("cloudfront")
        dists = cf.list_distributions().get("DistributionList", {}).get("Items", [])
        if dists:
            for dist in dists:
                total += 1
                origins = dist.get("Origins", {}).get("Items", [])
                for origin in origins:
                    if "s3" in origin.get("DomainName", "").lower():
                        oai = origin.get("S3OriginConfig", {}).get("OriginAccessIdentity", "")
                        oac = origin.get("OriginAccessControlId", "")
                        if not oai and not oac:
                            resources.append({"resource_name": dist["Id"], "note": f"S3 origin {origin['DomainName']} without OAI/OAC"})
                            break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "CloudFront", total, affected, "Medium")
    return _result("sebi_cloudfront_oai", "CloudFront", "SEBI-CSCRF-PR.AA-14",
                   "CloudFront distributions without OAI/OAC allow direct S3 access",
                   5.0, "Medium", resources, "Configure Origin Access Identity or Origin Access Control for S3 origins", total, affected)


def sebi_ec2_imdsv2_not_enforced(session, scan_meta_data):
    print("sebi_ec2_imdsv2_not_enforced")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst["State"]["Name"] == "terminated":
                        continue
                    total += 1
                    md_options = inst.get("MetadataOptions", {})
                    if md_options.get("HttpTokens", "optional") != "required":
                        name = ""
                        for tag in inst.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                                break
                        resources.append({"resource_name": inst["InstanceId"], "note": f"IMDSv2 not enforced. Name: {name}"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "EC2", total, affected, "High")
    return _result("sebi_ec2_imdsv2_not_enforced", "EC2", "SEBI-CSCRF-PR.AA-15",
                   "EC2 instances not enforcing IMDSv2 are vulnerable to SSRF credential theft",
                   7.5, "High", resources, "Set HttpTokens to 'required' to enforce IMDSv2 on all instances", total, affected)


# ===================== PR.DS: Data Security =====================

def sebi_s3_encryption(session, scan_meta_data):
    print("sebi_s3_encryption")
    resources = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            try:
                s3.get_bucket_encryption(Bucket=bucket["Name"])
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    resources.append({"resource_name": bucket["Name"], "note": "No server-side encryption configured"})
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "S3", total, affected, "Critical")
    return _result("sebi_s3_encryption", "S3", "SEBI-CSCRF-PR.DS-2",
                   "S3 buckets without encryption expose data at rest",
                   9.0, "Critical", resources, "Enable default SSE-S3 or SSE-KMS encryption on all buckets", total, affected)


def sebi_rds_encryption(session, scan_meta_data):
    print("sebi_rds_encryption")
    resources = []
    total = 0
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                total += 1
                if not db.get("StorageEncrypted", False):
                    resources.append({"resource_name": db["DBInstanceIdentifier"], "note": "Storage encryption disabled"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "RDS", total, affected, "High")
    return _result("sebi_rds_encryption", "RDS", "SEBI-CSCRF-PR.DS-3",
                   "Unencrypted RDS instances expose data at rest",
                   7.5, "High", resources, "Enable encryption at rest for all RDS instances", total, affected)


def sebi_dynamodb_encryption(session, scan_meta_data):
    print("sebi_dynamodb_encryption")
    resources = []
    total = 0
    try:
        dynamodb = session.client("dynamodb")
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page["TableNames"]:
                total += 1
                try:
                    desc = dynamodb.describe_table(TableName=table_name)["Table"]
                    sse = desc.get("SSEDescription", {})
                    if sse.get("SSEType") != "KMS":
                        resources.append({"resource_name": table_name, "note": "Not using CMK encryption"})
                except Exception:
                    pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "DynamoDB", total, affected, "Medium")
    return _result("sebi_dynamodb_encryption", "DynamoDB", "SEBI-CSCRF-PR.DS-4",
                   "DynamoDB tables without CMK encryption use default AWS-owned keys",
                   5.5, "Medium", resources, "Enable KMS CMK encryption on DynamoDB tables for better key control", total, affected)


def sebi_efs_encryption(session, scan_meta_data):
    print("sebi_efs_encryption")
    resources = []
    total = 0
    try:
        efs = session.client("efs")
        fs_list = efs.describe_file_systems()["FileSystems"]
        total = len(fs_list)
        for fs in fs_list:
            if not fs.get("Encrypted", False):
                resources.append({"resource_name": fs["FileSystemId"], "note": f"Name: {fs.get('Name', 'N/A')}, not encrypted"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "EFS", total, affected, "High")
    return _result("sebi_efs_encryption", "EFS", "SEBI-CSCRF-PR.DS-5",
                   "Unencrypted EFS file systems expose data at rest",
                   7.0, "High", resources, "Enable encryption at rest for all EFS file systems", total, affected)


def sebi_redshift_encryption(session, scan_meta_data):
    print("sebi_redshift_encryption")
    resources = []
    total = 0
    try:
        redshift = session.client("redshift")
        paginator = redshift.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for cluster in page["Clusters"]:
                total += 1
                if not cluster.get("Encrypted", False):
                    resources.append({"resource_name": cluster["ClusterIdentifier"], "note": "Cluster not encrypted"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "Redshift", total, affected, "High")
    return _result("sebi_redshift_encryption", "Redshift", "SEBI-CSCRF-PR.DS-6",
                   "Unencrypted Redshift clusters expose data at rest",
                   7.5, "High", resources, "Enable encryption for all Redshift clusters", total, affected)


def sebi_s3_ssl_enforcement(session, scan_meta_data):
    print("sebi_s3_ssl_enforcement")
    resources = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            ssl_enforced = False
            try:
                policy = json.loads(s3.get_bucket_policy(Bucket=bucket["Name"])["Policy"])
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Deny":
                        condition = stmt.get("Condition", {})
                        bool_cond = condition.get("Bool", {})
                        if bool_cond.get("aws:SecureTransport") == "false":
                            ssl_enforced = True
                            break
            except Exception:
                pass
            if not ssl_enforced:
                resources.append({"resource_name": bucket["Name"], "note": "No SSL enforcement in bucket policy"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "S3", total, affected, "High")
    return _result("sebi_s3_ssl_enforcement", "S3", "SEBI-CSCRF-PR.DS-7",
                   "S3 buckets without SSL enforcement allow unencrypted data transfer",
                   7.0, "High", resources, "Add bucket policy to deny requests where aws:SecureTransport is false", total, affected)


def sebi_rds_ssl_enforcement(session, scan_meta_data):
    print("sebi_rds_ssl_enforcement")
    resources = []
    total = 0
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                total += 1
                pg_name = db.get("DBParameterGroups", [{}])[0].get("DBParameterGroupName", "")
                if pg_name:
                    try:
                        params = rds.describe_db_parameters(DBParameterGroupName=pg_name)["Parameters"]
                        ssl_forced = False
                        for param in params:
                            if param["ParameterName"] in ("rds.force_ssl", "require_secure_transport"):
                                if param.get("ParameterValue") == "1":
                                    ssl_forced = True
                                    break
                        if not ssl_forced:
                            resources.append({"resource_name": db["DBInstanceIdentifier"], "note": f"Parameter group {pg_name} does not force SSL"})
                    except Exception:
                        pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "RDS", total, affected, "High")
    return _result("sebi_rds_ssl_enforcement", "RDS", "SEBI-CSCRF-PR.DS-8",
                   "RDS instances without forced SSL allow unencrypted connections",
                   7.0, "High", resources, "Set rds.force_ssl=1 or require_secure_transport=1 in parameter groups", total, affected)


def sebi_alb_https_only(session, scan_meta_data):
    print("sebi_alb_https_only")
    resources = []
    total = 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
        albs = [lb for lb in lbs if lb["Type"] == "application"]
        total = len(albs)
        for alb in albs:
            try:
                listeners = elbv2.describe_listeners(LoadBalancerArn=alb["LoadBalancerArn"])["Listeners"]
                for listener in listeners:
                    if listener["Protocol"] == "HTTP":
                        actions = listener.get("DefaultActions", [])
                        is_redirect = any(a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS" for a in actions)
                        if not is_redirect:
                            resources.append({"resource_name": alb["LoadBalancerName"], "note": f"HTTP listener on port {listener['Port']} without HTTPS redirect"})
                            break
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "ELB", total, affected, "High")
    return _result("sebi_alb_https_only", "ELB", "SEBI-CSCRF-PR.DS-9",
                   "ALBs with HTTP listeners expose data in transit",
                   7.0, "High", resources, "Configure HTTP listeners to redirect to HTTPS", total, affected)


def sebi_kms_key_rotation(session, scan_meta_data):
    print("sebi_kms_key_rotation")
    resources = []
    total = 0
    try:
        kms = session.client("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                try:
                    desc = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if desc["KeyManager"] == "CUSTOMER" and desc["KeyState"] == "Enabled":
                        total += 1
                        rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
                        if not rotation["KeyRotationEnabled"]:
                            resources.append({"resource_name": key["KeyId"], "note": "Automatic key rotation not enabled"})
                except Exception:
                    pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "KMS", total, affected, "High")
    return _result("sebi_kms_key_rotation", "KMS", "SEBI-CSCRF-PR.DS-10",
                   "KMS CMKs without automatic rotation increase key compromise risk",
                   7.0, "High", resources, "Enable automatic key rotation for all customer-managed KMS keys", total, affected)


def sebi_kms_pending_deletion(session, scan_meta_data):
    print("sebi_kms_pending_deletion")
    resources = []
    total = 0
    try:
        kms = session.client("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                total += 1
                try:
                    desc = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if desc["KeyState"] == "PendingDeletion":
                        resources.append({"resource_name": key["KeyId"], "note": f"Scheduled for deletion on {desc.get('DeletionDate', 'N/A')}"})
                except Exception:
                    pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "KMS", total, affected, "Critical")
    return _result("sebi_kms_pending_deletion", "KMS", "SEBI-CSCRF-PR.DS-11",
                   "KMS keys pending deletion may cause data loss if dependent services exist",
                   9.0, "Critical", resources, "Review and cancel deletion for keys that are still in use", total, affected)


def sebi_s3_public_access_block_account(session, scan_meta_data):
    print("sebi_s3_public_access_block_account")
    resources = []
    total = 1
    try:
        s3control = session.client("s3control")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        try:
            pab = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
            if not all([pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"),
                        pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets")]):
                resources.append({"resource_name": account_id, "note": "Account-level public access block is not fully enabled"})
        except Exception:
            resources.append({"resource_name": account_id, "note": "Account-level public access block not configured"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "S3", total, affected, "Critical")
    return _result("sebi_s3_public_access_block_account", "S3", "SEBI-CSCRF-PR.DS-12",
                   "Account-level S3 public access block not fully enabled",
                   9.5, "Critical", resources, "Enable all four account-level S3 public access block settings", total, affected)


def sebi_s3_bucket_public(session, scan_meta_data):
    print("sebi_s3_bucket_public")
    resources = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            is_public = False
            try:
                pab = s3.get_public_access_block(Bucket=bucket["Name"])["PublicAccessBlockConfiguration"]
                if all([pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"),
                        pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets")]):
                    continue
            except Exception:
                pass
            try:
                acl = s3.get_bucket_acl(Bucket=bucket["Name"])
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        is_public = True
                        break
            except Exception:
                pass
            if not is_public:
                try:
                    policy = json.loads(s3.get_bucket_policy(Bucket=bucket["Name"])["Policy"])
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") == "Allow" and stmt.get("Principal") in ("*", {"AWS": "*"}):
                            is_public = True
                            break
                except Exception:
                    pass
            if is_public:
                resources.append({"resource_name": bucket["Name"], "note": "Bucket is publicly accessible"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "S3", total, affected, "Critical")
    return _result("sebi_s3_bucket_public", "S3", "SEBI-CSCRF-PR.DS-13",
                   "Publicly accessible S3 buckets may expose sensitive data",
                   9.5, "Critical", resources, "Remove public access from bucket ACLs and policies; enable public access block", total, affected)


def sebi_secrets_rotation(session, scan_meta_data):
    print("sebi_secrets_rotation")
    resources = []
    total = 0
    try:
        sm = session.client("secretsmanager")
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page["SecretList"]:
                total += 1
                if not secret.get("RotationEnabled", False):
                    resources.append({"resource_name": secret["Name"], "note": "Rotation not enabled"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "SecretsManager", total, affected, "High")
    return _result("sebi_secrets_rotation", "SecretsManager", "SEBI-CSCRF-PR.DS-14",
                   "Secrets without automatic rotation increase exposure window",
                   7.0, "High", resources, "Enable automatic rotation for all secrets in Secrets Manager", total, affected)


def sebi_lambda_env_secrets(session, scan_meta_data):
    print("sebi_lambda_env_secrets")
    resources = []
    total = 0
    try:
        lam = session.client("lambda")
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page["Functions"]:
                total += 1
                env_vars = func.get("Environment", {}).get("Variables", {})
                for key, val in env_vars.items():
                    if SECRET_PATTERNS.search(key):
                        resources.append({"resource_name": func["FunctionName"], "note": f"Env var '{key}' may contain secret"})
                        break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "Lambda", total, affected, "High")
    return _result("sebi_lambda_env_secrets", "Lambda", "SEBI-CSCRF-PR.DS-15",
                   "Lambda functions with secrets in environment variables risk credential exposure",
                   7.5, "High", resources, "Use AWS Secrets Manager or Parameter Store instead of env vars for secrets", total, affected)


# ===================== PR.AC: Network Integrity =====================

def sebi_sg_unrestricted_ingress(session, scan_meta_data):
    print("sebi_sg_unrestricted_ingress")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                total += 1
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            resources.append({"resource_name": f"{sg['GroupId']} ({sg.get('GroupName', '')})", "note": "Has 0.0.0.0/0 ingress rule"})
                            break
                    else:
                        for ip6 in rule.get("Ipv6Ranges", []):
                            if ip6.get("CidrIpv6") == "::/0":
                                resources.append({"resource_name": f"{sg['GroupId']} ({sg.get('GroupName', '')})", "note": "Has ::/0 ingress rule"})
                                break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    # deduplicate
    seen = set()
    deduped = []
    for r in resources:
        if r["resource_name"] not in seen:
            seen.add(r["resource_name"])
            deduped.append(r)
    resources = deduped
    affected = len(resources)
    _update_meta(scan_meta_data, "EC2", total, affected, "High")
    return _result("sebi_sg_unrestricted_ingress", "EC2", "SEBI-CSCRF-PR.AC-1",
                   "Security groups with 0.0.0.0/0 ingress allow unrestricted network access",
                   7.5, "High", resources, "Restrict security group ingress to specific IP ranges", total, affected)


def sebi_sg_ssh_rdp_open(session, scan_meta_data):
    print("sebi_sg_ssh_rdp_open")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                total += 1
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)
                    if not (from_port <= 22 <= to_port or from_port <= 3389 <= to_port):
                        continue
                    open_cidrs = [r for r in rule.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
                    open_cidrs += [r for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
                    if open_cidrs:
                        ports = []
                        if from_port <= 22 <= to_port:
                            ports.append("22/SSH")
                        if from_port <= 3389 <= to_port:
                            ports.append("3389/RDP")
                        resources.append({"resource_name": f"{sg['GroupId']} ({sg.get('GroupName', '')})", "note": f"Ports {', '.join(ports)} open to internet"})
                        break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "EC2", total, affected, "Critical")
    return _result("sebi_sg_ssh_rdp_open", "EC2", "SEBI-CSCRF-PR.AC-2",
                   "Security groups with SSH/RDP open to internet are high-risk attack vectors",
                   9.5, "Critical", resources, "Restrict SSH/RDP access to specific trusted IPs or use Systems Manager", total, affected)


def sebi_default_sg_open(session, scan_meta_data):
    print("sebi_default_sg_open")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
            for sg in page["SecurityGroups"]:
                total += 1
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    has_rules = False
                    for rule in sg.get("IpPermissions", []):
                        has_rules = True
                        break
                    if not has_rules:
                        for rule in sg.get("IpPermissionsEgress", []):
                            if not (rule.get("IpProtocol") == "-1" and rule.get("IpRanges") == [{"CidrIp": "0.0.0.0/0"}]):
                                has_rules = True
                                break
                    if has_rules:
                        resources.append({"resource_name": f"{sg['GroupId']} (VPC: {sg.get('VpcId', 'N/A')})", "note": "Default SG has custom ingress rules"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "EC2", total, affected, "Medium")
    return _result("sebi_default_sg_open", "EC2", "SEBI-CSCRF-PR.AC-3",
                   "Default security groups with custom rules may inadvertently allow traffic",
                   5.0, "Medium", resources, "Remove all inbound/outbound rules from default security groups", total, affected)


def sebi_public_subnet_igw(session, scan_meta_data):
    print("sebi_public_subnet_igw")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        subnets = ec2.describe_subnets()["Subnets"]
        route_tables = ec2.describe_route_tables()["RouteTables"]
        total = len(subnets)
        subnet_rt_map = {}
        for rt in route_tables:
            has_igw = any(r.get("GatewayId", "").startswith("igw-") for r in rt.get("Routes", []))
            if has_igw:
                for assoc in rt.get("Associations", []):
                    if assoc.get("SubnetId"):
                        subnet_rt_map[assoc["SubnetId"]] = rt["RouteTableId"]
                    elif assoc.get("Main"):
                        for subnet in subnets:
                            if subnet["VpcId"] == rt.get("VpcId"):
                                subnet_rt_map.setdefault(subnet["SubnetId"], rt["RouteTableId"])
        for subnet in subnets:
            if subnet["SubnetId"] in subnet_rt_map:
                name = ""
                for tag in subnet.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break
                resources.append({"resource_name": subnet["SubnetId"], "note": f"Name: {name}, has IGW route via {subnet_rt_map[subnet['SubnetId']]}"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "VPC", total, affected, "Medium")
    return _result("sebi_public_subnet_igw", "VPC", "SEBI-CSCRF-PR.AC-4",
                   "Subnets with IGW routes are publicly accessible",
                   5.5, "Medium", resources, "Review subnets with IGW routes; ensure only intended public subnets have them", total, affected)


def sebi_opensearch_public(session, scan_meta_data):
    print("sebi_opensearch_public")
    resources = []
    total = 0
    try:
        es = session.client("opensearch")
        domains = es.list_domain_names().get("DomainNames", [])
        total = len(domains)
        for domain in domains:
            try:
                desc = es.describe_domain(DomainName=domain["DomainName"])["DomainStatus"]
                vpc_opts = desc.get("VPCOptions")
                if not vpc_opts or not vpc_opts.get("VPCId"):
                    resources.append({"resource_name": domain["DomainName"], "note": "Publicly accessible (not in VPC)"})
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "OpenSearch", total, affected, "High")
    return _result("sebi_opensearch_public", "OpenSearch", "SEBI-CSCRF-PR.AC-6",
                   "Publicly accessible OpenSearch domains expose data to the internet",
                   7.5, "High", resources, "Deploy OpenSearch domains within a VPC", total, affected)


def sebi_redshift_public(session, scan_meta_data):
    print("sebi_redshift_public")
    resources = []
    total = 0
    try:
        redshift = session.client("redshift")
        paginator = redshift.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for cluster in page["Clusters"]:
                total += 1
                if cluster.get("PubliclyAccessible", False):
                    resources.append({"resource_name": cluster["ClusterIdentifier"], "note": "Publicly accessible"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "Redshift", total, affected, "High")
    return _result("sebi_redshift_public", "Redshift", "SEBI-CSCRF-PR.AC-7",
                   "Publicly accessible Redshift clusters expose data to the internet",
                   7.5, "High", resources, "Disable public accessibility on Redshift clusters", total, affected)


def sebi_elasticache_no_vpc(session, scan_meta_data):
    print("sebi_elasticache_no_vpc")
    resources = []
    total = 0
    try:
        ec = session.client("elasticache")
        paginator = ec.get_paginator("describe_cache_clusters")
        for page in paginator.paginate():
            for cluster in page["CacheClusters"]:
                total += 1
                if not cluster.get("CacheSubnetGroupName"):
                    resources.append({"resource_name": cluster["CacheClusterId"], "note": "Not deployed in a VPC"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "ElastiCache", total, affected, "High")
    return _result("sebi_elasticache_no_vpc", "ElastiCache", "SEBI-CSCRF-PR.AC-8",
                   "ElastiCache clusters not in VPC lack network isolation",
                   7.0, "High", resources, "Deploy ElastiCache clusters within a VPC with appropriate subnet groups", total, affected)


def sebi_ec2_public_ip_private_subnet(session, scan_meta_data):
    print("sebi_ec2_public_ip_private_subnet")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        route_tables = ec2.describe_route_tables()["RouteTables"]
        # identify private subnets (no IGW route)
        public_subnets = set()
        for rt in route_tables:
            has_igw = any(r.get("GatewayId", "").startswith("igw-") for r in rt.get("Routes", []))
            if has_igw:
                for assoc in rt.get("Associations", []):
                    if assoc.get("SubnetId"):
                        public_subnets.add(assoc["SubnetId"])
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst["State"]["Name"] == "terminated":
                        continue
                    total += 1
                    pub_ip = inst.get("PublicIpAddress")
                    subnet_id = inst.get("SubnetId", "")
                    if pub_ip and subnet_id not in public_subnets:
                        name = ""
                        for tag in inst.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                                break
                        resources.append({"resource_name": inst["InstanceId"], "note": f"Name: {name}, public IP {pub_ip} in private subnet {subnet_id}"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "EC2", total, affected, "Medium")
    return _result("sebi_ec2_public_ip_private_subnet", "EC2", "SEBI-CSCRF-PR.AC-9",
                   "EC2 instances with public IPs in private subnets indicate misconfiguration",
                   5.5, "Medium", resources, "Remove public IPs from instances in private subnets or move to public subnets", total, affected)


def sebi_nacl_permissive(session, scan_meta_data):
    print("sebi_nacl_permissive")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        nacls = ec2.describe_network_acls()["NetworkAcls"]
        for nacl in nacls:
            if not nacl.get("IsDefault", False):
                continue
            total += 1
            for entry in nacl.get("Entries", []):
                if entry.get("RuleNumber") == 32767:
                    continue
                if entry.get("RuleAction") == "allow" and entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("Protocol") == "-1":
                    resources.append({"resource_name": nacl["NetworkAclId"], "note": f"VPC: {nacl.get('VpcId', 'N/A')}, allows all traffic"})
                    break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "VPC", total, affected, "Medium")
    return _result("sebi_nacl_permissive", "VPC", "SEBI-CSCRF-PR.AC-10",
                   "Default NACLs with permissive rules do not provide network segmentation",
                   5.0, "Medium", resources, "Customize default NACLs to restrict traffic or use custom NACLs", total, affected)


def sebi_route_tables_igw_exposure(session, scan_meta_data):
    print("sebi_route_tables_igw_exposure")
    resources = []
    total = 0
    try:
        ec2 = session.client("ec2")
        route_tables = ec2.describe_route_tables()["RouteTables"]
        total = len(route_tables)
        for rt in route_tables:
            has_igw = any(r.get("GatewayId", "").startswith("igw-") for r in rt.get("Routes", []))
            if has_igw:
                associations = rt.get("Associations", [])
                for assoc in associations:
                    if assoc.get("Main", False):
                        resources.append({"resource_name": rt["RouteTableId"], "note": f"Main route table in VPC {rt.get('VpcId', '')} has IGW route"})
                        break
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "VPC", total, affected, "Medium")
    return _result("sebi_route_tables_igw_exposure", "VPC", "SEBI-CSCRF-PR.AC-11",
                   "Main route tables with IGW routes expose all unassociated subnets to internet",
                   5.5, "Medium", resources, "Remove IGW routes from main route tables; use explicit subnet associations", total, affected)


def sebi_lb_without_waf(session, scan_meta_data):
    print("sebi_lb_without_waf")
    resources = []
    total = 0
    try:
        elbv2 = session.client("elbv2")
        waf = session.client("wafv2")
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
        internet_facing = [lb for lb in lbs if lb.get("Scheme") == "internet-facing"]
        total = len(internet_facing)
        for lb in internet_facing:
            try:
                associations = waf.get_web_acl_for_resource(ResourceArn=lb["LoadBalancerArn"])
                if not associations.get("WebACL"):
                    resources.append({"resource_name": lb["LoadBalancerName"], "note": "Internet-facing LB without WAF"})
            except Exception:
                resources.append({"resource_name": lb["LoadBalancerName"], "note": "Internet-facing LB - unable to verify WAF"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "ELB", total, affected, "High")
    return _result("sebi_lb_without_waf", "ELB", "SEBI-CSCRF-PR.AC-12",
                   "Internet-facing load balancers without WAF lack application-layer protection",
                   7.5, "High", resources, "Associate a WAF Web ACL with all internet-facing load balancers", total, affected)


# ===================== PR.PT: Protective Technology =====================

def sebi_shield_advanced(session, scan_meta_data):
    print("sebi_shield_advanced")
    resources = []
    total = 1
    try:
        shield = session.client("shield", region_name="us-east-1")
        try:
            sub = shield.get_subscription_state()
            if sub.get("SubscriptionState") != "ACTIVE":
                resources.append({"resource_name": "Account", "note": "Shield Advanced not active"})
        except Exception:
            resources.append({"resource_name": "Account", "note": "Shield Advanced not enabled"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "Shield", total, affected, "Medium")
    return _result("sebi_shield_advanced", "Shield", "SEBI-CSCRF-PR.PT-2",
                   "AWS Shield Advanced not enabled for DDoS protection",
                   5.0, "Medium", resources, "Enable AWS Shield Advanced for enhanced DDoS protection", total, affected)


def sebi_waf_rate_limiting(session, scan_meta_data):
    print("sebi_waf_rate_limiting")
    resources = []
    total = 0
    try:
        waf = session.client("wafv2")
        for scope in ["REGIONAL", "CLOUDFRONT"]:
            try:
                if scope == "CLOUDFRONT":
                    waf_cf = session.client("wafv2", region_name="us-east-1")
                    acls = waf_cf.list_web_acls(Scope=scope)["WebACLs"]
                else:
                    acls = waf.list_web_acls(Scope=scope)["WebACLs"]
                for acl in acls:
                    total += 1
                    try:
                        client = waf_cf if scope == "CLOUDFRONT" else waf
                        detail = client.get_web_acl(Name=acl["Name"], Scope=scope, Id=acl["Id"])["WebACL"]
                        rules = detail.get("Rules", [])
                        has_rate = any(r.get("Statement", {}).get("RateBasedStatement") for r in rules)
                        if not has_rate:
                            resources.append({"resource_name": acl["Name"], "note": f"Scope: {scope}, no rate-based rules"})
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "WAF", total, affected, "High")
    return _result("sebi_waf_rate_limiting", "WAF", "SEBI-CSCRF-PR.PT-3",
                   "WAF Web ACLs without rate-based rules lack brute-force/DDoS protection",
                   7.0, "High", resources, "Add rate-based rules to WAF Web ACLs to limit request rates", total, affected)


def sebi_cloudfront_waf(session, scan_meta_data):
    print("sebi_cloudfront_waf")
    resources = []
    total = 0
    try:
        cf = session.client("cloudfront")
        dists = cf.list_distributions().get("DistributionList", {}).get("Items", [])
        if dists:
            total = len(dists)
            for dist in dists:
                if not dist.get("WebACLId"):
                    resources.append({"resource_name": dist["Id"], "note": f"Domain: {dist.get('DomainName', '')}, no WAF associated"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "CloudFront", total, affected, "High")
    return _result("sebi_cloudfront_waf", "CloudFront", "SEBI-CSCRF-PR.PT-4",
                   "CloudFront distributions without WAF lack application-layer protection",
                   7.0, "High", resources, "Associate a WAF Web ACL with all CloudFront distributions", total, affected)


def sebi_alb_deletion_protection(session, scan_meta_data):
    print("sebi_alb_deletion_protection")
    resources = []
    total = 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers()["LoadBalancers"]
        albs = [lb for lb in lbs if lb["Type"] == "application"]
        total = len(albs)
        for alb in albs:
            try:
                attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=alb["LoadBalancerArn"])["Attributes"]
                del_prot = next((a for a in attrs if a["Key"] == "deletion_protection.enabled"), None)
                if not del_prot or del_prot["Value"] != "true":
                    resources.append({"resource_name": alb["LoadBalancerName"], "note": "Deletion protection not enabled"})
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "ELB", total, affected, "Medium")
    return _result("sebi_alb_deletion_protection", "ELB", "SEBI-CSCRF-PR.PT-5",
                   "ALBs without deletion protection can be accidentally deleted",
                   5.0, "Medium", resources, "Enable deletion protection on all production ALBs", total, affected)


def sebi_rds_deletion_protection(session, scan_meta_data):
    print("sebi_rds_deletion_protection")
    resources = []
    total = 0
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                total += 1
                if not db.get("DeletionProtection", False):
                    resources.append({"resource_name": db["DBInstanceIdentifier"], "note": "Deletion protection not enabled"})
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "RDS", total, affected, "Medium")
    return _result("sebi_rds_deletion_protection", "RDS", "SEBI-CSCRF-PR.PT-6",
                   "RDS instances without deletion protection can be accidentally deleted",
                   5.0, "Medium", resources, "Enable deletion protection on all production RDS instances", total, affected)


def sebi_s3_object_lock(session, scan_meta_data):
    print("sebi_s3_object_lock")
    resources = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            try:
                s3.get_object_lock_configuration(Bucket=bucket["Name"])
            except s3.exceptions.ClientError as e:
                if "ObjectLockConfigurationNotFoundError" in str(e):
                    resources.append({"resource_name": bucket["Name"], "note": "Object lock not enabled"})
            except Exception:
                pass
    except Exception as e:
        resources.append({"resource_name": "Error", "note": str(e)})
    affected = len(resources)
    _update_meta(scan_meta_data, "S3", total, affected, "Medium")
    return _result("sebi_s3_object_lock", "S3", "SEBI-CSCRF-PR.PT-7",
                   "S3 buckets without object lock cannot prevent object deletion or overwrite",
                   5.0, "Medium", resources, "Enable S3 Object Lock for compliance and data immutability requirements", total, affected)
