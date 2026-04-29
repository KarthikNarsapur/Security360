import boto3
import os
import json
from datetime import datetime, timezone, timedelta

# from backend.modules.Other import ou
from modules.AwsChecks import (
    ec2_checks,
    iam_checks,
    nacl_checks,
    rds_checks,
    s3_checks,
    security_checks,
    vpc_checks,
    ssm_checks,
    secrets_manager_checks,
    guardduty_checks,
    cloudtrail_checks,
    lambda_fun,
    ecs_checks,
    dynamodb,
    elasticache,
    tagging_checks,
    backup_checks,
    sns_checks,
    ou,
    attack_path_analysis,
    identity_risk_scoring,
    data_sensitivity,
    runtime_behavior,
    unified_risk_engine,
    cloudfront_checks,
    eks_checks,
    redshift_checks,
    opensearch_checks,
    sqs_checks,
    ecr_checks,
)
from Model.model import AccessTokenModel
from utils.upload_to_s3 import upload_to_s3

CONFIG_FILE = "./config/accounts.json"
REPORT_FILE = "./reports"
IST = timezone(timedelta(hours=5, minutes=30))


def run_checks(session, scan_meta_data={}, security_services_scan={}):

    security_services_scan["Amazon GuardDuty"] = security_checks.guardduty_enabled(
        session
    )
    security_services_scan["AWS Config"] = security_checks.aws_config_enabled(session)
    security_services_scan["Amazon Inspector"] = security_checks.inspector_enabled(
        session
    )
    security_services_scan["AWS Security Hub"] = security_checks.security_hub_enabled(
        session
    )
    security_services_scan["AWS Access Analyzer"] = (
        security_checks.access_analyzer_enabled(session)
    )
    security_services_scan["AWS Cloudtrail"] = security_checks.cloudtrail_enabled(
        session
    )
    security_services_scan["AWS WAF"] = security_checks.check_waf_enabled(session)
    security_services_scan["KMS Key Policies"] = security_checks.check_kms_permissive_policies(session)
    security_services_scan["CloudWatch Log Retention"] = security_checks.check_cloudwatch_log_retention(session)
    security_services_scan["CloudWatch Critical Alarms"] = security_checks.check_cloudwatch_critical_alarms(session)
    security_services_scan["ELB Access Logs"] = security_checks.check_elb_access_logs(session)
    security_services_scan["AWS Shield Advanced"] = security_checks.check_shield_advanced(session)
    security_services_scan["HTTPS Enforcement"] = security_checks.check_https_enforcement(session)
    security_services_scan["TLS Policy Strength"] = security_checks.check_tls_policy_strength(session)
    security_services_scan["WAF on API Gateway"] = security_checks.check_waf_on_api_gateway(session)
    security_services_scan["Unresolved Findings"] = security_checks.check_unresolved_security_findings(session)
    security_services_scan["Automated Remediation"] = security_checks.check_automated_remediation(session)
    security_services_scan["KMS Key Rotation"] = security_checks.check_kms_key_rotation(session)
    security_services_scan["KMS Pending Deletion"] = security_checks.check_kms_pending_deletion(session)
    security_services_scan["Amazon Macie"] = security_checks.check_macie_enabled(session)
    security_services_scan["EventBridge Security Rules"] = security_checks.check_eventbridge_security_rules(session)
    security_services_scan["ACM Expiring Certificates"] = security_checks.check_acm_expiring_certs(session)
    return {
        "default_vpcs": vpc_checks.check_default_vpcs(session, scan_meta_data),
        "open_security_groups": ec2_checks.check_open_security_groups(
            session, scan_meta_data
        ),
        "unused_security_groups": ec2_checks.find_unused_security_groups(
            session, scan_meta_data
        ),
        "unencrypted_ebs_volumes": ec2_checks.unencrypted_ebs_volumes(
            session, scan_meta_data
        ),
        "termination_protection": ec2_checks.check_ec2_termination_protection(
            session, scan_meta_data
        ),
        "rds_public": rds_checks.check_public_rds(session, scan_meta_data),
        "rds_unencrypted": rds_checks.check_unencrypted_rds(session, scan_meta_data),
        "delete protection": rds_checks.check_rds_cluster_deletion_protection(
            session, scan_meta_data
        ),
        "secrets_manager": secrets_manager_checks.check_secrets_manager_enabled(
            session, scan_meta_data
        ),
        "guardduty_findings": guardduty_checks.check_guardduty_enabled(
            session, scan_meta_data
        ),
        "iam_access_analyzer_findings": iam_checks.check_iam_access_analyzer(
            session, scan_meta_data
        ),
        "ssm_patch_manager": ssm_checks.non_compliant_patch_instances(
            session, scan_meta_data
        ),
        "subnet_separation": vpc_checks.check_subnet_separation(
            session, scan_meta_data
        ),
        "nat_gateway_private_subnets": vpc_checks.check_nat_gateway_for_private_subnets(
            session, scan_meta_data
        ),
        "private_resources_in_public_subnets": vpc_checks.check_private_subnet_direct_internet_access(
            session, scan_meta_data
        ),
        "vpc_endpoints": vpc_checks.check_vpc_endpoints(
            session, scan_meta_data
        ),
        "overly_permissive_outbound_sg": ec2_checks.check_overly_permissive_outbound_sg(
            session, scan_meta_data
        ),
        "ec2_without_iam_role": ec2_checks.check_ec2_iam_role_attached(
            session, scan_meta_data
        ),
        "ec2_userdata_secrets": ec2_checks.check_ec2_userdata_secrets(
            session, scan_meta_data
        ),
        "lambda_env_kms_encryption": lambda_fun.check_lambda_env_kms_encryption(
            session, scan_meta_data
        ),
        "lambda_env_secrets": lambda_fun.check_lambda_env_secrets(
            session, scan_meta_data
        ),
        "lambda_timeout": lambda_fun.check_lambda_timeout(
            session, scan_meta_data
        ),
        "lambda_vpc_enabled": lambda_fun.check_lambda_vpc_enabled(
            session, scan_meta_data
        ),
        "ecs_privileged_containers": ecs_checks.check_ecs_privileged_containers(
            session, scan_meta_data
        ),
        "ecs_root_user_containers": ecs_checks.check_ecs_root_user_containers(
            session, scan_meta_data
        ),
        "ecs_task_role_credentials": ecs_checks.check_ecs_task_role_and_credentials(
            session, scan_meta_data
        ),
        "ecs_plaintext_secrets": ecs_checks.check_ecs_secrets_from_secrets_manager(
            session, scan_meta_data
        ),
        "ecs_readonly_root_filesystem": ecs_checks.check_ecs_readonly_root_filesystem(
            session, scan_meta_data
        ),
        "ecs_logging_enabled": ecs_checks.check_ecs_logging_enabled(
            session, scan_meta_data
        ),
        "rds_automated_backups": rds_checks.check_rds_automated_backups(
            session, scan_meta_data
        ),
        "rds_multi_az": rds_checks.check_rds_multi_az(
            session, scan_meta_data
        ),
        "rds_iam_authentication": rds_checks.check_rds_iam_authentication(
            session, scan_meta_data
        ),
        "rds_default_ports_exposed": rds_checks.check_rds_default_ports_exposed(
            session, scan_meta_data
        ),
        "rds_security_groups_restricted": rds_checks.check_rds_security_groups_restricted(
            session, scan_meta_data
        ),
        "dynamodb_pitr": dynamodb.check_dynamodb_pitr(
            session, scan_meta_data
        ),
        "elasticache_transit_encryption": elasticache.check_elasticache_transit_encryption(
            session, scan_meta_data
        ),
        "elasticache_auth_enabled": elasticache.check_elasticache_auth_enabled(
            session, scan_meta_data
        ),
        "elasticache_public_accessibility": elasticache.check_elasticache_public_accessibility(
            session, scan_meta_data
        ),
        "efs_access_points": ec2_checks.check_efs_access_points(
            session, scan_meta_data
        ),
        "efs_security_groups": ec2_checks.check_efs_security_groups(
            session, scan_meta_data
        ),
        "secrets_manager_usage": secrets_manager_checks.check_secrets_manager_usage(
            session, scan_meta_data
        ),
        "tagging_enforcement": tagging_checks.check_required_tags(
            session, scan_meta_data
        ),
        "backup_policies": backup_checks.check_backup_policies(
            session, scan_meta_data
        ),
        "sns_alert_integration": sns_checks.check_sns_alert_integration(
            session, scan_meta_data
        ),
        "runtime_behavior": runtime_behavior.analyze_runtime_behavior(
            session, scan_meta_data
        ),
        "cloudfront_default_cert": cloudfront_checks.check_cloudfront_default_cert(session, scan_meta_data),
        "cloudfront_waf": cloudfront_checks.check_cloudfront_waf(session, scan_meta_data),
        "cloudfront_min_tls": cloudfront_checks.check_cloudfront_min_tls(session, scan_meta_data),
        "cloudfront_origin_protocol": cloudfront_checks.check_cloudfront_origin_protocol(session, scan_meta_data),
        "eks_public_endpoint": eks_checks.check_eks_public_endpoint(session, scan_meta_data),
        "eks_version_eol": eks_checks.check_eks_version_eol(session, scan_meta_data),
        "eks_logging": eks_checks.check_eks_logging(session, scan_meta_data),
        "eks_secrets_encryption": eks_checks.check_eks_secrets_encryption(session, scan_meta_data),
        "redshift_encryption": redshift_checks.check_redshift_encryption(session, scan_meta_data),
        "redshift_public": redshift_checks.check_redshift_public(session, scan_meta_data),
        "redshift_audit_logging": redshift_checks.check_redshift_audit_logging(session, scan_meta_data),
        "opensearch_encryption": opensearch_checks.check_opensearch_encryption(session, scan_meta_data),
        "opensearch_public": opensearch_checks.check_opensearch_public(session, scan_meta_data),
        "opensearch_node_encryption": opensearch_checks.check_opensearch_node_encryption(session, scan_meta_data),
        "sqs_encryption": sqs_checks.check_sqs_encryption(session, scan_meta_data),
        "sqs_wildcard_policy": sqs_checks.check_sqs_wildcard_policy(session, scan_meta_data),
        "ecr_scan_on_push": ecr_checks.check_ecr_scan_on_push(session, scan_meta_data),
        "ecr_lifecycle_policy": ecr_checks.check_ecr_lifecycle_policy(session, scan_meta_data),
        "ec2_imdsv2": ec2_checks.check_ec2_imdsv2(session, scan_meta_data),
        "ebs_default_encryption": ec2_checks.check_ebs_default_encryption(session, scan_meta_data),
        "public_ebs_snapshots": ec2_checks.check_public_ebs_snapshots(session, scan_meta_data),
        "stopped_instances": ec2_checks.check_stopped_instances(session, scan_meta_data),
        "unattached_ebs_volumes": ec2_checks.check_unattached_ebs_volumes(session, scan_meta_data),
        "rds_auto_minor_upgrade": rds_checks.check_rds_auto_minor_upgrade(session, scan_meta_data),
        "rds_instance_deletion_protection": rds_checks.check_rds_instance_deletion_protection(session, scan_meta_data),
        "lambda_public_access": lambda_fun.check_lambda_public_access(session, scan_meta_data),
        "lambda_deprecated_runtime": lambda_fun.check_lambda_deprecated_runtime(session, scan_meta_data),
        "dynamodb_cmk_encryption": dynamodb.check_dynamodb_cmk_encryption(session, scan_meta_data),
        "vpc_flow_logs": vpc_checks.check_vpc_flow_logs(session, scan_meta_data),
        "subnets_auto_assign_public_ip": vpc_checks.check_subnets_auto_assign_public_ip(session, scan_meta_data),
        "sns_encryption": sns_checks.check_sns_encryption(session, scan_meta_data),
        "sns_wildcard_policy": sns_checks.check_sns_wildcard_policy(session, scan_meta_data),
        
    }


def run_global_services_checks(session, scan_meta_data_global_services):

    iam = session.client("iam")

    # === Pre-fetch data ===
    users = iam.list_users()["Users"]
    policies = iam.list_policies(Scope="Local")["Policies"]
    account_summary = iam.get_account_summary()["SummaryMap"]
    roles = iam.list_roles()["Roles"]
    access_keys_map = {
        user["UserName"]: iam.list_access_keys(UserName=user["UserName"])[
            "AccessKeyMetadata"
        ]
        for user in users
    }

    return {
        "public_s3_buckets": s3_checks.public_s3_buckets(
            session, scan_meta_data_global_services
        ),
        "users_without_mfa": iam_checks.users_without_mfa(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            users=users,
        ),
        "overly_permissive_policies": iam_checks.overly_permissive_policies(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            policies=policies,
        ),
        "root_account_mfa_enabled": iam_checks.root_account_without_mfa(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            account_summary=account_summary,
        ),
        "access_keys_older_than_90_days": iam_checks.access_keys_older_than_90_days(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "active_access_keys_with_high_age": iam_checks.active_access_keys_with_high_age(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "iam_users_with_no_recent_activity": iam_checks.iam_users_with_no_recent_activity(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "passwords_older_than_90_days": iam_checks.passwords_older_than_90_days(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
        ),
        "multiple_active_access_keys": iam_checks.multiple_active_access_keys(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "iam_roles_without_recent_use": iam_checks.iam_roles_without_recent_use(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            roles=roles,
        ),
        "access_keys_last_used_over_90_days_ago": iam_checks.access_keys_last_used_over_90_days_ago(
            scan_meta_data_global_services=scan_meta_data_global_services,
            iam=iam,
            users=users,
            access_keys_map=access_keys_map,
        ),
        "cloudtrail_and_logging": cloudtrail_checks.cloudtrail_and_logging_check(
            session=session
        ),
        "wildcard_principal_bucket_policies": s3_checks.wildcard_principal_bucket_policies(
            session, scan_meta_data_global_services
        ),
        "cross_account_bucket_sharing": s3_checks.cross_account_bucket_sharing(
            session, scan_meta_data_global_services
        ),
        "root_account_recent_usage": iam_checks.root_account_recent_usage(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            account_summary=account_summary,
        ),
        "users_with_administrator_access": iam_checks.users_with_administrator_access(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            users=users,
        ),
        "wildcard_principal_in_trust_policies": iam_checks.wildcard_principal_in_trust_policies(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            roles=roles,
        ),
        "password_policy_complexity": iam_checks.password_policy_complexity(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
        ),
        "break_glass_role": iam_checks.check_break_glass_role(
            iam=iam,
            scan_meta_data_global_services=scan_meta_data_global_services,
            roles=roles,
        ),
        "cloudtrail_log_immutability": cloudtrail_checks.check_cloudtrail_log_immutability(
            session=session,
        ),
        "centralized_logging_account": cloudtrail_checks.check_centralized_logging_account(
            session=session,
        ),
        "scps_applied": ou.check_scps_applied(session=session),
        "region_restriction": ou.check_region_restriction(session=session),
        "service_restriction": ou.check_service_restriction(session=session),
        "identity_risk_scoring": identity_risk_scoring.analyze_identity_risks(
            session=session,
            scan_meta_data_global_services=scan_meta_data_global_services,
        ),
        "data_sensitivity": data_sensitivity.analyze_data_sensitivity(
            session=session,
            scan_meta_data_global_services=scan_meta_data_global_services,
        ),
        "iam_user_inline_policies": iam_checks.check_iam_user_inline_policies(
            iam=iam, scan_meta_data_global_services=scan_meta_data_global_services, users=users,
        ),
        "iam_group_inline_policies": iam_checks.check_iam_group_inline_policies(
            iam=iam, scan_meta_data_global_services=scan_meta_data_global_services,
        ),
        "root_access_keys_exist": iam_checks.check_root_access_keys_exist(
            iam=iam, scan_meta_data_global_services=scan_meta_data_global_services, account_summary=account_summary,
        ),
        "support_role_exists": iam_checks.check_support_role_exists(
            iam=iam, scan_meta_data_global_services=scan_meta_data_global_services, roles=roles,
        ),
        "s3_default_encryption": s3_checks.check_s3_default_encryption(
            session, scan_meta_data_global_services,
        ),
        "s3_versioning": s3_checks.check_s3_versioning(
            session, scan_meta_data_global_services,
        ),
        "s3_access_logging": s3_checks.check_s3_access_logging(
            session, scan_meta_data_global_services,
        ),
        "s3_ssl_enforcement": s3_checks.check_s3_ssl_enforcement(
            session, scan_meta_data_global_services,
        ),
    }


def run_scan(data: AccessTokenModel):

    try:
        # Route to cloud-specific scan
        cloud = getattr(data, "cloud", "aws") or "aws"

        if cloud == "azure":
            return run_azure_scan(data)
        elif cloud == "gcp":
            return {"status": "error", "error_message": "GCP scanning is not yet supported."}

        return run_aws_scan(data)

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {"status": "error", "error_message": "Unknown error occured"}


def run_azure_scan(data: AccessTokenModel):
    """Run Azure security scan for given subscription accounts."""
    try:
        from utils.upload_to_s3 import save_report, upload_to_s3
        from db.crud import increament_scan_count, check_scan_threshold
        from azure.azure_scan import run_azure_checks, get_azure_credential

        username = data.username
        if not username:
            return {"status": "error", "error_message": "Username is missing."}
        if not data.accounts or len(data.accounts) == 0:
            return {"status": "error", "error_message": "Azure accounts list is missing or empty."}

        threshold_response = check_scan_threshold(username=username, scan_type="azure_basic")
        if threshold_response.get("status") == "error":
            return threshold_response

        notifications = {"success": [], "error": []}

        for account in data.accounts:
            subscription_id = account.account_id or ""
            account_name = account.account_name or ""
            tenant_id = getattr(account, "tenant_id", "") or ""
            client_id = getattr(account, "client_id", "") or ""
            client_secret = getattr(account, "client_secret", "") or ""

            if not subscription_id:
                notifications["error"].append("Missing subscription ID")
                continue

            if not all([tenant_id, client_id, client_secret]):
                notifications["error"].append(
                    f"Missing Azure credentials for subscription: {subscription_id}. "
                    "Please provide tenant_id, client_id, and client_secret."
                )
                continue

            try:
                print(f"Scanning Azure subscription: {subscription_id}")
                credential = get_azure_credential(tenant_id, client_id, client_secret)
                results, sub_name = run_azure_checks(subscription_id, credential)
                account_name = account_name or sub_name

                # Format results to match the standard report structure
                regional_results = [{"region": "global", "data": results}]
                scan_meta_data = [{"region": "global", "data": {
                    "total_scanned": sum(r.get("additional_info", {}).get("total_scanned", 0) for r in results.values()),
                    "affected": sum(r.get("additional_info", {}).get("affected", 0) for r in results.values()),
                    "High": sum(1 for r in results.values() if r.get("severity_level") == "High" and r.get("additional_info", {}).get("affected", 0) > 0),
                    "Medium": sum(1 for r in results.values() if r.get("severity_level") == "Medium" and r.get("additional_info", {}).get("affected", 0) > 0),
                    "Low": sum(1 for r in results.values() if r.get("severity_level") == "Low" and r.get("additional_info", {}).get("affected", 0) > 0),
                    "Critical": 0,
                    "services_scanned": list(set(r.get("service", "") for r in results.values())),
                }}]

                saved_filename = save_report(
                    account_id=subscription_id,
                    username=username,
                    account_name=account_name,
                    results=regional_results,
                    type="summary",
                    scan_meta_data=scan_meta_data,
                    security_services_scan=[],
                    global_services_scan_results={},
                    scan_meta_data_global_services={},
                    output_dir=f"scan-reports/azure/{username}",
                    regions=["global"],
                )

                upload_to_s3(
                    file_name=saved_filename,
                    folder_name=f"scan-reports/azure/{username}",
                    s3_folder_name=f"azure-security-reports/{username}",
                )

                increament_scan_count(username=username, scan_type="azure_basic")
                notifications["success"].append(f"Scan successful: {subscription_id}")

            except Exception as e:
                print(f"Error scanning Azure subscription {subscription_id}: {e}")
                notifications["error"].append(f"Scan failed for: {subscription_id}")

        return {"status": "ok", "notifications": notifications}

    except Exception as e:
        print(f"Azure scan error: {str(e)}")
        return {"status": "error", "error_message": f"Azure scan failed: {str(e)}"}


def run_aws_scan(data: AccessTokenModel):

    try:
        from utils.upload_to_s3 import save_report
        from db.crud import increament_scan_count, check_scan_threshold

        # step 1 check data
        if not data.username:
            return {
                "status": "error",
                "error_message": "Username is missing.",
            }
        if not data.regions or len(data.regions) == 0:
            return {
                "status": "error",
                "error_message": "AWS regions list is missing or empty.",
            }
        if not data.accounts or len(data.accounts) == 0:
            return {
                "status": "error",
                "error_message": "AWS accounts list is missing or empty.",
            }

        REGIONS = data.regions
        username = data.username
        roles_info = data.accounts

        threshold_response = check_scan_threshold(username=username, scan_type="basic")
        if threshold_response.get("status") == "error":
            return threshold_response

        # print("Username: ", username)
        # print("Regions: ", REGIONS)
        # print("Roles Info: ", roles_info)

        notifications = {"success": [], "error": []}
        # step 2: loop through roles and run scan
        for role in roles_info:
            account_id = role.account_id or ""
            role_arn = role.role_arn or ""
            account_name = role.account_name or ""
            if account_id == "" or role_arn == "":
                print(f"Missing account details: {account_id}")
                continue
            try:
                # step 3: assume Role
                sts_client = boto3.client("sts")
                try:
                    assumed_role = sts_client.assume_role(
                        RoleArn=role_arn, RoleSessionName="SecurityAuditSession"
                    )
                except Exception as e:
                    print(f"Error assuming role for {account_id}: {e}")
                    notifications["error"].append(f"Role assume failed: {account_id}")
                    continue

                credentials = assumed_role["Credentials"]
                access_key = credentials["AccessKeyId"]
                secret_key = credentials["SecretAccessKey"]
                session_token = credentials["SessionToken"]

                regional_results = []
                region_scan_meta_data = []
                region_security_services_scan = []

                scan_meta_data_global_services = {
                    "total_scanned": 0,
                    "affected": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Critical": 0,
                    "services_scanned": [],
                }
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token,
                    region_name="ap-south-1",
                )
                global_services_scan_results = run_global_services_checks(
                    session, scan_meta_data_global_services
                )
                failed_regions = []
                for region in REGIONS:
                    session = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        aws_session_token=session_token,
                        region_name=region,
                    )

                    if not session:
                        print(f" Failed to create session for account {account_id}")
                        failed_regions.append(region)
                        continue

                    print(f" Checking region: {region}")
                    try:
                        scan_meta_data = {
                            "total_scanned": 0,
                            "affected": 0,
                            "High": 0,
                            "Medium": 0,
                            "Low": 0,
                            "Critical": 0,
                            "services_scanned": [],
                        }
                        security_services_scan = {}
                        results = run_checks(
                            session, scan_meta_data, security_services_scan
                        )
                        regional_results.append({"region": region, "data": results})
                        region_scan_meta_data.append(
                            {"region": region, "data": scan_meta_data}
                        )
                        region_security_services_scan.append(
                            {"region": region, "data": security_services_scan}
                        )
                    except Exception as e:
                        print(
                            f" Error scanning region {region} for account {account_id}: {e}"
                        )
                        import traceback
                        traceback.print_exc()
                        failed_regions.append(region)

                if len(failed_regions) > 0:
                    print(f"failed scan for {account_id} in regions: {failed_regions}")
                    notifications["error"].append(
                        f"Scan failed in regions: {', '.join(failed_regions)} for account: {account_id}"
                    )

                # step 4.5: Run cross-service attack path analysis
                try:
                    # Use first region's results for correlation (most checks are the same across regions)
                    first_regional = regional_results[0]["data"] if regional_results else {}
                    attack_path_meta = {
                        "total_scanned": 0, "affected": 0,
                        "High": 0, "Medium": 0, "Low": 0, "Critical": 0,
                        "services_scanned": [],
                    }
                    attack_path_result = attack_path_analysis.analyze_attack_paths(
                        session, first_regional, global_services_scan_results, attack_path_meta
                    )
                    global_services_scan_results["attack_path_analysis"] = attack_path_result
                except Exception as e:
                    print(f"Error in attack path analysis for {account_id}: {e}")

                # step 4.6: Run unified risk engine
                try:
                    unified_risk = unified_risk_engine.run_unified_risk_engine(
                        regional_results_list=regional_results,
                        global_results=global_services_scan_results,
                        attack_path_results=global_services_scan_results.get("attack_path_analysis"),
                        identity_risk_results=global_services_scan_results.get("identity_risk_scoring"),
                        data_sensitivity_results=global_services_scan_results.get("data_sensitivity"),
                        runtime_results_list=regional_results,
                    )
                    global_services_scan_results["unified_risk_engine"] = unified_risk
                except Exception as e:
                    print(f"Error in unified risk engine for {account_id}: {e}")

                # step 5: save report and upload to S3
                try:
                    saved_filename = save_report(
                        account_id=account_id,
                        username=username,
                        account_name=account_name,
                        results=regional_results,
                        type="summary",
                        scan_meta_data=region_scan_meta_data,
                        security_services_scan=region_security_services_scan,
                        global_services_scan_results=global_services_scan_results,
                        scan_meta_data_global_services=scan_meta_data_global_services,
                        output_dir=f"scan-reports/best-practices/{username}",
                        regions=REGIONS,
                    )
                except Exception as e:
                    print(f"Error saving scan report for account {account_id}: {e}")
                    notifications["error"].append(f"Report save failed: {account_id}")
                    continue
                try:
                    upload_to_s3(
                        file_name=saved_filename,
                        folder_name=f"scan-reports/best-practices/{username}",
                        s3_folder_name=f"aws-account-security-reports/{username}",
                    )

                except Exception as e:
                    print(f" Error uploading data to S3: {e}")
                    notifications["error"].append(
                        f" Error uploading data to S3 for account id: {account_id}"
                    )

                try:
                    increament_scan_count(username=username, scan_type="basic")
                    notifications["success"].append(f"scan successfull : {account_id}")
                except Exception as e:
                    print(
                        f"Error incrementing scan count for account {account_id}: {e}"
                    )
                    notifications["error"].append(
                        f"Failed to increment scan count for account: {account_id}"
                    )

            except Exception as e:
                print(f"got error for account id: {account_id}: {str(e)}")
                notifications["error"].append(
                    f"Unknown error occured for account id: {account_id}"
                )
        return {"status": "ok", "notifications": notifications}

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {"status": "error", "error_message": "Unknown error occured"}
