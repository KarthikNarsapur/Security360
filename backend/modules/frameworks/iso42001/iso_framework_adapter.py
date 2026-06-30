"""
Adapter to plug ISO 42001 checks into the unified framework_scan.py registry.
Converts the existing async ISO check dict into the standard (session, scan_meta_data) -> list format.
Includes both original 36 checks and extended 83 checks (AI-001 to AI-052+).
"""
from modules.frameworks.iso42001.iso_run_checks import iso_checks


def _get_extended_checks():
    """Lazy-load extended checks to avoid import overhead when not needed."""
    from modules.frameworks.iso42001.checks.iam_checks import (
        check_iam_access_analyzer_findings,
        check_ai_roles_wildcard_resources,
        check_ai_roles_wildcard_actions,
        check_ai_service_linked_roles,
        check_cross_account_trust_ai_roles,
        check_ai_users_long_lived_access_keys,
        check_ai_service_last_accessed,
    )
    from modules.frameworks.iso42001.checks.sagemaker_checks import (
        check_sagemaker_studio_domains_encrypted,
        check_sagemaker_studio_auth_mode,
        check_sagemaker_user_profiles_inventory,
        check_endpoint_status_validation,
        check_endpoint_config_encryption,
        check_async_inference_config,
        check_multi_model_endpoint,
        check_model_package_approval_workflow,
        check_processing_job_network_isolation,
        check_processing_job_vpc_config,
        check_hyperparameter_tuning_jobs,
        check_automl_jobs_inventory,
        check_batch_transform_jobs,
        check_feature_groups_inventory,
        check_data_wrangler_flows,
    )
    from modules.frameworks.iso42001.checks.bedrock_checks import (
        check_bedrock_custom_models,
        check_bedrock_provisioned_throughput,
        check_bedrock_inference_profiles,
        check_bedrock_knowledge_bases,
        check_knowledge_base_encryption,
        check_bedrock_agents,
        check_bedrock_agent_aliases,
        check_bedrock_prompt_management,
    )
    from modules.frameworks.iso42001.checks.s3_governance_checks import (
        check_bucket_object_lock,
        check_bucket_ownership_controls,
        check_bucket_acl_usage,
        check_bucket_policy_permissive,
        check_sse_kms_vs_s3,
        check_default_encryption_missing,
        check_bucket_replication,
    )
    from modules.frameworks.iso42001.checks.kms_checks import (
        check_customer_managed_keys_disabled,
        check_pending_deletion_keys,
        check_disabled_kms_keys,
        check_ai_workloads_aws_managed_keys,
    )
    from modules.frameworks.iso42001.checks.cloudtrail_logging_checks import (
        check_cloudtrail_insights_enabled,
        check_organization_trail,
        check_s3_data_events_enabled,
        check_lambda_data_events_enabled,
        check_cloudwatch_logs_retention,
        check_log_groups_encrypted,
    )
    from modules.frameworks.iso42001.checks.monitoring_checks import (
        check_missing_alarms_ai_endpoints,
        check_missing_alarms_training_failures,
        check_missing_alarms_invocation_failures,
        check_missing_alarms_endpoint_latency,
        check_missing_alarms_model_errors,
    )
    from modules.frameworks.iso42001.checks.networking_checks import (
        check_public_subnets_ai_resources,
        check_security_groups_sagemaker,
        check_security_groups_api_gateway,
        check_missing_vpc_endpoints_ai,
        check_nacls_unrestricted,
    )
    from modules.frameworks.iso42001.checks.secrets_config_backup_checks import (
        check_secrets_manager_encrypted,
        check_secret_rotation_enabled,
        check_stale_secrets,
        check_config_recorder_status,
        check_config_delivery_channel,
        check_backup_recovery_points,
        check_ecr_image_scanning,
        check_ecr_immutable_tags,
        check_ecr_encryption,
        check_resource_tagging_completeness,
    )
    from modules.frameworks.iso42001.checks.apigateway_checks import (
        check_api_authorization_enabled,
        check_api_logging_enabled,
        check_api_stages_encrypted,
    )
    from modules.frameworks.iso42001.checks.ecs_eks_checks import (
        check_ecr_public_repository,
        check_ecs_privileged_containers,
        check_containers_running_as_root,
        check_public_load_balancers_ai,
        check_missing_tls_listeners,
    )
    from modules.frameworks.iso42001.checks.miscellaneous_checks import (
        check_config_rules_compliance,
        check_conformance_pack_compliance,
        check_backup_vault_encryption,
        check_protected_ai_resources,
        check_unused_ai_resources,
        check_ai_resources_unsupported_regions,
        check_service_quota_utilization,
        check_trusted_advisor_ai_checks,
    )

    return {
        # IAM Checks (AI-001 to AI-007)
        "AI-001": check_iam_access_analyzer_findings,
        "AI-002": check_ai_roles_wildcard_resources,
        "AI-003": check_ai_roles_wildcard_actions,
        "AI-004": check_ai_service_linked_roles,
        "AI-005": check_cross_account_trust_ai_roles,
        "AI-006": check_ai_users_long_lived_access_keys,
        "AI-007": check_ai_service_last_accessed,
        # SageMaker Checks (AI-008 to AI-022)
        "AI-008": check_sagemaker_studio_domains_encrypted,
        "AI-009": check_sagemaker_studio_auth_mode,
        "AI-010": check_sagemaker_user_profiles_inventory,
        "AI-011": check_endpoint_status_validation,
        "AI-012": check_endpoint_config_encryption,
        "AI-013": check_async_inference_config,
        "AI-014": check_multi_model_endpoint,
        "AI-015": check_model_package_approval_workflow,
        "AI-016": check_processing_job_network_isolation,
        "AI-017": check_processing_job_vpc_config,
        "AI-018": check_hyperparameter_tuning_jobs,
        "AI-019": check_automl_jobs_inventory,
        "AI-020": check_batch_transform_jobs,
        "AI-021": check_feature_groups_inventory,
        "AI-022": check_data_wrangler_flows,
        # Bedrock Checks (AI-023 to AI-030)
        "AI-023": check_bedrock_custom_models,
        "AI-024": check_bedrock_provisioned_throughput,
        "AI-025": check_bedrock_inference_profiles,
        "AI-026": check_bedrock_knowledge_bases,
        "AI-027": check_knowledge_base_encryption,
        "AI-028": check_bedrock_agents,
        "AI-029": check_bedrock_agent_aliases,
        "AI-030": check_bedrock_prompt_management,
        # S3 Governance Checks (AI-031 to AI-037)
        "AI-031": check_bucket_object_lock,
        "AI-032": check_bucket_ownership_controls,
        "AI-033": check_bucket_acl_usage,
        "AI-034": check_bucket_policy_permissive,
        "AI-035": check_sse_kms_vs_s3,
        "AI-036": check_default_encryption_missing,
        "AI-037": check_bucket_replication,
        # KMS Checks (AI-038 to AI-041)
        "AI-038": check_customer_managed_keys_disabled,
        "AI-039": check_pending_deletion_keys,
        "AI-040": check_disabled_kms_keys,
        "AI-041": check_ai_workloads_aws_managed_keys,
        # CloudTrail & Logging Checks (AI-042 to AI-047)
        "AI-042": check_cloudtrail_insights_enabled,
        "AI-043": check_organization_trail,
        "AI-044": check_s3_data_events_enabled,
        "AI-045": check_lambda_data_events_enabled,
        "AI-046": check_cloudwatch_logs_retention,
        "AI-047": check_log_groups_encrypted,
        # Monitoring Checks (AI-048 to AI-052)
        "AI-048": check_missing_alarms_ai_endpoints,
        "AI-049": check_missing_alarms_training_failures,
        "AI-050": check_missing_alarms_invocation_failures,
        "AI-051": check_missing_alarms_endpoint_latency,
        "AI-052": check_missing_alarms_model_errors,
        # Networking Checks (AI-053 to AI-057)
        "AI-053": check_public_subnets_ai_resources,
        "AI-054": check_security_groups_sagemaker,
        "AI-055": check_security_groups_api_gateway,
        "AI-056": check_missing_vpc_endpoints_ai,
        "AI-057": check_nacls_unrestricted,
        # Secrets, Config, Backup, ECR Checks (AI-058 to AI-079)
        "AI-058": check_secrets_manager_encrypted,
        "AI-059": check_secret_rotation_enabled,
        "AI-060": check_stale_secrets,
        "AI-061": check_config_recorder_status,
        "AI-062": check_config_delivery_channel,
        "AI-063": check_config_rules_compliance,
        "AI-064": check_conformance_pack_compliance,
        "AI-065": check_backup_recovery_points,
        "AI-066": check_backup_vault_encryption,
        "AI-067": check_protected_ai_resources,
        # API Gateway Checks (AI-068 to AI-070)
        "AI-068": check_api_authorization_enabled,
        "AI-069": check_api_logging_enabled,
        "AI-070": check_api_stages_encrypted,
        # ECR & ECS/EKS Checks (AI-071 to AI-078)
        "AI-071": check_ecr_image_scanning,
        "AI-072": check_ecr_immutable_tags,
        "AI-073": check_ecr_encryption,
        "AI-074": check_ecr_public_repository,
        "AI-075": check_ecs_privileged_containers,
        "AI-076": check_containers_running_as_root,
        "AI-077": check_public_load_balancers_ai,
        "AI-078": check_missing_tls_listeners,
        # Miscellaneous Checks (AI-079 to AI-083)
        "AI-079": check_resource_tagging_completeness,
        "AI-080": check_unused_ai_resources,
        "AI-081": check_ai_resources_unsupported_regions,
        "AI-082": check_service_quota_utilization,
        "AI-083": check_trusted_advisor_ai_checks,
    }


def run_iso42001_checks_sync(session, scan_meta_data, progress_callback=None):
    """
    Synchronous wrapper for ISO 42001 checks compatible with framework_scan.py.
    Runs all original ISO checks + extended AI governance checks.
    progress_callback: optional fn(percent) to update scan progress.
    """
    results = []

    total_checks = len(iso_checks) + 83  # 36 original + 83 extended
    completed = 0

    def _update_percent():
        nonlocal completed
        completed += 1
        if progress_callback:
            # Scale from 2% to 95% across all checks
            percent = 2 + int((completed / total_checks) * 93)
            progress_callback(percent)

    # Phase 1: Run original 36 ISO 42001 checks
    for check_id, check_function in iso_checks.items():
        try:
            print(f"  ISO 42001 check: {check_id}")
            check_result = check_function(session)

            if check_result is None:
                _update_percent()
                continue

            if isinstance(check_result, dict):
                finding = _normalize_iso_finding(check_id, check_result, scan_meta_data)
                results.append(finding)
            elif isinstance(check_result, list):
                for item in check_result:
                    finding = _normalize_iso_finding(check_id, item, scan_meta_data)
                    results.append(finding)
        except Exception as e:
            print(f"  ISO 42001 check {check_id} error: {e}")
        _update_percent()

    # Phase 2: Run extended AI governance checks (AI-001 to AI-083)
    print("  Running extended AI governance checks...")
    extended_checks = _get_extended_checks()

    for check_id, check_function in extended_checks.items():
        try:
            print(f"  ISO 42001 extended check: {check_id}")
            check_result = check_function(session)

            if check_result is None:
                _update_percent()
                continue

            if isinstance(check_result, dict):
                finding = _normalize_iso_finding(check_id, check_result, scan_meta_data)
                results.append(finding)
            elif isinstance(check_result, list):
                for item in check_result:
                    finding = _normalize_iso_finding(check_id, item, scan_meta_data)
                    results.append(finding)
        except Exception as e:
            print(f"  ISO 42001 extended check {check_id} error: {e}")
        _update_percent()

    return results


def _normalize_iso_finding(check_id, raw, scan_meta_data):
    """Convert a raw ISO check result dict into the standard finding format."""
    severity = raw.get("severity_level", raw.get("severity", "Medium"))
    
    # Read from additional_info first (where check functions actually put them), fallback to top-level
    additional_info = raw.get("additional_info", {})
    affected = additional_info.get("affected", raw.get("affected", 0))
    total_scanned = additional_info.get("total_scanned", raw.get("total_scanned", 0))

    # Determine result: if no resources were scanned at all, mark as Not Applicable
    if total_scanned == 0 and affected == 0:
        result = "NOT_APPLICABLE"
    elif affected > 0:
        result = "FAIL"
    else:
        result = "PASS"

    # Update scan_meta_data counters
    scan_meta_data["total_scanned"] += total_scanned
    scan_meta_data["affected"] += affected
    if severity in scan_meta_data:
        scan_meta_data[severity] += (1 if affected > 0 else 0)

    service = raw.get("service", "AI Management")
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)

    return {
        "control_id": check_id,
        "check_name": raw.get("check_name", raw.get("title", check_id)),
        "service": service,
        "severity_level": severity,
        "severity_score": raw.get("severity_score", _severity_to_score(severity)),
        "affected": affected,
        "total_scanned": total_scanned,
        "result": result,
        "region": raw.get("region", "global"),
        "problem_statement": raw.get("problem_statement", raw.get("description", "")),
        "description": raw.get("description", raw.get("problem_statement", "")),
        "remediation": raw.get("remediation", raw.get("recommendation", "")),
        "frameworks": ["iso42001"],
        "additional_info": additional_info,
    }


def _severity_to_score(severity):
    return {"Critical": 10, "High": 8, "Medium": 5, "Low": 2}.get(severity, 3)
