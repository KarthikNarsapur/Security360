import re


def _get_active_task_definitions(session):
    """Helper to fetch all ACTIVE ECS task definition details."""
    ecs = session.client("ecs")
    task_def_arns = []
    paginator = ecs.get_paginator("list_task_definitions")
    for page in paginator.paginate(status="ACTIVE"):
        task_def_arns.extend(page.get("taskDefinitionArns", []))

    task_defs = []
    for arn in task_def_arns:
        try:
            td = ecs.describe_task_definition(taskDefinition=arn).get("taskDefinition", {})
            task_defs.append(td)
        except Exception as e:
            print(f"Error describing task definition {arn}: {e}")
    return task_defs


def check_ecs_privileged_containers(session, scan_meta_data):
    print("check_ecs_privileged_containers")
    task_defs = _get_active_task_definitions(session)
    resources_affected = []

    for td in task_defs:
        td_name = td.get("taskDefinitionArn", "").split("/")[-1]
        for container in td.get("containerDefinitions", []):
            if container.get("privileged", False):
                resources_affected.append({
                    "resource_name": td_name,
                    "container_name": container.get("name"),
                    "image": container.get("image"),
                    "issue": "Container runs in privileged mode.",
                })

    scan_meta_data["total_scanned"] += len(task_defs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["High"] += len(resources_affected)
    if "ECS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECS")

    return {
        "check_name": "ECS Privileged Containers",
        "service": "ECS",
        "problem_statement": "ECS task definitions have containers running in privileged mode, granting full host access.",
        "severity_score": 90,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "recommendation": "Remove privileged: true from container definitions unless absolutely required.",
        "additional_info": {"total_scanned": len(task_defs), "affected": len(resources_affected)},
    }


def check_ecs_root_user_containers(session, scan_meta_data):
    print("check_ecs_root_user_containers")
    task_defs = _get_active_task_definitions(session)
    resources_affected = []

    for td in task_defs:
        td_name = td.get("taskDefinitionArn", "").split("/")[-1]
        for container in td.get("containerDefinitions", []):
            user = container.get("user", "")
            # Flag if user is explicitly "root", "0", or not set at all
            if not user or user in ("root", "0"):
                resources_affected.append({
                    "resource_name": td_name,
                    "container_name": container.get("name"),
                    "image": container.get("image"),
                    "user_setting": user if user else "Not set (defaults to root)",
                    "issue": "Container runs as root user.",
                })

    scan_meta_data["total_scanned"] += len(task_defs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Medium"] += len(resources_affected)
    if "ECS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECS")

    return {
        "check_name": "ECS Root User Containers",
        "service": "ECS",
        "problem_statement": "ECS containers run as root user, increasing the blast radius of container escapes.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Set a non-root user in container definitions (e.g., user: '1000') or in the Dockerfile.",
        "additional_info": {"total_scanned": len(task_defs), "affected": len(resources_affected)},
    }


def check_ecs_task_role_and_credentials(session, scan_meta_data):
    print("check_ecs_task_role_and_credentials")
    task_defs = _get_active_task_definitions(session)
    resources_affected = []

    credential_keys = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}

    for td in task_defs:
        td_name = td.get("taskDefinitionArn", "").split("/")[-1]
        task_role = td.get("taskRoleArn", "")
        issues = []

        if not task_role:
            issues.append("No taskRoleArn configured")

        for container in td.get("containerDefinitions", []):
            env_vars = container.get("environment", [])
            for env in env_vars:
                if env.get("name", "") in credential_keys:
                    issues.append(
                        f"Container '{container.get('name')}' has hardcoded {env['name']}"
                    )

        if issues:
            resources_affected.append({
                "resource_name": td_name,
                "task_role_arn": task_role or "None",
                "issues": "; ".join(issues),
            })

    scan_meta_data["total_scanned"] += len(task_defs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["High"] += len(resources_affected)
    if "ECS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECS")

    return {
        "check_name": "ECS Task Roles and Hardcoded Credentials",
        "service": "ECS",
        "problem_statement": "ECS task definitions are missing task roles or have hardcoded AWS credentials in environment variables.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "recommendation": "Use taskRoleArn for AWS API access. Remove hardcoded AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from environment variables.",
        "additional_info": {"total_scanned": len(task_defs), "affected": len(resources_affected)},
    }


def check_ecs_secrets_from_secrets_manager(session, scan_meta_data):
    print("check_ecs_secrets_from_secrets_manager")
    task_defs = _get_active_task_definitions(session)
    resources_affected = []

    sensitive_key_pattern = re.compile(
        r"(password|passwd|secret|api_key|apikey|token|auth|private_key|db_pass|database_password|credentials|connection_string)",
        re.IGNORECASE,
    )

    for td in task_defs:
        td_name = td.get("taskDefinitionArn", "").split("/")[-1]

        for container in td.get("containerDefinitions", []):
            plaintext_secrets = []
            env_vars = container.get("environment", [])

            for env in env_vars:
                key = env.get("name", "")
                value = env.get("value", "")
                if sensitive_key_pattern.search(key) and value:
                    plaintext_secrets.append(key)

            if plaintext_secrets:
                resources_affected.append({
                    "resource_name": td_name,
                    "container_name": container.get("name"),
                    "plaintext_secret_keys": ", ".join(plaintext_secrets[:10]),
                    "issue": f"{len(plaintext_secrets)} sensitive env var(s) use plaintext 'value' instead of 'valueFrom'.",
                })

    scan_meta_data["total_scanned"] += len(task_defs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["High"] += len(resources_affected)
    if "ECS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECS")

    return {
        "check_name": "ECS Plaintext Secrets in Environment",
        "service": "ECS",
        "problem_statement": "ECS containers have sensitive environment variables using plaintext values instead of referencing Secrets Manager or SSM Parameter Store via valueFrom.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "recommendation": "Use 'secrets' with 'valueFrom' referencing Secrets Manager ARNs or SSM Parameter Store instead of plaintext 'environment' entries.",
        "additional_info": {"total_scanned": len(task_defs), "affected": len(resources_affected)},
    }


def check_ecs_readonly_root_filesystem(session, scan_meta_data):
    print("check_ecs_readonly_root_filesystem")
    task_defs = _get_active_task_definitions(session)
    resources_affected = []

    for td in task_defs:
        td_name = td.get("taskDefinitionArn", "").split("/")[-1]
        for container in td.get("containerDefinitions", []):
            if not container.get("readonlyRootFilesystem", False):
                resources_affected.append({
                    "resource_name": td_name,
                    "container_name": container.get("name"),
                    "image": container.get("image"),
                    "issue": "readonlyRootFilesystem is not enabled.",
                })

    scan_meta_data["total_scanned"] += len(task_defs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Low"] += len(resources_affected)
    if "ECS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECS")

    return {
        "check_name": "ECS Read-Only Root Filesystem",
        "service": "ECS",
        "problem_statement": "ECS containers do not have read-only root filesystems, allowing potential tampering with container files.",
        "severity_score": 40,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Enable readonlyRootFilesystem: true in container definitions. Use mounted volumes for writable paths.",
        "additional_info": {"total_scanned": len(task_defs), "affected": len(resources_affected)},
    }


def check_ecs_logging_enabled(session, scan_meta_data):
    print("check_ecs_logging_enabled")
    task_defs = _get_active_task_definitions(session)
    resources_affected = []

    for td in task_defs:
        td_name = td.get("taskDefinitionArn", "").split("/")[-1]
        for container in td.get("containerDefinitions", []):
            log_config = container.get("logConfiguration", {})
            log_driver = log_config.get("logDriver", "")

            if not log_driver:
                resources_affected.append({
                    "resource_name": td_name,
                    "container_name": container.get("name"),
                    "image": container.get("image"),
                    "log_driver": "None",
                    "issue": "No logConfiguration defined for container.",
                })
            elif log_driver != "awslogs":
                resources_affected.append({
                    "resource_name": td_name,
                    "container_name": container.get("name"),
                    "image": container.get("image"),
                    "log_driver": log_driver,
                    "issue": f"Log driver is '{log_driver}' instead of 'awslogs' (CloudWatch).",
                })

    scan_meta_data["total_scanned"] += len(task_defs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Medium"] += len(resources_affected)
    if "ECS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("ECS")

    return {
        "check_name": "ECS CloudWatch Logging",
        "service": "ECS",
        "problem_statement": "ECS containers do not have CloudWatch logging (awslogs driver) configured.",
        "severity_score": 55,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Configure logConfiguration with 'awslogs' driver to send container logs to CloudWatch for monitoring and troubleshooting.",
        "additional_info": {"total_scanned": len(task_defs), "affected": len(resources_affected)},
    }
