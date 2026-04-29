# Lambda: Check for Publicly Accessible Functions and Unencrypted Environment Variables

def check_lambda_compliance(session):
    lambda_client = session.client('lambda')
    functions = lambda_client.list_functions()['Functions']
    results = {
        "functions_with_env_variables": [],
        "functions_with_public_access": []
    }

    for func in functions:
        func_name = func['FunctionName']
        config = lambda_client.get_function_configuration(FunctionName=func_name)

        # Check if environment variables exist
        if config.get('Environment', {}).get('Variables'):
            results["functions_with_env_variables"].append(func_name)

        # Check if Lambda is attached to a public-facing URL (e.g., via URL config)
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=func_name)
            if url_config.get('AuthType') == 'NONE':
                results["functions_with_public_access"].append(func_name)
        except lambda_client.exceptions.ResourceNotFoundException:
            pass

    return results


import re


def check_lambda_env_kms_encryption(session, scan_meta_data):
    print("check_lambda_env_kms_encryption")
    lambda_client = session.client("lambda")
    functions = lambda_client.list_functions().get("Functions", [])
    resources_affected = []

    for func in functions:
        env_vars = func.get("Environment", {}).get("Variables", {})
        if not env_vars:
            continue

        kms_key = func.get("KMSKeyArn")
        if not kms_key:
            resources_affected.append({
                "resource_name": func["FunctionName"],
                "runtime": func.get("Runtime", "N/A"),
                "env_var_count": len(env_vars),
                "kms_key": "None (using default AWS managed key)",
                "issue": "Lambda function has environment variables but no customer-managed KMS key for encryption.",
            })

    scan_meta_data["total_scanned"] += len(functions)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Medium"] += len(resources_affected)
    if "Lambda" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Lambda")

    return {
        "check_name": "Lambda Environment Variables KMS Encryption",
        "service": "Lambda",
        "problem_statement": "Lambda functions with environment variables are not using a customer-managed KMS key for encryption.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Configure a customer-managed KMS key for Lambda environment variable encryption to maintain control over key rotation and access policies.",
        "additional_info": {"total_scanned": len(functions), "affected": len(resources_affected)},
    }


def check_lambda_env_secrets(session, scan_meta_data):
    print("check_lambda_env_secrets")
    lambda_client = session.client("lambda")
    functions = lambda_client.list_functions().get("Functions", [])
    resources_affected = []

    secret_patterns = [
        (re.compile(r"^AKIA[0-9A-Z]{16}$"), "AWS Access Key ID"),
        (re.compile(r"^[A-Za-z0-9/+=]{40}$"), "Possible AWS Secret Key"),
        (re.compile(r"-----BEGIN", re.IGNORECASE), "Private Key"),
        (re.compile(r"^(ghp_|github_pat_)", re.IGNORECASE), "GitHub Token"),
        (re.compile(r"^sk-[a-zA-Z0-9]{20,}$"), "API Secret Key"),
        (re.compile(r"^xox[bpas]-", re.IGNORECASE), "Slack Token"),
    ]

    sensitive_key_patterns = re.compile(
        r"(password|passwd|secret|api_key|apikey|token|auth|private_key|db_pass|database_password|credentials)",
        re.IGNORECASE,
    )

    for func in functions:
        env_vars = func.get("Environment", {}).get("Variables", {})
        if not env_vars:
            continue

        found_issues = []

        for key, value in env_vars.items():
            if not value or len(value) < 8:
                continue

            # Check if the key name suggests a secret
            if sensitive_key_patterns.search(key):
                # Skip if value looks like an SSM/Secrets Manager reference
                if value.startswith("arn:aws:") or value.startswith("{{resolve:"):
                    continue
                found_issues.append(f"Key '{key}' appears to contain a plaintext secret")
                continue

            # Check value against known secret patterns
            for pattern, label in secret_patterns:
                if pattern.search(value):
                    found_issues.append(f"Key '{key}' matches pattern: {label}")
                    break

        if found_issues:
            resources_affected.append({
                "resource_name": func["FunctionName"],
                "runtime": func.get("Runtime", "N/A"),
                "secrets_found": "; ".join(found_issues[:5]),
                "issue": f"Found {len(found_issues)} potential plaintext secret(s) in environment variables.",
            })

    scan_meta_data["total_scanned"] += len(functions)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["High"] += len(resources_affected)
    if "Lambda" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Lambda")

    return {
        "check_name": "Plaintext Secrets in Lambda Environment Variables",
        "service": "Lambda",
        "problem_statement": "Lambda functions have environment variables that appear to contain plaintext secrets such as passwords, API keys, or access tokens.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources_affected,
        "recommendation": "Store secrets in AWS Secrets Manager or SSM Parameter Store and reference them at runtime instead of embedding in environment variables.",
        "additional_info": {"total_scanned": len(functions), "affected": len(resources_affected)},
    }


def check_lambda_timeout(session, scan_meta_data):
    print("check_lambda_timeout")
    lambda_client = session.client("lambda")
    functions = lambda_client.list_functions().get("Functions", [])
    resources_affected = []

    DEFAULT_TIMEOUT = 3  # AWS default
    MAX_REASONABLE_TIMEOUT = 300  # 5 minutes — flag anything above

    for func in functions:
        timeout = func.get("Timeout", DEFAULT_TIMEOUT)

        issue = None
        if timeout == DEFAULT_TIMEOUT:
            issue = f"Timeout is at default ({DEFAULT_TIMEOUT}s) — may cause premature failures for longer operations."
        elif timeout > MAX_REASONABLE_TIMEOUT:
            issue = f"Timeout is excessively high ({timeout}s) — may indicate misconfiguration or unbounded execution."

        if issue:
            resources_affected.append({
                "resource_name": func["FunctionName"],
                "runtime": func.get("Runtime", "N/A"),
                "timeout_seconds": timeout,
                "memory_mb": func.get("MemorySize"),
                "issue": issue,
            })

    scan_meta_data["total_scanned"] += len(functions)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Low"] += len(resources_affected)
    if "Lambda" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Lambda")

    return {
        "check_name": "Lambda Timeout Configuration",
        "service": "Lambda",
        "problem_statement": "Lambda functions have timeout values that are either at the default (3s) or excessively high (>300s).",
        "severity_score": 30,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Set Lambda timeouts based on expected execution duration. Avoid defaults and excessively high values.",
        "additional_info": {"total_scanned": len(functions), "affected": len(resources_affected)},
    }


def check_lambda_vpc_enabled(session, scan_meta_data):
    print("check_lambda_vpc_enabled")
    lambda_client = session.client("lambda")
    functions = lambda_client.list_functions().get("Functions", [])
    resources_affected = []

    for func in functions:
        vpc_config = func.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])

        if not subnet_ids:
            resources_affected.append({
                "resource_name": func["FunctionName"],
                "runtime": func.get("Runtime", "N/A"),
                "memory_mb": func.get("MemorySize"),
                "timeout_seconds": func.get("Timeout"),
                "issue": "Lambda function is not attached to a VPC.",
            })

    scan_meta_data["total_scanned"] += len(functions)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Low"] += len(resources_affected)
    if "Lambda" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Lambda")

    return {
        "check_name": "Lambda Functions Not in VPC",
        "service": "Lambda",
        "problem_statement": "Lambda functions are not attached to a VPC, meaning they cannot access private resources and lack network-level isolation.",
        "severity_score": 35,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Attach Lambda functions that access sensitive resources (databases, internal APIs) to a VPC with appropriate subnets and security groups.",
        "additional_info": {"total_scanned": len(functions), "affected": len(resources_affected)},
    }
