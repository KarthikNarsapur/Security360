def check_secrets_manager_enabled(session, scan_meta_data):
    print("check_secrets_manager_enabled")
    secretsmanager = session.client("secretsmanager")
    enabled = False
    resources_affected = []

    try:
        response = secretsmanager.list_secrets(MaxResults=1)
        secrets = response.get("SecretList", [])

        if secrets:
            enabled = True
        else:
            resources_affected.append(
                {
                    "region": session.region_name,
                    "message": "No secrets found in this region.",
                }
            )

    except Exception as e:
        print(f"Error while checking Secrets Manager: {e}")

    scan_meta_data["services_scanned"].append("Secrets Manager")

    return {
        "check_name": "Secrets Manager Enabled",
        "service": "Secrets Manager",
        "problem_statement": "Checks if AWS Secrets Manager is being used in the region.",
        "severity_score": 10,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Ensure proper use of Secrets Manager for storing sensitive data securely.",
        "additional_info": {
            "enabled": enabled,
            "total_scanned": 0,
            "affected": 0,
        },
    }


def check_secrets_manager_usage(session, scan_meta_data):
    print("check_secrets_manager_usage")
    sm = session.client("secretsmanager")
    resources = []

    try:
        secrets = []
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))

        unused_secrets = []
        for secret in secrets:
            last_accessed = secret.get("LastAccessedDate")
            if not last_accessed:
                unused_secrets.append({
                    "resource_name": secret.get("Name"),
                    "arn": secret.get("ARN"),
                    "created_date": str(secret.get("CreatedDate", "")),
                    "last_accessed": "Never",
                    "issue": "Secret exists but has never been accessed — may not be referenced by services.",
                })

        if secrets:
            resources = unused_secrets

    except Exception as e:
        print(f"Error checking Secrets Manager usage: {e}")

    total_secrets = len(secrets) if 'secrets' in dir() else 0
    scan_meta_data["total_scanned"] += total_secrets
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "Secrets Manager" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Secrets Manager")

    return {
        "check_name": "Secrets Manager Adoption",
        "service": "Secrets Manager",
        "problem_statement": "Secrets Manager is not being actively used, or stored secrets are never accessed by services.",
        "severity_score": 30,
        "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Store all application secrets in Secrets Manager or SSM Parameter Store and reference them at runtime.",
        "additional_info": {"total_scanned": total_secrets, "affected": len(resources)},
    }
