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

    scan_meta_data["total_scanned"] += 1
    if not enabled:
        scan_meta_data["affected"] += 1
        scan_meta_data["Low"] += 1
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
            "total_scanned": 1,
            "affected": 0 if enabled else 1,
        },
    }
