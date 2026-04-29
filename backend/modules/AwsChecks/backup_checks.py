def check_backup_policies(session, scan_meta_data):
    print("check_backup_policies")
    resources = []

    try:
        backup = session.client("backup")

        # Check for backup vaults
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])

        # Check for backup plans
        plans = backup.list_backup_plans().get("BackupPlansList", [])

        if not vaults:
            resources.append({
                "resource_name": "AWS Backup",
                "issue": "No backup vaults exist in this region.",
                "vaults": 0,
                "plans": len(plans),
            })
        elif not plans:
            resources.append({
                "resource_name": "AWS Backup",
                "issue": "No backup plans defined despite having backup vaults.",
                "vaults": len(vaults),
                "plans": 0,
            })
        else:
            # Check if any plan has protected resources
            total_selections = 0
            for plan in plans:
                try:
                    selections = backup.list_backup_selections(
                        BackupPlanId=plan["BackupPlanId"]
                    ).get("BackupSelectionsList", [])
                    total_selections += len(selections)
                except Exception:
                    continue

            if total_selections == 0:
                resources.append({
                    "resource_name": "AWS Backup",
                    "issue": "Backup plans exist but no resources are assigned to them.",
                    "vaults": len(vaults),
                    "plans": len(plans),
                    "resource_selections": 0,
                })

    except Exception as e:
        print(f"Error checking AWS Backup: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "Backup" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Backup")

    return {
        "check_name": "AWS Backup Policies",
        "service": "Backup",
        "problem_statement": "AWS Backup is not configured with backup plans and protected resources.",
        "severity_score": 55,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Create AWS Backup plans with appropriate schedules and assign critical resources (RDS, EBS, EFS, DynamoDB).",
        "additional_info": {"total_scanned": 1, "affected": len(resources)},
    }
