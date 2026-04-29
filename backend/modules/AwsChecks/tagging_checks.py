def check_required_tags(session, scan_meta_data):
    print("check_required_tags")
    ec2 = session.client("ec2")
    resources = []
    required_tags = ["Owner", "Environment"]

    # Check EC2 instances
    reservations = ec2.describe_instances().get("Reservations", [])
    all_instances = []
    for res in reservations:
        for inst in res["Instances"]:
            if inst.get("State", {}).get("Name") == "terminated":
                continue
            all_instances.append(inst)

            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            missing = [t for t in required_tags if t not in tags]
            if missing:
                instance_name = tags.get("Name", "")
                resources.append({
                    "resource_name": inst["InstanceId"],
                    "resource_type": "EC2 Instance",
                    "instance_name": instance_name,
                    "missing_tags": ", ".join(missing),
                    "issue": f"Missing required tags: {', '.join(missing)}.",
                })

    # Check RDS instances
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        for db in dbs:
            db_arn = db.get("DBInstanceArn", "")
            try:
                tag_list = rds.list_tags_for_resource(ResourceName=db_arn).get("TagList", [])
            except Exception:
                tag_list = []
            tags = {t["Key"]: t["Value"] for t in tag_list}
            missing = [t for t in required_tags if t not in tags]
            if missing:
                resources.append({
                    "resource_name": db["DBInstanceIdentifier"],
                    "resource_type": "RDS Instance",
                    "missing_tags": ", ".join(missing),
                    "issue": f"Missing required tags: {', '.join(missing)}.",
                })
    except Exception as e:
        print(f"Error checking RDS tags: {e}")

    total = len(all_instances) + len(dbs) if 'dbs' in dir() else len(all_instances)
    scan_meta_data["total_scanned"] += total
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "Tagging" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Tagging")

    return {
        "check_name": "Required Tags Enforcement",
        "service": "Tagging",
        "problem_statement": "Resources are missing required tags (Owner, Environment) needed for cost allocation and governance.",
        "severity_score": 30,
        "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Enforce required tags via AWS Config rules or SCPs. Tag all resources with Owner and Environment.",
        "additional_info": {"total_scanned": total, "affected": len(resources)},
    }
