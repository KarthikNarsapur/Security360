def check_public_rds(session, scan_meta_data):
    print("check_public_rds")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []
    for db in dbs:
        if db.get("PubliclyAccessible"):
            resources.append(
                {
                    "resource_name": db.get("DBInstanceIdentifier"),
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "db_instance_class": db.get("DBInstanceClass"),
                    # "region": session.region_name,
                    # "arn": db.get("DBInstanceArn"),
                    "endpoint": db.get("Endpoint", {}).get("Address"),
                    "storage_encrypted": db.get("StorageEncrypted"),
                }
            )

    scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(dbs)
    scan_meta_data["affected"] = scan_meta_data["affected"] + len(resources)
    scan_meta_data["High"] = scan_meta_data["High"] + len(resources)

    scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "Publicly Accessible RDS Instances",
        "service": "RDS",
        "problem_statement": "RDS instances exposed publicly increase security risks.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Restrict RDS instances to private subnets or use security groups to limit access.",
        "additional_info": {"total_scanned": len(dbs), "affected": len(resources)},
    }


def check_unencrypted_rds(session, scan_meta_data):
    print("check_unencrypted_rds")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []
    for db in dbs:
        if not db.get("StorageEncrypted"):
            resources.append(
                {
                    "resource_name": db.get("DBInstanceIdentifier"),
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "db_instance_class": db.get("DBInstanceClass"),
                    # "region": session.region_name,
                    # "arn": db.get("DBInstanceArn"),
                    "endpoint": db.get("Endpoint", {}).get("Address"),
                    "publicly_accessible": db.get("PubliclyAccessible"),
                }
            )
    scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(dbs)
    scan_meta_data["affected"] = scan_meta_data["affected"] + len(resources)
    scan_meta_data["Medium"] = scan_meta_data["Medium"] + len(resources)

    return {
        "check_name": "Unencrypted RDS Instances",
        "service": "RDS",
        "problem_statement": "RDS instances without storage encryption risk data exposure.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable encryption for RDS instances at rest to protect sensitive data.",
        "additional_info": {"total_scanned": len(dbs), "affected": len(resources)},
    }


def check_rds_cluster_deletion_protection(session, scan_meta_data):
    print("check_rds_cluster_deletion_protection")
    rds = session.client("rds")
    try:
        clusters = rds.describe_db_clusters()["DBClusters"]
    except Exception as e:
        print(f"Error describing DB clusters: {e}")
        clusters = []

    resources = []
    for cluster in clusters:
        if not cluster.get("DeletionProtection", False):
            resources.append(
                {
                    "resource_name": cluster.get("DBClusterIdentifier"),
                    "engine": cluster.get("Engine"),
                    "engine_version": cluster.get("EngineVersion"),
                    "status": cluster.get("Status"),
                    "storage_encrypted": cluster.get("StorageEncrypted"),
                    "availability_zones": cluster.get("AvailabilityZones"),
                    # "region": session.region_name,
                    # "arn": cluster.get("DBClusterArn"),
                }
            )

    scan_meta_data["total_scanned"] += len(clusters)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RDS Cluster Deletion Protection",
        "service": "RDS",
        "problem_statement": "RDS clusters without deletion protection can be accidentally or maliciously deleted.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable deletion protection on all production RDS clusters to prevent accidental deletion.",
        "additional_info": {"total_scanned": len(clusters), "affected": len(resources)},
    }
