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


def check_rds_automated_backups(session, scan_meta_data):
    print("check_rds_automated_backups")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []

    for db in dbs:
        retention = db.get("BackupRetentionPeriod", 0)
        if retention == 0:
            resources.append({
                "resource_name": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine"),
                "db_instance_class": db.get("DBInstanceClass"),
                "backup_retention_period": retention,
                "issue": "Automated backups are disabled (BackupRetentionPeriod is 0).",
            })

    scan_meta_data["total_scanned"] += len(dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RDS Automated Backups Disabled",
        "service": "RDS",
        "problem_statement": "RDS instances have automated backups disabled, risking data loss.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Enable automated backups with a retention period of at least 7 days for production databases.",
        "additional_info": {"total_scanned": len(dbs), "affected": len(resources)},
    }


def check_rds_multi_az(session, scan_meta_data):
    print("check_rds_multi_az")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []

    for db in dbs:
        if not db.get("MultiAZ", False):
            resources.append({
                "resource_name": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine"),
                "db_instance_class": db.get("DBInstanceClass"),
                "endpoint": db.get("Endpoint", {}).get("Address"),
                "issue": "Multi-AZ is not enabled.",
            })

    scan_meta_data["total_scanned"] += len(dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RDS Multi-AZ Not Enabled",
        "service": "RDS",
        "problem_statement": "RDS instances without Multi-AZ lack automatic failover and high availability.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable Multi-AZ for production RDS instances to ensure automatic failover.",
        "additional_info": {"total_scanned": len(dbs), "affected": len(resources)},
    }


def check_rds_iam_authentication(session, scan_meta_data):
    print("check_rds_iam_authentication")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []

    # IAM auth is supported on MySQL, PostgreSQL, and Aurora
    iam_auth_supported_engines = ["mysql", "postgres", "aurora-mysql", "aurora-postgresql"]

    for db in dbs:
        engine = db.get("Engine", "").lower()
        if engine not in iam_auth_supported_engines:
            continue
        if not db.get("IAMDatabaseAuthenticationEnabled", False):
            resources.append({
                "resource_name": db.get("DBInstanceIdentifier"),
                "engine": db.get("Engine"),
                "engine_version": db.get("EngineVersion"),
                "db_instance_class": db.get("DBInstanceClass"),
                "issue": "IAM database authentication is not enabled.",
            })

    supported_dbs = [db for db in dbs if db.get("Engine", "").lower() in iam_auth_supported_engines]
    scan_meta_data["total_scanned"] += len(supported_dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RDS IAM Authentication Disabled",
        "service": "RDS",
        "problem_statement": "RDS instances with supported engines do not have IAM database authentication enabled.",
        "severity_score": 55,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Enable IAM database authentication for MySQL and PostgreSQL instances to avoid password-based access.",
        "additional_info": {"total_scanned": len(supported_dbs), "affected": len(resources)},
    }


def check_rds_default_ports_exposed(session, scan_meta_data):
    print("check_rds_default_ports_exposed")
    ec2 = session.client("ec2")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []

    default_ports = {
        "mysql": 3306, "aurora-mysql": 3306,
        "postgres": 5432, "aurora-postgresql": 5432,
        "sqlserver-ee": 1433, "sqlserver-se": 1433, "sqlserver-ex": 1433, "sqlserver-web": 1433,
        "oracle-ee": 1521, "oracle-se2": 1521, "oracle-se1": 1521, "oracle-se": 1521,
        "mariadb": 3306,
    }

    for db in dbs:
        engine = db.get("Engine", "").lower()
        port = db.get("Endpoint", {}).get("Port")
        expected_default = default_ports.get(engine)

        if port and expected_default and port == expected_default:
            # Check if the SG allows this port from 0.0.0.0/0
            sg_ids = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
            if not sg_ids:
                continue

            try:
                sgs = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
            except Exception:
                continue

            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    if from_port is None or to_port is None:
                        continue
                    if from_port <= port <= to_port:
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                resources.append({
                                    "resource_name": db.get("DBInstanceIdentifier"),
                                    "engine": db.get("Engine"),
                                    "port": port,
                                    "security_group": sg.get("GroupId"),
                                    "issue": f"Default port {port} is open to 0.0.0.0/0.",
                                })
                                break

    scan_meta_data["total_scanned"] += len(dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RDS Default Ports Exposed to Internet",
        "service": "RDS",
        "problem_statement": "RDS instances using default database ports have those ports open to the entire internet (0.0.0.0/0).",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Restrict security group rules to specific IP ranges. Consider changing default ports.",
        "additional_info": {"total_scanned": len(dbs), "affected": len(resources)},
    }


def check_rds_security_groups_restricted(session, scan_meta_data):
    print("check_rds_security_groups_restricted")
    ec2 = session.client("ec2")
    rds = session.client("rds")
    dbs = rds.describe_db_instances()["DBInstances"]
    resources = []

    for db in dbs:
        sg_ids = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
        if not sg_ids:
            continue

        try:
            sgs = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
        except Exception:
            continue

        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", "all")
                        to_port = perm.get("ToPort", "all")
                        resources.append({
                            "resource_name": db.get("DBInstanceIdentifier"),
                            "engine": db.get("Engine"),
                            "security_group": sg.get("GroupId"),
                            "security_group_name": sg.get("GroupName"),
                            "open_ports": f"{from_port}-{to_port}",
                            "issue": f"RDS security group {sg.get('GroupId')} allows inbound from 0.0.0.0/0.",
                        })
                        break

    scan_meta_data["total_scanned"] += len(dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["High"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("RDS")

    return {
        "check_name": "RDS Overly Permissive Security Groups",
        "service": "RDS",
        "problem_statement": "RDS instances have security groups that allow inbound traffic from anywhere (0.0.0.0/0).",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Restrict RDS security groups to specific application subnets or IP ranges only.",
        "additional_info": {"total_scanned": len(dbs), "affected": len(resources)},
    }


def check_rds_auto_minor_upgrade(session, scan_meta_data):
    print("check_rds_auto_minor_upgrade")
    rds = session.client("rds")
    resources = []
    dbs = rds.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("AutoMinorVersionUpgrade", True):
            resources.append({"resource_name": db.get("DBInstanceIdentifier"), "engine": db.get("Engine"), "issue": "Auto minor version upgrade disabled."})

    scan_meta_data["total_scanned"] += len(dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("RDS")
    return {"check_name": "RDS Auto Minor Version Upgrade", "service": "RDS", "problem_statement": "RDS instances have auto minor version upgrade disabled.", "severity_score": 50, "severity_level": "Medium", "resources_affected": resources, "recommendation": "Enable auto minor version upgrade.", "additional_info": {"total_scanned": len(dbs), "affected": len(resources)}}


def check_rds_instance_deletion_protection(session, scan_meta_data):
    print("check_rds_instance_deletion_protection")
    rds = session.client("rds")
    resources = []
    dbs = rds.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("DeletionProtection", False):
            resources.append({"resource_name": db.get("DBInstanceIdentifier"), "engine": db.get("Engine"), "issue": "Deletion protection disabled."})

    scan_meta_data["total_scanned"] += len(dbs)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "RDS" not in scan_meta_data["services_scanned"]: scan_meta_data["services_scanned"].append("RDS")
    return {"check_name": "RDS Instance Deletion Protection", "service": "RDS", "problem_statement": "RDS instances lack deletion protection.", "severity_score": 55, "severity_level": "Medium", "resources_affected": resources, "recommendation": "Enable deletion protection on production instances.", "additional_info": {"total_scanned": len(dbs), "affected": len(resources)}}
