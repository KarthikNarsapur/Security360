import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_redshift_publicly_accessible(session):
    # [Redshift.1]
    print("Checking Redshift clusters for public accessibility")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if cluster.get("PubliclyAccessible", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": "Redshift cluster is publicly accessible",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.1",
            "check_name": "Redshift cluster public accessibility",
            "problem_statement": "Redshift clusters should not be publicly accessible.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Disable public accessibility for Redshift clusters.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify cluster → Set 'Publicly Accessible' to 'No'.",
                "2. Ensure the cluster resides within a private subnet.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift public accessibility: {e}")
        return None


def check_redshift_encryption_in_transit(session):
    # [Redshift.2]
    print("Checking Redshift SSL (encryption in transit)")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if not cluster.get("Encrypted", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": "Encryption in transit not enforced (SSL disabled)",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.2",
            "check_name": "Encryption in transit (SSL) enabled",
            "problem_statement": "Redshift clusters should enforce SSL connections to protect data in transit.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable SSL for Redshift connections.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify cluster parameter group.",
                "2. Set 'require_ssl' parameter to true.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift SSL: {e}")
        return None


def check_redshift_automatic_snapshots(session):
    # [Redshift.3]
    print("Checking Redshift automatic snapshot configuration")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if cluster.get("AutomatedSnapshotRetentionPeriod", 0) == 0:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": "Automatic snapshots disabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.3",
            "check_name": "Automatic snapshots enabled",
            "problem_statement": "Automatic snapshots should be enabled for Redshift clusters.",
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable automated snapshot retention for Redshift clusters.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify cluster → Set AutomatedSnapshotRetentionPeriod > 0.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift automatic snapshots: {e}")
        return None


def check_redshift_audit_logging(session):
    # [Redshift.4]
    print("Checking Redshift audit logging")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if not cluster.get("LoggingStatus", {}).get("LoggingEnabled", False):
                # Some clusters return logging details via a separate call
                try:
                    logging = redshift.describe_logging_status(
                        ClusterIdentifier=cluster["ClusterIdentifier"]
                    )
                    if not logging.get("LoggingEnabled", False):
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": cluster["ClusterIdentifier"],
                                "resource_id_type": "RedshiftCluster",
                                "issue": "Audit logging disabled",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": cluster["ClusterIdentifier"],
                            "resource_id_type": "RedshiftCluster",
                            "issue": "Unable to verify audit logging status",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.4",
            "check_name": "Audit logging enabled",
            "problem_statement": "Audit logging should be enabled for Redshift clusters to capture user activities.",
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable audit logging and specify an S3 bucket destination.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify cluster → Enable audit logging.",
                "2. Provide an S3 bucket destination.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift audit logging: {e}")
        return None


def check_redshift_automatic_upgrades(session):
    # [Redshift.6]
    print("Checking Redshift maintenance upgrades")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if not cluster.get("AllowVersionUpgrade", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": "Automatic version upgrades disabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.6",
            "check_name": "Automatic upgrades enabled",
            "problem_statement": "Automatic version upgrades should be enabled to receive latest fixes and features.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable automatic version upgrades for all clusters.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify cluster → Enable automatic version upgrades.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift automatic upgrades: {e}")
        return None


def check_redshift_enhanced_vpc_routing(session):
    # [Redshift.7]
    print("Checking Redshift enhanced VPC routing")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if not cluster.get("EnhancedVpcRouting", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": "Enhanced VPC routing disabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.7",
            "check_name": "Enhanced VPC routing enabled",
            "problem_statement": "Enhanced VPC routing should be enabled to ensure all traffic flows through VPC endpoints.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable enhanced VPC routing for Redshift clusters.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Modify cluster → Enable Enhanced VPC Routing.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift enhanced VPC routing: {e}")
        return None


def check_redshift_default_admin_and_db(session):
    # [Redshift.8, Redshift.9]
    print("Checking Redshift default admin username and database name")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    default_users = {"awsuser", "admin", "root"}
    default_dbs = {"dev", "test"}

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            admin = cluster.get("MasterUsername", "").lower()
            dbname = cluster.get("DBName", "").lower()
            if admin in default_users or dbname in default_dbs:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": f"Cluster uses default admin ({admin}) or DB name ({dbname})",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.8/9",
            "check_name": "Redshift default admin/database names",
            "problem_statement": "Avoid default admin usernames and database names to reduce brute-force attack risk.",
            "severity_score": 50,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Use custom admin usernames and non-default DB names.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create a new cluster with custom admin user and DB name.",
                "2. Migrate data before deleting the old cluster.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift default admin/DB: {e}")
        return None


def check_redshift_encrypted_at_rest(session):
    # [Redshift.10]
    print("Checking Redshift encryption at rest")

    redshift = session.client("redshift")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        clusters = redshift.describe_clusters().get("Clusters", [])

        for cluster in clusters:
            if not cluster.get("Encrypted", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster["ClusterIdentifier"],
                        "resource_id_type": "RedshiftCluster",
                        "issue": "Cluster not encrypted at rest",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total = len(clusters)
        affected = len(resources_affected)
        return {
            "id": "Redshift.10",
            "check_name": "Redshift encryption at rest",
            "problem_statement": "All Redshift clusters should be encrypted at rest using AWS KMS.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable encryption at rest during cluster creation.",
            "additional_info": {"total_scanned": total, "affected": affected},
            "remediation_steps": [
                "1. Create new cluster with encryption enabled.",
                "2. Migrate data securely.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking Redshift encryption at rest: {e}")
        return None
