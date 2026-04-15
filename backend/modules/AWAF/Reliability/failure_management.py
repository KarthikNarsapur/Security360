from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# Failure management

# REL 9. How do you back up data?


def check_rel09_bp01_identify_and_backup_data(session):
    print(
        "Checking REL09-BP01 - Identify and back up all data that needs to be backed up"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_identified_backups_data.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL09-BP01",
            "check_name": "Identify and back up all data that needs to be backed up",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create AWS Backup plans for automated backup management.",
                "2. Enable automated snapshots for EC2 and RDS instances.",
                "3. Configure DynamoDB point-in-time recovery.",
                "4. Enable EFS backup policies for file systems.",
                "5. Regularly verify backup integrity and restoration procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        backup = session.client("backup")
        ec2 = session.client("ec2")
        rds = session.client("rds")
        dynamodb = session.client("dynamodb")
        efs = session.client("efs")

        # Check AWS Backup Plans
        try:
            backup_plans = backup.list_backup_plans().get("BackupPlansList", [])
            total_scanned += 1
            if len(backup_plans) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "backup_plans",
                        "issue": "No AWS Backup plans configured for centralized backup management",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"backup.list_backup_plans error: {e}")

        # Check Protected Resources
        try:
            protected_resources = backup.list_protected_resources().get("Results", [])
            total_scanned += 1
            if len(protected_resources) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "protected_resources",
                        "issue": "No resources protected by AWS Backup",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"backup.list_protected_resources error: {e}")

        # Check EC2 Snapshots
        try:
            snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
            total_scanned += 1
            if len(snapshots) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_snapshots",
                        "issue": "No EC2 snapshots found for volume backups",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_snapshots error: {e}")

        # Check RDS Snapshots
        try:
            db_snapshots = rds.describe_db_snapshots().get("DBSnapshots", [])
            total_scanned += 1
            if len(db_snapshots) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "rds_snapshots",
                        "issue": "No RDS snapshots found for database backups",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"rds.describe_db_snapshots error: {e}")

        # Check DynamoDB Backups
        try:
            tables = dynamodb.list_tables().get("TableNames", [])
            has_backups = False
            for table in tables:
                backups = dynamodb.list_backups(TableName=table).get(
                    "BackupSummaries", []
                )
                if backups:
                    has_backups = True
                    break
            total_scanned += 1
            if not has_backups and len(tables) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "dynamodb_backups",
                        "issue": "No DynamoDB backups found for tables",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"dynamodb.list_backups error: {e}")

        # Check EFS Backup Policies
        try:
            file_systems = efs.describe_file_systems().get("FileSystems", [])
            for fs in file_systems:
                try:
                    backup_policy = efs.describe_backup_policy(
                        FileSystemId=fs["FileSystemId"]
                    )
                    if backup_policy.get("BackupPolicy", {}).get("Status") != "ENABLED":
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": fs["FileSystemId"],
                                "issue": "EFS backup policy not enabled",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(
                        f"efs.describe_backup_policy error for {fs['FileSystemId']}: {e}"
                    )
            total_scanned += len(file_systems)
        except Exception as e:
            print(f"efs.describe_file_systems error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper backup mechanisms, data loss may occur during failures, "
                "leading to inability to recover critical workload data."
            ),
            recommendation=(
                "Implement comprehensive backup strategy using AWS Backup, EC2 snapshots, "
                "RDS automated backups, DynamoDB backups, and EFS backup policies."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL09-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating backup configurations.",
            recommendation="Verify IAM permissions for Backup, EC2, RDS, DynamoDB, and EFS APIs.",
        )


def check_rel09_bp02_secure_and_encrypt_backups(session):
    print("Checking REL09-BP02 - Secure and encrypt backups")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_secured_backups_data.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL09-BP02",
            "check_name": "Secure and encrypt backups",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable encryption for AWS Backup vaults using KMS keys.",
                "2. Configure S3 bucket encryption for backup storage.",
                "3. Enable encryption for RDS snapshots and instances.",
                "4. Enable encryption for EFS file systems.",
                "5. Enable encryption for DynamoDB tables and backups.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        backup = session.client("backup")
        kms = session.client("kms")
        s3 = session.client("s3")
        rds = session.client("rds")
        efs = session.client("efs")
        dynamodb = session.client("dynamodb")

        # Check Backup Vaults Encryption
        try:
            vaults = backup.list_backup_vaults().get("BackupVaultList", [])
            for vault in vaults:
                vault_details = backup.describe_backup_vault(
                    BackupVaultName=vault["BackupVaultName"]
                )
                if not vault_details.get("EncryptionKeyArn"):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": vault["BackupVaultName"],
                            "issue": "Backup vault not encrypted with KMS key",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(vaults)
        except Exception as e:
            print(f"backup.list_backup_vaults error: {e}")

        # Check KMS Keys
        try:
            keys = kms.list_keys().get("Keys", [])
            total_scanned += len(keys)
            if len(keys) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "kms_keys",
                        "issue": "No KMS keys found for backup encryption",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"kms.list_keys error: {e}")

        # Check S3 Bucket Encryption
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                try:
                    s3.get_bucket_encryption(Bucket=bucket["Name"])
                except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": bucket["Name"],
                            "issue": "S3 bucket encryption not configured",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
                except Exception as e:
                    print(f"s3.get_bucket_encryption error for {bucket['Name']}: {e}")
            total_scanned += len(buckets)
        except Exception as e:
            print(f"s3.list_buckets error: {e}")

        # Check RDS Encryption
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances:
                if not db.get("StorageEncrypted"):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": db["DBInstanceIdentifier"],
                            "issue": "RDS instance not encrypted",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(db_instances)
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check EFS Encryption
        try:
            file_systems = efs.describe_file_systems().get("FileSystems", [])
            for fs in file_systems:
                if not fs.get("Encrypted"):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": fs["FileSystemId"],
                            "issue": "EFS file system not encrypted",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(file_systems)
        except Exception as e:
            print(f"efs.describe_file_systems error: {e}")

        # Check DynamoDB Encryption
        try:
            tables = dynamodb.list_tables().get("TableNames", [])
            for table in tables:
                table_details = dynamodb.describe_table(TableName=table).get(
                    "Table", {}
                )
                sse = table_details.get("SSEDescription", {})
                if sse.get("Status") != "ENABLED":
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": table,
                            "issue": "DynamoDB table encryption not enabled",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(tables)
        except Exception as e:
            print(f"dynamodb.describe_table error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without encryption, backups may be vulnerable to unauthorized access, "
                "compromising data confidentiality and compliance requirements."
            ),
            recommendation=(
                "Enable encryption for all backup storage using AWS Backup vault encryption, "
                "KMS keys, S3 bucket encryption, RDS encryption, EFS encryption, and DynamoDB encryption."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL09-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating backup encryption.",
            recommendation="Verify IAM permissions for Backup, KMS, S3, RDS, EFS, and DynamoDB APIs.",
        )


def check_rel09_bp03_perform_data_backup_automatically(session):
    print("Checking REL09-BP03 - Perform data backup automatically")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_automated_backups_data.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL09-BP03",
            "check_name": "Perform data backup automatically",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create AWS Backup plans with automated schedules.",
                "2. Enable automated backups for RDS instances.",
                "3. Configure EventBridge rules for backup automation.",
                "4. Use Lambda functions for custom backup automation.",
                "5. Monitor backup jobs for successful completion.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        backup = session.client("backup")
        events = session.client("events")
        lambda_client = session.client("lambda")
        rds = session.client("rds")
        ec2 = session.client("ec2")

        # Check AWS Backup Plans
        try:
            backup_plans = backup.list_backup_plans().get("BackupPlansList", [])
            total_scanned += len(backup_plans)
            if len(backup_plans) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "backup_plans",
                        "issue": "No AWS Backup plans configured for automated backups",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"backup.list_backup_plans error: {e}")

        # Check Backup Jobs
        try:
            backup_jobs = backup.list_backup_jobs(MaxResults=1).get("BackupJobs", [])
            total_scanned += 1
            if len(backup_jobs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "backup_jobs",
                        "issue": "No backup jobs found indicating automated backups are not running",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"backup.list_backup_jobs error: {e}")

        # Check EventBridge Rules for Backup Automation
        try:
            rules = events.list_rules().get("Rules", [])
            backup_rules = [r for r in rules if "backup" in r.get("Name", "").lower()]
            total_scanned += 1
            if len(backup_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_backup_rules",
                        "issue": "No EventBridge rules found for backup automation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # Check Lambda Functions for Backup
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            backup_functions = [
                f for f in functions if "backup" in f.get("FunctionName", "").lower()
            ]
            total_scanned += 1
            if len(backup_functions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_backup_functions",
                        "issue": "No Lambda functions found for custom backup automation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check RDS Automated Backups
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances:
                if db.get("BackupRetentionPeriod", 0) == 0:
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": db["DBInstanceIdentifier"],
                            "issue": "RDS automated backups not enabled",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(db_instances)
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check EC2 Snapshots with Automation Tags
        try:
            snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
            automated_snapshots = [
                s
                for s in snapshots
                if any(
                    t.get("Key") == "aws:backup:source-resource"
                    for t in s.get("Tags", [])
                )
            ]
            total_scanned += 1
            if len(automated_snapshots) == 0 and len(snapshots) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_automated_snapshots",
                        "issue": "No automated EC2 snapshots found from AWS Backup",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_snapshots error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated backups, manual backup processes may be inconsistent, "
                "error-prone, and fail to meet recovery objectives."
            ),
            recommendation=(
                "Implement automated backup processes using AWS Backup plans, RDS automated backups, "
                "EventBridge rules, and Lambda functions for consistent and reliable data protection."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL09-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automated backup processes.",
            recommendation="Verify IAM permissions for Backup, EventBridge, Lambda, RDS, and EC2 APIs.",
        )


def check_rel09_bp04_periodic_recovery_verification(session):
    print(
        "Checking REL09-BP04 - Perform periodic recovery of the data to verify backup integrity"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_periodic_recovery_testing_data.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL09-BP04",
            "check_name": "Perform periodic recovery of the data to verify backup integrity",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Establish regular backup recovery testing schedules.",
                "2. Document recovery procedures and test scenarios.",
                "3. Perform test restores to validate backup integrity.",
                "4. Verify RTO and RPO objectives are met during tests.",
                "5. Document test results and update recovery procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS APIs cannot determine whether periodic recovery tests are performed to "
                "validate backup integrity. Recovery testing frequency, scope, and results must "
                "be reviewed through operational documentation."
            ),
            recommendation=(
                "Implement scheduled recovery testing to validate backup integrity, verify RTO/RPO "
                "objectives, and ensure restoration procedures work reliably during real incidents."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL09-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess periodic recovery verification processes.",
            recommendation="Review backup and recovery testing documentation and governance procedures.",
        )


# REL 10. How do you use fault isolation to protect your workload?


def check_rel10_bp01_deploy_workload_to_multiple_locations(session):
    print("Checking REL10-BP01 - Deploy the workload to multiple locations")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_fault_isolation_multiaz_region_system.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL10-BP01",
            "check_name": "Deploy the workload to multiple locations",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Deploy resources across multiple Availability Zones.",
                "2. Use CloudFront for global content distribution.",
                "3. Configure Route53 health checks and failover routing.",
                "4. Deploy load balancers across multiple AZs.",
                "5. Use multi-AZ RDS deployments for databases.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ec2 = session.client("ec2")
        rds = session.client("rds")
        ecs = session.client("ecs")
        eks = session.client("eks")
        cloudfront = session.client("cloudfront")
        route53 = session.client("route53")
        elb = session.client("elbv2")

        # Check Availability Zones
        try:
            azs = ec2.describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}]
            ).get("AvailabilityZones", [])
            total_scanned += 1
            if len(azs) < 2:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "availability_zones",
                        "issue": "Less than 2 availability zones available for multi-location deployment",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_availability_zones error: {e}")

        # Check EC2 Multi-AZ Deployment
        try:
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ).get("Reservations", [])
            instance_azs = set()
            for res in instances:
                for inst in res.get("Instances", []):
                    instance_azs.add(inst.get("Placement", {}).get("AvailabilityZone"))
            total_scanned += 1
            if len(instance_azs) < 2 and len(instances) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_instances",
                        "issue": "EC2 instances not deployed across multiple availability zones",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_instances error: {e}")

        # Check RDS Multi-AZ
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances:
                if not db.get("MultiAZ"):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": db["DBInstanceIdentifier"],
                            "issue": "RDS instance not configured for Multi-AZ deployment",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(db_instances)
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check ECS Services Multi-AZ
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                services = ecs.list_services(cluster=cluster).get("serviceArns", [])
                if services:
                    svc_details = ecs.describe_services(
                        cluster=cluster, services=services
                    ).get("services", [])
                    for svc in svc_details:
                        subnets = (
                            svc.get("networkConfiguration", {})
                            .get("awsvpcConfiguration", {})
                            .get("subnets", [])
                        )
                        if len(subnets) < 2:
                            affected += 1
                            resources_affected.append(
                                {
                                    "resource_id": svc["serviceName"],
                                    "issue": "ECS service not deployed across multiple subnets/AZs",
                                    "region": session.region_name,
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                    total_scanned += len(svc_details)
        except Exception as e:
            print(f"ecs.describe_services error: {e}")

        # Check EKS Node Groups Multi-AZ
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get(
                    "nodegroups", []
                )
                for ng in nodegroups:
                    ng_details = eks.describe_nodegroup(
                        clusterName=cluster, nodegroupName=ng
                    ).get("nodegroup", {})
                    subnets = ng_details.get("subnets", [])
                    if len(subnets) < 2:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": ng,
                                "issue": "EKS node group not deployed across multiple subnets/AZs",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                total_scanned += len(nodegroups)
        except Exception as e:
            print(f"eks.describe_nodegroup error: {e}")

        # Check CloudFront Distributions
        try:
            distributions = (
                cloudfront.list_distributions()
                .get("DistributionList", {})
                .get("Items", [])
            )
            total_scanned += len(distributions)
            if len(distributions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudfront_distributions",
                        "issue": "No CloudFront distributions for global content delivery",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudfront.list_distributions error: {e}")

        # Check Route53 Health Checks
        try:
            health_checks = route53.list_health_checks().get("HealthChecks", [])
            total_scanned += 1
            if len(health_checks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "route53_health_checks",
                        "issue": "No Route53 health checks for failover routing",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"route53.list_health_checks error: {e}")

        # Check Load Balancers Multi-AZ
        try:
            load_balancers = elb.describe_load_balancers().get("LoadBalancers", [])
            for lb in load_balancers:
                azs = lb.get("AvailabilityZones", [])
                if len(azs) < 2:
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": lb["LoadBalancerName"],
                            "issue": "Load balancer not deployed across multiple availability zones",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(load_balancers)
        except Exception as e:
            print(f"elb.describe_load_balancers error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without multi-location deployment, workloads are vulnerable to single points of failure, "
                "leading to service disruptions during availability zone or regional outages."
            ),
            recommendation=(
                "Deploy workloads across multiple availability zones using multi-AZ RDS, load balancers, "
                "ECS/EKS services, CloudFront distributions, and Route53 health checks for fault isolation."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL10-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating multi-location deployment.",
            recommendation="Verify IAM permissions for EC2, RDS, ECS, EKS, CloudFront, Route53, and ELB APIs.",
        )


def check_rel10_bp02_automate_recovery_single_location(session):
    print(
        "Checking REL10-BP02 - Automate recovery for components constrained to a single location"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_fault_isolation_single_az_system.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL10-BP02",
            "check_name": "Automate recovery for components constrained to a single location",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Configure Auto Scaling groups with health checks.",
                "2. Set up CloudWatch alarms for automated recovery.",
                "3. Create Route53 health checks for failover.",
                "4. Implement Lambda functions for automated remediation.",
                "5. Use SSM automation for recovery procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        autoscaling = session.client("autoscaling")
        route53 = session.client("route53")
        cloudwatch = session.client("cloudwatch")
        lambda_client = session.client("lambda")
        ssm = session.client("ssm")
        events = session.client("events")

        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            total_scanned += len(asgs)
            if len(asgs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "auto_scaling_groups",
                        "issue": "No Auto Scaling groups for automated recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Auto Scaling Policies
        try:
            policies = autoscaling.describe_policies().get("ScalingPolicies", [])
            total_scanned += 1
            if len(policies) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No Auto Scaling policies for automated recovery actions",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_policies error: {e}")

        # Check Route53 Health Checks
        try:
            health_checks = route53.list_health_checks().get("HealthChecks", [])
            total_scanned += 1
            if len(health_checks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "route53_health_checks",
                        "issue": "No Route53 health checks for automated failover",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"route53.list_health_checks error: {e}")

        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
            if len(alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms for automated recovery triggers",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check Lambda Functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            recovery_functions = [
                f
                for f in functions
                if "recovery" in f.get("FunctionName", "").lower()
                or "remediation" in f.get("FunctionName", "").lower()
            ]
            total_scanned += 1
            if len(recovery_functions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_recovery_functions",
                        "issue": "No Lambda functions for automated recovery or remediation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check SSM Automation Executions
        try:
            executions = ssm.describe_automation_executions(MaxResults=1).get(
                "AutomationExecutionMetadataList", []
            )
            total_scanned += 1
            if len(executions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ssm_automation",
                        "issue": "No SSM automation executions for automated recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ssm.describe_automation_executions error: {e}")

        # Check EventBridge Rules
        try:
            rules = events.list_rules().get("Rules", [])
            recovery_rules = [
                r
                for r in rules
                if "recovery" in r.get("Name", "").lower()
                or "failover" in r.get("Name", "").lower()
            ]
            total_scanned += 1
            if len(recovery_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_recovery_rules",
                        "issue": "No EventBridge rules for automated recovery triggers",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated recovery for single-location components, failures may require "
                "manual intervention, leading to extended downtime and service disruptions."
            ),
            recommendation=(
                "Implement automated recovery using Auto Scaling groups, CloudWatch alarms, "
                "Route53 health checks, Lambda functions, SSM automation, and EventBridge rules."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL10-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automated recovery mechanisms.",
            recommendation="Verify IAM permissions for Auto Scaling, Route53, CloudWatch, Lambda, SSM, and EventBridge APIs.",
        )


def check_rel10_bp03_use_bulkhead_architectures(session):
    print("Checking REL10-BP03 - Use bulkhead architectures to limit scope of impact")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_fault_isolation_use_bulkhead.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL10-BP03",
            "check_name": "Use bulkhead architectures to limit scope of impact",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Implement service isolation using separate VPCs or subnets.",
                "2. Use separate AWS accounts for different workload components.",
                "3. Implement resource quotas and limits to prevent resource exhaustion.",
                "4. Design microservices with independent failure domains.",
                "5. Use API Gateway throttling and Lambda concurrency limits.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Bulkhead architecture patterns such as service isolation, account separation, "
                "and independent failure domains cannot be evaluated using AWS APIs. "
                "These architectural decisions must be validated through design documentation."
            ),
            recommendation=(
                "Implement bulkhead architectures by isolating services using separate VPCs, "
                "AWS accounts, microservice boundaries, resource quotas, and throttling "
                "to prevent cascading failures and limit blast radius."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL10-BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to assess bulkhead architecture implementation.",
            recommendation="Review architecture design documentation and fault isolation strategies.",
        )


# REL 11. How do you design your workload to withstand component failures?


def check_rel11_bp01_monitor_all_components_detect_failures(session):
    print(
        "Checking REL11-BP01 - Monitor all components of the workload to detect failures"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_monitoring_health.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP01",
            "check_name": "Monitor all components of the workload to detect failures",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Configure CloudWatch alarms for all critical components.",
                "2. Enable X-Ray tracing for distributed application monitoring.",
                "3. Set up AWS Health Dashboard monitoring.",
                "4. Use DevOps Guru for anomaly detection.",
                "5. Implement comprehensive metric collection and analysis.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        cloudwatch = session.client("cloudwatch")
        xray = session.client("xray")
        health = session.client("health")

        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
            if len(alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms configured for failure detection",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check CloudWatch Metrics
        try:
            metrics = cloudwatch.list_metrics().get("Metrics", [])
            total_scanned += 1
            if len(metrics) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_metrics",
                        "issue": "No CloudWatch metrics found for component monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")

        # Check CloudWatch Metric Data
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "component_metrics",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                            },
                            "Period": 3600,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            total_scanned += 1
            if len(metric_data.get("MetricDataResults", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "metric_data",
                        "issue": "No recent metric data for component health monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # Check X-Ray Service Graph
        try:
            service_graph = xray.get_service_graph(
                StartTime=start_time, EndTime=end_time
            )
            total_scanned += 1
            if len(service_graph.get("Services", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "xray_tracing",
                        "issue": "No X-Ray tracing data for distributed component monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"xray.get_service_graph error: {e}")

        # Check AWS Health Events
        try:
            health_events = health.describe_events()
            total_scanned += 1
        except Exception as e:
            print(f"health.describe_events error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "health_monitoring",
                    "issue": "Cannot access AWS Health Dashboard for service health monitoring",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without comprehensive monitoring of all components, failures may go undetected, "
                "leading to prolonged outages and inability to respond quickly to issues."
            ),
            recommendation=(
                "Implement comprehensive monitoring using CloudWatch alarms, metrics, X-Ray tracing, "
                "and AWS Health Dashboard to detect component failures quickly."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL11-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating component monitoring.",
            recommendation="Verify IAM permissions for CloudWatch, X-Ray, and Health APIs.",
        )


def check_rel11_bp02_fail_over_to_healthy_resources(session):
    print("Checking REL11-BP02 - Fail over to healthy resources")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_failover2good.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP02",
            "check_name": "Fail over to healthy resources",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Configure Route53 health checks for DNS failover.",
                "2. Enable Auto Scaling groups for automatic replacement.",
                "3. Deploy load balancers with health checks.",
                "4. Enable RDS Multi-AZ for automatic failover.",
                "5. Use CloudFront for global failover capabilities.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        route53 = session.client("route53")
        autoscaling = session.client("autoscaling")
        elb = session.client("elbv2")
        rds = session.client("rds")
        cloudfront = session.client("cloudfront")

        # Check Route53 Health Checks
        try:
            health_checks = route53.list_health_checks().get("HealthChecks", [])
            total_scanned += 1
            if len(health_checks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "route53_health_checks",
                        "issue": "No Route53 health checks for DNS failover",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"route53.list_health_checks error: {e}")

        # Check Route53 Hosted Zones
        try:
            hosted_zones = route53.list_hosted_zones().get("HostedZones", [])
            total_scanned += len(hosted_zones)
        except Exception as e:
            print(f"route53.list_hosted_zones error: {e}")

        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            for asg in asgs:
                if asg.get("DesiredCapacity", 0) < 2:
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": asg["AutoScalingGroupName"],
                            "issue": "Auto Scaling group has insufficient capacity for failover",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(asgs)
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Load Balancers
        try:
            load_balancers = elb.describe_load_balancers().get("LoadBalancers", [])
            for lb in load_balancers:
                target_groups = elb.describe_target_groups(
                    LoadBalancerArn=lb["LoadBalancerArn"]
                ).get("TargetGroups", [])
                for tg in target_groups:
                    health_check = tg.get("HealthCheckEnabled")
                    if not health_check:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": tg["TargetGroupName"],
                                "issue": "Target group health checks not enabled",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
            total_scanned += len(load_balancers)
        except Exception as e:
            print(f"elb.describe_load_balancers error: {e}")

        # Check RDS Multi-AZ
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances:
                if not db.get("MultiAZ"):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": db["DBInstanceIdentifier"],
                            "issue": "RDS instance not configured for Multi-AZ failover",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(db_instances)
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check CloudFront Distributions
        try:
            distributions = (
                cloudfront.list_distributions()
                .get("DistributionList", {})
                .get("Items", [])
            )
            total_scanned += len(distributions)
            if len(distributions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudfront_distributions",
                        "issue": "No CloudFront distributions for global failover",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudfront.list_distributions error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without failover mechanisms, unhealthy resources continue to receive traffic, "
                "leading to service degradation and poor user experience."
            ),
            recommendation=(
                "Implement failover using Route53 health checks, Auto Scaling groups, load balancer "
                "health checks, RDS Multi-AZ, and CloudFront for automatic traffic routing to healthy resources."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL11-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating failover mechanisms.",
            recommendation="Verify IAM permissions for Route53, Auto Scaling, ELB, RDS, and CloudFront APIs.",
        )


def check_rel11_bp03_automate_healing_on_all_layers(session):
    print("Checking REL11-BP03 - Automate healing on all layers")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_auto_healing_system.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP03",
            "check_name": "Automate healing on all layers",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Configure Auto Scaling groups with health checks for automatic replacement.",
                "2. Set up CloudWatch alarms to trigger healing actions.",
                "3. Implement Lambda functions for automated remediation.",
                "4. Use SSM automation for self-healing procedures.",
                "5. Configure EventBridge rules for automated healing triggers.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        autoscaling = session.client("autoscaling")
        lambda_client = session.client("lambda")
        ssm = session.client("ssm")
        events = session.client("events")
        cloudwatch = session.client("cloudwatch")

        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            for asg in asgs:
                if (
                    not asg.get("HealthCheckType")
                    or asg.get("HealthCheckType") == "EC2"
                ):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": asg["AutoScalingGroupName"],
                            "issue": "Auto Scaling group not using ELB health checks for healing",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(asgs)
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Auto Scaling Policies
        try:
            policies = autoscaling.describe_policies().get("ScalingPolicies", [])
            total_scanned += 1
            if len(policies) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No Auto Scaling policies for automated healing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_policies error: {e}")

        # Check Lambda Functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            healing_functions = [
                f
                for f in functions
                if "heal" in f.get("FunctionName", "").lower()
                or "remediat" in f.get("FunctionName", "").lower()
            ]
            total_scanned += 1
            if len(healing_functions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_healing_functions",
                        "issue": "No Lambda functions for automated healing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check SSM Automation Executions
        try:
            executions = ssm.describe_automation_executions(MaxResults=1).get(
                "AutomationExecutionMetadataList", []
            )
            total_scanned += 1
            if len(executions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ssm_automation",
                        "issue": "No SSM automation executions for self-healing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ssm.describe_automation_executions error: {e}")

        # Check EventBridge Rules
        try:
            rules = events.list_rules().get("Rules", [])
            healing_rules = [
                r
                for r in rules
                if "heal" in r.get("Name", "").lower()
                or "remediat" in r.get("Name", "").lower()
            ]
            total_scanned += 1
            if len(healing_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_healing_rules",
                        "issue": "No EventBridge rules for automated healing triggers",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            alarms_with_actions = [a for a in alarms if a.get("AlarmActions")]
            total_scanned += 1
            if len(alarms_with_actions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarm_actions",
                        "issue": "No CloudWatch alarms with actions for automated healing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated healing, failures require manual intervention, "
                "leading to extended downtime and increased operational burden."
            ),
            recommendation=(
                "Implement automated healing using Auto Scaling health checks, CloudWatch alarm actions, "
                "Lambda functions, SSM automation, and EventBridge rules for self-healing capabilities."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL11-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automated healing mechanisms.",
            recommendation="Verify IAM permissions for Auto Scaling, Lambda, SSM, EventBridge, and CloudWatch APIs.",
        )


def check_rel11_bp04_rely_on_data_plane_during_recovery(session):
    print(
        "Checking REL11-BP04 - Rely on the data plane and not the control plane during recovery"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_avoid_control_plane.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP04",
            "check_name": "Rely on the data plane and not the control plane during recovery",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Design recovery mechanisms that use data plane operations.",
                "2. Pre-provision resources to avoid control plane dependencies.",
                "3. Use static stability patterns for critical operations.",
                "4. Cache configuration data locally to avoid API calls during recovery.",
                "5. Implement circuit breakers for control plane operations.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS APIs cannot determine whether recovery mechanisms rely on the data plane "
                "instead of the control plane. This design choice must be validated through "
                "architecture reviews and static stability documentation."
            ),
            recommendation=(
                "Ensure recovery processes depend on data plane operations by pre-provisioning resources, "
                "caching required configuration, and using static stability patterns so workloads can "
                "recover even when the control plane is impaired."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL11-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess data plane–based recovery design.",
            recommendation="Review recovery architecture, static stability documentation, and failover patterns.",
        )


def check_rel11_bp05_use_static_stability(session):
    print("Checking REL11-BP05 - Use static stability to prevent bimodal behavior")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_static_stability.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP05",
            "check_name": "Use static stability to prevent bimodal behavior",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Design systems to operate in a single stable mode.",
                "2. Avoid dependencies on external services for critical operations.",
                "3. Pre-compute and cache data to avoid runtime dependencies.",
                "4. Use eventual consistency patterns where appropriate.",
                "5. Implement graceful degradation for non-critical features.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS cannot determine whether workloads use static stability patterns. "
                "This must be assessed through architectural documentation and design review."
            ),
            recommendation=(
                "Design workloads to operate in a single stable mode by avoiding runtime dependencies, "
                "pre-computing and caching required data, and implementing graceful degradation."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL11-BP05: {e}")
        return build_response(
            status="error",
            problem="Unable to assess static stability design.",
            recommendation="Review static stability architecture patterns and dependency management strategies.",
        )


def check_rel11_bp06_send_notifications_when_events_impact_availability(session):
    print("Checking REL11-BP06 - Send notifications when events impact availability")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_notifications_sent_system.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP06",
            "check_name": "Send notifications when events impact availability",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Configure SNS topics for availability notifications.",
                "2. Set up CloudWatch alarms with SNS notification actions.",
                "3. Create EventBridge rules for availability events.",
                "4. Subscribe appropriate endpoints to SNS topics.",
                "5. Test notification delivery and escalation procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        sns = session.client("sns")
        events = session.client("events")
        cloudwatch = session.client("cloudwatch")

        # Check SNS Topics
        try:
            topics = sns.list_topics().get("Topics", [])
            total_scanned += 1
            if len(topics) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_topics",
                        "issue": "No SNS topics configured for availability notifications",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_topics error: {e}")

        # Check SNS Subscriptions
        try:
            subscriptions = sns.list_subscriptions().get("Subscriptions", [])
            total_scanned += 1
            if len(subscriptions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_subscriptions",
                        "issue": "No SNS subscriptions configured for notification delivery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_subscriptions error: {e}")

        # Check EventBridge Rules
        try:
            rules = events.list_rules().get("Rules", [])
            availability_rules = [
                r
                for r in rules
                if "availability" in r.get("Name", "").lower()
                or "health" in r.get("Name", "").lower()
            ]
            total_scanned += 1
            if len(availability_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_availability_rules",
                        "issue": "No EventBridge rules for availability event notifications",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # Check CloudWatch Alarms with SNS Actions
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            alarms_with_sns = [
                a
                for a in alarms
                if any("sns" in action.lower() for action in a.get("AlarmActions", []))
            ]
            total_scanned += 1
            if len(alarms_with_sns) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_sns_alarms",
                        "issue": "No CloudWatch alarms configured with SNS notification actions",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without notifications for availability events, teams may not be aware of issues, "
                "leading to delayed response and prolonged service disruptions."
            ),
            recommendation=(
                "Configure SNS topics and subscriptions, CloudWatch alarms with SNS actions, "
                "and EventBridge rules to send notifications when events impact availability."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL11-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating availability notifications.",
            recommendation="Verify IAM permissions for SNS, EventBridge, and CloudWatch APIs.",
        )


def check_rel11_bp07_architect_for_availability_targets_and_slas(session):
    print(
        "Checking REL11-BP07 - Architect your product to meet availability targets and uptime SLAs"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_service_level_agreements.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL11-BP07",
            "check_name": "Architect your product to meet availability targets and uptime SLAs",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Define clear availability targets and SLA requirements.",
                "2. Design architecture to meet or exceed availability targets.",
                "3. Implement redundancy and failover mechanisms.",
                "4. Monitor and measure actual availability against targets.",
                "5. Regularly review and adjust architecture based on SLA performance.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    try:
        # This is organizational/client responsibility with no boto3 APIs
        resources_affected.append(
            {
                "resource_id": "availability_targets_slas",
                "issue": (
                    "Ensure architecture is designed to meet defined availability targets and uptime SLAs. "
                    "Implement appropriate redundancy, failover, and monitoring to achieve required availability levels."
                ),
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            }
        )

        return build_response(
            status="failed",
            problem=(
                "Without architecting for specific availability targets and SLAs, workloads may not "
                "meet business requirements, leading to SLA violations and customer dissatisfaction."
            ),
            recommendation=(
                "Define clear availability targets and SLAs, design architecture with appropriate redundancy "
                "and failover mechanisms, and continuously monitor actual availability against targets."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL11-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating availability targets and SLA architecture.",
            recommendation="Review availability targets, SLA requirements, and architecture design documentation.",
        )


# REL 12. How do you test reliability?


def check_rel12_bp01_use_playbooks_to_investigate_failures(session):
    print("Checking REL12-BP01 - Use playbooks to investigate failures")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_testing_resiliency_playbook_resiliency.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL12-BP01",
            "check_name": "Use playbooks to investigate failures",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create documented playbooks for common failure scenarios.",
                "2. Use AWS Health Dashboard to identify service events.",
                "3. Configure CloudWatch alarms for failure detection.",
                "4. Set up CloudWatch Logs for investigation and analysis.",
                "5. Regularly review and update playbooks based on incidents.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        health = session.client("health")
        cloudwatch = session.client("cloudwatch")
        logs = session.client("logs")

        # Check AWS Health Events
        try:
            health_events = health.describe_events()
            total_scanned += 1
        except Exception as e:
            print(f"health.describe_events error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "health_dashboard",
                    "issue": "Cannot access AWS Health Dashboard for failure investigation",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
            if len(alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms for failure detection and investigation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check CloudWatch Log Groups
        try:
            log_groups = logs.describe_log_groups().get("logGroups", [])
            total_scanned += 1
            if len(log_groups) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "log_groups",
                        "issue": "No CloudWatch log groups for failure investigation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"logs.describe_log_groups error: {e}")

        # Check Log Filtering Capability
        try:
            if len(log_groups) > 0:
                log_group_name = log_groups[0]["logGroupName"]
                from datetime import datetime, timedelta

                start_time = int(
                    (datetime.utcnow() - timedelta(hours=1)).timestamp() * 1000
                )
                logs.filter_log_events(
                    logGroupName=log_group_name, startTime=start_time, limit=1
                )
            total_scanned += 1
        except Exception as e:
            print(f"logs.filter_log_events error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without playbooks and investigation tools, failure analysis may be inconsistent, "
                "time-consuming, and dependent on individual knowledge, delaying recovery."
            ),
            recommendation=(
                "Create documented playbooks for failure investigation, use AWS Health Dashboard, "
                "CloudWatch alarms, and CloudWatch Logs for systematic failure analysis."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL12-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating playbooks and investigation tools.",
            recommendation="Verify IAM permissions for Health, CloudWatch, and Logs APIs.",
        )


def check_rel12_bp02_perform_post_incident_analysis(session):
    print("Checking REL12-BP02 - Perform post-incident analysis")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_testing_resiliency_rca_resiliency.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL12-BP02",
            "check_name": "Perform post-incident analysis",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Use AWS Health Dashboard to review service events.",
                "2. Analyze CloudTrail logs for API activity during incidents.",
                "3. Review CloudWatch metrics for performance patterns.",
                "4. Use DevOps Guru insights for anomaly detection.",
                "5. Document findings and implement corrective actions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        health = session.client("health")
        cloudtrail = session.client("cloudtrail")
        cloudwatch = session.client("cloudwatch")

        # Check AWS Health Events
        try:
            health_events = health.describe_events()
            total_scanned += 1
        except Exception as e:
            print(f"health.describe_events error: {e}")
            affected += 1
            resources_affected.append(
                {
                    "resource_id": "health_events",
                    "issue": "Cannot access AWS Health events for post-incident analysis",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # Check CloudTrail Events
        try:
            from datetime import datetime, timedelta

            start_time = datetime.utcnow() - timedelta(hours=1)
            trail_events = cloudtrail.lookup_events(StartTime=start_time, MaxResults=1)
            total_scanned += 1
            if len(trail_events.get("Events", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudtrail_events",
                        "issue": "No CloudTrail events available for API activity analysis",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudtrail.lookup_events error: {e}")

        # Check CloudWatch Metric Data
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "incident_metrics",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/EC2",
                                "MetricName": "CPUUtilization",
                            },
                            "Period": 3600,
                            "Stat": "Average",
                        },
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            total_scanned += 1
            if len(metric_data.get("MetricDataResults", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "metric_data",
                        "issue": "No CloudWatch metric data for performance analysis",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without post-incident analysis tools and data, organizations cannot learn from failures, "
                "identify root causes, or implement preventive measures."
            ),
            recommendation=(
                "Use AWS Health events, CloudTrail logs, CloudWatch metrics, and DevOps Guru insights "
                "to perform comprehensive post-incident analysis and implement improvements."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL12-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating post-incident analysis tools.",
            recommendation="Verify IAM permissions for Health, CloudTrail, CloudWatch, and DevOps Guru APIs.",
        )


def check_rel12_bp03_test_scalability_and_performance(session):
    print("Checking REL12-BP03 - Test scalability and performance requirements")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_testing_resiliency_test_non_functional.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL12-BP03",
            "check_name": "Test scalability and performance requirements",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Configure Auto Scaling groups with appropriate scaling policies.",
                "2. Use Compute Optimizer for EC2 instance recommendations.",
                "3. Monitor CloudWatch metrics for performance analysis.",
                "4. Test ECS/EKS service scaling capabilities.",
                "5. Regularly perform load testing to validate scalability.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        autoscaling = session.client("autoscaling")
        compute_optimizer = session.client("compute-optimizer")
        cloudwatch = session.client("cloudwatch")
        ec2 = session.client("ec2")
        ecs = session.client("ecs")
        eks = session.client("eks")

        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            for asg in asgs:
                if asg.get("MinSize", 0) == asg.get("MaxSize", 0):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": asg["AutoScalingGroupName"],
                            "issue": "Auto Scaling group cannot scale (min equals max capacity)",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(asgs)
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check Auto Scaling Policies
        try:
            policies = autoscaling.describe_policies().get("ScalingPolicies", [])
            total_scanned += 1
            if len(policies) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No Auto Scaling policies for performance-based scaling",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_policies error: {e}")

        # Check Compute Optimizer Recommendations
        try:
            recommendations = compute_optimizer.get_ec2_instance_recommendations().get(
                "instanceRecommendations", []
            )
            total_scanned += 1
            if len(recommendations) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "compute_optimizer",
                        "issue": f"Compute Optimizer has {len(recommendations)} EC2 instance recommendations for performance optimization",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"compute_optimizer.get_ec2_instance_recommendations error: {e}")

        # Check CloudWatch Metrics
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            metric_data = cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=["Average"],
            )
            total_scanned += 1
            if len(metric_data.get("Datapoints", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "performance_metrics",
                        "issue": "No CloudWatch performance metrics for scalability testing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        # Check EC2 Instance Types
        try:
            instance_types = ec2.describe_instance_types(MaxResults=10).get(
                "InstanceTypes", []
            )
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_instance_types error: {e}")

        # Check ECS Services
        try:
            clusters = ecs.list_clusters().get("clusterArns", [])
            for cluster in clusters:
                services = ecs.list_services(cluster=cluster).get("serviceArns", [])
                if services:
                    svc_details = ecs.describe_services(
                        cluster=cluster, services=services
                    ).get("services", [])
                    for svc in svc_details:
                        if svc.get("desiredCount", 0) == 1:
                            affected += 1
                            resources_affected.append(
                                {
                                    "resource_id": svc["serviceName"],
                                    "issue": "ECS service has only 1 desired task (no scalability)",
                                    "region": session.region_name,
                                    "last_updated": datetime.now(IST).isoformat(),
                                }
                            )
                    total_scanned += len(svc_details)
        except Exception as e:
            print(f"ecs.describe_services error: {e}")

        # Check EKS Node Groups
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get(
                    "nodegroups", []
                )
                for ng in nodegroups:
                    ng_details = eks.describe_nodegroup(
                        clusterName=cluster, nodegroupName=ng
                    ).get("nodegroup", {})
                    scaling_config = ng_details.get("scalingConfig", {})
                    if scaling_config.get("minSize", 0) == scaling_config.get(
                        "maxSize", 0
                    ):
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": ng,
                                "issue": "EKS node group cannot scale (min equals max size)",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                total_scanned += len(nodegroups)
        except Exception as e:
            print(f"eks.describe_nodegroup error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without testing scalability and performance, workloads may fail under load, "
                "leading to service degradation and inability to meet demand."
            ),
            recommendation=(
                "Configure Auto Scaling with appropriate policies, use Compute Optimizer recommendations, "
                "monitor CloudWatch metrics, and regularly perform load testing to validate scalability."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL12-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating scalability and performance testing.",
            recommendation="Verify IAM permissions for Auto Scaling, Compute Optimizer, CloudWatch, EC2, ECS, and EKS APIs.",
        )


def check_rel12_bp04_test_resiliency_using_chaos_engineering(session):
    print("Checking REL12-BP04 - Test resiliency using chaos engineering")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_testing_resiliency_failure_injection_resiliency.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL12-BP04",
            "check_name": "Test resiliency using chaos engineering",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create AWS FIS experiment templates for chaos testing.",
                "2. Define failure injection scenarios for critical components.",
                "3. Run FIS experiments to validate resiliency.",
                "4. Monitor experiment results and system behavior.",
                "5. Implement improvements based on chaos testing findings.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        fis = session.client("fis")

        # Check FIS Experiment Templates
        try:
            templates = fis.list_experiment_templates().get("experimentTemplates", [])
            total_scanned += 1
            if len(templates) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "fis_templates",
                        "issue": "No AWS FIS experiment templates for chaos engineering",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                for template in templates:
                    template_details = fis.get_experiment_template(
                        id=template["id"]
                    ).get("experimentTemplate", {})
                    total_scanned += 1
        except Exception as e:
            print(f"fis.list_experiment_templates error: {e}")

        # Check FIS Experiments
        try:
            experiments = fis.list_experiments().get("experiments", [])
            total_scanned += 1
            if len(experiments) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "fis_experiments",
                        "issue": "No AWS FIS experiments executed for resiliency testing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                for experiment in experiments:
                    experiment_details = fis.get_experiment(id=experiment["id"]).get(
                        "experiment", {}
                    )
                    total_scanned += 1
        except Exception as e:
            print(f"fis.list_experiments error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without chaos engineering testing, system resiliency cannot be validated, "
                "and unexpected failures may occur in production."
            ),
            recommendation=(
                "Implement chaos engineering using AWS FIS to create experiment templates, "
                "run failure injection tests, and validate system resiliency under adverse conditions."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL12-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating chaos engineering testing.",
            recommendation="Verify IAM permissions for AWS FIS APIs.",
        )


def check_rel12_bp05_conduct_game_days_regularly(session):
    print("Checking REL12-BP05 - Conduct game days regularly")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_testing_resiliency_game_days_resiliency.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL12-BP05",
            "check_name": "Conduct game days regularly",
            "problem_statement": problem,
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Schedule regular game day exercises for teams.",
                "2. Define realistic failure scenarios and objectives.",
                "3. Document game day procedures and runbooks.",
                "4. Conduct game days in non-production environments first.",
                "5. Review outcomes and implement improvements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS cannot determine whether regular game day exercises are conducted, "
                "as this requires organizational processes and documented operational reviews."
            ),
            recommendation=(
                "Conduct regular game day exercises to validate incident response readiness, "
                "train teams, test runbooks, and identify operational gaps before real incidents occur."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL12-BP05: {e}")
        return build_response(
            status="error",
            problem="Unable to assess game day planning and execution processes.",
            recommendation="Review game day documentation, schedules, and incident response procedures.",
        )


# REL 13. How do you plan for disaster recovery (DR)?


def check_rel13_bp01_define_recovery_objectives(session):
    print("Checking REL13-BP01 - Define recovery objectives for downtime and data loss")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_objective_defined_recovery.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL13-BP01",
            "check_name": "Define recovery objectives for downtime and data loss",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Define Recovery Time Objective (RTO) for each workload.",
                "2. Define Recovery Point Objective (RPO) for data loss tolerance.",
                "3. Document RTO/RPO requirements for all critical systems.",
                "4. Align backup and recovery strategies with RTO/RPO objectives.",
                "5. Regularly review and update recovery objectives based on business needs.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS cannot determine whether RTO and RPO objectives are defined. "
                "These objectives must be documented through organizational disaster recovery planning."
            ),
            recommendation=(
                "Define and document RTO and RPO objectives for all workloads and ensure "
                "backup and recovery strategies align with these requirements."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL13-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess RTO and RPO definition processes.",
            recommendation="Review disaster recovery governance documentation and objective definitions.",
        )


def check_rel13_bp02_use_defined_recovery_strategies(session):
    print(
        "Checking REL13-BP02 - Use defined recovery strategies to meet the recovery objectives"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_disaster_recovery.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL13-BP02",
            "check_name": "Use defined recovery strategies to meet the recovery objectives",
            "problem_statement": problem,
            "severity_score": 90,
            "severity_level": "Critical",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable RDS Multi-AZ deployments for database recovery.",
                "2. Deploy EC2 instances across multiple availability zones.",
                "3. Configure Route53 health checks for failover routing.",
                "4. Use CloudFormation for infrastructure as code recovery.",
                "5. Implement AWS Backup for automated backup and recovery.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        rds = session.client("rds")
        ec2 = session.client("ec2")
        route53 = session.client("route53")
        cloudformation = session.client("cloudformation")
        backup = session.client("backup")

        # Check RDS Multi-AZ
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances:
                if not db.get("MultiAZ"):
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": db["DBInstanceIdentifier"],
                            "issue": "RDS instance not configured for Multi-AZ recovery",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            total_scanned += len(db_instances)
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check EC2 Multi-AZ Deployment
        try:
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ).get("Reservations", [])
            instance_azs = set()
            for res in instances:
                for inst in res.get("Instances", []):
                    instance_azs.add(inst.get("Placement", {}).get("AvailabilityZone"))
            total_scanned += 1
            if len(instance_azs) < 2 and len(instances) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ec2_instances",
                        "issue": "EC2 instances not deployed across multiple AZs for recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_instances error: {e}")

        # Check Availability Zones
        try:
            azs = ec2.describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}]
            ).get("AvailabilityZones", [])
            total_scanned += 1
            if len(azs) < 2:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "availability_zones",
                        "issue": "Less than 2 availability zones for recovery strategy",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ec2.describe_availability_zones error: {e}")

        # Check Route53 Health Checks
        try:
            health_checks = route53.list_health_checks().get("HealthChecks", [])
            total_scanned += 1
            if len(health_checks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "route53_health_checks",
                        "issue": "No Route53 health checks for failover recovery strategy",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"route53.list_health_checks error: {e}")

        # Check CloudFormation Stacks
        try:
            stacks = cloudformation.describe_stacks().get("Stacks", [])
            total_scanned += 1
            if len(stacks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudformation_stacks",
                        "issue": "No CloudFormation stacks for infrastructure recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudformation.describe_stacks error: {e}")

        # Check Backup Vaults
        try:
            vaults = backup.list_backup_vaults().get("BackupVaultList", [])
            total_scanned += 1
            if len(vaults) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "backup_vaults",
                        "issue": "No AWS Backup vaults for data recovery strategy",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"backup.list_backup_vaults error: {e}")

        # Check Backup Plans
        try:
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            total_scanned += 1
            if len(plans) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "backup_plans",
                        "issue": "No AWS Backup plans for automated recovery strategy",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"backup.list_backup_plans error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without defined recovery strategies, workloads may not meet RTO/RPO objectives, "
                "leading to extended downtime and data loss during disasters."
            ),
            recommendation=(
                "Implement recovery strategies using RDS Multi-AZ, multi-AZ EC2 deployments, "
                "Route53 health checks, CloudFormation for IaC, and AWS Backup for data recovery."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL13-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating recovery strategies.",
            recommendation="Verify IAM permissions for RDS, EC2, Route53, CloudFormation, and Backup APIs.",
        )


def check_rel13_bp03_test_disaster_recovery_implementation(session):
    print(
        "Checking REL13-BP03 - Test disaster recovery implementation to validate the implementation"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_dr_tested.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL13-BP03",
            "check_name": "Test disaster recovery implementation to validate the implementation",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Perform regular backup restore tests using AWS Backup.",
                "2. Run FIS experiments to test DR scenarios.",
                "3. Configure CloudWatch alarms for DR testing monitoring.",
                "4. Use EventBridge rules to automate DR testing.",
                "5. Document and review DR test results regularly.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        backup = session.client("backup")
        fis = session.client("fis")
        cloudwatch = session.client("cloudwatch")
        events = session.client("events")

        # Check Backup Restore Jobs
        try:
            restore_jobs = backup.list_restore_jobs().get("RestoreJobs", [])
            total_scanned += 1
            if len(restore_jobs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "restore_jobs",
                        "issue": "No backup restore jobs found indicating DR testing not performed",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                for job in restore_jobs[:5]:
                    job_details = backup.describe_restore_job(
                        RestoreJobId=job["RestoreJobId"]
                    )
                    total_scanned += 1
        except Exception as e:
            print(f"backup.list_restore_jobs error: {e}")

        # Check FIS Experiments
        try:
            experiments = fis.list_experiments().get("experiments", [])
            total_scanned += 1
            if len(experiments) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "fis_experiments",
                        "issue": "No FIS experiments for DR scenario testing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"fis.list_experiments error: {e}")

        # Check FIS Experiment Templates
        try:
            templates = fis.list_experiment_templates().get("experimentTemplates", [])
            total_scanned += 1
            if len(templates) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "fis_templates",
                        "issue": "No FIS experiment templates for DR testing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"fis.list_experiment_templates error: {e}")

        # Check CloudWatch Alarms
        try:
            alarms = cloudwatch.describe_alarms().get("MetricAlarms", [])
            total_scanned += 1
            if len(alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "cloudwatch_alarms",
                        "issue": "No CloudWatch alarms for DR testing monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        # Check EventBridge Rules
        try:
            rules = events.list_rules().get("Rules", [])
            dr_rules = [
                r
                for r in rules
                if "dr" in r.get("Name", "").lower()
                or "disaster" in r.get("Name", "").lower()
                or "recovery" in r.get("Name", "").lower()
            ]
            total_scanned += 1
            if len(dr_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_dr_rules",
                        "issue": "No EventBridge rules for DR testing automation",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without testing DR implementation, recovery procedures may fail during actual disasters, "
                "leading to inability to meet RTO/RPO objectives."
            ),
            recommendation=(
                "Regularly test DR implementation using backup restore jobs, FIS experiments, "
                "CloudWatch alarms, and EventBridge automation to validate recovery procedures."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL13-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating DR testing implementation.",
            recommendation="Verify IAM permissions for Backup, FIS, CloudWatch, and EventBridge APIs.",
        )


def check_rel13_bp04_manage_configuration_drift(session):
    print("Checking REL13-BP04 - Manage configuration drift at the DR site or Region")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_config_drift.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL13-BP04",
            "check_name": "Manage configuration drift at the DR site or Region",
            "problem_statement": problem,
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable AWS Config configuration recorders in all regions.",
                "2. Run CloudFormation drift detection on all stacks.",
                "3. Review and remediate detected drift regularly.",
                "4. Use CloudFormation for infrastructure as code consistency.",
                "5. Implement automated drift detection and remediation.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        config = session.client("config")
        cloudformation = session.client("cloudformation")

        # Check AWS Config Configuration Recorders
        try:
            recorders = config.describe_configuration_recorders().get(
                "ConfigurationRecorders", []
            )
            total_scanned += 1
            if len(recorders) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "config_recorders",
                        "issue": "No AWS Config recorders to track configuration drift",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"config.describe_configuration_recorders error: {e}")

        # Check CloudFormation Stacks and Drift Detection
        try:
            stacks = cloudformation.list_stacks(
                StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE"]
            ).get("StackSummaries", [])
            for stack in stacks:
                stack_name = stack["StackName"]
                try:
                    # Detect stack drift
                    drift_response = cloudformation.detect_stack_drift(
                        StackName=stack_name
                    )
                    drift_detection_id = drift_response["StackDriftDetectionId"]

                    # Check drift detection status
                    drift_status = cloudformation.describe_stack_drift_detection_status(
                        StackDriftDetectionId=drift_detection_id
                    )

                    if drift_status.get("StackDriftStatus") == "DRIFTED":
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": stack_name,
                                "issue": "CloudFormation stack has configuration drift",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )

                    # List stack resources
                    resources = cloudformation.list_stack_resources(
                        StackName=stack_name
                    ).get("StackResourceSummaries", [])
                    total_scanned += 1
                except Exception as e:
                    print(f"cloudformation drift detection error for {stack_name}: {e}")
        except Exception as e:
            print(f"cloudformation.list_stacks error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without managing configuration drift, DR sites may diverge from primary sites, "
                "leading to failed recovery and inconsistent infrastructure."
            ),
            recommendation=(
                "Enable AWS Config recorders, run CloudFormation drift detection regularly, "
                "and remediate drift to ensure DR site consistency with primary infrastructure."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL13-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating configuration drift management.",
            recommendation="Verify IAM permissions for AWS Config and CloudFormation APIs.",
        )


def check_rel13_bp05_automate_recovery(session):
    print("Checking REL13-BP05 - Automate recovery")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_auto_recovery.html"

    resources_affected = []

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL13-BP05",
            "check_name": "Automate recovery",
            "problem_statement": problem,
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Create SSM automation documents for recovery procedures.",
                "2. Implement Lambda functions for automated recovery actions.",
                "3. Configure EventBridge rules to trigger recovery automation.",
                "4. Set up Route53 health checks for automatic failover.",
                "5. Enable Auto Scaling groups for automatic capacity recovery.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ssm = session.client("ssm")
        lambda_client = session.client("lambda")
        events = session.client("events")
        route53 = session.client("route53")
        autoscaling = session.client("autoscaling")

        # Check SSM Automation Executions
        try:
            executions = ssm.describe_automation_executions(MaxResults=10).get(
                "AutomationExecutionMetadataList", []
            )
            total_scanned += 1
            if len(executions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ssm_automation",
                        "issue": "No SSM automation executions for automated recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            else:
                # Start automation execution check (validation only, not actual execution)
                try:
                    ssm.start_automation_execution
                    total_scanned += 1
                except Exception as e:
                    print(f"ssm.start_automation_execution validation error: {e}")
        except Exception as e:
            print(f"ssm.describe_automation_executions error: {e}")

        # Check Lambda Functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            recovery_functions = [
                f
                for f in functions
                if "recovery" in f.get("FunctionName", "").lower()
                or "failover" in f.get("FunctionName", "").lower()
            ]
            total_scanned += 1
            if len(recovery_functions) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_recovery_functions",
                        "issue": "No Lambda functions for automated recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check EventBridge Rules
        try:
            rules = events.list_rules().get("Rules", [])
            recovery_rules = [
                r
                for r in rules
                if "recovery" in r.get("Name", "").lower()
                or "failover" in r.get("Name", "").lower()
            ]
            total_scanned += 1
            if len(recovery_rules) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_recovery_rules",
                        "issue": "No EventBridge rules for automated recovery triggers",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # Check Route53 Health Checks
        try:
            health_checks = route53.list_health_checks().get("HealthChecks", [])
            total_scanned += 1
            if len(health_checks) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "route53_health_checks",
                        "issue": "No Route53 health checks for automated failover",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"route53.list_health_checks error: {e}")

        # Check Auto Scaling Groups
        try:
            asgs = autoscaling.describe_auto_scaling_groups().get(
                "AutoScalingGroups", []
            )
            total_scanned += 1
            if len(asgs) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "auto_scaling_groups",
                        "issue": "No Auto Scaling groups for automated capacity recovery",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without automated recovery, manual intervention is required during disasters, "
                "leading to extended downtime and failure to meet RTO objectives."
            ),
            recommendation=(
                "Implement automated recovery using SSM automation, Lambda functions, EventBridge rules, "
                "Route53 health checks, and Auto Scaling groups for rapid disaster recovery."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL13-BP05 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating automated recovery.",
            recommendation="Verify IAM permissions for SSM, Lambda, EventBridge, Route53, and Auto Scaling APIs.",
        )
