from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# PERF 3. How do you store, manage, and access data in your workload?

# PERF03-BP01 Use a purpose-built data store that best supports your data access and storage requirements
def check_perf03_bp01_purpose_built_datastore(session):
    print("Checking PERF03-BP01 – Use a purpose-built data store that best supports your data access and storage requirements")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_data_use_purpose_built_data_store.html"

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
            "id": "PERF03-BP01",
            "check_name": "Use a purpose-built data store that best supports your data access and storage requirements",
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
                "1. Use S3 for object storage and static content.",
                "2. Use RDS for relational database workloads.",
                "3. Use DynamoDB for NoSQL and key-value data.",
                "4. Use ElastiCache/MemoryDB for caching and in-memory data.",
                "5. Use purpose-built databases like Neptune, Redshift, EFS, FSx, Kinesis, and Kafka.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        s3 = session.client("s3")
        rds = session.client("rds")
        dynamodb = session.client("dynamodb")
        elasticache = session.client("elasticache")
        memorydb = session.client("memorydb")
        neptune = session.client("neptune")
        redshift = session.client("redshift")
        efs = session.client("efs")
        fsx = session.client("fsx")
        kinesis = session.client("kinesis")
        kafka = session.client("kafka")

        # Check S3 buckets
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            total_scanned += 1
        except Exception as e:
            print(f"s3.list_buckets error: {e}")

        # Check RDS instances
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            total_scanned += 1
        except Exception as e:
            print(f"rds.describe_db_instances error: {e}")

        # Check RDS engine versions
        try:
            engine_versions = rds.describe_db_engine_versions(MaxRecords=1).get("DBEngineVersions", [])
            total_scanned += 1
        except Exception as e:
            print(f"rds.describe_db_engine_versions error: {e}")

        # Check DynamoDB tables
        try:
            tables = dynamodb.list_tables().get("TableNames", [])
            total_scanned += 1
        except Exception as e:
            print(f"dynamodb.list_tables error: {e}")

        # Check ElastiCache clusters
        try:
            cache_clusters = elasticache.describe_cache_clusters().get("CacheClusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"elasticache.describe_cache_clusters error: {e}")

        # Check MemoryDB clusters
        try:
            memorydb_clusters = memorydb.describe_clusters().get("Clusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"memorydb.describe_clusters error: {e}")

        # Check Neptune clusters
        try:
            neptune_clusters = neptune.describe_db_clusters().get("DBClusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"neptune.describe_db_clusters error: {e}")

        # Check Redshift clusters
        try:
            redshift_clusters = redshift.describe_clusters().get("Clusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"redshift.describe_clusters error: {e}")

        # Check EFS file systems
        try:
            efs_filesystems = efs.describe_file_systems().get("FileSystems", [])
            total_scanned += 1
        except Exception as e:
            print(f"efs.describe_file_systems error: {e}")

        # Check FSx file systems
        try:
            fsx_filesystems = fsx.describe_file_systems().get("FileSystems", [])
            total_scanned += 1
        except Exception as e:
            print(f"fsx.describe_file_systems error: {e}")

        # Check Kinesis streams
        try:
            kinesis_streams = kinesis.list_streams().get("StreamNames", [])
            total_scanned += 1
        except Exception as e:
            print(f"kinesis.list_streams error: {e}")

        # Check Kafka clusters
        try:
            kafka_clusters = kafka.list_clusters().get("ClusterInfoList", [])
            total_scanned += 1
        except Exception as e:
            print(f"kafka.list_clusters error: {e}")

        if total_scanned == 0:
            affected += 1
            resources_affected.append({
                "resource_id": "data_stores",
                "issue": "No purpose-built data stores found in the account",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without using purpose-built data stores, workloads may experience suboptimal performance, "
                "higher costs, and operational complexity due to mismatched data access patterns."
            ),
            recommendation=(
                "Use purpose-built data stores like S3, RDS, DynamoDB, ElastiCache, Neptune, Redshift, EFS, "
                "FSx, Kinesis, and Kafka based on specific data access and storage requirements."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF03-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating purpose-built data stores.",
            recommendation="Verify IAM permissions for S3, RDS, DynamoDB, ElastiCache, MemoryDB, Neptune, Redshift, EFS, FSx, Kinesis, and Kafka APIs.",
        )


# PERF03-BP02 Evaluate available configuration options for data store
def check_perf03_bp02_evaluate_datastore_config(session):
    print("Checking PERF03-BP02 – Evaluate available configuration options for data store")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_data_evaluate_configuration_options_data_store.html"

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
            "id": "PERF03-BP02",
            "check_name": "Evaluate available configuration options for data store",
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
                "1. Enable CloudWatch metrics for data store monitoring.",
                "2. Configure RDS Performance Insights for database performance.",
                "3. Review DynamoDB table configurations and capacity modes.",
                "4. Monitor ElastiCache and Redshift cluster performance.",
                "5. Enable CloudWatch Logs for data store operations.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        cloudwatch = session.client("cloudwatch")
        rds = session.client("rds")
        dynamodb = session.client("dynamodb")
        elasticache = session.client("elasticache")
        redshift = session.client("redshift")
        logs = session.client("logs")

        # Check CloudWatch metrics
        try:
            metrics = cloudwatch.list_metrics(MaxRecords=1).get("Metrics", [])
            total_scanned += 1
            if len(metrics) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_metrics",
                    "issue": "No CloudWatch metrics found for data store monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"cloudwatch.list_metrics error: {e}")

        # Check CloudWatch metric data
        try:
            from datetime import timedelta
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_data(
                MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/RDS", "MetricName": "CPUUtilization"}, "Period": 300, "Stat": "Average"}}],
                StartTime=start_time,
                EndTime=end_time
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # Check CloudWatch metric statistics
        try:
            cloudwatch.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName="CPUUtilization",
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=["Average"]
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        # Check RDS Performance Insights
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances:
                if not db.get("PerformanceInsightsEnabled", False):
                    affected += 1
                    resources_affected.append({
                        "resource_id": db.get("DBInstanceIdentifier", "unknown"),
                        "issue": "RDS Performance Insights not enabled",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            total_scanned += 1
        except Exception as e:
            print(f"rds.describe_performance_insights error: {e}")

        # Check DynamoDB tables
        try:
            tables = dynamodb.list_tables().get("TableNames", [])
            for table in tables[:5]:
                dynamodb.describe_table(TableName=table)
                total_scanned += 1
        except Exception as e:
            print(f"dynamodb.describe_table error: {e}")

        # Check ElastiCache clusters
        try:
            cache_clusters = elasticache.describe_cache_clusters().get("CacheClusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"elasticache.describe_cache_clusters error: {e}")

        # Check Redshift clusters
        try:
            redshift_clusters = redshift.describe_clusters().get("Clusters", [])
            total_scanned += 1
        except Exception as e:
            print(f"redshift.describe_clusters error: {e}")

        # Check CloudWatch log groups
        try:
            log_groups = logs.describe_log_groups(limit=1).get("logGroups", [])
            total_scanned += 1
            if len(log_groups) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cloudwatch_logs",
                    "issue": "No CloudWatch log groups found for data store logging",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"logs.describe_log_groups error: {e}")

        # Check log streams
        try:
            if len(log_groups) > 0:
                logs.describe_log_streams(logGroupName=log_groups[0]["logGroupName"], limit=1)
            total_scanned += 1
        except Exception as e:
            print(f"logs.describe_log_streams error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without evaluating data store configuration options, organizations may miss opportunities "
                "to optimize performance, cost, and operational efficiency."
            ),
            recommendation=(
                "Enable CloudWatch metrics and logs, configure RDS Performance Insights, review DynamoDB "
                "table settings, and monitor ElastiCache and Redshift configurations."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF03-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating data store configurations.",
            recommendation="Verify IAM permissions for CloudWatch, RDS, DynamoDB, ElastiCache, Redshift, and CloudWatch Logs APIs.",
        )


# PERF03-BP03 Collect and record data store performance metrics
def check_perf03_bp03_collect_datastore_metrics(session):
    print("Checking PERF03-BP03 – Collect and record data store performance metrics")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_data_collect_record_data_store_performance_metrics.html"

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
            "id": "PERF03-BP03",
            "check_name": "Collect and record data store performance metrics",
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
                "1. Configure RDS parameter groups and enable automated snapshots.",
                "2. Review DynamoDB table metrics and performance settings.",
                "3. Configure ElastiCache parameter groups for optimization.",
                "4. Enable S3 bucket policies and lifecycle configurations.",
                "5. Monitor EFS mount targets and FSx file systems.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        rds = session.client("rds")
        dynamodb = session.client("dynamodb")
        elasticache = session.client("elasticache")
        s3 = session.client("s3")
        efs = session.client("efs")
        fsx = session.client("fsx")
        memorydb = session.client("memorydb")
        docdb = session.client("docdb")

        # Check RDS DB parameters
        try:
            db_instances = rds.describe_db_instances().get("DBInstances", [])
            for db in db_instances[:5]:
                param_group = db.get("DBParameterGroups", [])
                if param_group:
                    rds.describe_db_parameters(DBParameterGroupName=param_group[0]["DBParameterGroupName"], MaxRecords=20)
                total_scanned += 1
        except Exception as e:
            print(f"rds.describe_db_parameters error: {e}")

        # Check RDS snapshots
        try:
            snapshots = rds.describe_db_snapshots(MaxRecords=1).get("DBSnapshots", [])
            total_scanned += 1
            if len(snapshots) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "rds_snapshots",
                    "issue": "No RDS snapshots found for backup and recovery",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"rds.describe_db_snapshots error: {e}")

        # Check DynamoDB tables
        try:
            tables = dynamodb.list_tables().get("TableNames", [])
            for table in tables[:5]:
                dynamodb.describe_table(TableName=table)
                total_scanned += 1
        except Exception as e:
            print(f"dynamodb.describe_table error: {e}")

        # Check ElastiCache parameters
        try:
            cache_clusters = elasticache.describe_cache_clusters().get("CacheClusters", [])
            for cluster in cache_clusters[:5]:
                param_group = cluster.get("CacheParameterGroup", {})
                if param_group:
                    elasticache.describe_cache_parameters(CacheParameterGroupName=param_group.get("CacheParameterGroupName", ""), MaxRecords=20)
                total_scanned += 1
        except Exception as e:
            print(f"elasticache.describe_cache_parameters error: {e}")

        # Check S3 bucket policies
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets[:5]:
                try:
                    s3.get_bucket_policy(Bucket=bucket["Name"])
                except:
                    pass
                total_scanned += 1
        except Exception as e:
            print(f"s3.get_bucket_policy error: {e}")

        # Check S3 lifecycle configurations
        try:
            for bucket in buckets[:5]:
                try:
                    s3.get_bucket_lifecycle_configuration(Bucket=bucket["Name"])
                except:
                    pass
                total_scanned += 1
        except Exception as e:
            print(f"s3.get_bucket_lifecycle_configuration error: {e}")

        # Check EFS mount targets
        try:
            filesystems = efs.describe_file_systems().get("FileSystems", [])
            for fs in filesystems:
                efs.describe_mount_targets(FileSystemId=fs["FileSystemId"])
                total_scanned += 1
        except Exception as e:
            print(f"efs.describe_mount_targets error: {e}")

        # Check FSx file systems
        try:
            fsx_filesystems = fsx.describe_file_systems().get("FileSystems", [])
            total_scanned += 1
        except Exception as e:
            print(f"fsx.describe_file_systems error: {e}")

        # Check MemoryDB engine versions
        try:
            memorydb.describe_engine_versions()
            total_scanned += 1
        except Exception as e:
            print(f"memorydb.describe_engine_versions error: {e}")

        # Check DocumentDB instances
        try:
            docdb_instances = docdb.describe_db_instances().get("DBInstances", [])
            total_scanned += 1
        except Exception as e:
            print(f"docdb.describe_db_instances error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without collecting and recording data store performance metrics, organizations cannot "
                "identify bottlenecks, optimize configurations, or troubleshoot performance issues."
            ),
            recommendation=(
                "Configure RDS parameters and snapshots, review DynamoDB metrics, set up ElastiCache parameters, "
                "enable S3 policies and lifecycle rules, and monitor EFS/FSx file systems."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF03-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating data store metrics collection.",
            recommendation="Verify IAM permissions for RDS, DynamoDB, ElastiCache, S3, EFS, FSx, MemoryDB, and DocumentDB APIs.",
        )


# PERF03-BP04 Implement strategies to improve query performance in data store
def check_perf03_bp04_improve_query_performance(session):
    print("Checking PERF03-BP04 – Implement strategies to improve query performance in data store")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_data_implement_strategies_to_improve_query_performance.html"

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
            "id": "PERF03-BP04",
            "check_name": "Implement strategies to improve query performance in data store",
            "problem_statement": problem,
            "severity_score": 70,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Implement database indexing strategies for RDS and DynamoDB.",
                "2. Use query optimization techniques and execution plans.",
                "3. Implement caching layers with ElastiCache or MemoryDB.",
                "4. Use read replicas for read-heavy workloads.",
                "5. Optimize data partitioning and sharding strategies.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for query performance optimization strategies",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must implement strategies to improve query performance through indexing, caching, "
            "read replicas, and optimization techniques. This is an organizational responsibility."
        ),
        recommendation=(
            "Implement database indexing, use query optimization, deploy caching layers, configure read replicas, "
            "and optimize data partitioning for improved query performance."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF03-BP05 Implement data access patterns that utilize caching
def check_perf03_bp05_data_access_caching(session):
    print("Checking PERF03-BP05 – Implement data access patterns that utilize caching")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/performance-efficiency-pillar/perf_data_access_patterns_caching.html"

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
            "id": "PERF03-BP05",
            "check_name": "Implement data access patterns that utilize caching",
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
                "1. Implement ElastiCache or MemoryDB for application caching.",
                "2. Use CloudFront for content delivery and edge caching.",
                "3. Configure DynamoDB DAX for in-memory acceleration.",
                "4. Implement application-level caching strategies.",
                "5. Use RDS read replicas with caching layers.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for caching implementation in data access patterns",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must implement data access patterns that utilize caching to reduce latency, "
            "improve performance, and reduce load on data stores. This is an organizational responsibility."
        ),
        recommendation=(
            "Implement ElastiCache/MemoryDB for caching, use CloudFront for content delivery, configure "
            "DynamoDB DAX, and establish application-level caching strategies."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )
