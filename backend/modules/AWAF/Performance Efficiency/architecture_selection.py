from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# PERF 1. How do you select appropriate cloud resources and architecture for your workload?

# PERF01-BP01 Learn about and understand available cloud services and features
def check_perf01_bp01_learn_cloud_services(session):
    print("Checking PERF01-BP01 – Learn about and understand available cloud services and features")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/performance-efficiency-pillar/perf_select_resource_type_features_learn.html"

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
            "id": "PERF01-BP01",
            "check_name": "Learn about and understand available cloud services and features",
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
                "1. Subscribe to AWS What's New announcements.",
                "2. Attend AWS re:Invent, summits, and webinars.",
                "3. Review AWS Architecture Center and Well-Architected Framework.",
                "4. Conduct regular service evaluations for workload optimization.",
                "5. Implement AWS Service Catalog for standardized service offerings.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        servicecatalog = session.client("servicecatalog")
        ec2 = session.client("ec2")
        rds = session.client("rds")
        lambda_client = session.client("lambda")
        dynamodb = session.client("dynamodb")
        elasticache = session.client("elasticache")
        s3 = session.client("s3")

        # Check Service Catalog products
        try:
            products = servicecatalog.search_products_as_admin().get("ProductViewDetails", [])
            total_scanned += 1
            if len(products) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "service_catalog",
                    "issue": "No Service Catalog products for standardized service offerings",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"servicecatalog.search_products_as_admin error: {e}")

        # Check EC2 instance type offerings
        try:
            offerings = ec2.describe_instance_type_offerings().get("InstanceTypeOfferings", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_instance_type_offerings error: {e}")

        # Check RDS engine versions
        try:
            engines = rds.describe_db_engine_versions().get("DBEngineVersions", [])
            total_scanned += 1
        except Exception as e:
            print(f"rds.describe_db_engine_versions error: {e}")

        # Check Lambda functions
        try:
            functions = lambda_client.list_functions().get("Functions", [])
            total_scanned += 1
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # Check DynamoDB limits
        try:
            dynamodb.describe_limits()
            total_scanned += 1
        except Exception as e:
            print(f"dynamodb.describe_limits error: {e}")

        # Check ElastiCache engine versions
        try:
            cache_engines = elasticache.describe_cache_engine_versions().get("CacheEngineVersions", [])
            total_scanned += 1
        except Exception as e:
            print(f"elasticache.describe_cache_engine_versions error: {e}")

        # Check S3 buckets
        try:
            buckets = s3.list_buckets().get("Buckets", [])
            total_scanned += 1
        except Exception as e:
            print(f"s3.list_buckets error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without continuous learning about AWS services and features, organizations may miss "
                "opportunities to optimize workload performance and cost-effectiveness."
            ),
            recommendation=(
                "Regularly review AWS service offerings, attend training, and implement Service Catalog "
                "for standardized service discovery and usage."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF01-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating cloud service knowledge.",
            recommendation="Verify IAM permissions for Service Catalog, EC2, RDS, Lambda, DynamoDB, ElastiCache, and S3 APIs.",
        )


# PERF01-BP02 Use guidance from your cloud provider or an appropriate partner to learn about architecture patterns and best practices
def check_perf01_bp02_use_guidance_patterns(session):
    print("Checking PERF01-BP02 – Use guidance from your cloud provider or an appropriate partner to learn about architecture patterns and best practices")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_architecture_guidance_architecture_patterns_best_practices.html"

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
            "id": "PERF01-BP02",
            "check_name": "Use guidance from your cloud provider or an appropriate partner to learn about architecture patterns and best practices",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Engage with AWS Solutions Architects and Technical Account Managers.",
                "2. Review AWS Well-Architected Framework and Architecture Center.",
                "3. Participate in AWS Partner Network (APN) programs.",
                "4. Conduct Well-Architected Reviews for workloads.",
                "5. Implement reference architectures from AWS Solutions Library.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for architecture pattern guidance usage",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must actively seek and apply guidance from AWS or partners on architecture "
            "patterns and best practices. This is an organizational responsibility that requires governance."
        ),
        recommendation=(
            "Establish regular engagement with AWS Solutions Architects, conduct Well-Architected Reviews, "
            "and implement reference architectures from AWS Solutions Library."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF01-BP03 Factor cost into architectural decisions
def check_perf01_bp03_factor_cost_decisions(session):
    print("Checking PERF01-BP03 – Factor cost into architectural decisions")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_architecture_factor_cost_into_architectural_decisions.html"

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
            "id": "PERF01-BP03",
            "check_name": "Factor cost into architectural decisions",
            "problem_statement": problem,
            "severity_score": 65,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Enable AWS Cost Explorer and Cost Anomaly Detection.",
                "2. Implement AWS Budgets with alerts for cost thresholds.",
                "3. Use AWS Cost and Usage Reports for detailed analysis.",
                "4. Review architecture decisions with cost optimization in mind.",
                "5. Establish cost governance processes for architectural changes.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for cost-aware architectural decisions",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must factor cost into architectural decisions to balance performance and "
            "cost-effectiveness. This is an organizational responsibility requiring governance."
        ),
        recommendation=(
            "Enable Cost Explorer, implement budgets and alerts, and establish cost governance "
            "processes for all architectural decisions."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF01-BP04 Evaluate how trade-offs impact customers and architecture efficiency
def check_perf01_bp04_evaluate_tradeoffs(session):
    print("Checking PERF01-BP04 – Evaluate how trade-offs impact customers and architecture efficiency")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_architecture_evaluate_trade_offs.html"

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
            "id": "PERF01-BP04",
            "check_name": "Evaluate how trade-offs impact customers and architecture efficiency",
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
                "1. Enable AWS Cost Explorer for cost analysis.",
                "2. Configure Cost and Usage Reports for detailed tracking.",
                "3. Use AWS Compute Optimizer for resource recommendations.",
                "4. Implement Savings Plans for cost optimization.",
                "5. Use AWS Pricing API for cost estimation in decisions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ce = session.client("ce")
        cur = session.client("cur")
        compute_optimizer = session.client("compute-optimizer")
        savingsplans = session.client("savingsplans")
        pricing = session.client("pricing", region_name="us-east-1")

        # Check Cost Explorer usage
        try:
            from datetime import timedelta
            end_date = datetime.now().strftime("%Y-%m-%d")
            start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
            ce.get_cost_and_usage(TimePeriod={"Start": start_date, "End": end_date}, Granularity="DAILY", Metrics=["UnblendedCost"])
            total_scanned += 1
        except Exception as e:
            print(f"ce.get_cost_and_usage error: {e}")

        # Check Cost and Usage Reports
        try:
            reports = cur.describe_report_definitions().get("ReportDefinitions", [])
            total_scanned += 1
            if len(reports) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "cost_usage_reports",
                    "issue": "No Cost and Usage Reports configured for detailed cost tracking",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"cur.describe_report_definitions error: {e}")

        # Check Compute Optimizer recommendations
        try:
            summaries = compute_optimizer.get_recommendation_summaries().get("recommendationSummaries", [])
            total_scanned += 1
            if len(summaries) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "compute_optimizer",
                    "issue": "No Compute Optimizer recommendations available for resource optimization",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"compute_optimizer.get_recommendation_summaries error: {e}")

        # Check Savings Plans
        try:
            plans = savingsplans.describe_savings_plans().get("savingsPlans", [])
            total_scanned += 1
            if len(plans) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "savings_plans",
                    "issue": "No Savings Plans configured for cost optimization",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"savingsplans.describe_savings_plans error: {e}")

        # Check Pricing API access
        try:
            pricing.get_products(ServiceCode="AmazonEC2", MaxResults=1)
            total_scanned += 1
        except Exception as e:
            print(f"pricing.get_products error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without evaluating trade-offs between cost, performance, and efficiency, organizations "
                "may make suboptimal architectural decisions that impact customers and operational costs."
            ),
            recommendation=(
                "Enable Cost Explorer, configure Cost and Usage Reports, use Compute Optimizer recommendations, "
                "and implement Savings Plans for cost-effective architecture decisions."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF01-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating trade-off analysis capabilities.",
            recommendation="Verify IAM permissions for Cost Explorer, CUR, Compute Optimizer, Savings Plans, and Pricing APIs.",
        )


# PERF01-BP05 Use policies and reference architectures
def check_perf01_bp05_use_policies_architectures(session):
    print("Checking PERF01-BP05 – Use policies and reference architectures")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_architecture_use_policies_and_reference_architectures.html"

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
            "id": "PERF01-BP05",
            "check_name": "Use policies and reference architectures",
            "problem_statement": problem,
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Implement AWS Service Catalog for standardized architectures.",
                "2. Use AWS Organizations SCPs for policy enforcement.",
                "3. Deploy reference architectures from AWS Solutions Library.",
                "4. Establish architectural governance and review processes.",
                "5. Document and enforce architectural standards and patterns.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for policies and reference architecture usage",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must establish and enforce policies and reference architectures to ensure "
            "consistent, performant workload designs. This is an organizational responsibility."
        ),
        recommendation=(
            "Implement Service Catalog for standardized architectures, use Organizations SCPs for policy "
            "enforcement, and deploy reference architectures from AWS Solutions Library."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF01-BP06 Use benchmarking to drive architectural decisions
def check_perf01_bp06_use_benchmarking(session):
    print("Checking PERF01-BP06 – Use benchmarking to drive architectural decisions")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_architecture_use_benchmarking.html"

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
            "id": "PERF01-BP06",
            "check_name": "Use benchmarking to drive architectural decisions",
            "problem_statement": problem,
            "severity_score": 65,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": status,
            "recommendation": recommendation,
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Establish performance benchmarking processes for workloads.",
                "2. Use load testing tools to measure performance characteristics.",
                "3. Document baseline performance metrics for comparison.",
                "4. Conduct regular benchmarking before architectural changes.",
                "5. Compare results across different resource configurations.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for benchmarking practices",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must use benchmarking to validate architectural decisions and measure performance "
            "improvements. This is an organizational responsibility requiring governance."
        ),
        recommendation=(
            "Establish performance benchmarking processes, use load testing tools, and document baseline "
            "metrics to drive data-driven architectural decisions."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF01-BP07 Use a data-driven approach for architectural choices
def check_perf01_bp07_data_driven_approach(session):
    print("Checking PERF01-BP07 – Use a data-driven approach for architectural choices")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_architecture_use_data_driven_approach.html"

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
            "id": "PERF01-BP07",
            "check_name": "Use a data-driven approach for architectural choices",
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
                "1. Implement CloudWatch metrics and dashboards for performance data.",
                "2. Use AWS X-Ray for distributed tracing and analysis.",
                "3. Enable detailed monitoring and logging for workloads.",
                "4. Analyze performance data before making architectural changes.",
                "5. Establish data collection and analysis processes for decisions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for data-driven architectural decision processes",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must use data-driven approaches for architectural choices based on performance "
            "metrics and analysis. This is an organizational responsibility requiring governance."
        ),
        recommendation=(
            "Implement CloudWatch metrics, use X-Ray for tracing, enable detailed monitoring, and establish "
            "data collection processes to drive architectural decisions."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )
