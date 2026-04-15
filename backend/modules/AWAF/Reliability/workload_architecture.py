from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# Workload architecture

# REL 3. How do you design your workload service architecture?


def check_rel03_bp01_choose_how_to_segment_workload(session):
    print("Checking REL03-BP01 - Choose how to segment your workload")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_service_architecture_monolith_soa_microservice.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL03-BP01",
            "check_name": "Choose how to segment your workload",
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
                "1. Analyze workload requirements for latency, compliance, and availability.",
                "2. Choose regions based on proximity to users and regulatory requirements.",
                "3. Implement multi-region deployment for critical workloads.",
                "4. Document region selection criteria and decision rationale.",
                "5. Plan for data residency and sovereignty requirements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Workload segmentation decisions such as regional placement, latency boundaries, "
                "and compliance-driven partitioning cannot be assessed through AWS APIs. These "
                "must be defined through architectural planning and documentation."
            ),
            recommendation=(
                "Define workload segmentation strategy based on latency needs, compliance obligations, "
                "availability goals, and user geography. Document segmentation rationale and validate "
                "it through architecture reviews."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL03-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess workload segmentation strategy.",
            recommendation="Review architecture documentation and segmentation criteria.",
        )


def check_rel03_bp01_choose_how_to_segment_workload(session):
    print("Checking REL03-BP01 - Choose how to segment your workload")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_service_architecture_monolith_soa_microservice.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL03-BP01",
            "check_name": "Choose how to segment your workload",
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
                "1. Analyze workload requirements for latency, compliance, and availability.",
                "2. Choose regions based on proximity to users and regulatory requirements.",
                "3. Implement multi-region deployment for critical workloads.",
                "4. Document region selection criteria and decision rationale.",
                "5. Plan for data residency and sovereignty requirements.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Workload segmentation decisions such as regional placement, latency boundaries, "
                "and compliance-driven partitioning cannot be assessed through AWS APIs. These "
                "must be defined through architectural planning and documentation."
            ),
            recommendation=(
                "Define workload segmentation strategy based on latency needs, compliance obligations, "
                "availability goals, and user geography. Document segmentation rationale and validate "
                "it through architecture reviews."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL03-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess workload segmentation strategy.",
            recommendation="Review architecture documentation and segmentation criteria.",
        )


def check_rel03_bp03_provide_service_contracts_per_api(session):
    print("Checking REL03-BP03 - Provide service contracts per API")

    apigateway = session.client("apigateway")
    apigatewayv2 = session.client("apigatewayv2")
    appmesh = session.client("appmesh")
    ecs = session.client("ecs")
    lambda_client = session.client("lambda")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_service_architecture_api_contracts.html"

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
            "id": "REL03-BP03",
            "check_name": "Provide service contracts per API",
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
                "1. Define clear API contracts using OpenAPI specifications.",
                "2. Implement API versioning strategies for backward compatibility.",
                "3. Use API Gateway for centralized API management and documentation.",
                "4. Establish service mesh for inter-service communication contracts.",
                "5. Document API schemas, endpoints, and expected behaviors.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check API Gateway REST APIs ------------------------
        try:
            rest_apis = apigateway.get_rest_apis()
            if len(rest_apis.get("items", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "api_gateway_rest",
                        "issue": "No API Gateway REST APIs found for service contracts",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"apigateway.get_rest_apis error: {e}")

        # ------------------------ Check API Gateway v2 APIs ------------------------
        try:
            v2_apis = apigatewayv2.get_apis()
            if len(v2_apis.get("Items", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "api_gateway_v2",
                        "issue": "No API Gateway v2 APIs found for service contracts",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"apigatewayv2.get_apis error: {e}")

        # ------------------------ Check App Mesh ------------------------
        try:
            meshes = appmesh.list_meshes()
            if len(meshes.get("meshes", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "app_mesh",
                        "issue": "No App Mesh found for service-to-service communication contracts",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"appmesh.list_meshes error: {e}")

        # ------------------------ Check ECS Services ------------------------
        try:
            ecs_services = ecs.list_services()
            if len(ecs_services.get("serviceArns", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ecs_services",
                        "issue": "No ECS services found that may need API contracts",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ecs.list_services error: {e}")

        # ------------------------ Check Lambda Functions ------------------------
        try:
            functions = lambda_client.list_functions()
            if len(functions.get("Functions", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_functions",
                        "issue": "No Lambda functions found that may need API contracts",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without clear service contracts per API, services may have undefined "
                "interfaces leading to integration issues, versioning conflicts, and "
                "difficulty in maintaining backward compatibility."
            ),
            recommendation=(
                "Implement comprehensive API contracts using OpenAPI specifications, "
                "API Gateway for management, and service mesh for inter-service communication."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL03-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating API service contracts.",
            recommendation="Verify IAM permissions for API Gateway, App Mesh, ECS, and Lambda APIs.",
        )


# REL 4. How do you design interactions in a distributed system to prevent failures?


def check_rel04_bp01_identify_distributed_systems(session):
    print(
        "Checking REL04-BP01 - Identify the kind of distributed systems you depend on"
    )

    ecs = session.client("ecs")
    eks = session.client("eks")
    lambda_client = session.client("lambda")
    sqs = session.client("sqs")
    sns = session.client("sns")
    events = session.client("events")
    apigateway = session.client("apigateway")
    dynamodb = session.client("dynamodb")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_prevent_interaction_failure_identify.html"

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
            "id": "REL04-BP01",
            "check_name": "Identify the kind of distributed systems you depend on",
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
                "1. Catalog all distributed system components and dependencies.",
                "2. Document communication patterns between services.",
                "3. Identify synchronous vs asynchronous interactions.",
                "4. Map data flow and service dependencies.",
                "5. Assess failure modes and impact of each distributed component.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 8
    affected = 0

    try:
        # ------------------------ Check ECS Clusters ------------------------
        try:
            clusters = ecs.list_clusters()
            if len(clusters.get("clusterArns", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ecs_clusters",
                        "issue": "No ECS clusters found for containerized distributed systems",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ecs.list_clusters error: {e}")

        # ------------------------ Check EKS Clusters ------------------------
        try:
            eks_clusters = eks.list_clusters()
            if len(eks_clusters.get("clusters", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eks_clusters",
                        "issue": "No EKS clusters found for Kubernetes distributed systems",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"eks.list_clusters error: {e}")

        # ------------------------ Check Lambda Functions ------------------------
        try:
            functions = lambda_client.list_functions()
            if len(functions.get("Functions", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_functions",
                        "issue": "No Lambda functions found for serverless distributed components",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # ------------------------ Check SQS Queues ------------------------
        try:
            queues = sqs.list_queues()
            if len(queues.get("QueueUrls", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sqs_queues",
                        "issue": "No SQS queues found for asynchronous messaging",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sqs.list_queues error: {e}")

        # ------------------------ Check SNS Topics ------------------------
        try:
            topics = sns.list_topics()
            if len(topics.get("Topics", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_topics",
                        "issue": "No SNS topics found for pub/sub messaging",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_topics error: {e}")

        # ------------------------ Check EventBridge Buses ------------------------
        try:
            event_buses = events.list_event_buses()
            if len(event_buses.get("EventBuses", [])) <= 1:  # Default bus always exists
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "event_buses",
                        "issue": "No custom EventBridge buses found for event-driven architecture",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_event_buses error: {e}")

        # ------------------------ Check API Gateway ------------------------
        try:
            apis = apigateway.get_rest_apis()
            if len(apis.get("items", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "api_gateway",
                        "issue": "No API Gateway found for API-based distributed interactions",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"apigateway.get_rest_apis error: {e}")

        # ------------------------ Check DynamoDB Tables ------------------------
        try:
            tables = dynamodb.list_tables()
            if len(tables.get("TableNames", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "dynamodb_tables",
                        "issue": "No DynamoDB tables found for distributed data storage",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"dynamodb.list_tables error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without identifying distributed system components and dependencies, "
                "it's difficult to design for fault tolerance and understand failure modes "
                "that can impact system reliability."
            ),
            recommendation=(
                "Catalog all distributed system components including containers, serverless functions, "
                "messaging services, APIs, and databases to understand system architecture and dependencies."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL04-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while identifying distributed systems.",
            recommendation="Verify IAM permissions for ECS, EKS, Lambda, SQS, SNS, EventBridge, API Gateway, and DynamoDB APIs.",
        )


def check_rel04_bp02_implement_loosely_coupled_dependencies(session):
    print("Checking REL04-BP02 - Implement loosely coupled dependencies")

    sqs = session.client("sqs")
    sns = session.client("sns")
    events = session.client("events")
    stepfunctions = session.client("stepfunctions")
    lambda_client = session.client("lambda")
    kinesis = session.client("kinesis")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_prevent_interaction_failure_loosely_coupled_system.html"

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
            "id": "REL04-BP02",
            "check_name": "Implement loosely coupled dependencies",
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
                "1. Use message queues (SQS) for asynchronous communication.",
                "2. Implement pub/sub patterns with SNS for event-driven architecture.",
                "3. Use EventBridge for decoupled event routing.",
                "4. Implement Step Functions for workflow orchestration.",
                "5. Use Kinesis for real-time data streaming and processing.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 6
    affected = 0

    try:
        # ------------------------ Check SQS Queues ------------------------
        try:
            queues = sqs.list_queues()
            if len(queues.get("QueueUrls", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sqs_queues",
                        "issue": "No SQS queues found for loose coupling through message queuing",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sqs.list_queues error: {e}")

        # ------------------------ Check SNS Topics ------------------------
        try:
            topics = sns.list_topics()
            if len(topics.get("Topics", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_topics",
                        "issue": "No SNS topics found for pub/sub loose coupling patterns",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_topics error: {e}")

        # ------------------------ Check EventBridge Rules ------------------------
        try:
            rules = events.list_rules()
            if len(rules.get("Rules", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eventbridge_rules",
                        "issue": "No EventBridge rules found for event-driven loose coupling",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"events.list_rules error: {e}")

        # ------------------------ Check Step Functions ------------------------
        try:
            state_machines = stepfunctions.list_state_machines()
            if len(state_machines.get("stateMachines", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "step_functions",
                        "issue": "No Step Functions found for workflow orchestration and loose coupling",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"stepfunctions.list_state_machines error: {e}")

        # ------------------------ Check Lambda Event Source Mappings ------------------------
        try:
            mappings = lambda_client.list_event_source_mappings()
            if len(mappings.get("EventSourceMappings", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_event_mappings",
                        "issue": "No Lambda event source mappings found for event-driven loose coupling",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_event_source_mappings error: {e}")

        # ------------------------ Check Kinesis Streams ------------------------
        try:
            streams = kinesis.list_streams()
            if len(streams.get("StreamNames", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "kinesis_streams",
                        "issue": "No Kinesis streams found for real-time data processing loose coupling",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"kinesis.list_streams error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without loosely coupled dependencies, systems may experience cascading failures "
                "when one component fails, leading to reduced reliability and availability."
            ),
            recommendation=(
                "Implement loose coupling using message queues, pub/sub patterns, event-driven "
                "architecture, and workflow orchestration to improve system resilience."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL04-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating loose coupling implementation.",
            recommendation="Verify IAM permissions for SQS, SNS, EventBridge, Step Functions, Lambda, and Kinesis APIs.",
        )


def check_rel04_bp03_do_constant_work(session):
    print("Checking REL04-BP03 - Do constant work")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_prevent_interaction_failure_constant_work.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL04-BP03",
            "check_name": "Do constant work",
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
                "1. Design systems to perform consistent work regardless of load variations.",
                "2. Implement pre-scaling and resource pooling strategies.",
                "3. Use connection pooling and keep-alive mechanisms.",
                "4. Avoid on-demand resource allocation during peak loads.",
                "5. Implement steady-state operations and avoid bursty patterns.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS APIs cannot determine whether a system follows constant work patterns "
                "such as pre-scaling, resource pooling, or steady-state operations. These "
                "must be validated through architecture and system design reviews."
            ),
            recommendation=(
                "Adopt constant work principles by implementing steady-state operations, "
                "pre-scaling, connection pooling, and minimizing bursty behavior to improve "
                "performance consistency and reliability."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL04-BP03: {e}")
        return build_response(
            status="error",
            problem="Unable to assess constant work design.",
            recommendation="Review architecture documentation and workload pattern strategies.",
        )


def check_rel04_bp04_make_mutating_operations_idempotent(session):
    print("Checking REL04-BP04 - Make mutating operations idempotent")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_prevent_interaction_failure_idempotent.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL04-BP04",
            "check_name": "Make mutating operations idempotent",
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
                "1. Design all mutating operations to be idempotent.",
                "2. Use unique identifiers or tokens for operation deduplication.",
                "3. Implement proper state checking before performing mutations.",
                "4. Use database constraints and conditional operations.",
                "5. Document idempotency guarantees for all APIs and operations.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Idempotency of mutating operations cannot be validated through AWS APIs. "
                "Idempotent operation design—including deduplication, state checks, and "
                "unique identifiers—must be reviewed through architectural and API design documentation."
            ),
            recommendation=(
                "Ensure all mutating operations are idempotent by using unique request tokens, "
                "conditional updates, state validation, and deduplication mechanisms to prevent "
                "duplicate mutations during retries."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL04-BP04: {e}")
        return build_response(
            status="error",
            problem="Unable to assess idempotent operation design.",
            recommendation="Review API documentation and idempotency implementation patterns.",
        )


# REL 5. How do you design interactions in a distributed system to mitigate or withstand failures?


def check_rel05_bp01_implement_graceful_degradation(session):
    print(
        "Checking REL05-BP01 - Implement graceful degradation to transform hard dependencies into soft dependencies"
    )

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_graceful_degradation.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL05-BP01",
            "check_name": "Implement graceful degradation to transform hard dependencies into soft dependencies",
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
                "1. Identify hard dependencies that can be transformed into soft dependencies.",
                "2. Implement circuit breaker patterns for external service calls.",
                "3. Design fallback mechanisms and default responses.",
                "4. Implement caching strategies to reduce dependency on external services.",
                "5. Use timeout and retry mechanisms with exponential backoff.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Architectural resilience patterns such as graceful degradation, fallback handling, "
                "circuit breakers, and caching cannot be verified through AWS APIs. These must be "
                "validated through application design and implementation reviews."
            ),
            recommendation=(
                "Ensure workloads implement graceful degradation by using circuit breakers, fallback "
                "responses, caching, and timeout controls to maintain partial functionality when "
                "dependencies fail."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL05-BP01: {e}")
        return build_response(
            status="error",
            problem="Unable to assess graceful degradation implementation.",
            recommendation="Review resilience design patterns and dependency handling strategies.",
        )


def check_rel05_bp02_throttle_requests(session):
    print("Checking REL05-BP02 - Throttle requests")

    apigateway = session.client("apigateway")
    apigatewayv2 = session.client("apigatewayv2")
    lambda_client = session.client("lambda")
    autoscaling = session.client("application-autoscaling")
    cloudwatch = session.client("cloudwatch")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_throttle_requests.html"

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
            "id": "REL05-BP02",
            "check_name": "Throttle requests",
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
                "1. Configure API Gateway throttling limits and usage plans.",
                "2. Set Lambda concurrency limits to prevent resource exhaustion.",
                "3. Implement application-level rate limiting and circuit breakers.",
                "4. Use CloudWatch alarms to monitor throttling metrics.",
                "5. Configure auto-scaling policies with appropriate scaling thresholds.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check API Gateway REST APIs ------------------------
        try:
            rest_apis = apigateway.get_rest_apis()
            for api in rest_apis.get("items", []):
                api_id = api["id"]
                try:
                    stages = apigateway.get_stages(restApiId=api_id)
                    throttling_configured = any(
                        stage.get("throttleSettings", {}).get("rateLimit", 0) > 0
                        for stage in stages.get("item", [])
                    )
                    if not throttling_configured:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": api_id,
                                "issue": f"API Gateway {api['name']} has no throttling configured",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(f"apigateway.get_stages error for {api_id}: {e}")
        except Exception as e:
            print(f"apigateway.get_rest_apis error: {e}")

        # ------------------------ Check API Gateway v2 APIs ------------------------
        try:
            v2_apis = apigatewayv2.get_apis()
            if len(v2_apis.get("Items", [])) > 0:
                for api in v2_apis.get("Items", []):
                    # API Gateway v2 throttling is configured at route level
                    # For simplicity, we check if APIs exist without detailed throttling config
                    pass
        except Exception as e:
            print(f"apigatewayv2.get_apis error: {e}")

        # ------------------------ Check Lambda Concurrency ------------------------
        try:
            functions = lambda_client.list_functions()
            for function in functions.get("Functions", []):
                function_name = function["FunctionName"]
                try:
                    concurrency = lambda_client.get_function_concurrency(
                        FunctionName=function_name
                    )
                    if "ReservedConcurrencyLimit" not in concurrency:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": function_name,
                                "issue": f"Lambda function {function_name} has no concurrency limit configured",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(
                        f"lambda.get_function_concurrency error for {function_name}: {e}"
                    )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # ------------------------ Check Auto Scaling Policies ------------------------
        try:
            policies = autoscaling.describe_scaling_policies()
            if len(policies.get("ScalingPolicies", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "scaling_policies",
                        "issue": "No auto-scaling policies found for throttling protection",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"application-autoscaling.describe_scaling_policies error: {e}")

        # ------------------------ Check CloudWatch Alarms ------------------------
        try:
            alarms = cloudwatch.describe_alarms()
            throttle_alarms = [
                alarm
                for alarm in alarms.get("MetricAlarms", [])
                if "throttle" in alarm.get("AlarmName", "").lower()
                or "rate" in alarm.get("AlarmName", "").lower()
            ]
            if len(throttle_alarms) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "throttle_alarms",
                        "issue": "No CloudWatch alarms found for throttling monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.describe_alarms error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper request throttling, systems may become overwhelmed during "
                "traffic spikes, leading to service degradation or complete outages."
            ),
            recommendation=(
                "Implement comprehensive request throttling using API Gateway limits, "
                "Lambda concurrency controls, auto-scaling policies, and monitoring alarms."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL05-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating request throttling.",
            recommendation="Verify IAM permissions for API Gateway, Lambda, Auto Scaling, and CloudWatch APIs.",
        )


def check_rel05_bp03_control_limit_retry_calls(session):
    print("Checking REL05-BP03 - Control and limit retry calls")

    stepfunctions = session.client("stepfunctions")
    lambda_client = session.client("lambda")
    apigatewayv2 = session.client("apigatewayv2")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_limit_retries.html"

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
            "id": "REL05-BP03",
            "check_name": "Control and limit retry calls",
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
                "1. Configure Step Functions retry policies with exponential backoff.",
                "2. Set Lambda function retry configurations and dead letter queues.",
                "3. Implement circuit breaker patterns to prevent retry storms.",
                "4. Use jitter in retry mechanisms to avoid thundering herd problems.",
                "5. Monitor retry metrics and adjust policies based on failure patterns.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 3
    affected = 0

    try:
        # ------------------------ Check Step Functions State Machines ------------------------
        try:
            state_machines = stepfunctions.list_state_machines()
            for sm in state_machines.get("stateMachines", []):
                sm_arn = sm["stateMachineArn"]
                try:
                    sm_details = stepfunctions.describe_state_machine(
                        stateMachineArn=sm_arn
                    )
                    definition = sm_details.get("definition", "{}")
                    # Check if retry configuration exists in definition
                    if "Retry" not in definition:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": sm["name"],
                                "issue": f"Step Function {sm['name']} has no retry configuration",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(
                        f"stepfunctions.describe_state_machine error for {sm_arn}: {e}"
                    )
        except Exception as e:
            print(f"stepfunctions.list_state_machines error: {e}")

        # ------------------------ Check Lambda Event Invoke Config ------------------------
        try:
            functions = lambda_client.list_functions()
            for function in functions.get("Functions", []):
                function_name = function["FunctionName"]
                try:
                    invoke_config = lambda_client.get_function_event_invoke_config(
                        FunctionName=function_name
                    )
                    if "MaximumRetryAttempts" not in invoke_config:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": function_name,
                                "issue": f"Lambda function {function_name} has no retry configuration",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(
                        f"lambda.get_function_event_invoke_config error for {function_name}: {e}"
                    )
                    # If no config exists, it means default retry behavior is used
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": function_name,
                            "issue": f"Lambda function {function_name} uses default retry configuration",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # ------------------------ Check API Gateway v2 APIs ------------------------
        try:
            apis = apigatewayv2.get_apis()
            if len(apis.get("Items", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "api_gateway_v2",
                        "issue": "No API Gateway v2 APIs found for retry configuration assessment",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"apigatewayv2.get_apis error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper retry controls and limits, systems may experience retry storms, "
                "resource exhaustion, and cascading failures during error conditions."
            ),
            recommendation=(
                "Implement controlled retry mechanisms with exponential backoff, circuit breakers, "
                "and proper retry limits in Step Functions, Lambda, and API Gateway configurations."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL05-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating retry controls.",
            recommendation="Verify IAM permissions for Step Functions, Lambda, and API Gateway v2 APIs.",
        )


def check_rel05_bp04_fail_fast_limit_queues(session):
    print("Checking REL05-BP04 - Fail fast and limit queues")

    sqs = session.client("sqs")
    sns = session.client("sns")
    lambda_client = session.client("lambda")
    cloudwatch = session.client("cloudwatch")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_fail_fast.html"

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
            "id": "REL05-BP04",
            "check_name": "Fail fast and limit queues",
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
                "1. Configure SQS queue visibility timeout and message retention limits.",
                "2. Set up dead letter queues for failed message processing.",
                "3. Implement queue depth monitoring and alerting.",
                "4. Configure Lambda event source mapping batch sizes and error handling.",
                "5. Use CloudWatch metrics to monitor queue performance and failures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 4
    affected = 0

    try:
        # ------------------------ Check SQS Queues ------------------------
        try:
            queues = sqs.list_queues()
            for queue_url in queues.get("QueueUrls", []):
                try:
                    attrs = sqs.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=[
                            "VisibilityTimeoutSeconds",
                            "MessageRetentionPeriod",
                            "RedrivePolicy",
                        ],
                    )
                    attributes = attrs.get("Attributes", {})

                    # Check if dead letter queue is configured
                    if "RedrivePolicy" not in attributes:
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": queue_url.split("/")[-1],
                                "issue": f"SQS queue has no dead letter queue configured",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )

                    # Check visibility timeout (should be reasonable)
                    visibility_timeout = int(
                        attributes.get("VisibilityTimeoutSeconds", 30)
                    )
                    if visibility_timeout > 900:  # 15 minutes
                        affected += 1
                        resources_affected.append(
                            {
                                "resource_id": queue_url.split("/")[-1],
                                "issue": f"SQS queue has excessive visibility timeout ({visibility_timeout}s)",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
                except Exception as e:
                    print(f"sqs.get_queue_attributes error for {queue_url}: {e}")
        except Exception as e:
            print(f"sqs.list_queues error: {e}")

        # ------------------------ Check SNS Topics ------------------------
        try:
            topics = sns.list_topics()
            if len(topics.get("Topics", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "sns_topics",
                        "issue": "No SNS topics found for fail-fast messaging patterns",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"sns.list_topics error: {e}")

        # ------------------------ Check Lambda Event Source Mappings ------------------------
        try:
            mappings = lambda_client.list_event_source_mappings()
            for mapping in mappings.get("EventSourceMappings", []):
                batch_size = mapping.get("BatchSize", 10)
                if batch_size > 100:  # Large batch sizes can cause delays
                    affected += 1
                    resources_affected.append(
                        {
                            "resource_id": mapping["UUID"],
                            "issue": f"Lambda event source mapping has large batch size ({batch_size})",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception as e:
            print(f"lambda.list_event_source_mappings error: {e}")

        # ------------------------ Check CloudWatch Metrics ------------------------
        try:
            from datetime import datetime, timedelta

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            # Check for queue depth metrics
            metric_data = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "queue_depth",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/SQS",
                                "MetricName": "ApproximateNumberOfVisibleMessages",
                            },
                            "Period": 3600,
                            "Stat": "Maximum",
                        },
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )

            if len(metric_data.get("MetricDataResults", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "queue_metrics",
                        "issue": "No SQS queue depth metrics available for monitoring",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without proper queue limits and fail-fast mechanisms, systems may "
                "accumulate excessive backlogs, leading to increased latency and "
                "potential system instability."
            ),
            recommendation=(
                "Implement fail-fast patterns with proper queue limits, dead letter queues, "
                "appropriate timeouts, and monitoring to prevent queue buildup and ensure "
                "rapid failure detection."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL05-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating fail-fast and queue limits.",
            recommendation="Verify IAM permissions for SQS, SNS, Lambda, and CloudWatch APIs.",
        )


def check_rel05_bp05_set_client_timeouts(session):
    print("Checking REL05-BP05 - Set client timeouts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_client_timeouts.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL05-BP05",
            "check_name": "Set client timeouts",
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
                "1. Configure appropriate connection and read timeouts for all client calls.",
                "2. Implement timeout values based on service SLAs and user expectations.",
                "3. Use different timeout values for different types of operations.",
                "4. Configure timeout handling with proper error responses.",
                "5. Monitor timeout metrics and adjust values based on performance data.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "AWS APIs do not expose whether applications have properly configured client "
                "timeouts. Timeout settings—including connect, read, and request timeouts—must "
                "be validated through application configuration and code review."
            ),
            recommendation=(
                "Ensure all client calls use appropriate timeout values based on service SLAs and "
                "expected latency. Configure connect, read, and request timeouts and monitor timeout "
                "metrics to adjust values over time."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL05-BP05: {e}")
        return build_response(
            status="error",
            problem="Unable to assess client timeout configuration.",
            recommendation="Review client configuration, SDK timeout settings, and retry behavior.",
        )


def check_rel05_bp06_make_systems_stateless(session):
    print("Checking REL05-BP06 - Make systems stateless where possible")

    lambda_client = session.client("lambda")
    ecs = session.client("ecs")
    eks = session.client("eks")
    apigateway = session.client("apigateway")
    elb = session.client("elbv2")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_stateless.html"

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
            "id": "REL05-BP06",
            "check_name": "Make systems stateless where possible",
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
                "1. Design Lambda functions to be stateless with external state storage.",
                "2. Configure ECS services for stateless operation with external data stores.",
                "3. Use load balancers without session affinity for stateless distribution.",
                "4. Implement API Gateway for stateless API management.",
                "5. Store session data in external services like DynamoDB or ElastiCache.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 5
    affected = 0

    try:
        # ------------------------ Check Lambda Functions ------------------------
        try:
            functions = lambda_client.list_functions()
            if len(functions.get("Functions", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "lambda_functions",
                        "issue": "No Lambda functions found for stateless compute",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"lambda.list_functions error: {e}")

        # ------------------------ Check ECS Services ------------------------
        try:
            services = ecs.list_services()
            if len(services.get("serviceArns", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "ecs_services",
                        "issue": "No ECS services found for containerized stateless applications",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"ecs.list_services error: {e}")

        # ------------------------ Check EKS Clusters ------------------------
        try:
            clusters = eks.list_clusters()
            if len(clusters.get("clusters", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "eks_clusters",
                        "issue": "No EKS clusters found for Kubernetes stateless workloads",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"eks.list_clusters error: {e}")

        # ------------------------ Check API Gateway ------------------------
        try:
            apis = apigateway.get_rest_apis()
            if len(apis.get("items", [])) == 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "api_gateway",
                        "issue": "No API Gateway found for stateless API management",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"apigateway.get_rest_apis error: {e}")

        # ------------------------ Check Load Balancers ------------------------
        try:
            load_balancers = elb.describe_load_balancers()
            stateful_lbs = []
            for lb in load_balancers.get("LoadBalancers", []):
                # Check for session stickiness (indicates stateful behavior)
                try:
                    target_groups = elb.describe_target_groups(
                        LoadBalancerArn=lb["LoadBalancerArn"]
                    )
                    for tg in target_groups.get("TargetGroups", []):
                        attrs = elb.describe_target_group_attributes(
                            TargetGroupArn=tg["TargetGroupArn"]
                        )
                        for attr in attrs.get("Attributes", []):
                            if (
                                attr["Key"] == "stickiness.enabled"
                                and attr["Value"] == "true"
                            ):
                                stateful_lbs.append(lb["LoadBalancerName"])
                                break
                except Exception as e:
                    print(f"Error checking target group attributes: {e}")

            if len(stateful_lbs) > 0:
                affected += 1
                resources_affected.append(
                    {
                        "resource_id": "load_balancers_sticky",
                        "issue": f"Load balancers with session stickiness found: {', '.join(stateful_lbs)}",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
        except Exception as e:
            print(f"elbv2.describe_load_balancers error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without stateless system design, applications may have difficulty scaling, "
                "recovering from failures, and distributing load effectively across instances."
            ),
            recommendation=(
                "Implement stateless architecture using Lambda functions, containerized services, "
                "API Gateway, and load balancers without session affinity. Store state externally "
                "in databases or caching services."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during REL05-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating stateless system design.",
            recommendation="Verify IAM permissions for Lambda, ECS, EKS, API Gateway, and ELB APIs.",
        )


def check_rel05_bp07_implement_emergency_levers(session):
    print("Checking REL05-BP07 - Implement emergency levers")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_emergency_levers.html"

    def build_response(
        status,
        problem,
        recommendation,
        resources_affected=[],
        total_scanned=0,
        affected=0,
    ):
        return {
            "id": "REL05-BP07",
            "check_name": "Implement emergency levers",
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
                "1. Implement circuit breakers and kill switches for critical system components.",
                "2. Create emergency procedures for rapid service degradation or shutdown.",
                "3. Design feature flags to quickly disable problematic functionality.",
                "4. Establish emergency access procedures and escalation paths.",
                "5. Document and regularly test emergency response procedures.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    try:
        # Cannot be validated programmatically via AWS APIs

        return build_response(
            status="not_available",
            problem=(
                "Emergency levers such as kill switches, feature flags, and circuit breakers "
                "cannot be detected through AWS APIs. These mechanisms must be validated "
                "through architecture and operational documentation."
            ),
            recommendation=(
                "Ensure emergency response controls are implemented, including circuit breakers, "
                "kill switches, feature flags, and escalation procedures to rapidly mitigate failures."
            ),
            resources_affected=[],
        )

    except Exception as e:
        print(f"Error evaluating REL05-BP07: {e}")
        return build_response(
            status="error",
            problem="Unable to assess emergency levers implementation.",
            recommendation="Review incident response documentation and emergency mechanism designs.",
        )
