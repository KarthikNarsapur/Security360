from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))

# PERF 4. How do you select and configure networking resources in your workload?

# PERF04-BP01 Understand how networking impacts performance
def check_perf04_bp01_understand_networking_impacts_performance(session):
    print("Checking PERF04-BP01 – Understand how networking impacts performance")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_understand_how_networking_impacts_performance.html"

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
            "id": "PERF04-BP01",
            "check_name": "Understand how networking impacts performance",
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
                "1. Enable VPC Flow Logs for network traffic analysis.",
                "2. Use CloudWatch metrics to monitor network performance.",
                "3. Implement AWS X-Ray for distributed tracing.",
                "4. Analyze network latency and bandwidth requirements.",
                "5. Use AWS Network Manager for global network visibility.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ec2 = session.client("ec2")
        cloudwatch = session.client("cloudwatch")
        xray = session.client("xray")
        networkmanager = session.client("networkmanager")

        # Check VPCs
        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_vpcs error: {e}")

        # Check subnets
        try:
            subnets = ec2.describe_subnets().get("Subnets", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_subnets error: {e}")

        # Check route tables
        try:
            route_tables = ec2.describe_route_tables().get("RouteTables", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_route_tables error: {e}")

        # Check CloudWatch metrics
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="NetworkIn",
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=["Average"]
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        # Check X-Ray service graph
        try:
            xray.get_service_graph(StartTime=start_time, EndTime=end_time)
            total_scanned += 1
        except Exception as e:
            print(f"xray.get_service_graph error: {e}")

        # Check Network Manager global networks
        try:
            global_networks = networkmanager.describe_global_networks(MaxResults=5).get("GlobalNetworks", [])
            total_scanned += 1
        except Exception as e:
            print(f"networkmanager.describe_global_networks error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without understanding how networking impacts performance, organizations cannot optimize "
                "network configurations, reduce latency, or improve application responsiveness."
            ),
            recommendation=(
                "Enable VPC Flow Logs, monitor CloudWatch network metrics, implement X-Ray tracing, "
                "and use Network Manager for comprehensive network visibility and performance analysis."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF04-BP01 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating network performance impact.",
            recommendation="Verify IAM permissions for EC2, CloudWatch, X-Ray, and Network Manager APIs.",
        )


# PERF04-BP02 Evaluate available networking features
def check_perf04_bp02_evaluate_networking_features(session):
    print("Checking PERF04-BP02 – Evaluate available networking features")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_evaluate_networking_features.html"

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
            "id": "PERF04-BP02",
            "check_name": "Evaluate available networking features",
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
                "1. Use Global Accelerator for global application availability.",
                "2. Configure CloudFront for content delivery and edge caching.",
                "3. Set up Route 53 for DNS management and traffic routing.",
                "4. Implement Direct Connect for dedicated network connections.",
                "5. Use VPC Lattice for service-to-service connectivity.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        globalaccelerator = session.client("globalaccelerator", region_name="us-west-2")
        cloudfront = session.client("cloudfront")
        route53 = session.client("route53")
        directconnect = session.client("directconnect")
        vpclattice = session.client("vpc-lattice")
        cloudwatchrum = session.client("rum")

        # Check Global Accelerator
        try:
            accelerators = globalaccelerator.list_accelerators().get("Accelerators", [])
            total_scanned += 1
        except Exception as e:
            print(f"globalaccelerator.list_accelerators error: {e}")

        # Check CloudFront distributions
        try:
            distributions = cloudfront.list_distributions().get("DistributionList", {}).get("Items", [])
            total_scanned += 1
        except Exception as e:
            print(f"cloudfront.list_distributions error: {e}")

        # Check Route 53 hosted zones
        try:
            hosted_zones = route53.list_hosted_zones().get("HostedZones", [])
            total_scanned += 1
        except Exception as e:
            print(f"route53.list_hosted_zones error: {e}")

        # Check Direct Connect connections
        try:
            connections = directconnect.describe_connections().get("connections", [])
            total_scanned += 1
        except Exception as e:
            print(f"directconnect.describe_connections error: {e}")

        # Check VPC Lattice services
        try:
            lattice_services = vpclattice.list_services().get("items", [])
            total_scanned += 1
        except Exception as e:
            print(f"vpc-lattice.list_services error: {e}")

        # Check CloudWatch RUM app monitors
        try:
            app_monitors = cloudwatchrum.list_app_monitors().get("AppMonitorSummaries", [])
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatchrum.list_app_monitors error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without evaluating available networking features, organizations may miss opportunities "
                "to improve performance, reduce latency, and enhance user experience."
            ),
            recommendation=(
                "Evaluate and implement Global Accelerator, CloudFront, Route 53, Direct Connect, "
                "VPC Lattice, and CloudWatch RUM based on workload requirements."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF04-BP02 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating networking features.",
            recommendation="Verify IAM permissions for Global Accelerator, CloudFront, Route 53, Direct Connect, VPC Lattice, and CloudWatch RUM APIs.",
        )


# PERF04-BP03 Choose appropriate dedicated connectivity or VPN for your workload
def check_perf04_bp03_choose_dedicated_connectivity_vpn(session):
    print("Checking PERF04-BP03 – Choose appropriate dedicated connectivity or VPN for your workload")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_choose_appropriate_dedicated_connectivity_or_vpn.html"

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
            "id": "PERF04-BP03",
            "check_name": "Choose appropriate dedicated connectivity or VPN for your workload",
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
                "1. Use AWS Direct Connect for dedicated network connections.",
                "2. Configure Direct Connect virtual interfaces for connectivity.",
                "3. Set up VPN connections for secure encrypted connectivity.",
                "4. Configure VPN gateways for VPC connectivity.",
                "5. Use customer gateways for on-premises integration.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        directconnect = session.client("directconnect")
        ec2 = session.client("ec2")

        # Check Direct Connect connections
        try:
            connections = directconnect.describe_connections().get("connections", [])
            total_scanned += 1
        except Exception as e:
            print(f"directconnect.describe_connections error: {e}")

        # Check Direct Connect virtual interfaces
        try:
            virtual_interfaces = directconnect.describe_virtual_interfaces().get("virtualInterfaces", [])
            total_scanned += 1
        except Exception as e:
            print(f"directconnect.describe_virtual_interfaces error: {e}")

        # Check VPN connections
        try:
            vpn_connections = ec2.describe_vpn_connections().get("VpnConnections", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_vpn_connections error: {e}")

        # Check VPN gateways
        try:
            vpn_gateways = ec2.describe_vpn_gateways().get("VpnGateways", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_vpn_gateways error: {e}")

        # Check customer gateways
        try:
            customer_gateways = ec2.describe_customer_gateways().get("CustomerGateways", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_customer_gateways error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without appropriate dedicated connectivity or VPN, workloads may experience higher latency, "
                "lower bandwidth, and less reliable network connections to on-premises resources."
            ),
            recommendation=(
                "Evaluate and implement AWS Direct Connect for dedicated connectivity or VPN connections "
                "for secure encrypted connectivity based on workload requirements."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF04-BP03 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating dedicated connectivity and VPN.",
            recommendation="Verify IAM permissions for Direct Connect and EC2 VPN APIs.",
        )


# PERF04-BP04 Use load balancing to distribute traffic across multiple resources
def check_perf04_bp04_use_load_balancing(session):
    print("Checking PERF04-BP04 – Use load balancing to distribute traffic across multiple resources")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_load_balancing_distribute_traffic.html"

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
            "id": "PERF04-BP04",
            "check_name": "Use load balancing to distribute traffic across multiple resources",
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
                "1. Configure Application Load Balancers for HTTP/HTTPS traffic.",
                "2. Set up Network Load Balancers for TCP/UDP traffic.",
                "3. Configure listeners for load balancer routing.",
                "4. Create target groups for backend resources.",
                "5. Integrate Auto Scaling groups with load balancers.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        elbv2 = session.client("elbv2")
        autoscaling = session.client("autoscaling")
        cloudwatch = session.client("cloudwatch")

        # Check load balancers
        try:
            load_balancers = elbv2.describe_load_balancers().get("LoadBalancers", [])
            total_scanned += 1
            if len(load_balancers) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "load_balancers",
                    "issue": "No load balancers configured for traffic distribution",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"elbv2.describe_load_balancers error: {e}")

        # Check listeners
        try:
            for lb in load_balancers[:5]:
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
                total_scanned += 1
        except Exception as e:
            print(f"elbv2.describe_listeners error: {e}")

        # Check target groups
        try:
            target_groups = elbv2.describe_target_groups().get("TargetGroups", [])
            total_scanned += 1
        except Exception as e:
            print(f"elbv2.describe_target_groups error: {e}")

        # Check Auto Scaling groups
        try:
            asg_groups = autoscaling.describe_auto_scaling_groups().get("AutoScalingGroups", [])
            total_scanned += 1
        except Exception as e:
            print(f"autoscaling.describe_auto_scaling_groups error: {e}")

        # Check CloudWatch metrics
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_statistics(
                Namespace="AWS/ApplicationELB",
                MetricName="RequestCount",
                StartTime=start_time,
                EndTime=end_time,
                Period=300,
                Statistics=["Sum"]
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_statistics error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without load balancing, workloads cannot distribute traffic across multiple resources, "
                "leading to single points of failure and suboptimal resource utilization."
            ),
            recommendation=(
                "Configure Application or Network Load Balancers with listeners and target groups, "
                "and integrate with Auto Scaling groups for automatic traffic distribution."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF04-BP04 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating load balancing.",
            recommendation="Verify IAM permissions for ELBv2, Auto Scaling, and CloudWatch APIs.",
        )


# PERF04-BP05 Choose network protocols to improve performance
def check_perf04_bp05_choose_network_protocols(session):
    print("Checking PERF04-BP05 – Choose network protocols to improve performance")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_choose_network_protocols_improve_performance.html"

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
            "id": "PERF04-BP05",
            "check_name": "Choose network protocols to improve performance",
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
                "1. Use HTTP/2 and HTTP/3 for improved web performance.",
                "2. Implement gRPC for efficient microservices communication.",
                "3. Use QUIC protocol for reduced latency and improved reliability.",
                "4. Configure TCP optimization settings for long-lived connections.",
                "5. Evaluate UDP for real-time and streaming workloads.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 1
    affected = 1

    resources_affected.append({
        "resource_id": "organization_governance",
        "issue": "No automated validation for network protocol selection",
        "region": session.region_name,
        "last_updated": datetime.now(IST).isoformat(),
    })

    return build_response(
        status="failed",
        problem=(
            "Organizations must choose appropriate network protocols to improve performance based on "
            "workload requirements. This is an organizational responsibility."
        ),
        recommendation=(
            "Evaluate and implement modern network protocols like HTTP/2, HTTP/3, gRPC, and QUIC "
            "to improve performance, reduce latency, and optimize resource utilization."
        ),
        resources_affected=resources_affected,
        total_scanned=total_scanned,
        affected=affected,
    )


# PERF04-BP06 Choose your workload's location based on network requirements
def check_perf04_bp06_choose_workload_location(session):
    print("Checking PERF04-BP06 – Choose your workload's location based on network requirements")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_choose_workload_location_network_requirements.html"

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
            "id": "PERF04-BP06",
            "check_name": "Choose your workload's location based on network requirements",
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
                "1. Deploy workloads in multiple Availability Zones for high availability.",
                "2. Use AWS Outposts for on-premises workload requirements.",
                "3. Leverage Local Zones for low-latency applications.",
                "4. Use Wavelength Zones for 5G edge computing.",
                "5. Implement Global Accelerator for global workload distribution.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ec2 = session.client("ec2")
        outposts = session.client("outposts")
        globalaccelerator = session.client("globalaccelerator", region_name="us-west-2")

        # Check Availability Zones
        try:
            availability_zones = ec2.describe_availability_zones().get("AvailabilityZones", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_availability_zones error: {e}")

        # Check Outposts
        try:
            outposts_list = outposts.list_outposts().get("Outposts", [])
            total_scanned += 1
        except Exception as e:
            print(f"outposts.list_outposts error: {e}")

        # Check Local Zones (using describe_availability_zones with zone type filter)
        try:
            local_zones = ec2.describe_availability_zones(
                Filters=[{"Name": "zone-type", "Values": ["local-zone"]}]
            ).get("AvailabilityZones", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_availability_zones (local zones) error: {e}")

        # Check Wavelength Zones (using describe_availability_zones with zone type filter)
        try:
            wavelength_zones = ec2.describe_availability_zones(
                Filters=[{"Name": "zone-type", "Values": ["wavelength-zone"]}]
            ).get("AvailabilityZones", [])
            total_scanned += 1
        except Exception as e:
            print(f"ec2.describe_availability_zones (wavelength zones) error: {e}")

        # Check Global Accelerator
        try:
            accelerators = globalaccelerator.list_accelerators().get("Accelerators", [])
            total_scanned += 1
        except Exception as e:
            print(f"globalaccelerator.list_accelerators error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without choosing appropriate workload locations based on network requirements, "
                "organizations may experience higher latency, reduced availability, and suboptimal performance."
            ),
            recommendation=(
                "Deploy workloads across multiple Availability Zones, use Outposts for on-premises needs, "
                "leverage Local Zones and Wavelength Zones for edge computing, and implement Global Accelerator."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF04-BP06 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating workload location.",
            recommendation="Verify IAM permissions for EC2, Outposts, and Global Accelerator APIs.",
        )


# PERF04-BP07 Optimize network configuration based on metrics
def check_perf04_bp07_optimize_network_configuration(session):
    print("Checking PERF04-BP07 – Optimize network configuration based on metrics")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/perf_networking_optimize_network_configuration_based_on_metrics.html"

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
            "id": "PERF04-BP07",
            "check_name": "Optimize network configuration based on metrics",
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
                "1. Enable VPC Flow Logs for network traffic analysis.",
                "2. Use CloudWatch Logs to filter and analyze log events.",
                "3. Monitor network telemetry with Network Manager.",
                "4. Collect CloudWatch metric data for network performance.",
                "5. Review Inspector findings for network security issues.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    total_scanned = 0
    affected = 0

    try:
        ec2 = session.client("ec2")
        logs = session.client("logs")
        networkmanager = session.client("networkmanager")
        cloudwatch = session.client("cloudwatch")
        inspector2 = session.client("inspector2")

        # Check VPC Flow Logs
        try:
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
            total_scanned += 1
            if len(flow_logs) == 0:
                affected += 1
                resources_affected.append({
                    "resource_id": "vpc_flow_logs",
                    "issue": "No VPC Flow Logs configured for network monitoring",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })
        except Exception as e:
            print(f"ec2.describe_flow_logs error: {e}")

        # Check CloudWatch log events
        try:
            log_groups = logs.describe_log_groups(limit=1).get("logGroups", [])
            if len(log_groups) > 0:
                logs.filter_log_events(logGroupName=log_groups[0]["logGroupName"], limit=1)
            total_scanned += 1
        except Exception as e:
            print(f"logs.filter_log_events error: {e}")

        # Check Network Manager telemetry
        try:
            global_networks = networkmanager.describe_global_networks(MaxResults=1).get("GlobalNetworks", [])
            if len(global_networks) > 0:
                networkmanager.get_network_telemetry(GlobalNetworkId=global_networks[0]["GlobalNetworkId"])
            total_scanned += 1
        except Exception as e:
            print(f"networkmanager.get_network_telemetry error: {e}")

        # Check CloudWatch metric data
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            cloudwatch.get_metric_data(
                MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "NetworkIn"}, "Period": 300, "Stat": "Average"}}],
                StartTime=start_time,
                EndTime=end_time
            )
            total_scanned += 1
        except Exception as e:
            print(f"cloudwatch.get_metric_data error: {e}")

        # Check Inspector findings
        try:
            findings = inspector2.list_findings(maxResults=1).get("findings", [])
            total_scanned += 1
        except Exception as e:
            print(f"inspector2.list_findings error: {e}")

        return build_response(
            status="passed" if affected == 0 else "failed",
            problem=(
                "Without optimizing network configuration based on metrics, organizations cannot identify "
                "performance bottlenecks, security issues, or opportunities for improvement."
            ),
            recommendation=(
                "Enable VPC Flow Logs, use CloudWatch Logs and metrics, monitor Network Manager telemetry, "
                "and review Inspector findings to optimize network configuration."
            ),
            resources_affected=resources_affected,
            total_scanned=total_scanned,
            affected=affected,
        )

    except Exception as e:
        print(f"Error during PERF04-BP07 evaluation: {e}")
        return build_response(
            status="error",
            problem="Unexpected error occurred while evaluating network optimization.",
            recommendation="Verify IAM permissions for EC2, CloudWatch Logs, Network Manager, CloudWatch, and Inspector APIs.",
        )
