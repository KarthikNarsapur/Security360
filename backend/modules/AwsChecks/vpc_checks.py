def check_default_vpcs(session, scan_meta_data):
    print("Checking default VPCs...")
    ec2 = session.client("ec2")
    elbv2 = session.client("elbv2")
    rds = session.client("rds")

    vpcs = ec2.describe_vpcs()["Vpcs"]
    total_scanned = 0
    affected = 0
    default_vpcs = []

    for vpc in vpcs:
        if not vpc.get("IsDefault"):
            continue

        total_scanned += 1
        vpc_id = vpc.get("VpcId")

        # Check for attached resources
        # subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        instances = ec2.describe_instances(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Reservations"]
        # gateways = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
        # network_interfaces = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]
        # nat_gateways = ec2.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NatGateways"]
        load_balancers = elbv2.describe_load_balancers()["LoadBalancers"]
        lb_in_vpc = [lb for lb in load_balancers if lb["VpcId"] == vpc_id]

        rds_instances = rds.describe_db_instances()["DBInstances"]
        rds_in_vpc = [
            db
            for db in rds_instances
            if db.get("DBSubnetGroup", {}).get("VpcId") == vpc_id
        ]

        # Determine if anything is actively using this default VPC
        is_attached = any(
            [
                # subnets,
                instances,
                # gateways,
                # network_interfaces,
                # nat_gateways,
                lb_in_vpc,
                rds_in_vpc,
            ]
        )

        if is_attached:
            affected += 1
            default_vpcs.append(
                {
                    "resource_name": vpc_id,
                    "cidr_block": vpc.get("CidrBlock"),
                    "state": vpc.get("State"),
                    "attached_resources": {
                        # "subnets": len(subnets),
                        "instances": sum(len(r["Instances"]) for r in instances),
                        # "internet_gateways": len(gateways),
                        # "network_interfaces": len(network_interfaces),
                        # "nat_gateways": len(nat_gateways),
                        "load_balancers": len(lb_in_vpc),
                        "rds_instances": len(rds_in_vpc),
                    },
                }
            )

    scan_meta_data["total_scanned"] += total_scanned
    scan_meta_data["affected"] += affected
    scan_meta_data["Low"] = scan_meta_data["Low"] + affected
    scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "Default VPCs",
        "service": "VPC",
        "problem_statement": "Default VPCs may have less restrictive settings and can expose resources if in use.",
        "severity_score": 30,
        "severity_level": "Low",
        "resources_affected": default_vpcs,
        "recommendation": "Restrict or delete default VPCs if they are actively used and not properly secured.",
        "additional_info": {"total_scanned": total_scanned, "affected": affected},
    }


# def check_default_vpcs(session, scan_meta_data):
#     print("default vpc")
#     ec2 = session.client("ec2")
#     vpcs = ec2.describe_vpcs()["Vpcs"]
#     default_vpcs = []

#     for vpc in vpcs:
#         if vpc.get("IsDefault"):
#             default_vpcs.append(
#                 {
#                     "resource_name": vpc.get("VpcId"),
#                     "cidr_block": vpc.get("CidrBlock"),
#                     "state": vpc.get("State"),
#                     # "region": session.region_name,
#                     # "arn": f"arn:aws:ec2:{session.region_name}::vpc/{vpc.get('VpcId')}",
#                 }
#             )

#     severity = "low" if default_vpcs else "informational"
#     risk_score = 30 if default_vpcs else 0

#     scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(vpcs)
#     scan_meta_data["affected"] = scan_meta_data["affected"] + len(default_vpcs)
#     scan_meta_data["services_scanned"].append("VPC")

#     return {
#         "check_name": "Default VPCs",
#         "problem_statement": "Default VPCs may have less restrictive settings and can expose resources.",
#         "severity_score": risk_score,
#         "severity_level": severity.capitalize(),
#         "resources_affected": default_vpcs,
#         "recommendation": "Review and restrict default VPC usage or delete if unnecessary.",
#         "additional_info": {"total_scanned": len(vpcs), "affected": len(default_vpcs)},
#     }


def check_subnet_separation(session, scan_meta_data):
    print("check_subnet_separation")
    ec2 = session.client("ec2")

    vpcs = ec2.describe_vpcs()["Vpcs"]
    subnets = ec2.describe_subnets()["Subnets"]
    route_tables = ec2.describe_route_tables()["RouteTables"]
    resources_affected = []

    # Build a map of subnet -> is_public (has route to IGW)
    subnet_public_map = {}
    for rt in route_tables:
        has_igw_route = any(
            r.get("GatewayId", "").startswith("igw-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )
        for assoc in rt.get("Associations", []):
            subnet_id = assoc.get("SubnetId")
            if subnet_id:
                subnet_public_map[subnet_id] = has_igw_route

    # Also check subnets that auto-assign public IPs (implicit public)
    for subnet in subnets:
        sid = subnet["SubnetId"]
        if sid not in subnet_public_map:
            # Subnet uses main route table — check if main RT has IGW
            vpc_id = subnet["VpcId"]
            for rt in route_tables:
                for assoc in rt.get("Associations", []):
                    if assoc.get("Main") and rt.get("VpcId") == vpc_id:
                        has_igw = any(
                            r.get("GatewayId", "").startswith("igw-")
                            for r in rt.get("Routes", [])
                            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
                        )
                        subnet_public_map[sid] = has_igw

    # Group subnets by VPC
    vpc_subnets = {}
    for subnet in subnets:
        vpc_id = subnet["VpcId"]
        vpc_subnets.setdefault(vpc_id, {"public": [], "private": []})
        is_public = subnet_public_map.get(subnet["SubnetId"], False)
        if is_public:
            vpc_subnets[vpc_id]["public"].append(subnet["SubnetId"])
        else:
            vpc_subnets[vpc_id]["private"].append(subnet["SubnetId"])

    # Flag VPCs that have NO private subnets (all public) or NO public subnets
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc.get("IsDefault"):
            continue
        info = vpc_subnets.get(vpc_id, {"public": [], "private": []})
        public_count = len(info["public"])
        private_count = len(info["private"])
        total = public_count + private_count

        if total == 0:
            continue

        if private_count == 0 and public_count > 0:
            resources_affected.append({
                "resource_name": vpc_id,
                "cidr_block": vpc.get("CidrBlock"),
                "public_subnets": public_count,
                "private_subnets": 0,
                "issue": "VPC has only public subnets — no private subnet separation.",
            })

    scan_meta_data["total_scanned"] += len([v for v in vpcs if not v.get("IsDefault")])
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Medium"] += len(resources_affected)
    scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "Public/Private Subnet Separation",
        "service": "VPC",
        "problem_statement": "Some VPCs lack private subnets, meaning all workloads are in public subnets with direct internet exposure.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Create private subnets for backend workloads (databases, application servers) and use public subnets only for load balancers and NAT gateways.",
        "additional_info": {"total_scanned": len([v for v in vpcs if not v.get("IsDefault")]), "affected": len(resources_affected)},
    }


def check_nat_gateway_for_private_subnets(session, scan_meta_data):
    print("check_nat_gateway_for_private_subnets")
    ec2 = session.client("ec2")

    subnets = ec2.describe_subnets()["Subnets"]
    route_tables = ec2.describe_route_tables()["RouteTables"]
    nat_gateways = ec2.describe_nat_gateways(
        Filters=[{"Name": "state", "Values": ["available"]}]
    ).get("NatGateways", [])
    resources_affected = []

    # Build set of subnets that have NAT gateway routes
    subnets_with_nat = set()
    for rt in route_tables:
        has_nat_route = any(
            r.get("NatGatewayId", "").startswith("nat-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )
        if has_nat_route:
            for assoc in rt.get("Associations", []):
                if assoc.get("SubnetId"):
                    subnets_with_nat.add(assoc["SubnetId"])

    # Identify private subnets (no IGW route)
    public_subnets = set()
    for rt in route_tables:
        has_igw = any(
            r.get("GatewayId", "").startswith("igw-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )
        if has_igw:
            for assoc in rt.get("Associations", []):
                if assoc.get("SubnetId"):
                    public_subnets.add(assoc["SubnetId"])

    private_subnets = [s for s in subnets if s["SubnetId"] not in public_subnets]

    for subnet in private_subnets:
        sid = subnet["SubnetId"]
        if sid not in subnets_with_nat:
            resources_affected.append({
                "resource_name": sid,
                "vpc_id": subnet.get("VpcId"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "cidr_block": subnet.get("CidrBlock"),
                "issue": "Private subnet has no NAT Gateway route for outbound internet access.",
            })

    scan_meta_data["total_scanned"] += len(private_subnets)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Medium"] += len(resources_affected)
    if "VPC" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "NAT Gateway for Private Subnets",
        "service": "VPC",
        "problem_statement": "Private subnets without a NAT Gateway cannot reach the internet for updates, patches, or API calls.",
        "severity_score": 55,
        "severity_level": "Medium",
        "resources_affected": resources_affected,
        "recommendation": "Add a NAT Gateway in a public subnet and update private subnet route tables to route 0.0.0.0/0 through it.",
        "additional_info": {"total_scanned": len(private_subnets), "affected": len(resources_affected)},
    }


def check_private_subnet_direct_internet_access(session, scan_meta_data):
    print("check_private_subnet_direct_internet_access")
    ec2 = session.client("ec2")

    subnets = ec2.describe_subnets()["Subnets"]
    route_tables = ec2.describe_route_tables()["RouteTables"]
    resources_affected = []

    # Find subnets that have BOTH an IGW route AND instances with private workloads
    # A simpler heuristic: flag subnets that auto-assign public IPs AND have an IGW route
    igw_subnets = set()
    for rt in route_tables:
        has_igw = any(
            r.get("GatewayId", "").startswith("igw-")
            for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        )
        if has_igw:
            for assoc in rt.get("Associations", []):
                if assoc.get("SubnetId"):
                    igw_subnets.add(assoc["SubnetId"])

    # Check instances in subnets with IGW that have no public IP (should be in private subnet)
    instances = ec2.describe_instances()
    for reservation in instances.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            subnet_id = inst.get("SubnetId")
            if subnet_id in igw_subnets and not inst.get("PublicIpAddress"):
                # Instance in a public subnet but without a public IP — likely a private workload misplaced
                instance_name = next(
                    (tag["Value"] for tag in inst.get("Tags", []) if tag["Key"] == "Name"),
                    "",
                )
                resources_affected.append({
                    "resource_name": inst["InstanceId"],
                    "instance_name": instance_name,
                    "subnet_id": subnet_id,
                    "vpc_id": inst.get("VpcId"),
                    "issue": "Instance without public IP is in a public subnet (has IGW route). Should be in a private subnet.",
                })

    total_instances = sum(
        len(r["Instances"]) for r in instances.get("Reservations", [])
    )
    scan_meta_data["total_scanned"] += total_instances
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Low"] += len(resources_affected)
    if "VPC" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "Private Resources in Public Subnets",
        "service": "VPC",
        "problem_statement": "Instances without public IPs are placed in public subnets with direct internet gateway routes, increasing exposure risk.",
        "severity_score": 40,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Move private workloads (instances without public IPs) to private subnets without IGW routes.",
        "additional_info": {"total_scanned": total_instances, "affected": len(resources_affected)},
    }


def check_vpc_endpoints(session, scan_meta_data):
    print("check_vpc_endpoints")
    ec2 = session.client("ec2")

    vpcs = ec2.describe_vpcs()["Vpcs"]
    endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
    resources_affected = []

    required_services = [
        f"com.amazonaws.{session.region_name}.s3",
        f"com.amazonaws.{session.region_name}.dynamodb",
    ]

    # Build map of VPC -> existing endpoint services
    vpc_endpoints_map = {}
    for ep in endpoints:
        if ep.get("State") == "available":
            vpc_id = ep.get("VpcId")
            service_name = ep.get("ServiceName", "")
            vpc_endpoints_map.setdefault(vpc_id, set()).add(service_name)

    for vpc in vpcs:
        if vpc.get("IsDefault"):
            continue

        vpc_id = vpc["VpcId"]
        existing = vpc_endpoints_map.get(vpc_id, set())
        missing = [svc for svc in required_services if svc not in existing]

        if missing:
            resources_affected.append({
                "resource_name": vpc_id,
                "cidr_block": vpc.get("CidrBlock"),
                "missing_endpoints": [s.split(".")[-1] for s in missing],
                "existing_endpoints": [s.split(".")[-1] for s in existing] if existing else [],
                "issue": f"VPC is missing Gateway VPC endpoints for: {', '.join(s.split('.')[-1] for s in missing)}.",
            })

    non_default_vpcs = [v for v in vpcs if not v.get("IsDefault")]
    scan_meta_data["total_scanned"] += len(non_default_vpcs)
    scan_meta_data["affected"] += len(resources_affected)
    scan_meta_data["Low"] += len(resources_affected)
    if "VPC" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("VPC")

    return {
        "check_name": "VPC Endpoints for S3 and DynamoDB",
        "service": "VPC",
        "problem_statement": "VPCs are missing Gateway VPC endpoints for S3 and/or DynamoDB, causing traffic to route through the internet instead of staying within the AWS network.",
        "severity_score": 35,
        "severity_level": "Low",
        "resources_affected": resources_affected,
        "recommendation": "Create Gateway VPC endpoints for S3 and DynamoDB to keep traffic private and reduce data transfer costs.",
        "additional_info": {"total_scanned": len(non_default_vpcs), "affected": len(resources_affected)},
    }
