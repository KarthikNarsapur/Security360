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
