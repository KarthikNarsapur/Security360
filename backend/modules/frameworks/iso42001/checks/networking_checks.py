"""
ISO 42001 Extended Checks — Networking (AI-053 to AI-057)
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_public_subnets_ai_resources(session):
    """AI-053: Public subnets hosting AI resources"""
    print("Checking public subnets hosting AI resources")

    ec2 = session.client("ec2")
    sagemaker = session.client("sagemaker")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get public subnets (subnets with route to IGW)
        public_subnet_ids = set()
        try:
            route_tables = ec2.describe_route_tables().get("RouteTables", [])
            for rt in route_tables:
                has_igw = any(
                    r.get("GatewayId", "").startswith("igw-")
                    for r in rt.get("Routes", [])
                )
                if has_igw:
                    for assoc in rt.get("Associations", []):
                        subnet_id = assoc.get("SubnetId")
                        if subnet_id:
                            public_subnet_ids.add(subnet_id)
        except Exception:
            pass

        # Check SageMaker endpoints for public subnet placement
        total_scanned = 0
        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
            for ep in endpoints:
                total_scanned += 1
                try:
                    detail = sagemaker.describe_endpoint(EndpointName=ep["EndpointName"])
                    config_name = detail.get("EndpointConfigName", "")
                    if config_name:
                        config = sagemaker.describe_endpoint_config(EndpointConfigName=config_name)
                        vpc_config = config.get("VpcConfig", {})
                        subnets = vpc_config.get("Subnets", [])
                        for subnet in subnets:
                            if subnet in public_subnet_ids:
                                resources_affected.append({
                                    "account_id": account_id,
                                    "resource_id": ep["EndpointName"],
                                    "resource_id_type": "SageMakerEndpoint",
                                    "issue": f"Endpoint '{ep['EndpointName']}' deployed in public subnet {subnet}",
                                    "region": sagemaker.meta.region_name,
                                    "last_updated": datetime.now(IST).isoformat(),
                                })
                                break
                except Exception:
                    continue
        except Exception:
            pass

        return {
            "id": "AI-053",
            "check_name": "Public subnets hosting AI resources",
            "problem_statement": "AI resources should not be deployed in public subnets",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Deploy AI resources in private subnets with VPC endpoints for service access",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify AI resources in public subnets",
                "2. Create private subnets with NAT gateway or VPC endpoints",
                "3. Redeploy AI resources in private subnets",
                "4. Configure security groups to restrict access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking public subnets AI resources: {e}")
        return None


def check_security_groups_sagemaker(session):
    """AI-054: Security groups exposing SageMaker"""
    print("Checking security groups exposing SageMaker")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        security_groups = ec2.describe_security_groups().get("SecurityGroups", [])

        sagemaker_sgs = [
            sg for sg in security_groups
            if any("sagemaker" in (tag.get("Value", "").lower()) for tag in sg.get("Tags", []))
            or "sagemaker" in sg.get("GroupName", "").lower()
            or "ml" in sg.get("GroupName", "").lower()
        ]

        total_scanned = len(sagemaker_sgs)

        for sg in sagemaker_sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": sg["GroupId"],
                            "resource_id_type": "SecurityGroupId",
                            "issue": f"SageMaker security group '{sg['GroupId']}' allows 0.0.0.0/0 inbound",
                            "region": ec2.meta.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break

        return {
            "id": "AI-054",
            "check_name": "Security groups exposing SageMaker",
            "problem_statement": "Security groups for AI resources should not allow unrestricted inbound access",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Restrict security groups for AI resources to specific CIDR ranges",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Identify security groups used by SageMaker resources",
                "2. Remove 0.0.0.0/0 inbound rules",
                "3. Add specific CIDR ranges for authorized access",
                "4. Use VPC endpoints for AWS service access",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking security groups SageMaker: {e}")
        return None


def check_security_groups_api_gateway(session):
    """AI-055: Security groups exposing API Gateway"""
    print("Checking security groups exposing API Gateway")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        security_groups = ec2.describe_security_groups().get("SecurityGroups", [])

        api_sgs = [
            sg for sg in security_groups
            if any("api" in (tag.get("Value", "").lower()) for tag in sg.get("Tags", []))
            or "api" in sg.get("GroupName", "").lower()
        ]

        total_scanned = len(api_sgs)

        for sg in api_sgs:
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                # Check for wide port ranges
                if to_port - from_port > 100:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": sg["GroupId"],
                                "resource_id_type": "SecurityGroupId",
                                "issue": f"API security group '{sg['GroupId']}' allows wide port range ({from_port}-{to_port}) from 0.0.0.0/0",
                                "region": ec2.meta.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            })
                            break

        return {
            "id": "AI-055",
            "check_name": "Security groups exposing API Gateway",
            "problem_statement": "API-serving security groups should have minimal port exposure",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Restrict API-related security groups to specific ports (443/80) only",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review API-related security groups",
                "2. Restrict to ports 443/80 only",
                "3. Use WAF for additional protection",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking security groups API Gateway: {e}")
        return None


def check_missing_vpc_endpoints_ai(session):
    """AI-056: Missing VPC endpoints for AI services"""
    print("Checking missing VPC endpoints for AI services")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        # Get existing VPC endpoints
        try:
            vpc_endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        except Exception:
            vpc_endpoints = []

        existing_services = set(ep.get("ServiceName", "") for ep in vpc_endpoints)

        # AI services that should have VPC endpoints
        region = ec2.meta.region_name
        recommended_ai_endpoints = [
            f"com.amazonaws.{region}.sagemaker.api",
            f"com.amazonaws.{region}.sagemaker.runtime",
            f"com.amazonaws.{region}.bedrock",
            f"com.amazonaws.{region}.bedrock-runtime",
            f"com.amazonaws.{region}.s3",
        ]

        total_scanned = len(recommended_ai_endpoints)
        for svc in recommended_ai_endpoints:
            if svc not in existing_services:
                svc_short = svc.split(".")[-1] if "." in svc else svc
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": svc_short,
                    "resource_id_type": "VPCEndpoint",
                    "issue": f"Missing VPC endpoint for '{svc_short}' — AI traffic traverses public internet",
                    "region": region,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return {
            "id": "AI-056",
            "check_name": "Missing VPC endpoints for AI services",
            "problem_statement": "VPC endpoints should exist for AI services to keep traffic within AWS network",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Create VPC endpoints for SageMaker, Bedrock, and S3 services",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Create interface VPC endpoints for SageMaker API and Runtime",
                "2. Create interface VPC endpoint for Bedrock and Bedrock Runtime",
                "3. Create gateway VPC endpoint for S3",
                "4. Update route tables and security groups accordingly",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking VPC endpoints for AI: {e}")
        return None


def check_nacls_unrestricted(session):
    """AI-057: NACLs allowing unrestricted access"""
    print("Checking NACLs allowing unrestricted access")

    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            nacls = ec2.describe_network_acls().get("NetworkAcls", [])
        except Exception:
            nacls = []

        total_scanned = len(nacls)

        for nacl in nacls:
            nacl_id = nacl.get("NetworkAclId", "")
            is_default = nacl.get("IsDefault", False)
            if is_default:
                continue  # Skip default NACLs

            for entry in nacl.get("Entries", []):
                if (entry.get("RuleAction") == "allow" and
                        entry.get("CidrBlock") == "0.0.0.0/0" and
                        entry.get("Protocol") == "-1" and
                        not entry.get("Egress", False)):
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": nacl_id,
                        "resource_id_type": "NetworkAclId",
                        "issue": f"NACL '{nacl_id}' allows all inbound traffic from 0.0.0.0/0",
                        "region": ec2.meta.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
                    break

        return {
            "id": "AI-057",
            "check_name": "NACLs allowing unrestricted access",
            "problem_statement": "Network ACLs should restrict inbound traffic to AI workload subnets",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if len(resources_affected) == 0 else "failed",
            "recommendation": "Configure NACLs with specific allow rules instead of open inbound",
            "additional_info": {
                "total_scanned": max(total_scanned, 1),
                "affected": len(resources_affected),
            },
            "remediation_steps": [
                "1. Review custom NACLs for overly permissive inbound rules",
                "2. Replace allow-all rules with specific port/CIDR combinations",
                "3. Ensure ephemeral port ranges are handled for return traffic",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        print(f"Error checking NACLs unrestricted: {e}")
        return None
