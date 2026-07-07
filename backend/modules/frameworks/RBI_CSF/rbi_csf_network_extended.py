"""
RBI CSF — Network Extended Checks
Covers: NET.1 (segmentation), NET.6 (NACLs), NET.8 (VPC endpoints),
NET.9 (public subnets), NET.10 (TLS), NET.12 (DNSSEC),
plus additional network checks from the summary.

All checks use READ-ONLY APIs.
"""

import json as _json
from botocore.exceptions import ClientError

FRAMEWORK = "RBI CSF"
INDIA_REGIONS = {"ap-south-1", "ap-south-2"}


def _result(check_name, service, control_id, problem, max_score, max_severity,
            non_compliant, recommendation, total, region="global"):
    has_issues = len(non_compliant) > 0
    return {
        "check_name": check_name, "service": service, "framework": FRAMEWORK,
        "control_id": control_id, "problem_statement": problem,
        "severity_score": max_score if has_issues else 0,
        "severity_level": max_severity if has_issues else "None",
        "resources_affected": non_compliant, "recommendation": recommendation,
        "region": region,
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def _meta(meta, service, total, non_compliant, severity_key):
    meta["total_scanned"] += total
    meta["affected"] += len(non_compliant)
    meta[severity_key] += len(non_compliant)
    if service not in meta["services_scanned"]:
        meta["services_scanned"].append(service)


def rbi_net_segmentation(session, meta):
    """RBI.NET.1 — Network segmentation for critical systems."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = 1
        if len(vpcs) < 2:
            subnets = ec2.describe_subnets().get("Subnets", [])
            if len(subnets) < 3:
                nc.append({"resource_name": "Account",
                           "note": f"Only {len(vpcs)} VPC(s) and {len(subnets)} subnet(s) — minimal segmentation"})
    except Exception as e:
        print(f"rbi_net_segmentation error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("RBI CSF — Network Segmentation", "EC2", "RBI.NET.1",
        "RBI requires network segregation for critical financial systems (CBS, SWIFT, etc.).",
        60, "Medium", nc, "Use multiple VPCs/subnets to segregate financial workloads.", total)


def rbi_net_nacl_permissive(session, meta):
    """RBI.NET.6 — NACLs not overly permissive."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        nacls = ec2.describe_network_acls().get("NetworkAcls", [])
        total = len(nacls)
        for nacl in nacls:
            for entry in nacl.get("Entries", []):
                if (entry.get("RuleAction") == "allow" and
                    entry.get("CidrBlock") == "0.0.0.0/0" and
                    entry.get("Protocol") == "-1" and
                    not entry.get("Egress") and
                    entry.get("RuleNumber", 0) != 32767):
                    nc.append({"resource_name": nacl["NetworkAclId"],
                               "note": "Allow ALL inbound from 0.0.0.0/0"})
                    break
    except Exception as e:
        print(f"rbi_net_nacl_permissive error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("RBI CSF — NACL Permissive Rules", "EC2", "RBI.NET.6",
        "NACLs allowing all inbound traffic bypass security group restrictions.",
        65, "Medium", nc, "Remove allow-all inbound NACL rules. Use explicit port/CIDR rules.", total)


def rbi_net_vpc_endpoint_kms(session, meta):
    """RBI.NET.8a — VPC endpoint for KMS."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        total = 1
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        kms_ep = any("kms" in ep.get("ServiceName", "") for ep in endpoints)
        if not kms_ep:
            nc.append({"resource_name": "VPC", "note": "No VPC endpoint for KMS"})
    except Exception as e:
        print(f"rbi_net_vpc_endpoint_kms error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("RBI CSF — VPC Endpoint for KMS", "EC2", "RBI.NET.8a",
        "VPC endpoint keeps KMS traffic off public internet.",
        55, "Medium", nc, "Create interface VPC endpoint for KMS.", total)


def rbi_net_vpc_endpoint_secretsmanager(session, meta):
    """RBI.NET.8b — VPC endpoint for Secrets Manager."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        total = 1
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        sm_ep = any("secretsmanager" in ep.get("ServiceName", "") for ep in endpoints)
        if not sm_ep:
            nc.append({"resource_name": "VPC", "note": "No VPC endpoint for Secrets Manager"})
    except Exception as e:
        print(f"rbi_net_vpc_endpoint_secretsmanager error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("RBI CSF — VPC Endpoint for Secrets Manager", "EC2", "RBI.NET.8b",
        "VPC endpoint keeps secret retrieval traffic private.",
        55, "Medium", nc, "Create interface VPC endpoint for Secrets Manager.", total)


def rbi_net_public_subnets_db(session, meta):
    """RBI.NET.9 — No public subnets hosting databases."""
    ec2 = session.client("ec2")
    rds = session.client("rds")
    nc, total = [], 0
    try:
        route_tables = ec2.describe_route_tables().get("RouteTables", [])
        public_subnets = set()
        for rt in route_tables:
            has_igw = any(r.get("GatewayId", "").startswith("igw-") for r in rt.get("Routes", []))
            if has_igw:
                for assoc in rt.get("Associations", []):
                    sid = assoc.get("SubnetId")
                    if sid:
                        public_subnets.add(sid)
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            subnet_group = db.get("DBSubnetGroup", {})
            for subnet in subnet_group.get("Subnets", []):
                if subnet.get("SubnetIdentifier") in public_subnets:
                    nc.append({"resource_name": db["DBInstanceIdentifier"],
                               "note": f"In public subnet {subnet['SubnetIdentifier']}"})
                    break
    except Exception as e:
        print(f"rbi_net_public_subnets_db error: {e}")
    _meta(meta, "RDS", total, nc, "High")
    return _result("RBI CSF — No Public Subnets for Databases", "RDS", "RBI.NET.9",
        "Financial databases must not be in subnets with internet gateway routes.",
        80, "High", nc, "Move RDS to private subnets without IGW routes.", total)


def rbi_net_tls_enforcement(session, meta):
    """RBI.NET.10 — TLS 1.2+ on all listeners."""
    elbv2 = session.client("elbv2")
    nc, total = [], 0
    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"]).get("Listeners", [])
            for l in listeners:
                if l.get("Protocol") in ("HTTPS", "TLS"):
                    total += 1
                    policy = l.get("SslPolicy", "")
                    if any(old in policy for old in ["TLS-1-0", "TLS-1-1", "ELBSecurityPolicy-2015", "ELBSecurityPolicy-2016-08"]):
                        nc.append({"resource_name": lb["LoadBalancerName"],
                                   "note": f"Policy {policy} allows TLS < 1.2"})
                elif l.get("Protocol") == "HTTP":
                    total += 1
                    actions = l.get("DefaultActions", [])
                    is_redirect = any(a.get("Type") == "redirect" and
                                     a.get("RedirectConfig", {}).get("Protocol") == "HTTPS" for a in actions)
                    if not is_redirect:
                        nc.append({"resource_name": lb["LoadBalancerName"],
                                   "note": f"HTTP on port {l.get('Port')} without HTTPS redirect"})
    except Exception as e:
        print(f"rbi_net_tls_enforcement error: {e}")
    _meta(meta, "ELB", total, nc, "High")
    return _result("RBI CSF — TLS 1.2+ Enforcement", "ELB", "RBI.NET.10",
        "All financial data in transit must use TLS 1.2 minimum.",
        80, "High", nc, "Use TLS 1.2/1.3 security policies. Redirect HTTP to HTTPS.", total)


def rbi_net_dnssec(session, meta):
    """RBI.NET.12 — Route53 DNSSEC enabled."""
    nc, total = [], 0
    try:
        r53 = session.client("route53")
        zones = r53.list_hosted_zones().get("HostedZones", [])
        total = len(zones)
        for z in zones[:10]:
            if z.get("Config", {}).get("PrivateZone"):
                continue
            try:
                zone_id = z["Id"].split("/")[-1]
                dnssec = r53.get_dnssec(HostedZoneId=zone_id)
                status = dnssec.get("Status", {}).get("ServeSignature", "")
                if status != "SIGNING":
                    nc.append({"resource_name": z.get("Name", "unknown"),
                               "note": f"DNSSEC status: {status}"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_net_dnssec error: {e}")
    _meta(meta, "Route53", total, nc, "Low")
    return _result("RBI CSF — Route53 DNSSEC", "Route53", "RBI.NET.12",
        "DNSSEC protects financial service DNS from spoofing/hijacking.",
        40, "Low", nc, "Enable DNSSEC signing on public hosted zones.", total)
