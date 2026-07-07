"""
ISO 27001 Checks — Network Security
Controls: A.8.20, A.8.21, A.8.22, A.8.23, A.6.7
All checks use ReadOnlyAccess permissions only.
"""
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_security_groups(session):
    """A.8.20: No unrestricted inbound access on sensitive ports."""
    print("  ISO27001: Checking security groups")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        total = len(sgs)
        sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379]

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        # Check if it's a sensitive port or all ports
                        if from_port == 0 and to_port == 65535:
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": sg_id,
                                "resource_id_type": "Security Group",
                                "issue": f"SG '{sg_name}' ({sg_id}) allows 0.0.0.0/0 on ALL ports",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            })
                            break
                        elif any(from_port <= p <= to_port for p in sensitive_ports):
                            exposed = [p for p in sensitive_ports if from_port <= p <= to_port]
                            resources_affected.append({
                                "account_id": account_id,
                                "resource_id": sg_id,
                                "resource_id_type": "Security Group",
                                "issue": f"SG '{sg_name}' ({sg_id}) allows 0.0.0.0/0 on ports: {exposed}",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            })
                            break

        return _result("A.8.20", "Network security - Security group review",
                      resources_affected, max(total, 1), 90, "Critical")
    except Exception as e:
        print(f"Error checking security groups: {e}")
        return None


def check_network_acls(session):
    """A.8.20: Network ACLs should not have unrestricted rules."""
    print("  ISO27001: Checking Network ACLs")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        nacls = ec2.describe_network_acls().get("NetworkAcls", [])
        total = len(nacls)

        for nacl in nacls:
            nacl_id = nacl["NetworkAclId"]
            for entry in nacl.get("Entries", []):
                if entry.get("Egress", False):
                    continue
                if entry.get("RuleAction") != "allow":
                    continue
                cidr = entry.get("CidrBlock", "")
                if cidr == "0.0.0.0/0" and entry.get("Protocol") == "-1":
                    if entry.get("RuleNumber", 0) != 32767:  # skip default deny
                        resources_affected.append({
                            "account_id": account_id,
                            "resource_id": nacl_id,
                            "resource_id_type": "Network ACL",
                            "issue": f"NACL '{nacl_id}' has allow-all inbound rule (0.0.0.0/0, all protocols)",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        })
                        break

        return _result("A.8.20", "Network security - Network ACL review",
                      resources_affected, max(total, 1), 60, "Medium")
    except Exception as e:
        print(f"Error checking NACLs: {e}")
        return None


def check_vpc_flow_logs(session):
    """A.8.20/A.8.12: VPC Flow Logs should be enabled on all VPCs."""
    print("  ISO27001: Checking VPC Flow Logs")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = len(vpcs)

        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        vpc_ids_with_logs = set(fl.get("ResourceId") for fl in flow_logs if fl.get("ResourceId", "").startswith("vpc-"))

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            if vpc_id not in vpc_ids_with_logs:
                resources_affected.append({
                    "account_id": account_id,
                    "resource_id": vpc_id,
                    "resource_id_type": "VPC",
                    "issue": f"VPC '{vpc_id}' does not have flow logs enabled",
                    "region": session.region_name,
                    "last_updated": datetime.now(IST).isoformat(),
                })

        return _result("A.8.20", "Network security - VPC Flow Logs",
                      resources_affected, max(total, 1), 70, "High")
    except Exception as e:
        print(f"Error checking VPC flow logs: {e}")
        return None


def check_vpc_endpoints(session):
    """A.8.27: VPC endpoints for private connectivity to AWS services."""
    print("  ISO27001: Checking VPC endpoints")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        vpcs = ec2.describe_vpcs().get("Vpcs", [])

        if len(vpcs) > 0 and len(endpoints) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "VPC Endpoints",
                "resource_id_type": "Service",
                "issue": "No VPC endpoints configured (traffic goes over public internet)",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.27", "Secure system architecture - VPC endpoints",
                      resources_affected, max(len(vpcs), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking VPC endpoints: {e}")
        return None


def check_vpn_configuration(session):
    """A.6.7: VPN connections should be configured for remote working."""
    print("  ISO27001: Checking VPN configuration")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        vpn_connections = ec2.describe_vpn_connections().get("VpnConnections", [])
        active_vpns = [v for v in vpn_connections if v.get("State") == "available"]

        # This is informational - if no VPN, it's a finding but low severity
        if len(active_vpns) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "VPN",
                "resource_id_type": "Service",
                "issue": "No active VPN connections configured for secure remote access",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.6.7", "Remote working - VPN configuration",
                      resources_affected, 1, 40, "Low")
    except Exception as e:
        print(f"Error checking VPN: {e}")
        return None


def check_https_load_balancers(session):
    """A.8.21: Load balancers should use HTTPS/TLS listeners."""
    print("  ISO27001: Checking HTTPS load balancers")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        total = len(lbs)

        for lb in lbs:
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb.get("LoadBalancerName", "")
            try:
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                has_https = any(l.get("Protocol") in ("HTTPS", "TLS") for l in listeners)
                has_http_only = any(l.get("Protocol") == "HTTP" for l in listeners) and not has_https

                if has_http_only:
                    resources_affected.append({
                        "account_id": account_id,
                        "resource_id": lb_name,
                        "resource_id_type": "Load Balancer",
                        "issue": f"Load balancer '{lb_name}' has HTTP-only listeners (no HTTPS)",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    })
            except Exception:
                continue

        return _result("A.8.21", "Security of network services - HTTPS load balancers",
                      resources_affected, max(total, 1), 80, "High")
    except Exception as e:
        print(f"Error checking load balancers: {e}")
        return None


def check_waf_association(session):
    """A.8.23: WAF web ACLs should be configured for web filtering."""
    print("  ISO27001: Checking WAF association")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        waf = session.client("wafv2")

        try:
            acls = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        except Exception:
            acls = []

        if len(acls) == 0:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "WAFv2",
                "resource_id_type": "Service",
                "issue": "No WAF web ACLs configured for web application protection",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.23", "Web filtering - WAF association",
                      resources_affected, max(len(acls), 1), 70, "High")
    except Exception as e:
        print(f"Error checking WAF: {e}")
        return None


def check_network_segregation(session):
    """A.8.22: Network segregation via multiple VPCs/subnets."""
    print("  ISO27001: Checking network segregation")
    ec2 = session.client("ec2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        subnets = ec2.describe_subnets().get("Subnets", [])

        # Check if there's only one VPC with minimal subnets
        non_default_vpcs = [v for v in vpcs if not v.get("IsDefault", False)]
        if len(non_default_vpcs) == 0 and len(vpcs) <= 1:
            resources_affected.append({
                "account_id": account_id,
                "resource_id": "VPC",
                "resource_id_type": "Service",
                "issue": "Only default VPC exists — no network segregation for workloads",
                "region": session.region_name,
                "last_updated": datetime.now(IST).isoformat(),
            })

        return _result("A.8.22", "Segregation of networks",
                      resources_affected, max(len(vpcs), 1), 50, "Medium")
    except Exception as e:
        print(f"Error checking network segregation: {e}")
        return None


def _result(control_id, check_name, resources_affected, total_scanned, severity_score, severity_level):
    return {
        "id": control_id,
        "check_name": check_name,
        "service": "Networking",
        "problem_statement": f"ISO 27001 {control_id}: {check_name}",
        "severity_score": severity_score if len(resources_affected) > 0 else 0,
        "severity_level": severity_level,
        "resources_affected": resources_affected,
        "status": "passed" if len(resources_affected) == 0 else "failed",
        "recommendation": f"Remediate findings for {check_name} to meet ISO 27001 requirements",
        "additional_info": {
            "total_scanned": total_scanned,
            "affected": len(resources_affected),
        },
        "last_updated": datetime.now(IST).isoformat(),
    }
