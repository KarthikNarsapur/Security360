import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_elb_connection_draining(session):
    # [ELB.7]
    print("Checking Classic Load Balancer connection draining")

    elb = session.client("elb")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        lbs = elb.describe_load_balancers().get("LoadBalancerDescriptions", [])

        for lb in lbs:
            lb_name = lb["LoadBalancerName"]
            attrs = elb.describe_load_balancer_attributes(LoadBalancerName=lb_name)[
                "LoadBalancerAttributes"
            ]
            draining_enabled = attrs.get("ConnectionDraining", {}).get("Enabled", False)
            if not draining_enabled:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": lb_name,
                        "resource_id_type": "LoadBalancerName",
                        "issue": "Connection draining not enabled on Classic Load Balancer",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(lbs)
        affected = len(resources_affected)
        return {
            "id": "ELB.7",
            "check_name": "ELB connection draining enabled",
            "problem_statement": "Connection draining should be enabled on Classic Load Balancers to ensure graceful deregistration of instances.",
            "severity_score": 50,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable connection draining in ELB attributes.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Go to EC2 console → Load Balancers (Classic).",
                "2. Select the load balancer.",
                "3. Choose 'Attributes'.",
                "4. Enable 'Connection draining'.",
                "5. Set a suitable timeout value.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking ELB connection draining: {e}")
        return None


def check_elb_cross_zone_load_balancing(session):
    # [ELB.9]
    print("Checking Classic Load Balancer cross-zone load balancing")

    elb = session.client("elb")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        lbs = elb.describe_load_balancers().get("LoadBalancerDescriptions", [])

        for lb in lbs:
            lb_name = lb["LoadBalancerName"]
            attrs = elb.describe_load_balancer_attributes(LoadBalancerName=lb_name)[
                "LoadBalancerAttributes"
            ]
            cross_zone = attrs.get("CrossZoneLoadBalancing", {}).get("Enabled", False)
            if not cross_zone:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": lb_name,
                        "resource_id_type": "LoadBalancerName",
                        "issue": "Cross-zone load balancing not enabled on Classic Load Balancer",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(lbs)
        affected = len(resources_affected)
        return {
            "id": "ELB.9",
            "check_name": "ELB cross-zone load balancing enabled",
            "problem_statement": "Cross-zone load balancing should be enabled to evenly distribute traffic across Availability Zones.",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable cross-zone load balancing in ELB attributes.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open EC2 console → Load Balancers (Classic).",
                "2. Select a load balancer.",
                "3. Choose 'Attributes'.",
                "4. Enable 'Cross-zone load balancing'.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking ELB cross-zone load balancing: {e}")
        return None


def check_elb_waf_association(session):
    # [ELB.16]
    print("Checking ALB/WAF association")

    elbv2 = session.client("elbv2")
    wafv2 = session.client("wafv2")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])

        for lb in lbs:
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb["LoadBalancerName"]

            try:
                # WAFV2 regional web ACLs
                response = wafv2.get_web_acl_for_resource(ResourceArn=lb_arn)
                if not response.get("WebACL"):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": lb_name,
                            "resource_id_type": "LoadBalancerName",
                            "issue": "No WAF associated with Application Load Balancer",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except wafv2.exceptions.WAFNonexistentItemException:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": lb_name,
                        "resource_id_type": "LoadBalancerName",
                        "issue": "No WAF associated with Application Load Balancer",
                        "region": session.region_name,
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )
            except Exception as inner:
                print(f"Error checking WAF for {lb_name}: {inner}")

        total_scanned = len(lbs)
        affected = len(resources_affected)
        return {
            "id": "ELB.16",
            "check_name": "ELB associated with WAF",
            "problem_statement": "Application Load Balancers should have AWS WAF associated to protect against web attacks.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Associate a WAF web ACL with the load balancer.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open WAF & Shield console.",
                "2. Choose a Web ACL or create a new one.",
                "3. Associate the Web ACL with the ALB.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking ELB WAF association: {e}")
        return None
