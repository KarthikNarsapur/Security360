from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_sec05_bp01_create_network_layers(session):
    # SEC05-BP01 - Create network layers
    print("Checking CloudFront distributions for network layer implementation")

    cf = session.client("cloudfront")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_network_protection_create_layers.html"
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]

        dist_list = cf.list_distributions().get("DistributionList", {})
        items = dist_list.get("Items", [])
        total_scanned = 1
        affected = 0  # This check is informational, not a misconfiguration check

        return {
            "id": "SEC05-BP01",
            "check_name": "Create network layers",
            "problem_statement": "Use layered network architectures such as edge distributions and VPC segmentation.",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed",
            "recommendation": (
                "Use CloudFront, VPC subnets, and segmentation strategies to build layered network protections."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Create multiple network layers such as edge networks, perimeter, and application layers.",
                "2. Use CloudFront to isolate direct internet exposure.",
                "3. Apply security controls such as WAF or Shield at the perimeter layer.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC05-BP01: {e}")
        return None


def check_sec05_bp02_control_traffic_flow(session):
    print("Checking security groups, ELBs, and RDS for network traffic flow controls")

    ec2 = session.client("ec2")
    elb = session.client("elbv2")
    rds = session.client("rds")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_network_protection_layered.html"
    resources_affected = []
    total_scanned = 0

    try:
        account_id = sts.get_caller_identity()["Account"]

        # -----------------------------
        # 1. SG checks: sensitive ports / all TCP open / all UDP open
        # -----------------------------
        sg_data = ec2.describe_security_groups().get("SecurityGroups", [])
        total_scanned += len(sg_data)

        for sg in sg_data:
            sg_id = sg.get("GroupId")
            perms = sg.get("IpPermissions", [])

            for p in perms:
                from_p = p.get("FromPort")
                to_p = p.get("ToPort")
                ip_ranges = p.get("IpRanges", [])

                # 0.0.0.0/0 detection
                open_to_all = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)

                # ec2.SGSensitivePortOpenToAll
                sensitive_ports = [22, 3389]
                if from_p in sensitive_ports and open_to_all:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": sg_id,
                            "issue": f"Sensitive port {from_p} open to the world",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

                # ec2.SGAllTCPOpen
                if (
                    from_p == 0
                    and to_p == 65535
                    and p.get("IpProtocol") == "tcp"
                    and open_to_all
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": sg_id,
                            "issue": "All TCP ports open to the world",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

                # ec2.SGAllUDPOpen
                if (
                    from_p == 0
                    and to_p == 65535
                    and p.get("IpProtocol") == "udp"
                    and open_to_all
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": sg_id,
                            "issue": "All UDP ports open to the world",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # -----------------------------
        # 2. ELB insecure listeners
        # -----------------------------
        try:
            elbs = elb.describe_load_balancers().get("LoadBalancers", [])
            total_scanned += len(elbs)

            for lb in elbs:
                lb_arn = lb["LoadBalancerArn"]
                listeners = elb.describe_listeners(LoadBalancerArn=lb_arn).get(
                    "Listeners", []
                )

                for L in listeners:
                    if L["Protocol"] in ["HTTP"]:
                        resources_affected.append(
                            {
                                "account_id": account_id,
                                "resource_id": lb_arn,
                                "issue": "Insecure ELB listener (HTTP detected instead of HTTPS)",
                                "region": session.region_name,
                                "last_updated": datetime.now(IST).isoformat(),
                            }
                        )
        except Exception:
            pass

        # -----------------------------
        # 3. RDS publicly accessible
        # -----------------------------
        try:
            dbs = rds.describe_db_instances().get("DBInstances", [])
            total_scanned += len(dbs)

            for db in dbs:
                if db.get("PubliclyAccessible"):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": db["DBInstanceIdentifier"],
                            "issue": "RDS instance publicly accessible",
                            "region": session.region_name,
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
        except Exception:
            pass

        affected = len(resources_affected)

        return {
            "id": "SEC05-BP02",
            "check_name": "Control traffic flow within your network layers",
            "problem_statement": "Restrict network paths using layered traffic controls.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Restrict inbound traffic using security groups, NACLs, and private connectivity. "
                "Eliminate public exposure unless explicitly required."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Remove 0.0.0.0/0 access from security groups.",
                "2. Use HTTPS listeners on Load Balancers.",
                "3. Avoid publicly accessible RDS databases.",
                "4. Segment workloads using VPC subnets and routing.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC05-BP02: {e}")
        return None


def check_sec05_bp03_inspection_based_protection(session):
    # No measurable AWS API checks for this BP
    print("SEC05-BP03 is organizational and architecture-oriented")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_network_protection_inspection.html"

    return {
        "id": "SEC05-BP03",
        "check_name": "Implement inspection-based protection",
        "problem_statement": "Inspection mechanisms such as WAF and IDS/IPS should be applied where appropriate.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Use AWS WAF, Shield, Network Firewall, and traffic inspection layers to enhance network protection."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Deploy inspection services such as AWS WAF and AWS Network Firewall.",
            "2. Analyze traffic patterns and tune inspection rules.",
            "3. Integrate inspection alerts into SIEM/SOAR pipelines.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec05_bp04_automate_network_protection(session):
    print("SEC05-BP04 is process-driven and cannot be measured using API calls")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_network_auto_protect.html"

    return {
        "id": "SEC05-BP04",
        "check_name": "Automate network protection",
        "problem_statement": "Automate network security controls to reduce manual effort and misconfigurations.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Use automation tools such as AWS Firewall Manager, IaC, and EventBridge for network protection automation."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Use IaC templates to manage network configurations.",
            "2. Implement automated guardrails using Firewall Manager policies.",
            "3. Trigger auto-remediation for network policy violations using EventBridge.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec06_bp01_perform_vulnerability_management(session):
    print("Checking GuardDuty status for SEC06-BP01")

    gd = session.client("guardduty")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_vulnerability_management.html"
    resources_affected = []
    total_scanned = 1

    try:
        account_id = sts.get_caller_identity()["Account"]

        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": account_id,
                    "issue": "GuardDuty is not enabled",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        affected = len(resources_affected)

        return {
            "id": "SEC06-BP01",
            "check_name": "Perform vulnerability management",
            "problem_statement": "Continuously identify and manage vulnerabilities across compute resources.",
            "severity_score": 80,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable Amazon GuardDuty and integrate vulnerability scanning processes for compute resources."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable GuardDuty across all regions.",
                "2. Integrate GuardDuty findings with your SIEM system.",
                "3. Perform recurring vulnerability scans on EC2 and containerized workloads.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC06-BP01: {e}")
        return None


def check_sec06_bp02_hardened_images(session):
    print("SEC06-BP02 is based on image preparation practices, not direct API scanning")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_hardened_images.html"

    return {
        "id": "SEC06-BP02",
        "check_name": "Provision compute from hardened images",
        "problem_statement": "Use hardened and regularly updated images for all compute environments.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Adopt hardened AMIs such as CIS benchmarks, and automate continuous patching pipelines."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Use image pipelines (Image Builder) to build hardened AMIs.",
            "2. Enforce baseline configurations using automation.",
            "3. Replace outdated compute images during deployments.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec06_bp03_reduce_manual_management(session):
    print("SEC06-BP03 focuses on reducing interactive administrative access")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_reduce_manual_management.html"

    return {
        "id": "SEC06-BP03",
        "check_name": "Reduce manual management and interactive access",
        "problem_statement": "Limit direct administrative access and rely on automation for compute operations.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Use automation, session recording, and remove SSH/RDP access where possible."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Use Systems Manager Session Manager instead of SSH/RDP.",
            "2. Automate deployments using CI/CD pipelines.",
            "3. Enable logging and monitoring of all administrator access.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec06_bp04_validate_software_integrity(session):
    print("SEC06-BP04 relates to supply chain integrity; not directly API-driven")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_validate_software_integrity.html"

    return {
        "id": "SEC06-BP04",
        "check_name": "Validate software integrity",
        "problem_statement": "Ensure compute workloads run trusted and verified software artifacts.",
        "severity_score": 75,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Use code signing, SBOM validation, and integrity checks for software artifacts."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Use AWS Signer to sign code and binaries.",
            "2. Validate signatures before deployment.",
            "3. Use SBOM tools to track dependencies and vulnerabilities.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec06_bp05_automate_compute_protection(session):
    print("SEC06-BP05 involves automation strategy, not API scanning")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_auto_protection.html"

    return {
        "id": "SEC06-BP05",
        "check_name": "Automate compute protection",
        "problem_statement": "Automate compute protection mechanisms for scalability and consistency.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Use automated patching, SSM automation, and scanning workflows to secure compute resources."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Enable automatic updates using SSM Patch Manager.",
            "2. Automate security scans for all compute fleets.",
            "3. Use event-driven workflows to remediate compute-level risks.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }
