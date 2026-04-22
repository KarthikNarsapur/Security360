def check_risky_nacls(session, scan_meta_data):
    print("check_risky_nacls")
    ec2 = session.client("ec2")
    nacls = ec2.describe_network_acls()["NetworkAcls"]
    risky = []

    for nacl in nacls:
        risky_entries = [
            {
                "rule_number": entry.get("RuleNumber"),
                "protocol": entry.get("Protocol"),
                "rule_action": entry.get("RuleAction"),
                "cidr": entry.get("CidrBlock"),
                "egress": entry.get("Egress"),
            }
            for entry in nacl["Entries"]
            if entry.get("RuleAction") == "allow"
            and entry.get("CidrBlock") == "0.0.0.0/0"
        ]

        if risky_entries:
            risky.append(
                {
                    "resource_name": nacl.get("NetworkAclId"),
                    "vpc_id": nacl.get("VpcId"),
                    "is_default": nacl.get("IsDefault"),
                    # "region": session.region_name,
                    "entries_count": len(nacl.get("Entries", [])),
                    "associated_subnets": [
                        assoc.get("SubnetId") for assoc in nacl.get("Associations", [])
                    ],
                    # "arn": f"arn:aws:ec2:{session.region_name}::{nacl.get('NetworkAclId')}",
                    "risky_entry": risky_entries,
                }
            )

    scan_meta_data["total_scanned"] = scan_meta_data["total_scanned"] + len(nacls)
    scan_meta_data["affected"] = scan_meta_data["affected"] + len(risky)
    scan_meta_data["High"] = scan_meta_data["High"] + len(risky)
    scan_meta_data["services_scanned"].append("NACL")

    return {
        "check_name": "NACLs Allowing Inbound from 0.0.0.0/0",
        "service":"EC2",
        "problem_statement": "Some Network ACLs allow traffic from anywhere (0.0.0.0/0), which is risky.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": risky,
        "recommendation": "Restrict NACL rules to specific CIDR ranges instead of allowing open access.",
        "additional_info": {"total_scanned": len(nacls), "affected": len(risky)},
    }
