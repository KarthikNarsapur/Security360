from datetime import datetime, timezone, timedelta
import json
import urllib.parse

IST = timezone(timedelta(hours=5, minutes=30))
INDIA_REGIONS = ["ap-south-1", "ap-south-2"]


def _update_meta(scan_meta_data, service, total, affected, severity_level):
    scan_meta_data["total_scanned"] = scan_meta_data.get("total_scanned", 0) + total
    scan_meta_data["affected"] = scan_meta_data.get("affected", 0) + affected
    scan_meta_data[severity_level] = scan_meta_data.get(severity_level, 0) + affected
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)


# ─── GV: Governance ────────────────────────────────────────────────────────────

def sebi_organizations_enabled(session, scan_meta_data):
    print("sebi_organizations_enabled")
    service = "Organizations"
    non_compliant = []
    total = 1
    try:
        org_client = session.client("organizations")
        org_client.describe_organization()
    except Exception:
        non_compliant.append({"resource": "AWS Organization", "reason": "AWS Organizations is not enabled for this account", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_organizations_enabled",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.OC-1",
        "problem_statement": "AWS Organizations is not enabled, preventing centralized governance and policy enforcement across accounts.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable AWS Organizations and set up a multi-account structure for centralized governance.",
        "additional_info": "SEBI CSCRF mandates centralized oversight of all cloud workloads."
    }


def sebi_scps_configured(session, scan_meta_data):
    print("sebi_scps_configured")
    service = "Organizations"
    non_compliant = []
    total = 1
    try:
        org_client = session.client("organizations")
        paginator = org_client.get_paginator("list_policies")
        custom_scps = []
        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            for policy in page.get("Policies", []):
                if policy["Name"] != "FullAWSAccess":
                    custom_scps.append(policy["Name"])
        if not custom_scps:
            non_compliant.append({"resource": "Service Control Policies", "reason": "No custom SCPs configured beyond FullAWSAccess", "region": "global"})
        total = max(1, len(custom_scps))
    except Exception as e:
        non_compliant.append({"resource": "Service Control Policies", "reason": f"Unable to list SCPs: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_scps_configured",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.OC-2",
        "problem_statement": "No Service Control Policies (SCPs) are configured beyond the default FullAWSAccess, leaving accounts without guardrails.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Implement SCPs to restrict actions such as disabling CloudTrail, leaving approved regions, or creating non-compliant resources.",
        "additional_info": "SCPs enforce preventive controls across all accounts in the organization."
    }


def sebi_cross_account_trust_audit(session, scan_meta_data):
    print("sebi_cross_account_trust_audit")
    service = "IAM"
    non_compliant = []
    total = 0
    try:
        iam = session.client("iam")
        sts = session.client("sts")
        current_account = sts.get_caller_identity()["Account"]
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                total += 1
                trust_policy = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust_policy, str):
                    trust_policy = json.loads(urllib.parse.unquote(trust_policy))
                for stmt in trust_policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principals = stmt.get("Principal", {})
                        aws_principals = principals.get("AWS", []) if isinstance(principals, dict) else []
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        for p in aws_principals:
                            if current_account not in p and p != "*":
                                non_compliant.append({"resource": role["RoleName"], "reason": f"Trusts external account: {p}", "region": "global"})
                                break
    except Exception as e:
        non_compliant.append({"resource": "IAM Roles", "reason": f"Error auditing roles: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_cross_account_trust_audit",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.SC-1",
        "problem_statement": "IAM roles with cross-account trust relationships to external accounts may expose resources to unauthorized access.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Review and restrict cross-account trust policies. Remove trusts to unknown or unnecessary external accounts.",
        "additional_info": "SEBI requires strict supply chain and third-party risk management."
    }


def sebi_access_analyzer_enabled(session, scan_meta_data):
    print("sebi_access_analyzer_enabled")
    service = "IAM"
    non_compliant = []
    total = 1
    try:
        aa = session.client("accessanalyzer")
        analyzers = aa.list_analyzers(Type="ACCOUNT").get("analyzers", [])
        if not analyzers:
            non_compliant.append({"resource": "IAM Access Analyzer", "reason": "No Access Analyzer configured for this account", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "IAM Access Analyzer", "reason": f"Error checking Access Analyzer: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_access_analyzer_enabled",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.SC-2",
        "problem_statement": "IAM Access Analyzer is not enabled, preventing detection of resources shared with external entities.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable IAM Access Analyzer in all regions to identify resources accessible from outside your account.",
        "additional_info": "Access Analyzer helps detect unintended public or cross-account access to resources."
    }


def sebi_lambda_third_party_layers(session, scan_meta_data):
    print("sebi_lambda_third_party_layers")
    service = "Lambda"
    non_compliant = []
    total = 0
    try:
        lam = session.client("lambda")
        sts = session.client("sts")
        current_account = sts.get_caller_identity()["Account"]
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                total += 1
                for layer in fn.get("Layers", []):
                    layer_arn = layer.get("Arn", "")
                    # ARN format: arn:aws:lambda:region:account:layer:name:version
                    parts = layer_arn.split(":")
                    if len(parts) >= 5 and parts[4] != current_account:
                        non_compliant.append({"resource": fn["FunctionName"], "reason": f"Uses third-party layer: {layer_arn}", "region": session.region_name})
                        break
    except Exception as e:
        non_compliant.append({"resource": "Lambda Functions", "reason": f"Error checking Lambda layers: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_lambda_third_party_layers",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.SC-3",
        "problem_statement": "Lambda functions using layers from external accounts introduce supply chain risk.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Audit third-party Lambda layers. Copy approved layers into your own account to control versions and integrity.",
        "additional_info": "Third-party layers can be modified by external owners, posing a supply chain risk."
    }


def sebi_config_tag_rules(session, scan_meta_data):
    print("sebi_config_tag_rules")
    service = "Config"
    non_compliant = []
    total = 1
    try:
        config = session.client("config")
        rules = config.describe_config_rules().get("ConfigRules", [])
        tag_rules = [r for r in rules if "tag" in r.get("ConfigRuleName", "").lower() or "required-tags" in r.get("Source", {}).get("SourceIdentifier", "").lower()]
        if not tag_rules:
            non_compliant.append({"resource": "AWS Config", "reason": "No Config rules enforcing required tags found", "region": session.region_name})
        total = max(1, len(rules))
    except Exception as e:
        non_compliant.append({"resource": "AWS Config", "reason": f"Error checking Config rules: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_config_tag_rules",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.PO-1",
        "problem_statement": "No AWS Config rules enforce required tagging policies for resource classification and governance.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Create Config rules (e.g., required-tags) to enforce mandatory tags like Owner, DataClassification, and Environment.",
        "additional_info": "Tagging policies are essential for asset management and data classification under SEBI CSCRF."
    }


def sebi_trusted_advisor_checks(session, scan_meta_data):
    print("sebi_trusted_advisor_checks")
    service = "Support"
    non_compliant = []
    total = 1
    try:
        support = session.client("support", region_name="us-east-1")
        checks = support.describe_trusted_advisor_checks(language="en").get("checks", [])
        if not checks:
            non_compliant.append({"resource": "Trusted Advisor", "reason": "No Trusted Advisor checks available (Business/Enterprise support required)", "region": "global"})
        total = len(checks) if checks else 1
    except Exception as e:
        non_compliant.append({"resource": "Trusted Advisor", "reason": f"Unable to access Trusted Advisor: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_trusted_advisor_checks",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.RM-1",
        "problem_statement": "Trusted Advisor checks are not accessible, limiting proactive risk identification.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Ensure Business or Enterprise AWS Support plan is active to leverage Trusted Advisor for risk management.",
        "additional_info": "Trusted Advisor provides automated checks for security, cost, performance, and fault tolerance."
    }


def sebi_cloudtrail_org_trail(session, scan_meta_data):
    print("sebi_cloudtrail_org_trail")
    service = "CloudTrail"
    non_compliant = []
    total = 1
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        org_trails = [t for t in trails if t.get("IsOrganizationTrail", False)]
        if not org_trails:
            non_compliant.append({"resource": "CloudTrail", "reason": "No organization-level CloudTrail trail configured", "region": "global"})
        total = max(1, len(trails))
    except Exception as e:
        non_compliant.append({"resource": "CloudTrail", "reason": f"Error checking CloudTrail: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_cloudtrail_org_trail",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-GV.OV-1",
        "problem_statement": "No organization-level CloudTrail trail exists, limiting centralized audit logging across all accounts.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Create an organization trail in CloudTrail to ensure all accounts have centralized, immutable audit logs.",
        "additional_info": "SEBI CSCRF requires comprehensive audit trail capabilities for oversight and governance."
    }


# ─── ID: Identify ──────────────────────────────────────────────────────────────

def sebi_s3_inventory_config(session, scan_meta_data):
    print("sebi_s3_inventory_config")
    service = "S3"
    non_compliant = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            name = bucket["Name"]
            try:
                inv = s3.list_bucket_inventory_configurations(Bucket=name)
                if not inv.get("InventoryConfigurationList"):
                    non_compliant.append({"resource": name, "reason": "No S3 Inventory configuration", "region": "global"})
            except Exception:
                non_compliant.append({"resource": name, "reason": "No S3 Inventory configuration", "region": "global"})
    except Exception as e:
        non_compliant.append({"resource": "S3", "reason": f"Error listing buckets: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_s3_inventory_config",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-2",
        "problem_statement": "S3 buckets without inventory configuration lack automated asset tracking and data management visibility.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable S3 Inventory on all buckets to maintain a complete asset register of stored objects.",
        "additional_info": "Asset management requires complete visibility into data stored across S3 buckets."
    }


def sebi_ec2_ssm_managed(session, scan_meta_data):
    print("sebi_ec2_ssm_managed")
    service = "SSM"
    non_compliant = []
    total = 0
    try:
        ec2 = session.client("ec2")
        ssm = session.client("ssm")
        instances = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    instances.append(inst["InstanceId"])
        total = len(instances)
        managed_ids = set()
        ssm_paginator = ssm.get_paginator("describe_instance_information")
        for page in ssm_paginator.paginate():
            for info in page.get("InstanceInformationList", []):
                managed_ids.add(info["InstanceId"])
        for iid in instances:
            if iid not in managed_ids:
                non_compliant.append({"resource": iid, "reason": "Instance not managed by SSM", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "SSM", "reason": f"Error checking SSM: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_ec2_ssm_managed",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-3",
        "problem_statement": "EC2 instances not managed by SSM cannot be patched, inventoried, or remotely managed centrally.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Install and configure the SSM agent on all EC2 instances and attach the AmazonSSMManagedInstanceCore IAM policy.",
        "additional_info": "SSM provides centralized management, patching, and compliance reporting for instances."
    }


def sebi_unattached_ebs(session, scan_meta_data):
    print("sebi_unattached_ebs")
    service = "EC2"
    non_compliant = []
    total = 0
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                total += 1
                if vol["State"] == "available":
                    non_compliant.append({"resource": vol["VolumeId"], "reason": "EBS volume is unattached (available state)", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "EBS", "reason": f"Error checking volumes: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Low")
    return {
        "check_name": "sebi_unattached_ebs",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-4",
        "problem_statement": "Unattached EBS volumes represent unmanaged assets that may contain sensitive data without proper controls.",
        "severity_score": 3,
        "severity_level": "Low",
        "resources_affected": non_compliant,
        "recommendation": "Review unattached EBS volumes. Delete those no longer needed or attach them to appropriate instances.",
        "additional_info": "Orphaned volumes increase attack surface and cost without providing value."
    }


def sebi_unassociated_eips(session, scan_meta_data):
    print("sebi_unassociated_eips")
    service = "EC2"
    non_compliant = []
    total = 0
    try:
        ec2 = session.client("ec2")
        addresses = ec2.describe_addresses().get("Addresses", [])
        total = len(addresses)
        for addr in addresses:
            if not addr.get("AssociationId"):
                non_compliant.append({"resource": addr.get("PublicIp", addr.get("AllocationId")), "reason": "Elastic IP is not associated with any resource", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "EIP", "reason": f"Error checking EIPs: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Low")
    return {
        "check_name": "sebi_unassociated_eips",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-5",
        "problem_statement": "Unassociated Elastic IPs are unused assets that incur cost and indicate incomplete resource lifecycle management.",
        "severity_score": 3,
        "severity_level": "Low",
        "resources_affected": non_compliant,
        "recommendation": "Release unassociated Elastic IPs or associate them with active resources.",
        "additional_info": "Proper asset lifecycle management requires tracking and decommissioning unused resources."
    }


def sebi_s3_data_classification(session, scan_meta_data):
    print("sebi_s3_data_classification")
    service = "S3"
    non_compliant = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            name = bucket["Name"]
            try:
                tags = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
                tag_keys = [t["Key"] for t in tags]
                if "DataClassification" not in tag_keys:
                    non_compliant.append({"resource": name, "reason": "Missing DataClassification tag", "region": "global"})
            except Exception:
                non_compliant.append({"resource": name, "reason": "Missing DataClassification tag (no tags)", "region": "global"})
    except Exception as e:
        non_compliant.append({"resource": "S3", "reason": f"Error checking buckets: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_s3_data_classification",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-6",
        "problem_statement": "S3 buckets without DataClassification tags lack proper data categorization required for regulatory compliance.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Tag all S3 buckets with a DataClassification tag (e.g., Public, Internal, Confidential, Restricted).",
        "additional_info": "SEBI CSCRF requires data classification to apply appropriate security controls based on sensitivity."
    }


def sebi_dynamodb_classification(session, scan_meta_data):
    print("sebi_dynamodb_classification")
    service = "DynamoDB"
    non_compliant = []
    total = 0
    try:
        ddb = session.client("dynamodb")
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                total += 1
                try:
                    desc = ddb.describe_table(TableName=table_name)
                    arn = desc["Table"]["TableArn"]
                    tags = ddb.list_tags_of_resource(ResourceArn=arn).get("Tags", [])
                    tag_keys = [t["Key"] for t in tags]
                    if "DataClassification" not in tag_keys:
                        non_compliant.append({"resource": table_name, "reason": "Missing DataClassification tag", "region": session.region_name})
                except Exception:
                    non_compliant.append({"resource": table_name, "reason": "Unable to check tags", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "DynamoDB", "reason": f"Error listing tables: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_dynamodb_classification",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.AM-7",
        "problem_statement": "DynamoDB tables without classification tags cannot be properly governed under data protection policies.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Apply DataClassification tags to all DynamoDB tables to enable policy-based data governance.",
        "additional_info": "Data classification is foundational to applying appropriate access and encryption controls."
    }


def sebi_inspector_enabled(session, scan_meta_data):
    print("sebi_inspector_enabled")
    service = "Inspector"
    non_compliant = []
    total = 1
    try:
        inspector = session.client("inspector2")
        status = inspector.batch_get_account_status(accountIds=[session.client("sts").get_caller_identity()["Account"]])
        accounts = status.get("accounts", [])
        if accounts:
            state = accounts[0].get("state", {}).get("status", "")
            if state != "ENABLED":
                non_compliant.append({"resource": "Amazon Inspector", "reason": f"Inspector status: {state}", "region": session.region_name})
        else:
            non_compliant.append({"resource": "Amazon Inspector", "reason": "Inspector is not enabled", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "Amazon Inspector", "reason": f"Inspector not enabled or error: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_inspector_enabled",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.RA-1",
        "problem_statement": "Amazon Inspector is not enabled, preventing automated vulnerability assessment of workloads.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Enable Amazon Inspector to perform continuous vulnerability scanning of EC2 instances, Lambda functions, and container images.",
        "additional_info": "SEBI CSCRF requires regular vulnerability assessments as part of risk identification."
    }


def sebi_securityhub_findings_summary(session, scan_meta_data):
    print("sebi_securityhub_findings_summary")
    service = "SecurityHub"
    non_compliant = []
    total = 1
    try:
        sh = session.client("securityhub")
        findings = sh.get_findings(Filters={"WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}], "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}, MaxResults=100)
        finding_list = findings.get("Findings", [])
        count = len(finding_list)
        if count > 0:
            non_compliant.append({"resource": "SecurityHub", "reason": f"{count} active findings in NEW state require attention", "region": session.region_name})
        total = max(1, count)
    except Exception as e:
        non_compliant.append({"resource": "SecurityHub", "reason": f"SecurityHub not enabled or error: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_securityhub_findings_summary",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.RA-2",
        "problem_statement": "Active Security Hub findings indicate unresolved security issues requiring risk assessment and remediation.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Review and remediate active SecurityHub findings. Establish a process for triaging and resolving findings within SLA.",
        "additional_info": "Regular review of security findings is required for continuous risk assessment."
    }


def sebi_securityhub_critical_findings(session, scan_meta_data):
    print("sebi_securityhub_critical_findings")
    service = "SecurityHub"
    non_compliant = []
    total = 1
    try:
        sh = session.client("securityhub")
        findings = sh.get_findings(Filters={
            "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
        }, MaxResults=100)
        for f in findings.get("Findings", []):
            total += 1
            non_compliant.append({"resource": f.get("Title", "Unknown"), "reason": f"Critical finding: {f.get('Description', '')[:100]}", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "SecurityHub", "reason": f"Error fetching critical findings: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Critical")
    return {
        "check_name": "sebi_securityhub_critical_findings",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.RA-3",
        "problem_statement": "Open critical-severity findings in SecurityHub indicate severe vulnerabilities requiring immediate remediation.",
        "severity_score": 10,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Immediately investigate and remediate all critical SecurityHub findings. Escalate to CISO as per incident response procedure.",
        "additional_info": "Critical findings often indicate actively exploitable vulnerabilities or misconfigurations."
    }


def sebi_macie_enabled(session, scan_meta_data):
    print("sebi_macie_enabled")
    service = "Macie"
    non_compliant = []
    total = 1
    try:
        macie = session.client("macie2")
        status = macie.get_macie_session()
        if status.get("status") != "ENABLED":
            non_compliant.append({"resource": "Amazon Macie", "reason": "Macie is not enabled", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "Amazon Macie", "reason": f"Macie not enabled or error: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_macie_enabled",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.RA-4",
        "problem_statement": "Amazon Macie is not enabled, limiting automated discovery of sensitive data in S3 buckets.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Enable Amazon Macie to automatically discover and classify sensitive data (PII, financial data) in S3.",
        "additional_info": "Macie uses ML to identify sensitive data, supporting SEBI's data classification requirements."
    }


def sebi_public_amis(session, scan_meta_data):
    print("sebi_public_amis")
    service = "EC2"
    non_compliant = []
    total = 0
    try:
        ec2 = session.client("ec2")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        images = ec2.describe_images(Owners=[account_id], Filters=[{"Name": "is-public", "Values": ["true"]}]).get("Images", [])
        total = len(images) if images else 1
        for img in images:
            non_compliant.append({"resource": img["ImageId"], "reason": f"AMI is publicly shared: {img.get('Name', 'N/A')}", "region": session.region_name})
    except Exception as e:
        non_compliant.append({"resource": "EC2 AMIs", "reason": f"Error checking AMIs: {str(e)}", "region": session.region_name})
        total = 1

    _update_meta(scan_meta_data, service, total, len(non_compliant), "Medium")
    return {
        "check_name": "sebi_public_amis",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.RA-5",
        "problem_statement": "Publicly shared AMIs may expose proprietary configurations, software, or embedded credentials.",
        "severity_score": 5,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Make AMIs private unless there is an explicit business requirement for public sharing. Review AMIs for sensitive data.",
        "additional_info": "Public AMIs can be launched by anyone, potentially exposing internal configurations."
    }


def sebi_public_ebs_snapshots(session, scan_meta_data):
    print("sebi_public_ebs_snapshots")
    service = "EC2"
    non_compliant = []
    total = 0
    try:
        ec2 = session.client("ec2")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        snapshots = ec2.describe_snapshots(OwnerIds=[account_id], Filters=[{"Name": "status", "Values": ["completed"]}]).get("Snapshots", [])
        total = len(snapshots) if snapshots else 1
        for snap in snapshots:
            try:
                attrs = ec2.describe_snapshot_attribute(SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission")
                perms = attrs.get("CreateVolumePermissions", [])
                for perm in perms:
                    if perm.get("Group") == "all":
                        non_compliant.append({"resource": snap["SnapshotId"], "reason": "EBS snapshot is publicly shared", "region": session.region_name})
                        break
            except Exception:
                pass
    except Exception as e:
        non_compliant.append({"resource": "EBS Snapshots", "reason": f"Error checking snapshots: {str(e)}", "region": session.region_name})
        total = 1

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_public_ebs_snapshots",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ID.RA-6",
        "problem_statement": "Publicly shared EBS snapshots can expose sensitive data including databases, credentials, and application data.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Remove public sharing from all EBS snapshots immediately. Use AWS RAM for controlled cross-account sharing.",
        "additional_info": "Public snapshots can be copied and mounted by any AWS account, exposing all stored data."
    }


# ─── DL: Data Localization ─────────────────────────────────────────────────────

def sebi_s3_india_localization(session, scan_meta_data):
    print("sebi_s3_india_localization")
    service = "S3"
    non_compliant = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            name = bucket["Name"]
            try:
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
                if region not in INDIA_REGIONS:
                    non_compliant.append({"resource": name, "reason": f"Bucket located in {region} (outside India)", "region": region})
            except Exception:
                non_compliant.append({"resource": name, "reason": "Unable to determine bucket location", "region": "unknown"})
    except Exception as e:
        non_compliant.append({"resource": "S3", "reason": f"Error listing buckets: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_s3_india_localization",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DL-1",
        "problem_statement": "S3 buckets located outside India (ap-south-1/ap-south-2) violate SEBI data localization requirements.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Migrate all S3 buckets containing regulated data to ap-south-1 or ap-south-2 regions.",
        "additional_info": "SEBI mandates that all regulated entity data must reside within India."
    }


def sebi_rds_india_localization(session, scan_meta_data):
    print("sebi_rds_india_localization")
    service = "RDS"
    non_compliant = []
    total = 0
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                total += 1
                az = db.get("AvailabilityZone", "")
                region = az[:-1] if az else ""
                if region not in INDIA_REGIONS:
                    non_compliant.append({"resource": db["DBInstanceIdentifier"], "reason": f"RDS instance in {region} (outside India)", "region": region})
    except Exception as e:
        non_compliant.append({"resource": "RDS", "reason": f"Error checking RDS: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_rds_india_localization",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DL-2",
        "problem_statement": "RDS instances located outside India violate SEBI data localization requirements for regulated entities.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Migrate RDS instances to ap-south-1 or ap-south-2. Use DMS for minimal-downtime migrations.",
        "additional_info": "Database instances containing regulated data must be hosted within Indian territory."
    }


def sebi_dynamodb_india_localization(session, scan_meta_data):
    print("sebi_dynamodb_india_localization")
    service = "DynamoDB"
    non_compliant = []
    total = 0
    try:
        current_region = session.region_name
        ddb = session.client("dynamodb")
        paginator = ddb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                total += 1
                if current_region not in INDIA_REGIONS:
                    non_compliant.append({"resource": table_name, "reason": f"DynamoDB table in {current_region} (outside India)", "region": current_region})
    except Exception as e:
        non_compliant.append({"resource": "DynamoDB", "reason": f"Error checking DynamoDB: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_dynamodb_india_localization",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DL-3",
        "problem_statement": "DynamoDB tables located outside India violate SEBI data localization mandates.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Recreate DynamoDB tables in ap-south-1 or ap-south-2 and migrate data using DynamoDB export/import or AWS DMS.",
        "additional_info": "All NoSQL databases containing regulated entity data must reside in Indian regions."
    }


def sebi_s3_replication_non_india(session, scan_meta_data):
    print("sebi_s3_replication_non_india")
    service = "S3"
    non_compliant = []
    total = 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for bucket in buckets:
            name = bucket["Name"]
            try:
                repl = s3.get_bucket_replication(Bucket=name)
                rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
                for rule in rules:
                    dest = rule.get("Destination", {})
                    dest_bucket = dest.get("Bucket", "")
                    # Check destination bucket region
                    dest_name = dest_bucket.split(":::")[-1] if ":::" in dest_bucket else ""
                    if dest_name:
                        try:
                            dest_loc = s3.get_bucket_location(Bucket=dest_name)
                            dest_region = dest_loc.get("LocationConstraint") or "us-east-1"
                            if dest_region not in INDIA_REGIONS:
                                non_compliant.append({"resource": name, "reason": f"Replicates to {dest_name} in {dest_region} (outside India)", "region": dest_region})
                        except Exception:
                            pass
            except Exception:
                pass  # No replication configured is fine
    except Exception as e:
        non_compliant.append({"resource": "S3", "reason": f"Error checking replication: {str(e)}", "region": "global"})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_s3_replication_non_india",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DL-4",
        "problem_statement": "S3 replication to non-India regions causes regulated data to leave Indian territory.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Reconfigure S3 replication to target only ap-south-1 or ap-south-2 destination buckets.",
        "additional_info": "Cross-region replication to non-Indian regions violates SEBI data residency requirements."
    }


def sebi_rds_replicas_non_india(session, scan_meta_data):
    print("sebi_rds_replicas_non_india")
    service = "RDS"
    non_compliant = []
    total = 0
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                total += 1
                replicas = db.get("ReadReplicaDBInstanceIdentifiers", [])
                for replica_id in replicas:
                    try:
                        replica_desc = rds.describe_db_instances(DBInstanceIdentifier=replica_id)
                        for r in replica_desc.get("DBInstances", []):
                            az = r.get("AvailabilityZone", "")
                            region = az[:-1] if az else ""
                            if region not in INDIA_REGIONS:
                                non_compliant.append({"resource": replica_id, "reason": f"Read replica in {region} (outside India), source: {db['DBInstanceIdentifier']}", "region": region})
                    except Exception:
                        pass
    except Exception as e:
        non_compliant.append({"resource": "RDS", "reason": f"Error checking RDS replicas: {str(e)}", "region": session.region_name})

    _update_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "sebi_rds_replicas_non_india",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-DL-5",
        "problem_statement": "RDS read replicas outside India cause regulated data to be stored in non-compliant regions.",
        "severity_score": 8,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Remove or migrate read replicas to ap-south-1 or ap-south-2. Use in-region replicas for DR.",
        "additional_info": "Database replicas containing regulated data must remain within Indian territory per SEBI directives."
    }
