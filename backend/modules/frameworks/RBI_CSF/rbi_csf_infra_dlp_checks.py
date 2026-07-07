"""
RBI CSF — Infrastructure, DLP, Governance & Asset Checks
Covers remaining checks from Sections A, I, L, M, N, O, P, Q not yet implemented.

All checks use READ-ONLY APIs compatible with arn:aws:iam::aws:policy/ReadOnlyAccess
"""

import json as _json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "RBI CSF"
INDIA_REGIONS = {"ap-south-1", "ap-south-2"}


def _result(check_name, service, control_id, problem, max_score, max_severity,
            non_compliant, recommendation, total, region="global"):
    has_issues = len(non_compliant) > 0
    return {
        "check_name": check_name,
        "service": service,
        "framework": FRAMEWORK,
        "control_id": control_id,
        "problem_statement": problem,
        "severity_score": max_score if has_issues else 0,
        "severity_level": max_severity if has_issues else "None",
        "resources_affected": non_compliant,
        "recommendation": recommendation,
        "region": region,
        "additional_info": {"total_scanned": total, "affected": len(non_compliant)},
    }


def _meta(meta, service, total, non_compliant, severity_key):
    meta["total_scanned"] += total
    meta["affected"] += len(non_compliant)
    meta[severity_key] += len(non_compliant)
    if service not in meta["services_scanned"]:
        meta["services_scanned"].append(service)


# ═══════════════════════════════════════════════════════════════════════════════
# ASSET INVENTORY (AST.1-AST.5)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_ast_config_recorder(session, meta):
    """RBI.AST.1 — Config records all resource types."""
    nc, total = [], 0
    try:
        config = session.client("config")
        total = 1
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recorders:
            nc.append({"resource_name": "Account", "note": "No Config recorder"})
        else:
            group = recorders[0].get("recordingGroup", {})
            if not group.get("allSupported"):
                nc.append({"resource_name": "Config", "note": "Not recording all resources"})
            if not group.get("includeGlobalResourceTypes"):
                nc.append({"resource_name": "Config", "note": "Not including global resources"})
    except Exception as e:
        print(f"rbi_ast_config_recorder error: {e}")
    _meta(meta, "Config", total, nc, "High")
    return _result("RBI CSF — IT Asset Inventory (Config)", "Config", "RBI.AST.1",
        "Complete asset inventory requires Config recording all resource types.",
        75, "High", nc, "Enable allSupported + includeGlobalResourceTypes.", total)


def rbi_ast_tagging(session, meta):
    """RBI.AST.2 — Asset tagging and classification."""
    nc, total = [], 0
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        untagged = 0
        for b in buckets[:30]:
            try:
                tags = s3.get_bucket_tagging(Bucket=b["Name"]).get("TagSet", [])
                tag_keys = {t["Key"].lower() for t in tags}
                if not any(k in tag_keys for k in {"environment", "dataclassification", "criticality", "owner"}):
                    untagged += 1
            except ClientError:
                untagged += 1
            except Exception:
                pass
        if untagged > 0:
            nc.append({"resource_name": f"{untagged} buckets",
                       "note": "Missing required classification tags (Environment/DataClassification/Criticality)"})
    except Exception as e:
        print(f"rbi_ast_tagging error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("RBI CSF — Asset Classification Tagging", "S3", "RBI.AST.2",
        "RBI requires all IT assets classified by criticality (High/Medium/Low).",
        60, "Medium", nc, "Tag all resources with Environment, DataClassification, Criticality, Owner.", total)


def rbi_ast_ssm_managed(session, meta):
    """RBI.AST.5 — Software inventory via SSM."""
    nc, total = [], 0
    try:
        ssm = session.client("ssm")
        managed = ssm.describe_instance_information().get("InstanceInformationList", [])
        total = 1
        if not managed:
            nc.append({"resource_name": "Account", "note": "No SSM-managed instances (no software inventory)"})
    except Exception as e:
        print(f"rbi_ast_ssm_managed error: {e}")
    _meta(meta, "SSM", total, nc, "Medium")
    return _result("RBI CSF — Software Inventory (SSM)", "SSM", "RBI.AST.5",
        "SSM-managed instances provide automated software inventory.",
        55, "Medium", nc, "Install SSM agent on all instances for inventory visibility.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# DLP EXTENDED (DLP.3-DLP.10)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_dlp_s3_ownership(session, meta):
    """RBI.DLP.3 — S3 ACLs disabled (BucketOwnerEnforced)."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                own = s3.get_bucket_ownership_controls(Bucket=b["Name"])
                rules = own.get("OwnershipControls", {}).get("Rules", [])
                if not any(r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules):
                    nc.append({"resource_name": b["Name"], "note": "Not BucketOwnerEnforced"})
            except ClientError as e:
                if "OwnershipControlsNotFoundError" in str(e):
                    nc.append({"resource_name": b["Name"], "note": "No ownership controls"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_dlp_s3_ownership error: {e}")
    _meta(meta, "S3", total, nc, "Medium")
    return _result("RBI CSF — S3 ACLs Disabled (BucketOwnerEnforced)", "S3", "RBI.DLP.3",
        "BucketOwnerEnforced disables ACLs, preventing uncontrolled access grants.",
        70, "Medium", nc, "Set ObjectOwnership=BucketOwnerEnforced on all buckets.", total)


def rbi_dlp_object_lock(session, meta):
    """RBI.DLP.5 — S3 Object Lock for compliance."""
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        has_lock = False
        for b in buckets:
            try:
                s3.get_object_lock_configuration(Bucket=b["Name"])
                has_lock = True
                break
            except ClientError:
                pass
            except Exception:
                pass
        if not has_lock:
            nc.append({"resource_name": "Account", "note": "No buckets with Object Lock enabled"})
    except Exception as e:
        print(f"rbi_dlp_object_lock error: {e}")
    _meta(meta, "S3", total, nc, "Low")
    return _result("RBI CSF — S3 Object Lock (WORM)", "S3", "RBI.DLP.5",
        "Object Lock prevents deletion of regulatory data before retention period expires.",
        40, "Low", nc, "Enable Object Lock on regulatory compliance buckets.", total)


def rbi_dlp_public_snapshots(session, meta):
    """RBI.DLP.9 — No public EBS snapshots."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        snapshots = ec2.describe_snapshots(OwnerIds=[account_id]).get("Snapshots", [])
        total = len(snapshots)
        for snap in snapshots[:100]:
            try:
                attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission"
                ).get("CreateVolumePermissions", [])
                if any(p.get("Group") == "all" for p in attrs):
                    nc.append({"resource_name": snap["SnapshotId"], "note": "Shared publicly"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_dlp_public_snapshots error: {e}")
    _meta(meta, "EC2", total, nc, "Critical")
    return _result("RBI CSF — No Public EBS Snapshots", "EC2", "RBI.DLP.9",
        "Public snapshots can expose financial data volumes to anyone.",
        95, "Critical", nc, "Remove 'all' from createVolumePermission on snapshots.", total)


def rbi_dlp_public_rds_snapshots(session, meta):
    """RBI.DLP.10 — No public RDS snapshots."""
    nc, total = [], 0
    try:
        rds = session.client("rds")
        snapshots = rds.describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", [])
        total = len(snapshots)
        for snap in snapshots[:50]:
            try:
                attrs = rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]
                ).get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])
                for attr in attrs:
                    if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                        nc.append({"resource_name": snap["DBSnapshotIdentifier"], "note": "Shared publicly"})
                        break
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_dlp_public_rds_snapshots error: {e}")
    _meta(meta, "RDS", total, nc, "Critical")
    return _result("RBI CSF — No Public RDS Snapshots", "RDS", "RBI.DLP.10",
        "Public RDS snapshots expose financial database contents.",
        95, "Critical", nc, "Remove 'all' from restore attribute on RDS snapshots.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE (INF.5-INF.15)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_inf_imdsv2(session, meta):
    """RBI.INF.5 — EC2 IMDSv2 enforced."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ).get("Reservations", [])
        for r in reservations:
            for i in r.get("Instances", []):
                total += 1
                md = i.get("MetadataOptions", {})
                if md.get("HttpTokens") != "required":
                    nc.append({"resource_name": i["InstanceId"], "note": "IMDSv2 not enforced"})
    except Exception as e:
        print(f"rbi_inf_imdsv2 error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("RBI CSF — EC2 IMDSv2 Enforcement", "EC2", "RBI.INF.5",
        "IMDSv2 prevents SSRF-based credential theft from instance metadata.",
        75, "High", nc, "Set HttpTokens=required on all EC2 instances.", total)


def rbi_inf_lambda_vpc(session, meta):
    """RBI.INF.12 — Lambda functions in VPC."""
    nc, total = [], 0
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        total = len(functions)
        for f in functions:
            vpc = f.get("VpcConfig", {})
            if not vpc.get("SubnetIds"):
                nc.append({"resource_name": f["FunctionName"], "note": "Not in VPC"})
    except Exception as e:
        print(f"rbi_inf_lambda_vpc error: {e}")
    _meta(meta, "Lambda", total, nc, "Medium")
    return _result("RBI CSF — Lambda in VPC", "Lambda", "RBI.INF.12",
        "Financial processing functions should run in VPC for network isolation.",
        55, "Medium", nc, "Configure VPC settings for financial Lambda functions.", total)


def rbi_inf_lambda_dlq(session, meta):
    """RBI.INF.14 — Lambda Dead Letter Queue configured."""
    nc, total = [], 0
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        total = len(functions)
        for f in functions:
            dlq = f.get("DeadLetterConfig", {})
            if not dlq.get("TargetArn"):
                nc.append({"resource_name": f["FunctionName"], "note": "No DLQ configured"})
    except Exception as e:
        print(f"rbi_inf_lambda_dlq error: {e}")
    _meta(meta, "Lambda", total, nc, "Low")
    return _result("RBI CSF — Lambda Dead Letter Queue", "Lambda", "RBI.INF.14",
        "DLQ prevents silent loss of financial processing events on failure.",
        40, "Low", nc, "Configure DLQ (SQS/SNS) on financial event Lambda functions.", total)


def rbi_inf_elasticache_encryption(session, meta):
    """RBI.ENC.15 — ElastiCache encryption."""
    nc, total = [], 0
    try:
        ec = session.client("elasticache")
        groups = ec.describe_replication_groups().get("ReplicationGroups", [])
        total = len(groups)
        for g in groups:
            issues = []
            if not g.get("AtRestEncryptionEnabled"):
                issues.append("at-rest")
            if not g.get("TransitEncryptionEnabled"):
                issues.append("in-transit")
            if issues:
                nc.append({"resource_name": g["ReplicationGroupId"],
                           "note": f"Missing encryption: {', '.join(issues)}"})
    except Exception as e:
        print(f"rbi_inf_elasticache_encryption error: {e}")
    _meta(meta, "ElastiCache", total, nc, "High")
    return _result("RBI CSF — ElastiCache Encryption", "ElastiCache", "RBI.ENC.15",
        "Session/cache data for financial apps must be encrypted at rest and in transit.",
        75, "High", nc, "Enable AtRestEncryption + TransitEncryption on all clusters.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK EXTENDED (NET.5, NET.6, NET.11)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_net_default_sg(session, meta):
    """RBI.NET.5 — Default security group restricts all traffic."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        ).get("SecurityGroups", [])
        total = len(sgs)
        for sg in sgs:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                has_rules = any(sg.get("IpPermissions", []))
                if has_rules:
                    nc.append({"resource_name": f"{sg['GroupId']} ({sg.get('VpcId', '')})",
                               "note": "Default SG has active inbound rules"})
    except Exception as e:
        print(f"rbi_net_default_sg error: {e}")
    _meta(meta, "EC2", total, nc, "Medium")
    return _result("RBI CSF — Default Security Group Locked", "EC2", "RBI.NET.5",
        "Default SGs should have no inbound/outbound rules (deny all).",
        60, "Medium", nc, "Remove all rules from default security groups.", total)


def rbi_net_ssh_restricted(session, meta):
    """RBI.NET.11 — SSH/RDP not open to 0.0.0.0/0."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        total = len(sgs)
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                if from_port in (22, 3389) or to_port in (22, 3389):
                    for ip in perm.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            nc.append({"resource_name": sg["GroupId"],
                                       "note": f"Port {from_port} open to 0.0.0.0/0"})
                            break
    except Exception as e:
        print(f"rbi_net_ssh_restricted error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("RBI CSF — SSH/RDP Restricted", "EC2", "RBI.NET.11",
        "SSH(22) and RDP(3389) must not be open to the internet.",
        80, "High", nc, "Restrict SSH/RDP to specific management IPs or use SSM.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# DATA RESIDENCY EXTENDED (DR.4-DR.10)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_dr_dynamodb_global(session, meta):
    """RBI.DR.5 — DynamoDB Global Tables India only."""
    nc, total = [], 0
    try:
        ddb = session.client("dynamodb")
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables[:20]:
            try:
                desc = ddb.describe_table(TableName=t)["Table"]
                replicas = desc.get("Replicas", [])
                for r in replicas:
                    region = r.get("RegionName", "")
                    if region and region not in INDIA_REGIONS:
                        nc.append({"resource_name": t,
                                   "note": f"Global replica in {region} — outside India"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_dr_dynamodb_global error: {e}")
    _meta(meta, "DynamoDB", total, nc, "Critical")
    return _result("RBI CSF — DynamoDB Global Tables (India Only)", "DynamoDB", "RBI.DR.5",
        "Global table replicas must only exist in Indian regions.",
        90, "Critical", nc, "Remove global table replicas outside ap-south-1/ap-south-2.", total)


def rbi_dr_backup_india(session, meta):
    """RBI.DR.6 — Backup copies only to Indian regions."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        total = len(plans)
        for p in plans[:10]:
            try:
                plan = backup.get_backup_plan(BackupPlanId=p["BackupPlanId"])["BackupPlan"]
                for rule in plan.get("Rules", []):
                    for copy in rule.get("CopyActions", []):
                        dest = copy.get("DestinationBackupVaultArn", "")
                        # Extract region from ARN
                        parts = dest.split(":")
                        if len(parts) >= 4:
                            dest_region = parts[3]
                            if dest_region and dest_region not in INDIA_REGIONS:
                                nc.append({"resource_name": p.get("BackupPlanName", "unknown"),
                                           "note": f"Copy to {dest_region} — outside India"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_dr_backup_india error: {e}")
    _meta(meta, "Backup", total, nc, "Critical")
    return _result("RBI CSF — Backup Copies India Only", "Backup", "RBI.DR.6",
        "RBI data localization requires all backup copies remain within India.",
        90, "Critical", nc, "Ensure CopyActions target only ap-south-1/ap-south-2 vaults.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# THIRD-PARTY RISK (TPR.1-TPR.7)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_tpr_sns_policy(session, meta):
    """RBI.TPR.4 — SNS topic policies no public publish."""
    nc, total = [], 0
    try:
        sns = session.client("sns")
        topics = sns.list_topics().get("Topics", [])
        total = len(topics)
        for t in topics[:20]:
            try:
                attrs = sns.get_topic_attributes(TopicArn=t["TopicArn"]).get("Attributes", {})
                policy = _json.loads(attrs.get("Policy", "{}"))
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            if not stmt.get("Condition"):
                                nc.append({"resource_name": t["TopicArn"].split(":")[-1],
                                           "note": "Public publish allowed"})
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_tpr_sns_policy error: {e}")
    _meta(meta, "SNS", total, nc, "Medium")
    return _result("RBI CSF — SNS Topic Policy (No Public)", "SNS", "RBI.TPR.4",
        "Topic policies with Principal:* allow unauthorized message injection.",
        65, "Medium", nc, "Remove wildcard principals from SNS topic policies.", total)


def rbi_tpr_sqs_policy(session, meta):
    """RBI.TPR.5 — SQS queue policies no wildcard principals."""
    nc, total = [], 0
    try:
        sqs = session.client("sqs")
        queues = sqs.list_queues().get("QueueUrls", [])
        total = len(queues)
        for q in queues[:20]:
            try:
                attrs = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["Policy"]).get("Attributes", {})
                policy = _json.loads(attrs.get("Policy", "{}"))
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            if not stmt.get("Condition"):
                                nc.append({"resource_name": q.split("/")[-1], "note": "Wildcard principal"})
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_tpr_sqs_policy error: {e}")
    _meta(meta, "SQS", total, nc, "Medium")
    return _result("RBI CSF — SQS Queue Policy (No Wildcard)", "SQS", "RBI.TPR.5",
        "Queue policies with wildcard principals allow unauthorized message access.",
        65, "Medium", nc, "Restrict SQS policies to authorized accounts only.", total)


def rbi_tpr_sqs_dlq(session, meta):
    """RBI.TPR.6 — SQS Dead Letter Queue configured."""
    nc, total = [], 0
    try:
        sqs = session.client("sqs")
        queues = sqs.list_queues().get("QueueUrls", [])
        total = len(queues)
        for q in queues[:20]:
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=q, AttributeNames=["RedrivePolicy"]
                ).get("Attributes", {})
                if not attrs.get("RedrivePolicy"):
                    nc.append({"resource_name": q.split("/")[-1], "note": "No DLQ configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_tpr_sqs_dlq error: {e}")
    _meta(meta, "SQS", total, nc, "Low")
    return _result("RBI CSF — SQS Dead Letter Queue", "SQS", "RBI.TPR.6",
        "DLQ prevents silent loss of financial messages on processing failure.",
        40, "Low", nc, "Configure RedrivePolicy on all financial processing queues.", total)
