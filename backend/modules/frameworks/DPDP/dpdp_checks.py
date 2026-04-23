"""
DPDP Act 2023 — Digital Personal Data Protection Act (India)
AWS Security Checks mapped to DPDP Act obligations.

Sections referenced:
  S4  — Consent & Lawful Processing
  S8  — Rights of Data Principal (access, correction, erasure)
  S9  — Obligations of Data Fiduciary (security safeguards)
  S11 — Data Breach Notification
  S12 — Restrictions on Transfer of Personal Data

Architecture notes:
  - Global checks (S3, IAM) run once per account
  - Regional checks (EC2, RDS, VPC, GuardDuty) run per-region via framework_scan.py
  - SubscriptionRequiredException = service not enabled = valid finding (not error)
  - Severity is dynamic: "None" when 0 affected, actual severity when issues found
  - Resources are deduped via control_id + resource_name key
"""

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "DPDP Act 2023"


def _result(check_name, service, control_id, problem, max_score, max_severity,
            non_compliant, recommendation, total, region="global"):
    """Build check result with dynamic severity based on actual findings."""
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


def _update_meta(meta, service, total, non_compliant, severity_key):
    """Update scan metadata consistently. Counts unique resources only."""
    meta["total_scanned"] += total
    meta["affected"] += len(non_compliant)
    meta[severity_key] += len(non_compliant)
    if service not in meta["services_scanned"]:
        meta["services_scanned"].append(service)


# ═══════════════════════════════════════════════════════════════════════════════
# 🗄️ DATA LAYER — Personal Data Storage Protection (Global: S3)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_s3_public_bucket(session, meta):
    """DPDP S9 — Public S3 buckets expose personal data to the internet."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            name = b["Name"]
            try:
                pa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([pa.get("BlockPublicAcls"), pa.get("IgnorePublicAcls"),
                            pa.get("BlockPublicPolicy"), pa.get("RestrictPublicBuckets")]):
                    non_compliant.append({"resource_name": name, "note": "Public access block not fully enabled"})
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                non_compliant.append({"resource_name": name, "note": "No public access block configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_public_bucket error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Critical")
    return _result("DPDP — S3 Public Bucket Check", "S3", "DPDP-S9-DATA-01",
        "Publicly accessible S3 buckets can expose personal data of Indian citizens, violating Section 9.",
        95, "Critical", non_compliant,
        "Enable S3 Block Public Access at account level. Review and restrict bucket policies.", total)


def dpdp_s3_encryption(session, meta):
    """DPDP S9 — Unencrypted S3 buckets fail to protect personal data at rest."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            name = b["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                has_enc = any(r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                             in ("AES256", "aws:kms", "aws:kms:dsse") for r in rules)
                if not has_enc:
                    non_compliant.append({"resource_name": name, "note": "No valid encryption algorithm"})
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    non_compliant.append({"resource_name": name, "note": "No default encryption configured"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_encryption error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Critical")
    return _result("DPDP — S3 Encryption Check", "S3", "DPDP-S9-DATA-02",
        "S3 buckets without encryption leave personal data unprotected at rest, violating Section 9.",
        90, "Critical", non_compliant,
        "Enable SSE-S3 or SSE-KMS default encryption on all buckets.", total)


def dpdp_s3_versioning(session, meta):
    """DPDP S8 — Versioning supports data principal's right to correction/erasure."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                v = s3.get_bucket_versioning(Bucket=b["Name"])
                if v.get("Status") != "Enabled":
                    non_compliant.append({"resource_name": b["Name"], "note": "Versioning not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_versioning error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result("DPDP — S3 Versioning Check", "S3", "DPDP-S8-DATA-03",
        "Without versioning, personal data cannot be recovered after deletion, undermining Section 8 rights.",
        60, "Medium", non_compliant,
        "Enable versioning on all S3 buckets storing personal data.", total)


def dpdp_s3_access_logging(session, meta):
    """DPDP S11 — Access logging is essential for breach detection."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                log = s3.get_bucket_logging(Bucket=b["Name"])
                if "LoggingEnabled" not in log:
                    non_compliant.append({"resource_name": b["Name"], "note": "Access logging disabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_access_logging error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result("DPDP — S3 Access Logging Check", "S3", "DPDP-S11-LOG-01",
        "Without access logging, unauthorized access to personal data cannot be detected, violating Section 11.",
        70, "Medium", non_compliant,
        "Enable server access logging on all S3 buckets.", total)


def dpdp_s3_lifecycle(session, meta):
    """DPDP S8/S9 — Data retention policies via S3 lifecycle rules."""
    s3 = session.client("s3")
    non_compliant = []
    total = 0
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        total = len(buckets)
        for b in buckets:
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
            except ClientError as e:
                if "NoSuchLifecycleConfiguration" in str(e):
                    non_compliant.append({"resource_name": b["Name"], "note": "No lifecycle policy — data retained indefinitely"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_s3_lifecycle error: {e}")
    _update_meta(meta, "S3", total, non_compliant, "Medium")
    return _result("DPDP — S3 Data Retention Check", "S3", "DPDP-S9-RETENTION-01",
        "S3 buckets without lifecycle policies retain personal data indefinitely, violating Section 8 erasure obligations and Section 9 data minimization.",
        65, "Medium", non_compliant,
        "Add lifecycle policies to expire or transition objects. Align retention with your data processing purpose.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🗄️ DATA LAYER — Regional (RDS, DynamoDB, EFS)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_rds_public_access(session, meta):
    """DPDP S9 — Publicly accessible databases expose personal data."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if db.get("PubliclyAccessible"):
                non_compliant.append({"resource_name": db["DBInstanceIdentifier"], "engine": db.get("Engine"), "note": "Database publicly accessible"})
    except Exception as e:
        print(f"dpdp_rds_public_access error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "Critical")
    return _result("DPDP — RDS Public Access Check", "RDS", "DPDP-S9-DATA-04",
        "Publicly accessible RDS instances expose personal data to the internet, violating Section 9.",
        95, "Critical", non_compliant,
        "Disable public accessibility on all RDS instances. Place in private subnets.", total)


def dpdp_rds_encryption(session, meta):
    """DPDP S9 — Unencrypted databases fail to protect personal data at rest."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("StorageEncrypted"):
                non_compliant.append({"resource_name": db["DBInstanceIdentifier"], "note": "Storage not encrypted"})
    except Exception as e:
        print(f"dpdp_rds_encryption error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "High")
    return _result("DPDP — RDS Encryption Check", "RDS", "DPDP-S9-DATA-05",
        "Unencrypted RDS instances leave personal data exposed, violating Section 9.",
        85, "High", non_compliant,
        "Enable encryption at rest for all RDS instances via KMS.", total)


def dpdp_rds_backup_retention(session, meta):
    """DPDP S8/S9 — Backups support data recovery and principal's rights."""
    rds = session.client("rds")
    non_compliant = []
    total = 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            ret = db.get("BackupRetentionPeriod", 0)
            if ret < 7:
                non_compliant.append({"resource_name": db["DBInstanceIdentifier"], "retention_days": ret, "note": f"Retention {ret} days — should be 7+"})
    except Exception as e:
        print(f"dpdp_rds_backup_retention error: {e}")
    _update_meta(meta, "RDS", total, non_compliant, "Medium")
    return _result("DPDP — RDS Backup Retention Check", "RDS", "DPDP-S9-BACKUP-01",
        "Insufficient backup retention risks permanent loss of personal data, violating Section 8.",
        65, "Medium", non_compliant,
        "Set backup retention to at least 7 days for databases storing personal data.", total)


def dpdp_dynamodb_pitr(session, meta):
    """DPDP S8/S9 — Point-in-time recovery for DynamoDB tables."""
    ddb = session.client("dynamodb")
    non_compliant = []
    total = 0
    try:
        tables = ddb.list_tables().get("TableNames", [])
        total = len(tables)
        for t in tables:
            try:
                cb = ddb.describe_continuous_backups(TableName=t)
                pitr = cb.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {})
                if pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
                    non_compliant.append({"resource_name": t, "note": "PITR not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_dynamodb_pitr error: {e}")
    _update_meta(meta, "DynamoDB", total, non_compliant, "Medium")
    return _result("DPDP — DynamoDB Point-in-Time Recovery", "DynamoDB", "DPDP-S9-BACKUP-02",
        "DynamoDB tables without PITR cannot recover personal data after deletion.",
        65, "Medium", non_compliant,
        "Enable PITR on all DynamoDB tables storing personal data.", total)


def dpdp_efs_encryption(session, meta):
    """DPDP S9 — EFS file systems must be encrypted."""
    efs = session.client("efs")
    non_compliant = []
    total = 0
    try:
        filesystems = efs.describe_file_systems().get("FileSystems", [])
        total = len(filesystems)
        for fs in filesystems:
            if not fs.get("Encrypted"):
                non_compliant.append({"resource_name": fs["FileSystemId"], "note": "EFS not encrypted"})
    except Exception as e:
        print(f"dpdp_efs_encryption error: {e}")
    _update_meta(meta, "EFS", total, non_compliant, "High")
    return _result("DPDP — EFS Encryption Check", "EFS", "DPDP-S9-DATA-06",
        "Unencrypted EFS file systems expose personal data at rest, violating Section 9.",
        80, "High", non_compliant,
        "Enable encryption at rest for all EFS file systems.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔐 IAM LAYER — Access Control (Global)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_root_mfa(session, meta):
    """DPDP S9 — Root account without MFA is a critical access control failure."""
    iam = session.client("iam")
    non_compliant = []
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if not summary.get("AccountMFAEnabled"):
            non_compliant.append({"resource_name": "Root Account", "note": "MFA not enabled"})
    except Exception as e:
        print(f"dpdp_root_mfa error: {e}")
    _update_meta(meta, "IAM", 1, non_compliant, "Critical")
    return _result("DPDP — Root Account MFA Check", "IAM", "DPDP-S9-IAM-01",
        "Root account without MFA allows unrestricted access to all personal data, violating Section 9.",
        95, "Critical", non_compliant,
        "Enable hardware or virtual MFA on the root account immediately.", 1)


def dpdp_iam_user_mfa(session, meta, users, iam):
    """DPDP S9 — All users accessing personal data must have MFA."""
    non_compliant = []
    for user in users:
        uname = user["UserName"]
        try:
            try:
                iam.get_login_profile(UserName=uname)
            except iam.exceptions.NoSuchEntityException:
                continue
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa:
                non_compliant.append({"resource_name": uname, "note": "Console user without MFA"})
        except Exception:
            pass
    _update_meta(meta, "IAM", len(users), non_compliant, "High")
    return _result("DPDP — IAM User MFA Check", "IAM", "DPDP-S9-IAM-02",
        "IAM users without MFA can access personal data with just a password, violating Section 9.",
        85, "High", non_compliant,
        "Enable MFA for all IAM users with console access.", len(users))


def dpdp_access_key_age(session, meta, users, iam):
    """DPDP S9 — Old access keys increase risk of unauthorized data access."""
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    for user in users:
        try:
            keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
            total += len(keys)
            for key in keys:
                if key.get("Status") == "Active":
                    age = (now - key["CreateDate"]).days
                    if age > 90:
                        non_compliant.append({"resource_name": f"{user['UserName']}/{key['AccessKeyId']}", "age_days": age, "note": f"Key is {age} days old"})
        except Exception:
            pass
    _update_meta(meta, "IAM", total, non_compliant, "High")
    return _result("DPDP — Access Key Age Check", "IAM", "DPDP-S9-IAM-03",
        "Access keys older than 90 days increase risk of compromised credentials accessing personal data.",
        80, "High", non_compliant,
        "Rotate access keys every 90 days. Use IAM roles instead of long-lived keys.", total)


def dpdp_wildcard_policy(session, meta, iam):
    """DPDP S9 — Overly permissive policies grant unrestricted access."""
    import json as _json
    non_compliant = []
    total = 0
    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
        total = len(policies)
        for pol in policies:
            try:
                ver = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])
                doc = ver["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = _json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str): actions = [actions]
                        if isinstance(resources, str): resources = [resources]
                        if "*" in actions and "*" in resources:
                            non_compliant.append({"resource_name": pol["PolicyName"], "arn": pol["Arn"], "note": "Policy grants *:*"})
                            break
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_wildcard_policy error: {e}")
    _update_meta(meta, "IAM", total, non_compliant, "Critical")
    return _result("DPDP — Wildcard IAM Policy Check", "IAM", "DPDP-S9-IAM-04",
        "Policies with *:* permissions grant unrestricted access to all personal data, violating Section 9.",
        95, "Critical", non_compliant,
        "Replace wildcard policies with least-privilege policies. Use AWS Access Analyzer.", total)


def dpdp_password_policy(session, meta):
    """DPDP S9 — Weak password policy undermines access control."""
    iam = session.client("iam")
    non_compliant = []
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 12: issues.append(f"Min length {policy.get('MinimumPasswordLength', 0)}")
        if not policy.get("RequireUppercaseCharacters"): issues.append("No uppercase required")
        if not policy.get("RequireLowercaseCharacters"): issues.append("No lowercase required")
        if not policy.get("RequireNumbers"): issues.append("No numbers required")
        if not policy.get("RequireSymbols"): issues.append("No symbols required")
        if policy.get("MaxPasswordAge", 999) > 90: issues.append(f"Expiry {policy.get('MaxPasswordAge')} days")
        if issues:
            non_compliant.append({"resource_name": "Password Policy", "issues": issues})
    except iam.exceptions.NoSuchEntityException:
        non_compliant.append({"resource_name": "Password Policy", "note": "No password policy configured"})
    except Exception as e:
        print(f"dpdp_password_policy error: {e}")
    _update_meta(meta, "IAM", 1, non_compliant, "Medium")
    return _result("DPDP — IAM Password Policy Check", "IAM", "DPDP-S9-IAM-05",
        "Weak password policy increases risk of unauthorized access to personal data.",
        70, "Medium", non_compliant,
        "Set min length 12, require mixed case/numbers/symbols, 90-day expiry.", 1)


# ═══════════════════════════════════════════════════════════════════════════════
# 🌐 NETWORK LAYER — Regional
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_security_group_open_ports(session, meta):
    """DPDP S9 — Open security groups expose infrastructure hosting personal data."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    seen = set()
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        total = len(sgs)
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        key = sg["GroupId"]
                        if key not in seen:
                            seen.add(key)
                            port = rule.get("FromPort", "All")
                            non_compliant.append({"resource_name": key, "group_name": sg.get("GroupName"), "port": port, "note": f"Port {port} open to 0.0.0.0/0"})
                        break
    except Exception as e:
        print(f"dpdp_security_group_open_ports error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "High")
    return _result("DPDP — Security Group Open Ports", "EC2", "DPDP-S9-NET-01",
        "Security groups open to the internet expose systems processing personal data.",
        85, "High", non_compliant,
        "Restrict security group rules to specific IP ranges.", total)


def dpdp_vpc_flow_logs(session, meta):
    """DPDP S11 — VPC Flow Logs are essential for breach detection."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = len(vpcs)
        for vpc in vpcs:
            vid = vpc["VpcId"]
            try:
                fl = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vid]}]).get("FlowLogs", [])
                if not any(f.get("FlowLogStatus") == "ACTIVE" for f in fl):
                    non_compliant.append({"resource_name": vid, "note": "No active VPC flow logs"})
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_vpc_flow_logs error: {e}")
    _update_meta(meta, "VPC", total, non_compliant, "High")
    return _result("DPDP — VPC Flow Logs Enabled", "VPC", "DPDP-S11-NET-02",
        "Without VPC flow logs, network breaches involving personal data cannot be detected, violating Section 11.",
        80, "High", non_compliant,
        "Enable VPC Flow Logs on all VPCs.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🧱 INFRASTRUCTURE LAYER — Regional
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_ec2_public_ip(session, meta):
    """DPDP S9 — EC2 instances with public IPs expose personal data systems."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        reservations = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]).get("Reservations", [])
        for r in reservations:
            for inst in r.get("Instances", []):
                total += 1
                if inst.get("PublicIpAddress"):
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                    non_compliant.append({"resource_name": name, "instance_id": inst["InstanceId"], "public_ip": inst["PublicIpAddress"], "note": "Instance has public IP"})
    except Exception as e:
        print(f"dpdp_ec2_public_ip error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "High")
    return _result("DPDP — EC2 Public IP Check", "EC2", "DPDP-S9-INFRA-01",
        "EC2 instances with public IPs are directly reachable from the internet.",
        80, "High", non_compliant,
        "Remove public IPs from instances processing personal data. Use NAT gateways and load balancers.", total)


def dpdp_ebs_encryption(session, meta):
    """DPDP S9 — Unencrypted EBS volumes fail to protect personal data."""
    ec2 = session.client("ec2")
    non_compliant = []
    total = 0
    try:
        volumes = ec2.describe_volumes().get("Volumes", [])
        total = len(volumes)
        for vol in volumes:
            if not vol.get("Encrypted"):
                non_compliant.append({"resource_name": vol["VolumeId"], "size_gb": vol.get("Size"), "note": "EBS volume not encrypted"})
    except Exception as e:
        print(f"dpdp_ebs_encryption error: {e}")
    _update_meta(meta, "EC2", total, non_compliant, "High")
    return _result("DPDP — EBS Encryption Check", "EC2", "DPDP-S9-INFRA-02",
        "Unencrypted EBS volumes leave personal data unprotected at rest, violating Section 9.",
        85, "High", non_compliant,
        "Enable EBS encryption by default at account level.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 📊 LOGGING & MONITORING — Breach Detection (Section 11) — Regional
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_cloudtrail_enabled(session, meta):
    """DPDP S11 — CloudTrail is essential for breach detection."""
    ct = session.client("cloudtrail")
    non_compliant = []
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            non_compliant.append({"resource_name": "CloudTrail", "note": "No CloudTrail configured"})
        else:
            for trail in trails:
                issues = []
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if not status.get("IsLogging"): issues.append("Logging disabled")
                    if not trail.get("IsMultiRegionTrail"): issues.append("Not multi-region")
                    if not trail.get("LogFileValidationEnabled"): issues.append("Log validation disabled")
                    if issues:
                        non_compliant.append({"resource_name": trail["Name"], "issues": issues})
                except Exception:
                    pass
    except Exception as e:
        print(f"dpdp_cloudtrail_enabled error: {e}")
    _update_meta(meta, "CloudTrail", 1, non_compliant, "High")
    return _result("DPDP — CloudTrail Audit Logging", "CloudTrail", "DPDP-S11-LOG-02",
        "Without CloudTrail, API activity involving personal data cannot be audited, violating Section 11.",
        85, "High", non_compliant,
        "Enable multi-region CloudTrail with log file validation.", 1)


def dpdp_guardduty_enabled(session, meta):
    """DPDP S11 — GuardDuty provides automated breach detection.
    SubscriptionRequiredException = service never enabled = valid finding."""
    gd = session.client("guardduty")
    non_compliant = []
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            non_compliant.append({"resource_name": "GuardDuty", "note": "GuardDuty not enabled in this region"})
        else:
            for did in detectors:
                d = gd.get_detector(DetectorId=did)
                if d.get("Status") != "ENABLED":
                    non_compliant.append({"resource_name": did, "note": "GuardDuty detector disabled"})
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "SubscriptionRequiredException":
            non_compliant.append({"resource_name": "GuardDuty", "note": "Service not enabled (not subscribed)"})
        else:
            print(f"dpdp_guardduty_enabled unexpected error: {code}")
    except Exception as e:
        print(f"dpdp_guardduty_enabled error: {e}")
    _update_meta(meta, "GuardDuty", 1, non_compliant, "Critical")
    return _result("DPDP — GuardDuty Threat Detection", "GuardDuty", "DPDP-S11-SEC-01",
        "Without GuardDuty, threats to personal data cannot be automatically detected, violating Section 11.",
        90, "Critical", non_compliant,
        "Enable GuardDuty in all regions. Configure SNS notifications for high-severity findings.", 1)


def dpdp_config_enabled(session, meta):
    """DPDP S9 — AWS Config tracks configuration changes.
    SubscriptionRequiredException = service never enabled = valid finding."""
    cfg = session.client("config")
    non_compliant = []
    try:
        recorders = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        if not any(r.get("recording") for r in recorders):
            non_compliant.append({"resource_name": "AWS Config", "note": "Config recording not active"})
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "SubscriptionRequiredException":
            non_compliant.append({"resource_name": "AWS Config", "note": "Service not enabled (not subscribed)"})
        else:
            print(f"dpdp_config_enabled unexpected error: {code}")
    except Exception as e:
        print(f"dpdp_config_enabled error: {e}")
    _update_meta(meta, "Config", 1, non_compliant, "High")
    return _result("DPDP — AWS Config Enabled", "Config", "DPDP-S9-LOG-03",
        "Without AWS Config, changes to resources storing personal data are not tracked.",
        80, "High", non_compliant,
        "Enable AWS Config with recording for all resource types.", 1)


def dpdp_cloudwatch_log_retention(session, meta):
    """DPDP S11 — CloudWatch log groups without retention retain data indefinitely."""
    logs = session.client("logs")
    non_compliant = []
    total = 0
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                total += 1
                if not lg.get("retentionInDays"):
                    non_compliant.append({"resource_name": lg["logGroupName"], "note": "No retention policy — logs retained forever"})
    except Exception as e:
        print(f"dpdp_cloudwatch_log_retention error: {e}")
    _update_meta(meta, "CloudWatch", total, non_compliant, "Medium")
    return _result("DPDP — CloudWatch Log Retention", "CloudWatch", "DPDP-S9-RETENTION-02",
        "Log groups without retention policies retain data indefinitely, violating data minimization under Section 9.",
        65, "Medium", non_compliant,
        "Set retention policies on all CloudWatch log groups. Align with your data retention requirements.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔑 SECRETS MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_secrets_manager_usage(session, meta):
    """DPDP S9 — Secrets Manager should be used for credential management."""
    sm = session.client("secretsmanager")
    non_compliant = []
    total = 0
    try:
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if not s.get("RotationEnabled"):
                non_compliant.append({"resource_name": s["Name"], "note": "Secret rotation not enabled"})
    except Exception as e:
        print(f"dpdp_secrets_manager_usage error: {e}")
    _update_meta(meta, "SecretsManager", max(total, 1), non_compliant, "Medium")
    return _result("DPDP — Secrets Manager Rotation", "SecretsManager", "DPDP-S9-SECRET-01",
        "Secrets without automatic rotation increase risk of credential compromise affecting personal data.",
        70, "Medium", non_compliant,
        "Enable automatic rotation for all secrets in Secrets Manager.", max(total, 1))


def dpdp_lambda_env_secrets(session, meta):
    """DPDP S9 — Lambda functions should not store secrets in environment variables."""
    lam = session.client("lambda")
    non_compliant = []
    total = 0
    SECRET_PATTERNS = ["password", "secret", "api_key", "apikey", "token", "db_pass", "private_key", "access_key"]
    try:
        functions = lam.list_functions().get("Functions", [])
        total = len(functions)
        for fn in functions:
            env_vars = fn.get("Environment", {}).get("Variables", {})
            for key in env_vars:
                if any(p in key.lower() for p in SECRET_PATTERNS):
                    non_compliant.append({"resource_name": fn["FunctionName"], "env_var": key, "note": f"Suspicious env var: {key}"})
                    break
    except Exception as e:
        print(f"dpdp_lambda_env_secrets error: {e}")
    _update_meta(meta, "Lambda", total, non_compliant, "High")
    return _result("DPDP — Lambda Environment Secrets", "Lambda", "DPDP-S9-SECRET-02",
        "Lambda functions with secrets in environment variables risk exposing credentials for personal data access.",
        80, "High", non_compliant,
        "Move secrets to AWS Secrets Manager or SSM Parameter Store. Reference them at runtime.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🧑‍💻 APPLICATION LAYER — Regional
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_lambda_public_access(session, meta):
    """DPDP S9 — Lambda functions with public access expose personal data processing."""
    import json as _json
    lam = session.client("lambda")
    non_compliant = []
    total = 0
    try:
        functions = lam.list_functions().get("Functions", [])
        total = len(functions)
        for fn in functions:
            try:
                pol = lam.get_policy(FunctionName=fn["FunctionName"])
                doc = _json.loads(pol["Policy"])
                for stmt in doc.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                        non_compliant.append({"resource_name": fn["FunctionName"], "note": "Lambda has public invoke access"})
                        break
            except lam.exceptions.ResourceNotFoundException:
                pass
            except Exception:
                pass
    except Exception as e:
        print(f"dpdp_lambda_public_access error: {e}")
    _update_meta(meta, "Lambda", total, non_compliant, "High")
    return _result("DPDP — Lambda Public Access Check", "Lambda", "DPDP-S9-APP-01",
        "Lambda functions with public invoke permissions can be triggered by anyone.",
        80, "High", non_compliant,
        "Remove public access from Lambda resource policies. Use API Gateway with authentication.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# 🔔 ALERTING — Breach Notification Readiness (Section 11)
# ═══════════════════════════════════════════════════════════════════════════════


def dpdp_sns_topic_exists(session, meta):
    """DPDP S11 — SNS topics needed for breach notification alerting."""
    sns = session.client("sns")
    non_compliant = []
    total = 0
    try:
        topics = sns.list_topics().get("Topics", [])
        total = len(topics)
        if total == 0:
            non_compliant.append({"resource_name": "SNS", "note": "No SNS topics — no alerting mechanism for breach notification"})
    except Exception as e:
        print(f"dpdp_sns_topic_exists error: {e}")
    _update_meta(meta, "SNS", max(total, 1), non_compliant, "Medium")
    return _result("DPDP — SNS Alerting Check", "SNS", "DPDP-S11-ALERT-01",
        "Without SNS topics, there is no mechanism to alert teams about security incidents involving personal data.",
        65, "Medium", non_compliant,
        "Create SNS topics for security alerts. Subscribe security team emails. Integrate with GuardDuty and CloudWatch alarms.", max(total, 1))
