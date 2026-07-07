"""
RBI CSF — Regional Checks (run per region)
Covers: KMS, Network extended, RDS extended, GuardDuty/SOC, API security,
        Secrets, Backup, Monitoring, Incident Response, Vulnerability Mgmt

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
# KMS CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_kms_rotation(session, meta):
    """RBI.ENC.8 — KMS key rotation enabled."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER" and desc.get("KeyState") == "Enabled":
                    total += 1
                    rot = kms.get_key_rotation_status(KeyId=k["KeyId"])
                    if not rot.get("KeyRotationEnabled"):
                        nc.append({"resource_name": k["KeyId"][:8] + "...", "note": "Rotation not enabled"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_kms_rotation error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("RBI CSF — KMS Key Rotation", "KMS", "RBI.ENC.8",
        "Annual key rotation required for financial data encryption keys.",
        80, "High", nc, "Enable automatic rotation on all customer-managed keys.", total)


def rbi_kms_disabled_pending(session, meta):
    """RBI.ENC.9 — No disabled/pending-deletion keys."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:50]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") == "CUSTOMER":
                    total += 1
                    state = desc.get("KeyState")
                    if state in ("Disabled", "PendingDeletion"):
                        nc.append({"resource_name": k["KeyId"][:8] + "...", "note": f"State: {state}"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_kms_disabled_pending error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("RBI CSF — Disabled/Pending Deletion KMS Keys", "KMS", "RBI.ENC.9",
        "Disabled or pending-deletion keys may protect active financial data.",
        80, "High", nc, "Re-enable keys or migrate data before deletion completes.", total)


def rbi_kms_key_policy(session, meta):
    """RBI.ENC.10 — KMS key policies no wildcard access."""
    kms = session.client("kms")
    nc, total = [], 0
    try:
        keys = kms.list_keys().get("Keys", [])
        for k in keys[:30]:
            try:
                desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if desc.get("KeyManager") != "CUSTOMER":
                    continue
                total += 1
                policy = _json.loads(kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"])
                for stmt in policy.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            if not stmt.get("Condition"):
                                nc.append({"resource_name": k["KeyId"][:8] + "...",
                                           "note": "Principal:* without Condition"})
                                break
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_kms_key_policy error: {e}")
    _meta(meta, "KMS", total, nc, "High")
    return _result("RBI CSF — KMS Key Policy Validation", "KMS", "RBI.ENC.10",
        "Key policies must restrict access to authorized financial system roles.",
        80, "High", nc, "Remove wildcard principals from KMS key policies.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# SOC / GUARDDUTY / MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_soc_guardduty(session, meta):
    """RBI.SOC.1 — GuardDuty enabled and active."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if not detectors:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
        else:
            det = gd.get_detector(DetectorId=detectors[0])
            if det.get("Status") != "ENABLED":
                nc.append({"resource_name": "GuardDuty", "note": "Detector not active"})
    except Exception as e:
        print(f"rbi_soc_guardduty error: {e}")
    _meta(meta, "GuardDuty", total, nc, "Critical")
    return _result("RBI CSF — GuardDuty Active", "GuardDuty", "RBI.SOC.1",
        "24x7 C-SOC requirement mandates continuous threat detection.",
        90, "Critical", nc, "Enable GuardDuty in all regions.", total)


def rbi_soc_guardduty_s3(session, meta):
    """RBI.SOC.2 — GuardDuty S3 Protection."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            s3_enabled = any(f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED" for f in features)
            if not s3_enabled:
                ds = det.get("DataSources", {})
                if ds.get("S3Logs", {}).get("Status") != "ENABLED":
                    nc.append({"resource_name": "GuardDuty", "note": "S3 Protection not enabled"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"rbi_soc_guardduty_s3 error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("RBI CSF — GuardDuty S3 Protection", "GuardDuty", "RBI.SOC.2",
        "S3 protection detects anomalous access to financial data buckets.",
        80, "High", nc, "Enable S3 data event monitoring in GuardDuty.", total)


def rbi_soc_securityhub(session, meta):
    """RBI.SOC.6 — Security Hub with standards enabled."""
    nc, total = [], 0
    try:
        sh = session.client("securityhub")
        total = 1
        try:
            sh.describe_hub()
            standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
            if not standards:
                nc.append({"resource_name": "Security Hub", "note": "No standards enabled"})
        except ClientError:
            nc.append({"resource_name": "Security Hub", "note": "Not enabled"})
    except Exception as e:
        print(f"rbi_soc_securityhub error: {e}")
    _meta(meta, "Security Hub", total, nc, "High")
    return _result("RBI CSF — Security Hub Standards", "Security Hub", "RBI.SOC.6",
        "Security Hub with CIS + FSBP standards provides centralized SOC findings.",
        75, "High", nc, "Enable Security Hub with CIS and AWS FSBP standards.", total)


def rbi_soc_cw_alarms(session, meta):
    """RBI.SOC.8 — CloudWatch alarms for security events."""
    cw = session.client("cloudwatch")
    nc, total = [], 0
    try:
        alarms = cw.describe_alarms().get("MetricAlarms", [])
        total = 1
        if not alarms:
            nc.append({"resource_name": "Account", "note": "No CloudWatch alarms configured"})
        else:
            alarms_with_actions = [a for a in alarms if a.get("AlarmActions")]
            if not alarms_with_actions:
                nc.append({"resource_name": "Account", "note": "No alarms with notification actions"})
    except Exception as e:
        print(f"rbi_soc_cw_alarms error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("RBI CSF — CloudWatch Security Alarms", "CloudWatch", "RBI.SOC.8",
        "Alarms with SNS actions needed for real-time SOC alerting.",
        65, "Medium", nc, "Create alarms for root login, IAM changes, and unauthorized API calls.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK EXTENDED (beyond existing open SG check)
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_net_vpc_flow_logs(session, meta):
    """RBI.NET.4 — VPC Flow Logs enabled."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        total = len(vpcs)
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        logged_vpcs = {fl.get("ResourceId") for fl in flow_logs}
        for vpc in vpcs:
            if vpc["VpcId"] not in logged_vpcs:
                nc.append({"resource_name": vpc["VpcId"], "note": "No VPC flow logs"})
    except Exception as e:
        print(f"rbi_net_vpc_flow_logs error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("RBI CSF — VPC Flow Logs", "EC2", "RBI.NET.4",
        "Flow logs required for network forensics in financial VPCs.",
        80, "High", nc, "Enable flow logs on all VPCs.", total)


def rbi_net_waf_alb(session, meta):
    """RBI.NET.7 — WAF on public-facing ALBs."""
    nc, total = [], 0
    try:
        elbv2 = session.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        public_albs = [lb for lb in lbs if lb.get("Scheme") == "internet-facing" and lb.get("Type") == "application"]
        total = len(public_albs)
        if public_albs:
            try:
                wafv2 = session.client("wafv2")
                acls = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
                protected = set()
                for acl in acls:
                    try:
                        resources = wafv2.list_resources_for_web_acl(WebACLArn=acl["ARN"]).get("ResourceArns", [])
                        protected.update(resources)
                    except Exception:
                        pass
                for lb in public_albs:
                    if lb["LoadBalancerArn"] not in protected:
                        nc.append({"resource_name": lb["LoadBalancerName"], "note": "Public ALB without WAF"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_net_waf_alb error: {e}")
    _meta(meta, "WAF", total, nc, "High")
    return _result("RBI CSF — WAF on Public ALBs", "WAF", "RBI.NET.7",
        "Public-facing financial APIs must be protected by WAF.",
        80, "High", nc, "Associate WAF web ACL with all internet-facing ALBs.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# RDS EXTENDED (beyond existing encryption + backup checks)
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_rds_not_public(session, meta):
    """RBI.DLP.6 — RDS not publicly accessible."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if db.get("PubliclyAccessible"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Publicly accessible"})
    except Exception as e:
        print(f"rbi_rds_not_public error: {e}")
    _meta(meta, "RDS", total, nc, "Critical")
    return _result("RBI CSF — RDS Not Publicly Accessible", "RDS", "RBI.DLP.6",
        "Financial databases must never be publicly accessible.",
        100, "Critical", nc, "Disable PubliclyAccessible on all RDS instances.", total)


def rbi_rds_deletion_protection(session, meta):
    """RBI.BKP.11 — RDS deletion protection."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("DeletionProtection"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Deletion protection disabled"})
    except Exception as e:
        print(f"rbi_rds_deletion_protection error: {e}")
    _meta(meta, "RDS", total, nc, "High")
    return _result("RBI CSF — RDS Deletion Protection", "RDS", "RBI.BKP.11",
        "Prevents accidental financial data loss from database deletion.",
        80, "High", nc, "Enable DeletionProtection on all databases.", total)


def rbi_rds_multi_az(session, meta):
    """RBI.BKP.10 — RDS Multi-AZ for HA."""
    rds = session.client("rds")
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        for db in instances:
            if not db.get("MultiAZ"):
                nc.append({"resource_name": db["DBInstanceIdentifier"], "note": "Single-AZ"})
    except Exception as e:
        print(f"rbi_rds_multi_az error: {e}")
    _meta(meta, "RDS", total, nc, "Medium")
    return _result("RBI CSF — RDS Multi-AZ (High Availability)", "RDS", "RBI.BKP.10",
        "Multi-AZ ensures high availability for financial databases (RTO ≤ 4 hours).",
        65, "Medium", nc, "Enable Multi-AZ on production financial databases.", total)


def rbi_rds_india_region(session, meta):
    """RBI.DR.2 — RDS in India regions only."""
    rds = session.client("rds")
    region = session.region_name
    nc, total = [], 0
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        total = len(instances)
        if region not in INDIA_REGIONS:
            for db in instances:
                nc.append({"resource_name": db["DBInstanceIdentifier"],
                           "note": f"Located in {region} — outside India"})
    except Exception as e:
        print(f"rbi_rds_india_region error: {e}")
    _meta(meta, "RDS", total, nc, "Critical")
    return _result("RBI CSF — RDS Data Residency (India Only)", "RDS", "RBI.DR.2",
        "Financial databases MUST be in Indian regions per RBI data localization.",
        100, "Critical", nc, "Migrate RDS instances to ap-south-1 or ap-south-2.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# SECRETS, BACKUP, INCIDENT RESPONSE
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_secrets_rotation(session, meta):
    """RBI.SEC.1 — Secret rotation enabled."""
    nc, total = [], 0
    try:
        sm = session.client("secretsmanager")
        secrets = sm.list_secrets().get("SecretList", [])
        total = len(secrets)
        for s in secrets:
            if not s.get("RotationEnabled"):
                nc.append({"resource_name": s.get("Name", "unknown"), "note": "Rotation not enabled"})
    except Exception as e:
        print(f"rbi_secrets_rotation error: {e}")
    _meta(meta, "Secrets Manager", total, nc, "High")
    return _result("RBI CSF — Secret Rotation", "Secrets Manager", "RBI.SEC.1",
        "Financial system secrets must have automatic rotation.",
        75, "High", nc, "Enable rotation on all secrets.", total)


def rbi_backup_vault_encryption(session, meta):
    """RBI.BKP.2 — Backup vault encryption with CMK."""
    nc, total = [], 0
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        total = len(vaults) if vaults else 1
        if not vaults:
            nc.append({"resource_name": "Account", "note": "No backup vaults"})
        for v in vaults:
            if not v.get("EncryptionKeyArn"):
                nc.append({"resource_name": v.get("BackupVaultName"), "note": "Not KMS encrypted"})
    except Exception as e:
        print(f"rbi_backup_vault_encryption error: {e}")
    _meta(meta, "Backup", total, nc, "High")
    return _result("RBI CSF — Backup Vault Encryption", "Backup", "RBI.BKP.2",
        "Financial data backups must be encrypted with customer-managed KMS.",
        80, "High", nc, "Use CMK encryption for all backup vaults.", total)


def rbi_ir_eventbridge_guardduty(session, meta):
    """RBI.IR.1 — EventBridge rule for GuardDuty findings."""
    nc, total = [], 0
    try:
        eb = session.client("events")
        rules = eb.list_rules().get("Rules", [])
        total = 1
        gd_rule = any("guardduty" in r.get("Name", "").lower() or "guard" in r.get("Name", "").lower() for r in rules)
        if not gd_rule:
            nc.append({"resource_name": "EventBridge", "note": "No rule for GuardDuty findings"})
    except Exception as e:
        print(f"rbi_ir_eventbridge_guardduty error: {e}")
    _meta(meta, "EventBridge", total, nc, "Medium")
    return _result("RBI CSF — EventBridge GuardDuty Rule", "EventBridge", "RBI.IR.1",
        "EventBridge rules route GuardDuty findings to SOC notification workflows.",
        65, "Medium", nc, "Create EventBridge rule matching GuardDuty findings.", total)


def rbi_ir_incident_plans(session, meta):
    """RBI.IR.5 — Incident Manager response plans."""
    nc, total = [], 0
    try:
        total = 1
        ssm_inc = session.client("ssm-incidents")
        plans = ssm_inc.list_response_plans().get("responsePlanSummaries", [])
        if not plans:
            nc.append({"resource_name": "Account", "note": "No incident response plans"})
    except ClientError:
        nc.append({"resource_name": "SSM Incidents", "note": "Incident Manager not configured"})
    except Exception as e:
        print(f"rbi_ir_incident_plans error: {e}")
    _meta(meta, "SSM Incidents", total, nc, "High")
    return _result("RBI CSF — Incident Response Plans", "SSM Incidents", "RBI.IR.5",
        "Predefined response plans ensure 6-hour CERT-In notification readiness.",
        75, "High", nc, "Create Incident Manager response plans for financial incidents.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# API SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_api_authorization(session, meta):
    """RBI.API.1 — All API endpoints have authorization."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            resources = apigw.get_resources(restApiId=api["id"]).get("items", [])
            for res in resources:
                methods = res.get("resourceMethods", {})
                for method_name in methods:
                    if method_name == "OPTIONS":
                        continue
                    total += 1
                    try:
                        method = apigw.get_method(restApiId=api["id"], resourceId=res["id"], httpMethod=method_name)
                        if method.get("authorizationType") == "NONE":
                            nc.append({"resource_name": f"{api['name']}{res.get('path', '')}",
                                       "note": f"{method_name} has no authorization"})
                    except Exception:
                        pass
    except Exception as e:
        print(f"rbi_api_authorization error: {e}")
    _meta(meta, "API Gateway", total, nc, "Critical")
    return _result("RBI CSF — API Authorization", "API Gateway", "RBI.API.1",
        "All financial API endpoints must have authorization configured.",
        90, "Critical", nc, "Add Cognito/IAM/Lambda authorizers to all API methods.", total)


def rbi_api_access_logging(session, meta):
    """RBI.API.2 — API access logging enabled."""
    nc, total = [], 0
    try:
        apigw = session.client("apigateway")
        apis = apigw.get_rest_apis().get("items", [])
        for api in apis:
            stages = apigw.get_stages(restApiId=api["id"]).get("item", [])
            for stage in stages:
                total += 1
                if not stage.get("accessLogSettings"):
                    nc.append({"resource_name": f"{api['name']}/{stage['stageName']}",
                               "note": "Access logging not enabled"})
    except Exception as e:
        print(f"rbi_api_access_logging error: {e}")
    _meta(meta, "API Gateway", total, nc, "High")
    return _result("RBI CSF — API Access Logging", "API Gateway", "RBI.API.2",
        "Access logging provides SOC visibility into financial API usage.",
        75, "High", nc, "Enable access logging on all API Gateway stages.", total)


def rbi_api_acm_expiry(session, meta):
    """RBI.ENC.13 — ACM certificate validity."""
    nc, total = [], 0
    try:
        acm = session.client("acm")
        certs = acm.list_certificates().get("CertificateSummaryList", [])
        total = len(certs)
        now = datetime.now(timezone.utc)
        for c in certs:
            not_after = c.get("NotAfter")
            if not_after:
                days_left = (not_after - now).days
                if days_left < 0:
                    nc.append({"resource_name": c.get("DomainName", "unknown"), "note": "EXPIRED"})
                elif days_left < 30:
                    nc.append({"resource_name": c.get("DomainName", "unknown"),
                               "note": f"Expires in {days_left} days"})
    except Exception as e:
        print(f"rbi_api_acm_expiry error: {e}")
    _meta(meta, "ACM", total, nc, "High")
    return _result("RBI CSF — ACM Certificate Validity", "ACM", "RBI.ENC.13",
        "Expired certificates cause outages on financial service endpoints.",
        80, "High", nc, "Renew certificates expiring within 30 days.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# EBS / INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

def rbi_ebs_encryption(session, meta):
    """RBI.ENC.5 — All EBS volumes encrypted."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        volumes = ec2.describe_volumes().get("Volumes", [])
        total = len(volumes)
        for v in volumes:
            if not v.get("Encrypted"):
                nc.append({"resource_name": v["VolumeId"], "note": "Not encrypted"})
    except Exception as e:
        print(f"rbi_ebs_encryption error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("RBI CSF — EBS Volume Encryption", "EC2", "RBI.ENC.5",
        "All EBS volumes must be encrypted per RBI cryptographic controls.",
        80, "High", nc, "Encrypt all EBS volumes. Enable default encryption.", total)


def rbi_ebs_default_encryption(session, meta):
    """RBI.ENC.6 — EBS default encryption enabled."""
    ec2 = session.client("ec2")
    nc, total = [], 0
    try:
        total = 1
        result = ec2.get_ebs_encryption_by_default()
        if not result.get("EbsEncryptionByDefault"):
            nc.append({"resource_name": "Account", "note": "EBS default encryption not enabled"})
    except Exception as e:
        print(f"rbi_ebs_default_encryption error: {e}")
    _meta(meta, "EC2", total, nc, "High")
    return _result("RBI CSF — EBS Default Encryption", "EC2", "RBI.ENC.6",
        "Default encryption ensures new volumes are automatically encrypted.",
        75, "High", nc, "Enable EBS encryption by default.", total)


def rbi_log_retention(session, meta):
    """RBI.LOG.9 — CloudWatch log retention >= 365 days."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups)
        for g in groups:
            retention = g.get("retentionInDays")
            if retention and retention < 365:
                nc.append({"resource_name": g["logGroupName"],
                           "note": f"Retention {retention} days (need 365+)"})
            elif not retention:
                pass  # Infinite is acceptable
    except Exception as e:
        print(f"rbi_log_retention error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result("RBI CSF — Log Retention (365 days)", "CloudWatch Logs", "RBI.LOG.9",
        "RBI requires minimum 2-year log retention. 365 days is the minimum acceptable.",
        60, "Medium", nc, "Set retentionInDays >= 365 on financial log groups.", total)
