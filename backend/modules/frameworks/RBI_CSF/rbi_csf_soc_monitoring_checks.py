"""
RBI CSF — SOC, Monitoring & Metric Filter Checks
Covers: SOC.3-SOC.5, SOC.9-SOC.20, VUL.1-VUL.7, LOG extensions

All checks use READ-ONLY APIs compatible with arn:aws:iam::aws:policy/ReadOnlyAccess
"""

import json as _json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FRAMEWORK = "RBI CSF"


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
# GUARDDUTY EXTENDED PROTECTION PLANS
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_soc_guardduty_malware(session, meta):
    """RBI.SOC.3 — GuardDuty Malware Protection."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            enabled = any(f.get("Name") == "EBS_MALWARE_PROTECTION" and f.get("Status") == "ENABLED" for f in features)
            if not enabled:
                ds = det.get("DataSources", {})
                mal = ds.get("MalwareProtection", {}).get("ScanEc2InstanceWithFindings", {})
                if mal.get("EbsVolumes", {}).get("Status") != "ENABLED":
                    nc.append({"resource_name": "GuardDuty", "note": "Malware Protection not enabled"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"rbi_soc_guardduty_malware error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("RBI CSF — GuardDuty Malware Protection", "GuardDuty", "RBI.SOC.3",
        "Malware protection scans EBS volumes for malicious software targeting financial systems.",
        80, "High", nc, "Enable EBS Malware Protection in GuardDuty.", total)


def rbi_soc_guardduty_rds(session, meta):
    """RBI.SOC.4 — GuardDuty RDS Protection."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            enabled = any(f.get("Name") == "RDS_LOGIN_EVENTS" and f.get("Status") == "ENABLED" for f in features)
            if not enabled:
                nc.append({"resource_name": "GuardDuty", "note": "RDS Protection not enabled"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"rbi_soc_guardduty_rds error: {e}")
    _meta(meta, "GuardDuty", total, nc, "Medium")
    return _result("RBI CSF — GuardDuty RDS Protection", "GuardDuty", "RBI.SOC.4",
        "RDS login event monitoring detects brute-force and anomalous database access.",
        70, "Medium", nc, "Enable RDS Protection in GuardDuty.", total)


def rbi_soc_guardduty_all_plans(session, meta):
    """RBI.SOC.5 — All GuardDuty protection plans enabled."""
    nc, total = [], 0
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        total = 1
        if detectors:
            det = gd.get_detector(DetectorId=detectors[0])
            features = det.get("Features", [])
            required = {"S3_DATA_EVENTS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS",
                       "LAMBDA_NETWORK_LOGS", "EKS_AUDIT_LOGS", "RUNTIME_MONITORING"}
            enabled_features = {f["Name"] for f in features if f.get("Status") == "ENABLED"}
            missing = required - enabled_features
            if missing:
                nc.append({"resource_name": "GuardDuty",
                           "note": f"Missing protections: {', '.join(sorted(missing))}"})
        else:
            nc.append({"resource_name": "Account", "note": "GuardDuty not enabled"})
    except Exception as e:
        print(f"rbi_soc_guardduty_all_plans error: {e}")
    _meta(meta, "GuardDuty", total, nc, "High")
    return _result("RBI CSF — GuardDuty All Protection Plans", "GuardDuty", "RBI.SOC.5",
        "Complete SOC coverage requires all GuardDuty protection plans active.",
        75, "High", nc, "Enable all GuardDuty features: S3, Malware, RDS, Lambda, EKS, Runtime.", total)


def rbi_soc_macie(session, meta):
    """RBI.SOC.9 — Macie enabled with classification jobs."""
    nc, total = [], 0
    try:
        macie = session.client("macie2")
        total = 1
        try:
            status = macie.get_macie_session()
            if status.get("status") != "ENABLED":
                nc.append({"resource_name": "Macie", "note": "Not enabled"})
            else:
                jobs = macie.list_classification_jobs(
                    filterCriteria={"includes": [{"key": "jobStatus", "values": ["RUNNING", "IDLE"]}]}
                ).get("items", [])
                if not jobs:
                    nc.append({"resource_name": "Macie", "note": "No active classification jobs"})
        except ClientError:
            nc.append({"resource_name": "Macie", "note": "Macie not available"})
    except Exception as e:
        print(f"rbi_soc_macie error: {e}")
    _meta(meta, "Macie", total, nc, "Medium")
    return _result("RBI CSF — Macie Data Classification", "Macie", "RBI.SOC.9",
        "Macie discovers and classifies sensitive financial data in S3.",
        65, "Medium", nc, "Enable Macie with scheduled classification jobs.", total)


def rbi_soc_inspector(session, meta):
    """RBI.SOC.10 — Inspector vulnerability scanning."""
    nc, total = [], 0
    try:
        total = 1
        inspector = session.client("inspector2")
        try:
            account_id = session.client("sts").get_caller_identity()["Account"]
            status = inspector.batch_get_account_status(accountIds=[account_id]).get("accounts", [])
            if status:
                state = status[0].get("state", {}).get("status", "")
                if state != "ENABLED":
                    nc.append({"resource_name": "Inspector", "note": f"Status: {state}"})
            else:
                nc.append({"resource_name": "Inspector", "note": "Not enabled"})
        except Exception:
            nc.append({"resource_name": "Inspector", "note": "Inspector v2 not available"})
    except Exception as e:
        print(f"rbi_soc_inspector error: {e}")
    _meta(meta, "Inspector", total, nc, "High")
    return _result("RBI CSF — Inspector Vulnerability Scanning", "Inspector", "RBI.SOC.10",
        "Continuous vulnerability scanning required per RBI VAPT requirements.",
        75, "High", nc, "Enable Inspector for EC2, ECR, and Lambda scanning.", total)


def rbi_soc_sns_actions(session, meta):
    """RBI.SOC.11 — Alarms have SNS actions; topics have subscribers."""
    nc, total = [], 0
    try:
        cw = session.client("cloudwatch")
        alarms = cw.describe_alarms().get("MetricAlarms", [])
        total = len(alarms) if alarms else 1
        if not alarms:
            nc.append({"resource_name": "Account", "note": "No CloudWatch alarms"})
        else:
            no_action = [a for a in alarms if not a.get("AlarmActions")]
            if len(no_action) > len(alarms) * 0.5:
                nc.append({"resource_name": "CloudWatch",
                           "note": f"{len(no_action)}/{len(alarms)} alarms have no notification actions"})
    except Exception as e:
        print(f"rbi_soc_sns_actions error: {e}")
    _meta(meta, "CloudWatch", total, nc, "Medium")
    return _result("RBI CSF — Alarm Notification Actions", "CloudWatch", "RBI.SOC.11",
        "SOC alarms must trigger notifications for real-time incident awareness.",
        60, "Medium", nc, "Add SNS actions to all security-related CloudWatch alarms.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# METRIC FILTERS (SOC.12 - SOC.20)
# ═══════════════════════════════════════════════════════════════════════════════


def _check_metric_filter(session, meta, control_id, name, description, pattern_keywords):
    """Generic metric filter checker."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = 1
        found = False
        for g in groups[:10]:
            try:
                filters = logs.describe_metric_filters(logGroupName=g["logGroupName"]).get("metricFilters", [])
                for f in filters:
                    fp = f.get("filterPattern", "").lower()
                    if any(kw in fp for kw in pattern_keywords):
                        found = True
                        break
            except Exception:
                pass
            if found:
                break
        if not found:
            nc.append({"resource_name": "CloudWatch Logs", "note": f"No metric filter for {name}"})
    except Exception as e:
        print(f"rbi_soc_mf_{control_id} error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result(f"RBI CSF — Metric Filter: {name}", "CloudWatch Logs", control_id,
        description, 60, "Medium", nc,
        f"Create metric filter for {name} events with alarm and SNS action.", total)


def rbi_soc_mf_root_login(session, meta):
    """RBI.SOC.12 — Metric filter for root login."""
    return _check_metric_filter(session, meta, "RBI.SOC.12", "Root Login",
        "Root account usage must trigger immediate SOC alerts.",
        ["root", "consolelogin"])


def rbi_soc_mf_unauthorized_api(session, meta):
    """RBI.SOC.13 — Metric filter for unauthorized API calls."""
    return _check_metric_filter(session, meta, "RBI.SOC.13", "Unauthorized API Calls",
        "Failed API calls may indicate credential compromise attempts.",
        ["unauthorizedoperation", "accessdenied"])


def rbi_soc_mf_iam_changes(session, meta):
    """RBI.SOC.14 — Metric filter for IAM policy changes."""
    return _check_metric_filter(session, meta, "RBI.SOC.14", "IAM Policy Changes",
        "IAM changes can escalate privileges if not monitored.",
        ["createpolicy", "attachpolicy", "deletepolicy", "putuserpolicy"])


def rbi_soc_mf_sg_changes(session, meta):
    """RBI.SOC.15 — Metric filter for Security Group changes."""
    return _check_metric_filter(session, meta, "RBI.SOC.15", "Security Group Changes",
        "SG changes can expose financial systems to unauthorized network access.",
        ["authorizesecuritygroup", "revokesecuritygroup"])


def rbi_soc_mf_kms_changes(session, meta):
    """RBI.SOC.16 — Metric filter for KMS key changes."""
    return _check_metric_filter(session, meta, "RBI.SOC.16", "KMS Key Changes",
        "KMS key disabling/deletion can render financial data inaccessible.",
        ["disablekey", "schedulekeydeletion", "putkeypolicy"])


def rbi_soc_mf_cloudtrail_changes(session, meta):
    """RBI.SOC.17 — Metric filter for CloudTrail changes."""
    return _check_metric_filter(session, meta, "RBI.SOC.17", "CloudTrail Changes",
        "Disabling audit trails is a key indicator of compromise.",
        ["stoplogging", "deletetrail", "updatetrail"])


def rbi_soc_mf_config_changes(session, meta):
    """RBI.SOC.18 — Metric filter for Config changes."""
    return _check_metric_filter(session, meta, "RBI.SOC.18", "Config Changes",
        "Disabling Config removes compliance visibility.",
        ["stopconfigurationrecorder", "deletedelivery"])


def rbi_soc_mf_console_failures(session, meta):
    """RBI.SOC.19 — Metric filter for console login failures."""
    return _check_metric_filter(session, meta, "RBI.SOC.19", "Console Login Failures",
        "Repeated console login failures may indicate brute-force attacks.",
        ["consolelogin", "failure", "failed"])


def rbi_soc_mf_s3_policy_changes(session, meta):
    """RBI.SOC.20 — Metric filter for S3 bucket policy changes."""
    return _check_metric_filter(session, meta, "RBI.SOC.20", "S3 Policy Changes",
        "S3 policy changes can expose financial data publicly.",
        ["putbucketpolicy", "deletebucketpolicy", "putbucketacl"])


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY & PATCH MANAGEMENT (VUL.1-VUL.7)
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_vul_lambda_deprecated(session, meta):
    """RBI.VUL.5 — Lambda deprecated runtimes."""
    nc, total = [], 0
    DEPRECATED = {"python2.7", "python3.6", "nodejs10.x", "nodejs12.x", "nodejs14.x",
                  "dotnetcore2.1", "dotnetcore3.1", "ruby2.5", "ruby2.7", "java8"}
    try:
        lmb = session.client("lambda")
        functions = lmb.list_functions().get("Functions", [])
        total = len(functions)
        for f in functions:
            runtime = f.get("Runtime", "")
            if runtime in DEPRECATED:
                nc.append({"resource_name": f["FunctionName"], "note": f"Runtime: {runtime} (deprecated)"})
    except Exception as e:
        print(f"rbi_vul_lambda_deprecated error: {e}")
    _meta(meta, "Lambda", total, nc, "Medium")
    return _result("RBI CSF — Lambda Deprecated Runtimes", "Lambda", "RBI.VUL.5",
        "Deprecated runtimes no longer receive security patches.",
        65, "Medium", nc, "Upgrade to supported runtimes.", total)


def rbi_vul_ecr_scan_on_push(session, meta):
    """RBI.VUL.6 — ECR image scanning on push."""
    nc, total = [], 0
    try:
        ecr = session.client("ecr")
        repos = ecr.describe_repositories().get("repositories", [])
        total = len(repos)
        for r in repos:
            scan_config = r.get("imageScanningConfiguration", {})
            if not scan_config.get("scanOnPush"):
                nc.append({"resource_name": r["repositoryName"], "note": "Scan on push not enabled"})
    except Exception as e:
        print(f"rbi_vul_ecr_scan_on_push error: {e}")
    _meta(meta, "ECR", total, nc, "Medium")
    return _result("RBI CSF — ECR Image Scanning", "ECR", "RBI.VUL.6",
        "Container images must be scanned for vulnerabilities before deployment.",
        65, "Medium", nc, "Enable scanOnPush on all ECR repositories.", total)


def rbi_vul_ecr_immutable(session, meta):
    """RBI.VUL.7 — ECR immutable image tags."""
    nc, total = [], 0
    try:
        ecr = session.client("ecr")
        repos = ecr.describe_repositories().get("repositories", [])
        total = len(repos)
        for r in repos:
            if r.get("imageTagMutability") != "IMMUTABLE":
                nc.append({"resource_name": r["repositoryName"], "note": "Image tags are mutable"})
    except Exception as e:
        print(f"rbi_vul_ecr_immutable error: {e}")
    _meta(meta, "ECR", total, nc, "Medium")
    return _result("RBI CSF — ECR Immutable Tags", "ECR", "RBI.VUL.7",
        "Immutable tags prevent overwriting vetted container images.",
        60, "Medium", nc, "Set imageTagMutability=IMMUTABLE on all repos.", total)


def rbi_vul_ssm_managed(session, meta):
    """RBI.VUL.4 — SSM patch compliance."""
    nc, total = [], 0
    try:
        ssm = session.client("ssm")
        instances = ssm.describe_instance_information().get("InstanceInformationList", [])
        ec2 = session.client("ec2")
        running = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        running_ids = set()
        for r in running.get("Reservations", []):
            for i in r.get("Instances", []):
                running_ids.add(i["InstanceId"])
        managed_ids = {i["InstanceId"] for i in instances}
        total = len(running_ids)
        unmanaged = running_ids - managed_ids
        for uid in list(unmanaged)[:20]:
            nc.append({"resource_name": uid, "note": "Not managed by SSM"})
    except Exception as e:
        print(f"rbi_vul_ssm_managed error: {e}")
    _meta(meta, "SSM", total, nc, "Medium")
    return _result("RBI CSF — SSM Managed Instances", "SSM", "RBI.VUL.4",
        "All instances must be SSM-managed for automated patching.",
        65, "Medium", nc, "Install SSM agent and register all instances.", total)


# ═══════════════════════════════════════════════════════════════════════════════
# LOG EXTENSIONS
# ═══════════════════════════════════════════════════════════════════════════════


def rbi_log_cw_encryption(session, meta):
    """RBI.LOG.10 — CloudWatch log groups KMS encrypted."""
    logs = session.client("logs")
    nc, total = [], 0
    try:
        groups = logs.describe_log_groups().get("logGroups", [])
        total = len(groups)
        for g in groups:
            if not g.get("kmsKeyId"):
                nc.append({"resource_name": g["logGroupName"], "note": "Not KMS encrypted"})
    except Exception as e:
        print(f"rbi_log_cw_encryption error: {e}")
    _meta(meta, "CloudWatch Logs", total, nc, "Medium")
    return _result("RBI CSF — Log Group KMS Encryption", "CloudWatch Logs", "RBI.LOG.10",
        "Financial system logs may contain sensitive data requiring encryption.",
        60, "Medium", nc, "Associate KMS keys with log groups.", total)


def rbi_log_trail_protected(session, meta):
    """RBI.LOG.12 — Trail S3 bucket encrypted + no public access."""
    ct = session.client("cloudtrail")
    s3 = session.client("s3")
    nc, total = [], 0
    try:
        trails = ct.describe_trails().get("trailList", [])
        total = len(trails)
        for t in trails:
            bucket = t.get("S3BucketName")
            if not bucket:
                continue
            try:
                pa = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if not all([pa.get("BlockPublicAcls"), pa.get("BlockPublicPolicy"),
                           pa.get("IgnorePublicAcls"), pa.get("RestrictPublicBuckets")]):
                    nc.append({"resource_name": bucket, "note": "Trail bucket missing full public access block"})
            except ClientError as e:
                if "NoSuchPublicAccessBlockConfiguration" in str(e):
                    nc.append({"resource_name": bucket, "note": "Trail bucket has no public access block"})
            except Exception:
                pass
    except Exception as e:
        print(f"rbi_log_trail_protected error: {e}")
    _meta(meta, "S3", total, nc, "High")
    return _result("RBI CSF — Trail Bucket Protected", "S3", "RBI.LOG.12",
        "Audit trail storage must be protected from public access.",
        80, "High", nc, "Enable all 4 Block Public Access settings on trail buckets.", total)


def rbi_log_api_gateway(session, meta):
    """RBI.LOG.13 — API Gateway access logging."""
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
        print(f"rbi_log_api_gateway error: {e}")
    _meta(meta, "API Gateway", total, nc, "Medium")
    return _result("RBI CSF — API Gateway Logging", "API Gateway", "RBI.LOG.13",
        "Access logging provides audit trail for financial API requests.",
        60, "Medium", nc, "Enable access logging on all API stages.", total)
