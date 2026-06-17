from datetime import datetime, timezone, timedelta
import json

IST = timezone(timedelta(hours=5, minutes=30))

INDIA_REGIONS = ["ap-south-1", "ap-south-2"]


def update_scan_meta(scan_meta_data, service, total, affected, severity):
    scan_meta_data["total_scanned"] = scan_meta_data.get("total_scanned", 0) + total
    scan_meta_data["affected"] = scan_meta_data.get("affected", 0) + affected
    sev_key = severity
    scan_meta_data[sev_key] = scan_meta_data.get(sev_key, 0) + affected
    if service not in scan_meta_data.get("services_scanned", []):
        scan_meta_data.setdefault("services_scanned", []).append(service)


def sebi_org_delegated_admin(session, scan_meta_data):
    """SEBI-CSCRF-ENH-01: Check delegated admin accounts for security services."""
    print("Running sebi_org_delegated_admin...")
    service = "Organizations"
    non_compliant = []
    security_services = [
        "guardduty.amazonaws.com",
        "securityhub.amazonaws.com",
        "config-multiaccountsetup.amazonaws.com",
        "macie.amazonaws.com"
    ]
    try:
        org_client = session.client("organizations")
        for svc in security_services:
            try:
                resp = org_client.list_delegated_administrators(ServicePrincipal=svc)
                admins = resp.get("DelegatedAdministrators", [])
                if not admins:
                    non_compliant.append({
                        "resource": svc,
                        "reason": "No delegated administrator configured",
                        "service_principal": svc
                    })
            except org_client.exceptions.AWSOrganizationsNotInUseException:
                non_compliant.append({
                    "resource": svc,
                    "reason": "AWS Organizations not enabled",
                    "service_principal": svc
                })
            except Exception as e:
                if "AccessDenied" not in str(e):
                    non_compliant.append({
                        "resource": svc,
                        "reason": f"Unable to check: {str(e)[:100]}",
                        "service_principal": svc
                    })
    except Exception as e:
        non_compliant.append({"resource": "Organizations", "reason": str(e)[:200]})

    total = len(security_services)
    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "Delegated Admin for Security Services",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-01",
        "problem_statement": "Security services without delegated administrator lack centralized management required by SEBI CSCRF.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Configure delegated administrator accounts for GuardDuty, Security Hub, Config, and Macie to enable centralized security management.",
        "additional_info": {"services_checked": security_services, "total_checked": total, "missing_delegation": len(non_compliant)}
    }


def sebi_cross_account_data_exposure(session, scan_meta_data):
    """SEBI-CSCRF-ENH-02: Check for cross-account data exposure in resource policies."""
    print("Running sebi_cross_account_data_exposure...")
    service = "Multi-Service"
    non_compliant = []
    total = 0

    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
    except Exception:
        account_id = ""

    # Check S3 bucket policies
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            total += 1
            try:
                policy_str = s3.get_bucket_policy(Bucket=bucket["Name"])["Policy"]
                policy = json.loads(policy_str)
                external_accounts = set()
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if isinstance(principal, str):
                        principals = [principal]
                    else:
                        principals = principal.get("AWS", [])
                        if isinstance(principals, str):
                            principals = [principals]
                    for p in principals:
                        if p == "*":
                            external_accounts.add("*")
                        elif account_id and account_id not in p:
                            external_accounts.add(p)
                if external_accounts:
                    non_compliant.append({
                        "resource": f"s3://{bucket['Name']}",
                        "reason": "Cross-account access in bucket policy",
                        "external_principals": list(external_accounts)
                    })
            except s3.exceptions.from_service("NoSuchBucketPolicy") if hasattr(s3, 'exceptions') else Exception:
                pass
            except Exception:
                pass
    except Exception:
        pass

    # Check KMS key policies
    try:
        kms = session.client("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                total += 1
                try:
                    policy_str = kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")["Policy"]
                    policy = json.loads(policy_str)
                    external_accounts = set()
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        if isinstance(principal, str):
                            principals = [principal]
                        else:
                            principals = principal.get("AWS", [])
                            if isinstance(principals, str):
                                principals = [principals]
                        for p in principals:
                            if p == "*" and stmt.get("Effect") == "Allow":
                                external_accounts.add("*")
                            elif account_id and account_id not in str(p) and p != "*":
                                external_accounts.add(p)
                    if external_accounts:
                        non_compliant.append({
                            "resource": f"kms:{key['KeyId'][:8]}...",
                            "reason": "Cross-account access in key policy",
                            "external_principals": list(external_accounts)
                        })
                except Exception:
                    pass
    except Exception:
        pass

    # Check SNS topic policies
    try:
        sns = session.client("sns")
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                total += 1
                try:
                    attrs = sns.get_topic_attributes(TopicArn=topic["TopicArn"])
                    policy_str = attrs["Attributes"].get("Policy", "{}")
                    policy = json.loads(policy_str)
                    external_accounts = set()
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        if isinstance(principal, str):
                            principals = [principal]
                        else:
                            principals = principal.get("AWS", [])
                            if isinstance(principals, str):
                                principals = [principals]
                        for p in principals:
                            if p == "*" and stmt.get("Effect") == "Allow":
                                cond = stmt.get("Condition", {})
                                if not cond:
                                    external_accounts.add("*")
                            elif account_id and account_id not in str(p) and p != "*":
                                external_accounts.add(p)
                    if external_accounts:
                        non_compliant.append({
                            "resource": topic["TopicArn"].split(":")[-1],
                            "reason": "Cross-account access in topic policy",
                            "external_principals": list(external_accounts)
                        })
                except Exception:
                    pass
    except Exception:
        pass

    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "Cross-Account Data Exposure Assessment",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-02",
        "problem_statement": "Resources with cross-account access policies may expose sensitive financial data to unauthorized accounts.",
        "severity_score": 8.0,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Review and restrict cross-account access. Ensure only authorized accounts from your organization have access. Remove wildcard principals.",
        "additional_info": {"total_resources_checked": total, "resources_with_cross_account_access": len(non_compliant)}
    }


def sebi_advanced_kms_assessment(session, scan_meta_data):
    """SEBI-CSCRF-ENH-03: Deep KMS analysis."""
    print("Running sebi_advanced_kms_assessment...")
    service = "KMS"
    non_compliant = []
    total = 0

    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
    except Exception:
        account_id = ""

    try:
        kms = session.client("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page.get("Keys", []):
                total += 1
                key_id = key["KeyId"]
                issues = []
                try:
                    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    if meta.get("KeyManager") == "AWS":
                        continue
                    if meta.get("KeyState") != "Enabled":
                        continue

                    # Check policy for wildcard principal
                    policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
                    policy = json.loads(policy_str)
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                                if not stmt.get("Condition"):
                                    issues.append("Policy allows wildcard principal without conditions")
                                    break

                    # Check grants for external accounts
                    try:
                        grants = kms.list_grants(KeyId=key_id).get("Grants", [])
                        for grant in grants:
                            grantee = grant.get("GranteePrincipal", "")
                            if account_id and account_id not in grantee:
                                issues.append(f"Grant to external account: {grantee[:50]}")
                                break
                    except Exception:
                        pass

                    # Check for tag-based access control (key should have tags)
                    try:
                        tags = kms.list_resource_tags(KeyId=key_id).get("Tags", [])
                        if not tags:
                            issues.append("No tags for tag-based access control")
                    except Exception:
                        pass

                    # Key spec analysis
                    spec = meta.get("KeySpec", "")
                    usage = meta.get("KeyUsage", "")
                    if spec == "SYMMETRIC_DEFAULT" and usage == "ENCRYPT_DECRYPT":
                        pass  # Normal
                    elif "RSA" in spec or "ECC" in spec:
                        issues.append(f"Asymmetric key ({spec}) - verify usage justification")

                    if issues:
                        non_compliant.append({
                            "resource": key_id,
                            "reason": "; ".join(issues),
                            "key_spec": spec,
                            "key_usage": usage
                        })
                except Exception:
                    pass
    except Exception as e:
        non_compliant.append({"resource": "KMS", "reason": str(e)[:200]})

    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "Advanced KMS Key Assessment",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-03",
        "problem_statement": "KMS keys with overly permissive policies, external grants, or missing access controls weaken encryption posture.",
        "severity_score": 8.0,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Restrict KMS key policies to specific principals, remove external grants, implement tag-based access control, and document asymmetric key usage.",
        "additional_info": {"total_keys_analyzed": total, "keys_with_issues": len(non_compliant)}
    }


def sebi_advanced_secrets_manager(session, scan_meta_data):
    """SEBI-CSCRF-ENH-04: Advanced Secrets Manager assessment."""
    print("Running sebi_advanced_secrets_manager...")
    service = "SecretsManager"
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)

    try:
        sm = session.client("secretsmanager")
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                total += 1
                secret_name = secret.get("Name", "")
                issues = []

                # Check age > 365 days
                created = secret.get("CreatedDate")
                if created:
                    age_days = (now - created).days
                    if age_days > 365:
                        issues.append(f"Secret is {age_days} days old (>365)")

                # Check last accessed
                last_accessed = secret.get("LastAccessedDate")
                if last_accessed and (now - last_accessed).days > 90:
                    issues.append(f"Not accessed in {(now - last_accessed).days} days")

                # Check resource policy
                try:
                    policy_resp = sm.get_resource_policy(SecretId=secret["ARN"])
                    policy_str = policy_resp.get("ResourcePolicy")
                    if not policy_str:
                        issues.append("No resource policy configured")
                    else:
                        policy = json.loads(policy_str)
                        for stmt in policy.get("Statement", []):
                            if stmt.get("Effect") == "Allow":
                                principal = stmt.get("Principal", {})
                                if principal == "*" or (isinstance(principal, dict) and "*" in str(principal.get("AWS", ""))):
                                    issues.append("Overly permissive resource policy (wildcard principal)")
                                    break
                except Exception:
                    issues.append("Unable to retrieve resource policy")

                if issues:
                    non_compliant.append({
                        "resource": secret_name,
                        "reason": "; ".join(issues),
                        "arn": secret.get("ARN", ""),
                        "last_rotated": str(secret.get("LastRotatedDate", "Never"))
                    })
    except Exception as e:
        non_compliant.append({"resource": "SecretsManager", "reason": str(e)[:200]})

    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "Advanced Secrets Manager Assessment",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-04",
        "problem_statement": "Secrets with poor lifecycle management, missing policies, or overly permissive access increase credential compromise risk.",
        "severity_score": 7.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Rotate secrets older than 365 days, add restrictive resource policies, enable automatic rotation, and remove unused secrets.",
        "additional_info": {"total_secrets": total, "secrets_with_issues": len(non_compliant)}
    }


def sebi_securityhub_compliance_score(session, scan_meta_data):
    """SEBI-CSCRF-ENH-05: Calculate Security Hub compliance scoring."""
    print("Running sebi_securityhub_compliance_score...")
    service = "SecurityHub"
    non_compliant = []
    total = 0
    standards_scores = {}

    try:
        sh = session.client("securityhub")
        # Get enabled standards
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        if not standards:
            non_compliant.append({
                "resource": "SecurityHub",
                "reason": "No security standards enabled",
                "pass_rate": 0
            })
        else:
            for std in standards:
                std_arn = std["StandardsSubscriptionArn"]
                std_name = std_arn.split("/")[-2] if "/" in std_arn else std_arn
                total_controls = 0
                passed = 0
                failed = 0
                try:
                    paginator = sh.get_paginator("describe_standards_controls")
                    for page in paginator.paginate(StandardsSubscriptionArn=std_arn):
                        for ctrl in page.get("Controls", []):
                            total_controls += 1
                            total += 1
                            status = ctrl.get("ComplianceStatus", "")
                            if status == "PASSED":
                                passed += 1
                            elif status == "FAILED":
                                failed += 1
                except Exception:
                    pass

                pass_rate = round((passed / total_controls * 100), 1) if total_controls > 0 else 0
                standards_scores[std_name] = {
                    "total_controls": total_controls,
                    "passed": passed,
                    "failed": failed,
                    "pass_rate": pass_rate
                }
                if pass_rate < 80:
                    non_compliant.append({
                        "resource": std_name,
                        "reason": f"Compliance pass rate {pass_rate}% is below 80% threshold",
                        "pass_rate": pass_rate,
                        "failed_controls": failed
                    })
    except Exception as e:
        if "not subscribed" in str(e).lower() or "InvalidAccessException" in str(e):
            non_compliant.append({"resource": "SecurityHub", "reason": "Security Hub not enabled"})
        else:
            non_compliant.append({"resource": "SecurityHub", "reason": str(e)[:200]})

    update_scan_meta(scan_meta_data, service, max(total, 1), len(non_compliant), "High")
    return {
        "check_name": "Security Hub Compliance Score",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-05",
        "problem_statement": "Low Security Hub compliance scores indicate systemic security control failures across the environment.",
        "severity_score": 8.0,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Remediate failed Security Hub controls prioritizing critical/high severity. Target 90%+ pass rate across all enabled standards.",
        "additional_info": {"standards_scores": standards_scores, "total_controls_evaluated": total}
    }


def sebi_ransomware_readiness(session, scan_meta_data):
    """SEBI-CSCRF-ENH-06: Ransomware readiness assessment."""
    print("Running sebi_ransomware_readiness...")
    service = "Multi-Service"
    non_compliant = []
    total = 0
    score = 0
    max_score = 60
    breakdown = {}

    # 1. Backup vault lock (10 pts)
    total += 1
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        locked = [v for v in vaults if v.get("Locked")]
        if locked:
            score += 10
            breakdown["backup_vault_lock"] = "PASS"
        else:
            breakdown["backup_vault_lock"] = "FAIL"
            non_compliant.append({"resource": "Backup Vaults", "reason": "No backup vaults with vault lock enabled"})
    except Exception:
        breakdown["backup_vault_lock"] = "ERROR"

    # 2. S3 versioning + MFA delete (10 pts)
    total += 1
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        versioned_mfa = 0
        for b in buckets[:20]:  # Sample
            try:
                v = s3.get_bucket_versioning(Bucket=b["Name"])
                if v.get("Status") == "Enabled" and v.get("MFADelete") == "Enabled":
                    versioned_mfa += 1
            except Exception:
                pass
        if versioned_mfa > 0:
            score += 10
            breakdown["s3_versioning_mfa_delete"] = "PASS"
        else:
            breakdown["s3_versioning_mfa_delete"] = "FAIL"
            non_compliant.append({"resource": "S3 Buckets", "reason": "No buckets with versioning + MFA delete enabled"})
    except Exception:
        breakdown["s3_versioning_mfa_delete"] = "ERROR"

    # 3. GuardDuty malware protection (10 pts)
    total += 1
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        malware_enabled = False
        for det_id in detectors:
            det = gd.get_detector(DetectorId=det_id)
            features = det.get("Features", [])
            for f in features:
                if f.get("Name") == "EBS_MALWARE_PROTECTION" and f.get("Status") == "ENABLED":
                    malware_enabled = True
                    break
        if malware_enabled:
            score += 10
            breakdown["guardduty_malware"] = "PASS"
        else:
            breakdown["guardduty_malware"] = "FAIL"
            non_compliant.append({"resource": "GuardDuty", "reason": "Malware protection not enabled"})
    except Exception:
        breakdown["guardduty_malware"] = "ERROR"

    # 4. Cross-region backups (10 pts)
    total += 1
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        cross_region = False
        for plan in plans:
            try:
                detail = backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"])
                rules = detail.get("BackupPlan", {}).get("Rules", [])
                for rule in rules:
                    if rule.get("CopyActions"):
                        cross_region = True
                        break
            except Exception:
                pass
            if cross_region:
                break
        if cross_region:
            score += 10
            breakdown["cross_region_backups"] = "PASS"
        else:
            breakdown["cross_region_backups"] = "FAIL"
            non_compliant.append({"resource": "Backup Plans", "reason": "No cross-region backup copy rules configured"})
    except Exception:
        breakdown["cross_region_backups"] = "ERROR"

    # 5. Deletion protection on RDS (10 pts)
    total += 1
    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        if instances:
            protected = [i for i in instances if i.get("DeletionProtection")]
            if len(protected) == len(instances):
                score += 10
                breakdown["deletion_protection"] = "PASS"
            else:
                breakdown["deletion_protection"] = "FAIL"
                non_compliant.append({
                    "resource": "RDS Instances",
                    "reason": f"{len(instances) - len(protected)}/{len(instances)} instances without deletion protection"
                })
        else:
            score += 10
            breakdown["deletion_protection"] = "PASS (no instances)"
    except Exception:
        breakdown["deletion_protection"] = "ERROR"

    # 6. Immutable backups / S3 Object Lock (10 pts)
    total += 1
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        object_lock_found = False
        for b in buckets[:20]:
            try:
                olc = s3.get_object_lock_configuration(Bucket=b["Name"])
                if olc.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled":
                    object_lock_found = True
                    break
            except Exception:
                pass
        if object_lock_found:
            score += 10
            breakdown["immutable_backups"] = "PASS"
        else:
            breakdown["immutable_backups"] = "FAIL"
            non_compliant.append({"resource": "S3 Buckets", "reason": "No S3 buckets with Object Lock for immutable backups"})
    except Exception:
        breakdown["immutable_backups"] = "ERROR"

    readiness_pct = round((score / max_score) * 100, 1)
    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "Critical")
    return {
        "check_name": "Ransomware Readiness Assessment",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-06",
        "problem_statement": "Insufficient ransomware protection controls expose the organization to data loss and extortion attacks.",
        "severity_score": 9.5,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Enable backup vault locks, S3 MFA delete, GuardDuty malware protection, cross-region backups, deletion protection, and immutable storage.",
        "additional_info": {"ransomware_readiness_score": readiness_pct, "score": f"{score}/{max_score}", "breakdown": breakdown}
    }


def sebi_enhanced_data_localization(session, scan_meta_data):
    """SEBI-CSCRF-ENH-07: Deep data localization check for India regions."""
    print("Running sebi_enhanced_data_localization...")
    service = "Multi-Service"
    non_compliant = []
    total = 0

    # 1. CloudTrail log bucket region
    try:
        ct = session.client("cloudtrail")
        s3 = session.client("s3")
        trails = ct.describe_trails().get("trailList", [])
        for trail in trails:
            total += 1
            bucket_name = trail.get("S3BucketName", "")
            if bucket_name:
                try:
                    loc = s3.get_bucket_location(Bucket=bucket_name)
                    region = loc.get("LocationConstraint") or "us-east-1"
                    if region not in INDIA_REGIONS:
                        non_compliant.append({
                            "resource": f"CloudTrail bucket: {bucket_name}",
                            "reason": f"Log bucket in {region} (not in India)",
                            "region": region
                        })
                except Exception:
                    pass
    except Exception:
        pass

    # 2. Backup vault regions
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        for vault in vaults:
            total += 1
            arn = vault.get("BackupVaultArn", "")
            # Extract region from ARN
            parts = arn.split(":")
            if len(parts) > 3:
                region = parts[3]
                if region not in INDIA_REGIONS:
                    non_compliant.append({
                        "resource": f"Backup Vault: {vault.get('BackupVaultName', '')}",
                        "reason": f"Vault in {region} (not in India)",
                        "region": region
                    })
    except Exception:
        pass

    # 3. ECR repositories
    try:
        ecr = session.client("ecr")
        repos = ecr.describe_repositories().get("repositories", [])
        for repo in repos:
            total += 1
            arn = repo.get("repositoryArn", "")
            parts = arn.split(":")
            if len(parts) > 3:
                region = parts[3]
                if region not in INDIA_REGIONS:
                    non_compliant.append({
                        "resource": f"ECR: {repo.get('repositoryName', '')}",
                        "reason": f"Repository in {region}",
                        "region": region
                    })
    except Exception:
        pass

    # 4. EFS file systems
    try:
        efs = session.client("efs")
        filesystems = efs.describe_file_systems().get("FileSystems", [])
        for fs in filesystems:
            total += 1
            # EFS is regional - check current session region
            arn = fs.get("FileSystemArn", "")
            parts = arn.split(":")
            if len(parts) > 3:
                region = parts[3]
                if region not in INDIA_REGIONS:
                    non_compliant.append({
                        "resource": f"EFS: {fs.get('FileSystemId', '')}",
                        "reason": f"File system in {region}",
                        "region": region
                    })
    except Exception:
        pass

    # 5. OpenSearch domains
    try:
        os_client = session.client("opensearch")
        domains = os_client.list_domain_names().get("DomainNames", [])
        for domain in domains:
            total += 1
            try:
                detail = os_client.describe_domain(DomainName=domain["DomainName"])
                arn = detail.get("DomainStatus", {}).get("ARN", "")
                parts = arn.split(":")
                if len(parts) > 3:
                    region = parts[3]
                    if region not in INDIA_REGIONS:
                        non_compliant.append({
                            "resource": f"OpenSearch: {domain['DomainName']}",
                            "reason": f"Domain in {region}",
                            "region": region
                        })
            except Exception:
                pass
    except Exception:
        pass

    # 6. Lambda functions
    try:
        lam = session.client("lambda")
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                total += 1
                arn = func.get("FunctionArn", "")
                parts = arn.split(":")
                if len(parts) > 3:
                    region = parts[3]
                    if region not in INDIA_REGIONS:
                        non_compliant.append({
                            "resource": f"Lambda: {func.get('FunctionName', '')}",
                            "reason": f"Function in {region}",
                            "region": region
                        })
    except Exception:
        pass

    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "Enhanced Data Localization Check",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-07",
        "problem_statement": "SEBI mandates data localization within India. Resources outside ap-south-1/ap-south-2 violate regulatory requirements.",
        "severity_score": 8.5,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Migrate all resources and data stores to ap-south-1 or ap-south-2 regions to comply with SEBI data localization requirements.",
        "additional_info": {"total_resources_checked": total, "resources_outside_india": len(non_compliant), "allowed_regions": INDIA_REGIONS}
    }


def sebi_vulnerability_aging(session, scan_meta_data):
    """SEBI-CSCRF-ENH-08: Check vulnerability aging from Inspector and Security Hub."""
    print("Running sebi_vulnerability_aging...")
    service = "Inspector/SecurityHub"
    non_compliant = []
    total = 0
    now = datetime.now(timezone.utc)
    aging_summary = {"critical_over_30d": 0, "high_over_60d": 0, "medium_over_90d": 0}

    # Check Security Hub findings for aging
    try:
        sh = session.client("securityhub")
        # Critical findings > 30 days
        critical_filters = {
            "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "CreatedAt": [{"DateRange": {"Value": 30, "Unit": "DAYS"}}]
        }
        try:
            resp = sh.get_findings(Filters={
                "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            }, MaxResults=100)
            for finding in resp.get("Findings", []):
                total += 1
                created = finding.get("CreatedAt", "")
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        age = (now - created_dt).days
                        if age > 30:
                            aging_summary["critical_over_30d"] += 1
                    except Exception:
                        pass
        except Exception:
            pass

        # High findings > 60 days
        try:
            resp = sh.get_findings(Filters={
                "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            }, MaxResults=100)
            for finding in resp.get("Findings", []):
                total += 1
                created = finding.get("CreatedAt", "")
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        age = (now - created_dt).days
                        if age > 60:
                            aging_summary["high_over_60d"] += 1
                    except Exception:
                        pass
        except Exception:
            pass

        # Medium findings > 90 days
        try:
            resp = sh.get_findings(Filters={
                "SeverityLabel": [{"Value": "MEDIUM", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            }, MaxResults=100)
            for finding in resp.get("Findings", []):
                total += 1
                created = finding.get("CreatedAt", "")
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        age = (now - created_dt).days
                        if age > 90:
                            aging_summary["medium_over_90d"] += 1
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass

    # Check Inspector findings
    try:
        inspector = session.client("inspector2")
        try:
            resp = inspector.list_findings(
                filterCriteria={
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
                },
                maxResults=100
            )
            for finding in resp.get("findings", []):
                total += 1
                created = finding.get("firstObservedAt")
                severity = finding.get("severity", "")
                if created:
                    age = (now - created).days
                    if severity == "CRITICAL" and age > 30:
                        aging_summary["critical_over_30d"] += 1
                    elif severity == "HIGH" and age > 60:
                        aging_summary["high_over_60d"] += 1
                    elif severity == "MEDIUM" and age > 90:
                        aging_summary["medium_over_90d"] += 1
        except Exception:
            pass
    except Exception:
        pass

    aged_total = sum(aging_summary.values())
    if aging_summary["critical_over_30d"] > 0:
        non_compliant.append({
            "resource": "Critical Vulnerabilities",
            "reason": f"{aging_summary['critical_over_30d']} critical findings older than 30 days",
            "count": aging_summary["critical_over_30d"],
            "threshold": "30 days"
        })
    if aging_summary["high_over_60d"] > 0:
        non_compliant.append({
            "resource": "High Vulnerabilities",
            "reason": f"{aging_summary['high_over_60d']} high findings older than 60 days",
            "count": aging_summary["high_over_60d"],
            "threshold": "60 days"
        })
    if aging_summary["medium_over_90d"] > 0:
        non_compliant.append({
            "resource": "Medium Vulnerabilities",
            "reason": f"{aging_summary['medium_over_90d']} medium findings older than 90 days",
            "count": aging_summary["medium_over_90d"],
            "threshold": "90 days"
        })

    update_scan_meta(scan_meta_data, service, max(total, 1), len(non_compliant), "High")
    return {
        "check_name": "Vulnerability Aging Analysis",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-08",
        "problem_statement": "Unresolved vulnerabilities beyond SLA thresholds indicate inadequate vulnerability management processes.",
        "severity_score": 8.0,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Remediate critical vulnerabilities within 30 days, high within 60 days, and medium within 90 days per SEBI CSCRF timelines.",
        "additional_info": {"aging_summary": aging_summary, "total_aged_findings": aged_total, "total_findings_checked": total}
    }


def sebi_attack_path_analysis(session, scan_meta_data):
    """SEBI-CSCRF-ENH-09: Identify dangerous attack path combinations."""
    print("Running sebi_attack_path_analysis...")
    service = "Multi-Service"
    non_compliant = []
    total = 0

    # 1. Public EC2 + Admin Role
    try:
        ec2 = session.client("ec2")
        iam = session.client("iam")
        instances = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
        for res in instances.get("Reservations", []):
            for inst in res.get("Instances", []):
                total += 1
                public_ip = inst.get("PublicIpAddress")
                if public_ip:
                    profile = inst.get("IamInstanceProfile", {})
                    if profile:
                        profile_arn = profile.get("Arn", "")
                        profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else ""
                        if profile_name:
                            try:
                                ip_resp = iam.get_instance_profile(InstanceProfileName=profile_name)
                                roles = ip_resp.get("InstanceProfile", {}).get("Roles", [])
                                for role in roles:
                                    try:
                                        policies = iam.list_attached_role_policies(RoleName=role["RoleName"])
                                        for pol in policies.get("AttachedPolicies", []):
                                            if "AdministratorAccess" in pol.get("PolicyName", ""):
                                                non_compliant.append({
                                                    "resource": inst["InstanceId"],
                                                    "reason": "Public EC2 with AdministratorAccess role - critical attack path",
                                                    "attack_path": "Public EC2 + Admin Role",
                                                    "public_ip": public_ip,
                                                    "role": role["RoleName"]
                                                })
                                    except Exception:
                                        pass
                            except Exception:
                                pass
    except Exception:
        pass

    # 2. Public RDS + No Encryption
    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        for db in instances:
            total += 1
            if db.get("PubliclyAccessible") and not db.get("StorageEncrypted"):
                non_compliant.append({
                    "resource": db["DBInstanceIdentifier"],
                    "reason": "Publicly accessible RDS without encryption - data exposure risk",
                    "attack_path": "Public RDS + No Encryption",
                    "engine": db.get("Engine", "")
                })
    except Exception:
        pass

    # 3. Public S3 + Sensitive data tags
    try:
        s3 = session.client("s3")
        s3control = session.client("s3control")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            total += 1
            try:
                # Check if public
                acl = s3.get_bucket_acl(Bucket=bucket["Name"])
                is_public = False
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]:
                        is_public = True
                        break
                if is_public:
                    # Check tags for sensitive classification
                    try:
                        tags = s3.get_bucket_tagging(Bucket=bucket["Name"]).get("TagSet", [])
                        for tag in tags:
                            if tag.get("Key", "").lower() in ["dataclassification", "data-classification", "sensitivity"]:
                                if tag.get("Value", "").lower() in ["confidential", "sensitive", "restricted", "pii"]:
                                    non_compliant.append({
                                        "resource": bucket["Name"],
                                        "reason": "Public S3 bucket with sensitive data classification tag",
                                        "attack_path": "Public S3 + Sensitive Data",
                                        "classification": tag["Value"]
                                    })
                                    break
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass

    # 4. Internet-facing LB + No WAF + No logging
    try:
        elbv2 = session.client("elbv2")
        waf = session.client("wafv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            total += 1
            if lb.get("Scheme") == "internet-facing":
                lb_arn = lb["LoadBalancerArn"]
                has_waf = False
                has_logging = False
                # Check WAF
                try:
                    waf_resp = waf.get_web_acl_for_resource(ResourceArn=lb_arn)
                    if waf_resp.get("WebACL"):
                        has_waf = True
                except Exception:
                    pass
                # Check logging
                try:
                    attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                    for attr in attrs.get("Attributes", []):
                        if attr.get("Key") == "access_logs.s3.enabled" and attr.get("Value") == "true":
                            has_logging = True
                except Exception:
                    pass
                if not has_waf and not has_logging:
                    non_compliant.append({
                        "resource": lb.get("LoadBalancerName", ""),
                        "reason": "Internet-facing LB without WAF and without access logging",
                        "attack_path": "Public LB + No WAF + No Logging",
                        "lb_arn": lb_arn
                    })
    except Exception:
        pass

    update_scan_meta(scan_meta_data, service, max(total, 1), len(non_compliant), "Critical")
    return {
        "check_name": "Attack Path Analysis",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-09",
        "problem_statement": "Dangerous combinations of misconfigurations create exploitable attack paths that could lead to data breaches.",
        "severity_score": 9.5,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Remediate attack paths immediately: remove public access from sensitive resources, enforce least-privilege roles, enable WAF and logging on all internet-facing resources.",
        "additional_info": {"total_resources_analyzed": total, "attack_paths_found": len(non_compliant)}
    }


def sebi_cyber_resilience_score(session, scan_meta_data):
    """SEBI-CSCRF-ENH-10: Calculate overall SEBI Cyber Resilience Score (0-100)."""
    print("Running sebi_cyber_resilience_score...")
    service = "Multi-Service"
    non_compliant = []
    total = 10
    score = 0
    breakdown = {}

    # 1. GuardDuty enabled (10pts)
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if detectors:
            score += 10
            breakdown["guardduty_enabled"] = 10
        else:
            breakdown["guardduty_enabled"] = 0
            non_compliant.append({"resource": "GuardDuty", "reason": "Not enabled", "points_lost": 10})
    except Exception:
        breakdown["guardduty_enabled"] = 0

    # 2. Security Hub enabled (10pts)
    try:
        sh = session.client("securityhub")
        sh.describe_hub()
        score += 10
        breakdown["securityhub_enabled"] = 10
    except Exception:
        breakdown["securityhub_enabled"] = 0
        non_compliant.append({"resource": "Security Hub", "reason": "Not enabled", "points_lost": 10})

    # 3. Config enabled (10pts)
    try:
        config = session.client("config")
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if recorders:
            status = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            if any(s.get("recording") for s in status):
                score += 10
                breakdown["config_enabled"] = 10
            else:
                breakdown["config_enabled"] = 0
                non_compliant.append({"resource": "AWS Config", "reason": "Recorder not recording", "points_lost": 10})
        else:
            breakdown["config_enabled"] = 0
            non_compliant.append({"resource": "AWS Config", "reason": "No recorder configured", "points_lost": 10})
    except Exception:
        breakdown["config_enabled"] = 0

    # 4. CloudTrail multi-region (10pts)
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
        if multi_region:
            score += 10
            breakdown["cloudtrail_multiregion"] = 10
        else:
            breakdown["cloudtrail_multiregion"] = 0
            non_compliant.append({"resource": "CloudTrail", "reason": "No multi-region trail", "points_lost": 10})
    except Exception:
        breakdown["cloudtrail_multiregion"] = 0

    # 5. Backup vaults with lock (10pts)
    try:
        backup = session.client("backup")
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        locked = [v for v in vaults if v.get("Locked")]
        if locked:
            score += 10
            breakdown["backup_vault_lock"] = 10
        else:
            breakdown["backup_vault_lock"] = 0
            non_compliant.append({"resource": "Backup Vaults", "reason": "No vaults with lock enabled", "points_lost": 10})
    except Exception:
        breakdown["backup_vault_lock"] = 0

    # 6. Encryption at rest coverage (10pts) - check RDS + S3
    try:
        enc_score = 0
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        if instances:
            encrypted = [i for i in instances if i.get("StorageEncrypted")]
            if len(encrypted) == len(instances):
                enc_score += 5
        else:
            enc_score += 5
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        encrypted_buckets = 0
        checked = 0
        for b in buckets[:10]:
            checked += 1
            try:
                s3.get_bucket_encryption(Bucket=b["Name"])
                encrypted_buckets += 1
            except Exception:
                pass
        if checked == 0 or encrypted_buckets == checked:
            enc_score += 5
        score += enc_score
        breakdown["encryption_at_rest"] = enc_score
        if enc_score < 10:
            non_compliant.append({"resource": "Encryption", "reason": "Incomplete encryption at rest coverage", "points_lost": 10 - enc_score})
    except Exception:
        breakdown["encryption_at_rest"] = 0

    # 7. MFA coverage (10pts)
    try:
        iam = session.client("iam")
        users = iam.list_users().get("Users", [])
        if users:
            mfa_users = 0
            for user in users:
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
                if mfa:
                    mfa_users += 1
            coverage = mfa_users / len(users) if users else 1
            pts = int(coverage * 10)
            score += pts
            breakdown["mfa_coverage"] = pts
            if pts < 10:
                non_compliant.append({"resource": "IAM MFA", "reason": f"MFA coverage {int(coverage*100)}%", "points_lost": 10 - pts})
        else:
            score += 10
            breakdown["mfa_coverage"] = 10
    except Exception:
        breakdown["mfa_coverage"] = 0

    # 8. VPC flow logs (10pts)
    try:
        ec2 = session.client("ec2")
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        if vpcs:
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
            vpc_ids_with_logs = {fl.get("ResourceId") for fl in flow_logs}
            all_covered = all(v["VpcId"] in vpc_ids_with_logs for v in vpcs)
            if all_covered:
                score += 10
                breakdown["vpc_flow_logs"] = 10
            else:
                breakdown["vpc_flow_logs"] = 0
                non_compliant.append({"resource": "VPC Flow Logs", "reason": "Not all VPCs have flow logs enabled", "points_lost": 10})
        else:
            score += 10
            breakdown["vpc_flow_logs"] = 10
    except Exception:
        breakdown["vpc_flow_logs"] = 0

    # 9. WAF coverage (10pts)
    try:
        elbv2 = session.client("elbv2")
        waf = session.client("wafv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        internet_facing = [lb for lb in lbs if lb.get("Scheme") == "internet-facing"]
        if internet_facing:
            waf_count = 0
            for lb in internet_facing:
                try:
                    resp = waf.get_web_acl_for_resource(ResourceArn=lb["LoadBalancerArn"])
                    if resp.get("WebACL"):
                        waf_count += 1
                except Exception:
                    pass
            coverage = waf_count / len(internet_facing)
            pts = int(coverage * 10)
            score += pts
            breakdown["waf_coverage"] = pts
            if pts < 10:
                non_compliant.append({"resource": "WAF", "reason": f"WAF covers {waf_count}/{len(internet_facing)} internet-facing LBs", "points_lost": 10 - pts})
        else:
            score += 10
            breakdown["waf_coverage"] = 10
    except Exception:
        breakdown["waf_coverage"] = 0

    # 10. No critical findings (10pts)
    try:
        sh = session.client("securityhub")
        resp = sh.get_findings(Filters={
            "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
        }, MaxResults=1)
        if not resp.get("Findings"):
            score += 10
            breakdown["no_critical_findings"] = 10
        else:
            breakdown["no_critical_findings"] = 0
            non_compliant.append({"resource": "Critical Findings", "reason": "Active critical findings exist", "points_lost": 10})
    except Exception:
        breakdown["no_critical_findings"] = 5  # Benefit of doubt if SH not available
        score += 5

    update_scan_meta(scan_meta_data, service, total, len(non_compliant), "High")
    return {
        "check_name": "SEBI Cyber Resilience Score",
        "service": service,
        "framework": "SEBI CSCRF 2024",
        "control_id": "SEBI-CSCRF-ENH-10",
        "problem_statement": "Overall cyber resilience posture assessment based on SEBI CSCRF 2024 key security controls.",
        "severity_score": 8.0,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Address all gaps identified in the resilience score breakdown. Target a minimum score of 80/100 for SEBI CSCRF compliance.",
        "additional_info": {"cyber_resilience_score": score, "max_score": 100, "breakdown": breakdown, "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"}
    }
