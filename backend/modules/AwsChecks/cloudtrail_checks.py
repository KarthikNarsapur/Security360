def cloudtrail_and_logging_check(session):
    print("cloudtrail_and_logging_check")

    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    print("trails in global: ", trails)

    best_trail = None
    best_score = -1
    best_findings = []

    for trail in trails:
        
        score = 0
        if trail.get("IsMultiRegionTrail"):
            score += 1
        if trail.get("KmsKeyId"):
            score += 1
        if trail.get("LogFileValidationEnabled"):
            score += 1
        if trail.get("CloudWatchLogsLogGroupArn"):
            score += 1

        if score > best_score:
            best_score = score
            best_trail = trail

    if best_trail:
        region = best_trail.get("HomeRegion", "Global")
        
        # Multi-region Logging
        multi_region = (
            "Enabled" if best_trail.get("IsMultiRegionTrail") else "Not Enabled"
        )
        best_findings.append(
            {
                "parameter": "Multi-Region Logging",
                "status": multi_region,
                "region": region,
                "recommendation": "Enable multi-region logging for centralized auditing",
            }
        )

        # S3 Encryption
        s3_encryption = "Enabled (AES-256)"
        if best_trail.get("KmsKeyId"):
            s3_encryption = "Enabled (KMS)"
        best_findings.append(
            {
                "parameter": "S3 Log Encryption",
                "status": s3_encryption,
                "region": region,
                "recommendation": "Upgrade to KMS encryption for enhanced key management",
            }
        )

        # Log File Validation
        log_val = (
            "Enabled" if best_trail.get("LogFileValidationEnabled") else "Not Enabled"
        )
        best_findings.append(
            {
                "parameter": "Log File Validation",
                "status": log_val,
                "region": region,
                "recommendation": "Enable log file validation for integrity protection",
            }
        )

        # CloudWatch Integration
        cloudwatch = (
            "Enabled" if best_trail.get("CloudWatchLogsLogGroupArn") else "Not Enabled"
        )
        best_findings.append(
            {
                "parameter": "CloudWatch Integration",
                "status": cloudwatch,
                "region": region,
                "recommendation": "Enable CloudWatch Logs integration for real-time monitoring"
            }
        )

    # scan_meta_data["services_scanned"].append("CloudTrail & Logging")

    return {
        "check_name": "CloudTrail & Logging",
        "service": "CloudTrail",
        "problem_statement": "CloudTrail is not optimally configured for centralized, auditable logging.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": best_findings,
        "recommendation": "Ensure multi-region logging, log integrity validation, and CloudWatch log streaming",
        "additional_info": {
            "total_scanned":0,
            "affected":0    
        },
    }


# def cloudtrail_and_logging_check(session, scan_meta_data):
#     print("cloudtrail_and_logging_check")

#     ct = session.client("cloudtrail")
#     trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

#     findings = []

#     for trail in trails:
#         region = session.region_name
#         trail_name = trail.get("Name", "-")

#         # ---- Multi-Region Logging ----
#         multi_region = "Enabled" if trail.get("IsMultiRegionTrail") else "Not Enabled"
#         findings.append({
#             "parameter": "Multi-Region Logging",
#             "status": multi_region,
#             "region": region,
#             "recommendation": "Good – Management-events trail active" if multi_region == "Enabled"
#                               else "Enable multi-region logging for centralized auditing"
#         })

#         # ---- S3 Encryption ----
#         s3_encryption = "Enabled (AES-256)"
#         if trail.get("KmsKeyId"):
#             s3_encryption = "Enabled (KMS)"

#         findings.append({
#             "parameter": "S3 Log Encryption",
#             "status": s3_encryption,
#             "region": region,
#             "recommendation": "Upgrade to KMS encryption for enhanced key management"
#                               if s3_encryption != "Enabled (KMS)" else "Good"
#         })

#         # ---- Log File Validation ----
#         log_validation = "Enabled" if trail.get("LogFileValidationEnabled") else "Not Enabled"
#         findings.append({
#             "parameter": "Log File Validation",
#             "status": log_validation,
#             "region": region,
#             "recommendation": "Good" if log_validation == "Enabled"
#                               else "Enable log file validation for integrity protection"
#         })

#         # ---- CloudWatch Integration ----
#         cloudwatch = "Enabled" if trail.get("CloudWatchLogsLogGroupArn") else "Not Enabled"
#         findings.append({
#             "parameter": "CloudWatch Integration",
#             "status": cloudwatch,
#             "region": region,
#             "recommendation": "Enable CloudWatch Logs integration for real-time monitoring"
#                               if cloudwatch == "Not Enabled" else "Good"
#         })

#     scan_meta_data["services_scanned"].append("CloudTrail & Logging")

#     return {
#         "check_name": "CloudTrail & Logging",
#         "service": "CloudTrail",
#         "problem_statement": "CloudTrail is not optimally configured for centralized, auditable logging.",
#         "severity_score": 70,
#         "severity_level": "Medium",
#         "resources_affected": findings,
#         "recommendation": "Ensure multi-region logging, log integrity validation, and CloudWatch log streaming",
#         "additional_info": {
#             "affected": len(findings),
#             "total_scanned": 4*len(trails)
#         },
#     }


def check_cloudtrail_log_immutability(session):
    print("check_cloudtrail_log_immutability")
    ct = session.client("cloudtrail")
    s3 = session.client("s3")
    resources = []

    trails = ct.describe_trails().get("trailList", [])
    for trail in trails:
        bucket_name = trail.get("S3BucketName")
        if not bucket_name:
            continue

        issues = []
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get("Status") != "Enabled":
                issues.append("S3 versioning not enabled")
        except Exception:
            issues.append("Could not check S3 versioning")

        try:
            lock = s3.get_object_lock_configuration(Bucket=bucket_name)
            if not lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled":
                issues.append("S3 Object Lock not enabled")
        except Exception:
            issues.append("S3 Object Lock not configured")

        if issues:
            resources.append({
                "resource_name": trail.get("Name"),
                "s3_bucket": bucket_name,
                "issues": "; ".join(issues),
            })

    return {
        "check_name": "CloudTrail Log Immutability",
        "service": "CloudTrail",
        "problem_statement": "CloudTrail log S3 buckets lack versioning or Object Lock, making logs vulnerable to tampering or deletion.",
        "severity_score": 75,
        "severity_level": "High",
        "resources_affected": resources,
        "recommendation": "Enable S3 versioning and Object Lock on CloudTrail log buckets to ensure log immutability.",
        "additional_info": {"total_scanned": len(trails), "affected": len(resources)},
    }


def check_centralized_logging_account(session):
    print("check_centralized_logging_account")
    ct = session.client("cloudtrail")
    sts = session.client("sts")
    resources = []

    try:
        current_account = sts.get_caller_identity()["Account"]
        trails = ct.describe_trails().get("trailList", [])

        all_local = True
        for trail in trails:
            # If trail's S3 bucket is in a different account, it's centralized
            # We can check if the trail is an organization trail
            if trail.get("IsOrganizationTrail"):
                all_local = False
                break

        if all_local and trails:
            resources.append({
                "resource_name": "CloudTrail Configuration",
                "current_account": current_account,
                "issue": "All CloudTrail trails log to the current account. No centralized logging account detected.",
            })
    except Exception as e:
        print(f"Error checking centralized logging: {e}")

    return {
        "check_name": "Centralized Logging Account",
        "service": "CloudTrail",
        "problem_statement": "CloudTrail logs are not sent to a centralized logging account, reducing audit isolation.",
        "severity_score": 45,
        "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Configure an organization trail that sends logs to a dedicated logging account for tamper-proof audit trails.",
        "additional_info": {"total_scanned": 1, "affected": len(resources)},
    }
