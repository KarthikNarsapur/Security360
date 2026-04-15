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
