"""
Data Sensitivity Analysis Engine

Identifies resources likely containing sensitive data based on:
- Naming patterns (PII, financial, health, credentials)
- Macie findings (if enabled)
- Encryption status
- Access patterns

All APIs: s3:List*, s3:Get*, macie2:Get*, macie2:List*,
          rds:Describe*, dynamodb:Describe* — all in ReadOnlyAccess.
"""

import re
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

# Patterns that suggest sensitive data
SENSITIVE_NAME_PATTERNS = [
    (re.compile(r"(pii|personal|ssn|social.?security|passport)", re.I), "PII"),
    (re.compile(r"(financial|payment|billing|invoice|credit.?card|bank)", re.I), "Financial"),
    (re.compile(r"(health|hipaa|medical|patient|pharma)", re.I), "Healthcare"),
    (re.compile(r"(secret|credential|password|token|key|auth)", re.I), "Credentials"),
    (re.compile(r"(backup|archive|disaster.?recovery|dr)", re.I), "Backup"),
    (re.compile(r"(log|audit|trail|compliance)", re.I), "Audit/Compliance"),
    (re.compile(r"(customer|user.?data|client|account)", re.I), "Customer Data"),
    (re.compile(r"(prod|production)", re.I), "Production"),
]


def analyze_data_sensitivity(session, scan_meta_data_global_services):
    """
    Analyze S3 buckets, RDS instances, and DynamoDB tables for
    data sensitivity indicators.
    """
    print("analyze_data_sensitivity")
    resources_affected = []

    # ── S3 Buckets ───────────────────────────────────────────────────────
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            risk_factors = []
            sensitivity_tags = set()

            # Check name patterns
            for pattern, label in SENSITIVE_NAME_PATTERNS:
                if pattern.search(bucket_name):
                    sensitivity_tags.add(label)

            # Check bucket tags
            try:
                tags = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
                tag_dict = {t["Key"].lower(): t["Value"].lower() for t in tags}

                for key, value in tag_dict.items():
                    for pattern, label in SENSITIVE_NAME_PATTERNS:
                        if pattern.search(key) or pattern.search(value):
                            sensitivity_tags.add(label)

                # Check classification tags
                if "classification" in tag_dict:
                    classification = tag_dict["classification"]
                    if classification in ("confidential", "restricted", "sensitive", "internal"):
                        sensitivity_tags.add(f"Tagged: {classification}")

                if "environment" in tag_dict and tag_dict["environment"] in ("prod", "production"):
                    sensitivity_tags.add("Production")

            except Exception:
                pass  # No tags

            # Check encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if not rules:
                    risk_factors.append("No encryption configured")
                else:
                    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                    if algo == "AES256":
                        risk_factors.append("Using AES-256 (consider CMK for sensitive data)")
            except Exception:
                risk_factors.append("No encryption configured")

            # Check public access
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration", {})
                if not all(pab.get(k, False) for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]):
                    risk_factors.append("Public access not fully blocked")
            except Exception:
                risk_factors.append("No public access block configured")

            # Check versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=bucket_name)
                if ver.get("Status") != "Enabled":
                    risk_factors.append("Versioning not enabled")
            except Exception:
                pass

            if sensitivity_tags:
                exposure = "High" if "Public access not fully blocked" in risk_factors else \
                           "Medium" if "No encryption configured" in risk_factors else "Low"
                resources_affected.append({
                    "resource_name": bucket_name,
                    "resource_type": "S3 Bucket",
                    "sensitivity_classification": ", ".join(sorted(sensitivity_tags)),
                    "exposure_level": exposure,
                    "risk_factors": "; ".join(risk_factors) if risk_factors else "None",
                    "issue": f"Bucket likely contains {', '.join(sorted(sensitivity_tags))} data. Exposure: {exposure}.",
                })

    except Exception as e:
        print(f"Error analyzing S3 sensitivity: {e}")

    # ── RDS Instances ────────────────────────────────────────────────────
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])

        for db in dbs:
            db_id = db.get("DBInstanceIdentifier", "")
            db_name = db.get("DBName", "")
            sensitivity_tags = set()
            risk_factors = []

            # Check name patterns
            for name in [db_id, db_name]:
                for pattern, label in SENSITIVE_NAME_PATTERNS:
                    if pattern.search(name):
                        sensitivity_tags.add(label)

            # Check tags
            try:
                tag_list = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"]).get("TagList", [])
                for tag in tag_list:
                    for pattern, label in SENSITIVE_NAME_PATTERNS:
                        if pattern.search(tag.get("Key", "")) or pattern.search(tag.get("Value", "")):
                            sensitivity_tags.add(label)
            except Exception:
                pass

            # Check encryption
            if not db.get("StorageEncrypted"):
                risk_factors.append("Storage not encrypted")

            # Check public access
            if db.get("PubliclyAccessible"):
                risk_factors.append("Publicly accessible")

            if sensitivity_tags:
                exposure = "Critical" if "Publicly accessible" in risk_factors and "Storage not encrypted" in risk_factors else \
                           "High" if "Publicly accessible" in risk_factors else \
                           "Medium" if "Storage not encrypted" in risk_factors else "Low"
                resources_affected.append({
                    "resource_name": db_id,
                    "resource_type": "RDS Instance",
                    "engine": db.get("Engine"),
                    "sensitivity_classification": ", ".join(sorted(sensitivity_tags)),
                    "exposure_level": exposure,
                    "risk_factors": "; ".join(risk_factors) if risk_factors else "None",
                    "issue": f"Database likely contains {', '.join(sorted(sensitivity_tags))} data. Exposure: {exposure}.",
                })

    except Exception as e:
        print(f"Error analyzing RDS sensitivity: {e}")

    # ── DynamoDB Tables ──────────────────────────────────────────────────
    try:
        dynamodb = session.client("dynamodb")
        tables = dynamodb.list_tables().get("TableNames", [])

        for table_name in tables:
            sensitivity_tags = set()
            risk_factors = []

            for pattern, label in SENSITIVE_NAME_PATTERNS:
                if pattern.search(table_name):
                    sensitivity_tags.add(label)

            try:
                desc = dynamodb.describe_table(TableName=table_name)["Table"]
                sse = desc.get("SSEDescription", {})
                if not sse or sse.get("Status") != "ENABLED":
                    risk_factors.append("Encryption not using CMK")

                # Check tags
                tags = dynamodb.list_tags_of_resource(ResourceArn=desc["TableArn"]).get("Tags", [])
                for tag in tags:
                    for pattern, label in SENSITIVE_NAME_PATTERNS:
                        if pattern.search(tag.get("Key", "")) or pattern.search(tag.get("Value", "")):
                            sensitivity_tags.add(label)
            except Exception:
                pass

            if sensitivity_tags:
                resources_affected.append({
                    "resource_name": table_name,
                    "resource_type": "DynamoDB Table",
                    "sensitivity_classification": ", ".join(sorted(sensitivity_tags)),
                    "exposure_level": "Medium" if risk_factors else "Low",
                    "risk_factors": "; ".join(risk_factors) if risk_factors else "None",
                    "issue": f"Table likely contains {', '.join(sorted(sensitivity_tags))} data.",
                })

    except Exception as e:
        print(f"Error analyzing DynamoDB sensitivity: {e}")

    # ── Macie Integration (if enabled) ───────────────────────────────────
    try:
        macie = session.client("macie2")
        macie.get_macie_session()  # Check if enabled

        # Get recent findings summary
        findings = macie.list_findings(
            findingCriteria={"criterion": {"severity.description": {"eq": ["High", "Critical"]}}},
            maxResults=10,
        ).get("findingIds", [])

        if findings:
            finding_details = macie.get_findings(findingIds=findings[:10]).get("findings", [])
            for f in finding_details:
                bucket = f.get("resourcesAffected", {}).get("s3Bucket", {}).get("name", "Unknown")
                resources_affected.append({
                    "resource_name": bucket,
                    "resource_type": "S3 Bucket (Macie Finding)",
                    "sensitivity_classification": f.get("type", "Unknown"),
                    "exposure_level": "High",
                    "risk_factors": f.get("description", ""),
                    "issue": f"Macie detected sensitive data: {f.get('type', '')}",
                })
    except Exception:
        pass  # Macie not enabled — skip silently

    # Sort by exposure level
    exposure_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    resources_affected.sort(key=lambda x: exposure_order.get(x.get("exposure_level", "Low"), 4))

    scan_meta_data_global_services["total_scanned"] += 1
    scan_meta_data_global_services["affected"] += len(resources_affected)
    high_exposure = len([r for r in resources_affected if r["exposure_level"] in ("Critical", "High")])
    scan_meta_data_global_services["High"] += high_exposure
    scan_meta_data_global_services["Medium"] += len(resources_affected) - high_exposure

    severity = "High" if high_exposure else "Medium" if resources_affected else "Low"

    return {
        "check_name": "Data Sensitivity Analysis",
        "service": "Data Classification",
        "problem_statement": "Resources containing potentially sensitive data have been identified based on naming patterns, tags, and security posture.",
        "severity_score": 75 if high_exposure else 50 if resources_affected else 10,
        "severity_level": severity,
        "resources_affected": resources_affected,
        "recommendation": "Review identified resources. Apply encryption, restrict access, enable logging, and consider enabling Amazon Macie for automated data discovery.",
        "additional_info": {
            "total_scanned": 1,
            "affected": len(resources_affected),
            "high_exposure_resources": high_exposure,
            "classifications_found": list(set(
                tag for r in resources_affected
                for tag in r.get("sensitivity_classification", "").split(", ")
            )),
        },
    }
