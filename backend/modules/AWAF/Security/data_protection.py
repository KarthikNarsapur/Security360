from datetime import datetime, timezone, timedelta
import boto3

IST = timezone(timedelta(hours=5, minutes=30))


def check_sec07_bp01_understand_data_classification(session):
    print("SEC07-BP01 focuses on organizational data classification practices")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_data_classification_identify_data.html"

    return {
        "id": "SEC07-BP01",
        "check_name": "Understand your data classification scheme",
        "problem_statement": "Define and maintain a clear data classification scheme for your organization.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Establish a formal data classification model outlining sensitivity levels and handling requirements."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Develop a multi-tier data classification model.",
            "2. Identify data owners for each category.",
            "3. Document handling procedures for each classification level.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec07_bp02_apply_controls_by_sensitivity(session):
    print("SEC07-BP02 is about applying data protection based on sensitivity levels")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_data_classification_define_protection.html"

    return {
        "id": "SEC07-BP02",
        "check_name": "Apply data protection controls based on sensitivity",
        "problem_statement": "Protect data using controls aligned with its sensitivity level.",
        "severity_score": 70,
        "severity_level": "High",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Align encryption, retention, and access controls with your data classification categories."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Map protection requirements for each data classification tier.",
            "2. Enforce encryption standards in storage and transit.",
            "3. Apply access restrictions using IAM and resource policies.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec07_bp03_automate_data_classification(session):
    print("SEC07-BP03 focuses on automated mechanisms for data identification")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_data_classification_auto_classification.html"

    return {
        "id": "SEC07-BP03",
        "check_name": "Automate identification and classification",
        "problem_statement": "Automate identification and ongoing classification of sensitive data.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Implement tools like Amazon Macie or custom workflows to automate data discovery and classification."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Enable automated scanning tools such as Amazon Macie.",
            "2. Configure classification rules based on your data policy.",
            "3. Integrate classification output into security workflows.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec07_bp04_data_lifecycle_management(session):
    print("Checking Macie status for SEC07-BP04")

    macie = session.client("macie2")
    sts = session.client("sts")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_data_classification_lifecycle_management.html"
    resources_affected = []
    total_scanned = 1

    try:
        account_id = sts.get_caller_identity()["Account"]

        try:
            macie_status = macie.get_macie_session()
            is_macie_enabled = macie_status.get("status") == "ENABLED"
        except macie.exceptions.AccessDeniedException:
            is_macie_enabled = False

        if not is_macie_enabled:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": account_id,
                    "issue": "Amazon Macie is not enabled for data discovery and lifecycle workflows",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        affected = len(resources_affected)

        return {
            "id": "SEC07-BP04",
            "check_name": "Define scalable data lifecycle management",
            "problem_statement": "Implement scalable processes to manage data retention and lifecycle across storage systems.",
            "severity_score": 75,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable Amazon Macie and configure data lifecycle policies for long-term data management."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable Amazon Macie across all regions.",
                "2. Configure automated data discovery and classification jobs.",
                "3. Apply lifecycle policies using S3 Lifecycle rules or governance tools.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking SEC07-BP04: {e}")
        return None


def check_sec08_bp01_secure_key_management(session):
    print("SEC08-BP01 focuses on secure key management practices.")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_key_mgmt.html"

    return {
        "id": "SEC08-BP01",
        "check_name": "Implement secure key management",
        "problem_statement": "Establish secure processes for creating, storing, rotating, and protecting encryption keys.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Design and maintain a key management strategy using AWS KMS or external HSMs, "
            "ensuring proper rotation, access control, and monitoring."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Define a key management policy covering creation, rotation, and usage of keys.",
            "2. Use AWS KMS for centralized and auditable key operations.",
            "3. Implement strict IAM controls for key access and administration.",
            "4. Automate key rotation where applicable.",
            "5. Monitor key usage through AWS CloudTrail logs.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec08_bp02_encryption_at_rest(session):
    print("Running SEC08-BP02 encryption-at-rest checks")

    sts = session.client("sts")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    efs = session.client("efs")
    rds = session.client("rds")
    redshift = session.client("redshift")
    cloudfront = session.client("cloudfront")
    apigw = session.client("apigateway")
    sqs = session.client("sqs")
    eks = session.client("eks")
    lambda_client = session.client("lambda")
    cloudtrail = session.client("cloudtrail")

    resources_affected = []
    total_scanned = 0

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html"

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ----------------------------
        # 1) CloudTrail KMS requirement
        # ----------------------------
        trails = cloudtrail.describe_trails().get("trailList", [])
        total_scanned += len(trails)

        for trail in trails:
            if not trail.get("KmsKeyId"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": trail.get("Name"),
                        "issue": "CloudTrail is not encrypted with a CMK",
                        "resource_id_type": "cloudtrail",
                        "region": trail.get("HomeRegion"),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 2) EKS secrets encryption
        # ----------------------------
        eks_clusters = eks.list_clusters().get("clusters", [])
        total_scanned += len(eks_clusters)

        for name in eks_clusters:
            desc = eks.describe_cluster(name=name)["cluster"]
            encryption = desc.get("encryptionConfig", [])
            if not encryption:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "EKS cluster secrets encryption is not enabled",
                        "resource_id_type": "eks",
                        "region": desc.get("arn").split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 3) Lambda CMK encryption check
        # ----------------------------
        lambdas = lambda_client.list_functions().get("Functions", [])
        total_scanned += len(lambdas)

        for fn in lambdas:
            if "KMSKeyArn" not in fn:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": fn["FunctionName"],
                        "issue": "Lambda does not use CMK for encryption",
                        "resource_id_type": "lambda",
                        "region": fn["FunctionArn"].split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 4) S3 encryption
        # ----------------------------
        buckets = s3.list_buckets().get("Buckets", [])
        total_scanned += len(buckets)

        for bucket in buckets:
            name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                kms_enabled = any(
                    r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    == "aws:kms"
                    for r in rules
                )
                if not kms_enabled:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": name,
                            "issue": "S3 bucket is not using SSE-KMS encryption",
                            "resource_id_type": "s3",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "S3 bucket does not have any server-side encryption enabled",
                        "resource_id_type": "s3",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 5) EBS encryption
        # ----------------------------
        volumes = ec2.describe_volumes().get("Volumes", [])
        total_scanned += len(volumes)

        for vol in volumes:
            if not vol.get("Encrypted"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": vol["VolumeId"],
                        "issue": "EBS volume is not encrypted",
                        "resource_id_type": "ebs",
                        "region": vol["AvailabilityZone"][:-1],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 6) EFS encryption
        # ----------------------------
        efs_list = efs.describe_file_systems().get("FileSystems", [])
        total_scanned += len(efs_list)

        for fs in efs_list:
            if not fs.get("Encrypted"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": fs["FileSystemId"],
                        "issue": "EFS file system is not encrypted",
                        "resource_id_type": "efs",
                        "region": (
                            fs["AvailabilityZoneName"].split(":")[3]
                            if "AvailabilityZoneName" in fs
                            else "unknown"
                        ),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 7) RDS encryption
        # ----------------------------
        dbs = rds.describe_db_instances().get("DBInstances", [])
        total_scanned += len(dbs)

        for db in dbs:
            if not db.get("StorageEncrypted"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "issue": "RDS storage encryption is disabled",
                        "resource_id_type": "rds",
                        "region": db["AvailabilityZone"][:-1],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 8) Redshift encryption
        # ----------------------------
        clusters = redshift.describe_clusters().get("Clusters", [])
        total_scanned += len(clusters)

        for cl in clusters:
            if not cl.get("Encrypted"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cl["ClusterIdentifier"],
                        "issue": "Redshift cluster is not encrypted",
                        "resource_id_type": "redshift",
                        "region": cl["ClusterNamespaceArn"].split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 9) CloudFront field-level encryption
        # ----------------------------
        cfront = cloudfront.list_distributions().get("DistributionList", {})
        items = cfront.get("Items", [])
        total_scanned += len(items)

        for dist in items:
            if not dist.get("DefaultCacheBehavior", {}).get("FieldLevelEncryptionId"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist["Id"],
                        "issue": "CloudFront field-level encryption disabled",
                        "resource_id_type": "cloudfront",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------
        # 10) API Gateway encryption
        # ----------------------------
        apis = apigw.get_rest_apis().get("items", [])
        total_scanned += len(apis)

        for api in apis:
            # API Gateway does not expose encryption-at-rest attribute per API
            # We treat missing encryption config as non-compliant
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_id": api["id"],
                    "issue": "API Gateway encryption at rest / transit cannot be fully validated (manual review recommended)",
                    "resource_id_type": "apigateway",
                    "region": "global",
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        # ----------------------------
        # 11) SQS encryption
        # ----------------------------
        queues = sqs.list_queues().get("QueueUrls", [])
        total_scanned += len(queues)

        for qurl in queues:
            attrs = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["All"]).get(
                "Attributes", {}
            )
            if "KmsMasterKeyId" not in attrs:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": qurl,
                        "issue": "SQS queue is not encrypted with KMS",
                        "resource_id_type": "sqs",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # FINAL RESPONSE
        affected = len(resources_affected)

        return {
            "id": "SEC08-BP02",
            "check_name": "Enforce encryption at rest",
            "problem_statement": "Ensure all services store data in encrypted form using strong encryption keys.",
            "severity_score": 90,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable KMS-based encryption across all AWS services handling sensitive or persistent data."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable CMK encryption for S3, EBS, RDS, Lambda, and other storage-based services.",
                "2. Configure CloudTrail trails with KMS encryption.",
                "3. Enable EKS Secrets Encryption using CMK.",
                "4. Ensure SQS, CloudFront, and Redshift use encryption at rest.",
                "5. Apply uniform encryption policies across accounts and regions.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error running SEC08-BP02 encryption checks: {e}")
        return None


def check_sec08_bp03_automate_data_at_rest_protection(session):
    # SEC08-BP03 Automate data at rest protection
    print("SEC08-BP03 focuses on automation of data-at-rest protection")

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_automate_protection.html"

    return {
        "id": "SEC08-BP03",
        "check_name": "Automate data at rest protection",
        "problem_statement": "Automate protection and remediation of data-at-rest risks to ensure consistent control application.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "not_available",
        "recommendation": (
            "Use automation (e.g., guardrails, AWS Config rules, AWS Lambda, EventBridge) to detect and remediate weak data-at-rest protections."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Define AWS Config rules or SCPs to enforce encryption-at-rest standards.",
            "2. Implement automated workflows to remediate non-compliant resources.",
            "3. Audit and verify the automation process regularly for effectiveness.",
        ],
        "aws_doc_link": aws_doc_link,
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec08_bp04_enforce_access_control(session):
    print("Running SEC08-BP04 enforce access control checks")

    sts = session.client("sts")
    iam = session.client("iam")
    eks = session.client("eks")
    s3 = session.client("s3")
    sqs = session.client("sqs")
    lambda_client = session.client("lambda")
    ec2 = session.client("ec2")

    resources_affected = []
    total_scanned = 0

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_access_control.html"

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ----------------------------------------------------------------------
        # 1) S3 Versioning
        # ----------------------------------------------------------------------
        buckets = s3.list_buckets().get("Buckets", [])
        total_scanned += len(buckets)

        for bucket in buckets:
            name = bucket["Name"]

            # S3 VERSIONING
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get("Status") != "Enabled":
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": name,
                            "issue": "S3 bucket does not have versioning enabled",
                            "resource_id_type": "s3",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "Unable to check S3 versioning configuration",
                        "resource_id_type": "s3",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            # S3 OBJECT LOCK
            try:
                lock = s3.get_object_lock_configuration(Bucket=name)
                if "ObjectLockConfiguration" not in lock:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": name,
                            "issue": "S3 object lock is not enabled",
                            "resource_id_type": "s3",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "S3 bucket does not have object lock configuration",
                        "resource_id_type": "s3",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            # S3 PUBLIC ACCESS BLOCK
            try:
                pab = s3.get_public_access_block(Bucket=name)
                cfg = pab.get("PublicAccessBlockConfiguration", {})
                if not all(cfg.values()):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": name,
                            "issue": "S3 bucket does not fully block public access",
                            "resource_id_type": "s3",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except Exception:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "Public access block configuration missing for S3 bucket",
                        "resource_id_type": "s3",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # 2) SQS Dead Letter Queue + FIFO configuration
        # ----------------------------------------------------------------------
        queues = sqs.list_queues().get("QueueUrls", [])
        total_scanned += len(queues)

        for qurl in queues:
            attrs = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["All"]).get(
                "Attributes", {}
            )

            # DLQ
            if "RedrivePolicy" not in attrs:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": qurl,
                        "issue": "SQS queue does not have a Dead Letter Queue configured",
                        "resource_id_type": "sqs",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            # FIFO check
            if qurl.endswith(".fifo") and attrs.get("FifoQueue") != "true":
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": qurl,
                        "issue": "FIFO queue configuration is inconsistent",
                        "resource_id_type": "sqs",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # 3) EKS Cluster Role Least Privilege (best-effort detection)
        # ----------------------------------------------------------------------
        clusters = eks.list_clusters().get("clusters", [])
        total_scanned += len(clusters)

        for cluster in clusters:
            desc = eks.describe_cluster(name=cluster)["cluster"]
            role = desc.get("roleArn", "")
            if "Admin" in role or "FullAccess" in role:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": cluster,
                        "issue": "EKS cluster uses a role that may exceed least privilege",
                        "resource_id_type": "eks",
                        "region": desc["arn"].split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # 4) Lambda Role Reuse (basic check if same role is used excessively)
        # ----------------------------------------------------------------------
        functions = lambda_client.list_functions().get("Functions", [])
        total_scanned += len(functions)

        role_usage_map = {}
        for fn in functions:
            role = fn.get("Role")
            role_usage_map.setdefault(role, 0)
            role_usage_map[role] += 1

        for role, count in role_usage_map.items():
            if count > 10:  # heuristic threshold
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": role,
                        "issue": "Lambda execution role is reused excessively across functions",
                        "resource_id_type": "iam_role",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # 5) IAM Full Admin or Inline Admin Policies (best-effort)
        # ----------------------------------------------------------------------
        users = iam.list_users().get("Users", [])
        total_scanned += len(users)

        for user in users:
            uname = user["UserName"]

            # INLINE POLICIES
            inline_policies = iam.list_user_policies(UserName=uname).get(
                "PolicyNames", []
            )
            for pol in inline_policies:
                pol_doc = iam.get_user_policy(UserName=uname, PolicyName=pol)
                if '"Action": "*"' in str(pol_doc) or '"Effect": "Allow"' in str(
                    pol_doc
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": uname,
                            "issue": "User has inline policy with overly broad permissions",
                            "resource_id_type": "iam_user",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

            # ATTACHED POLICIES
            attached = iam.list_attached_user_policies(UserName=uname).get(
                "AttachedPolicies", []
            )
            for pol in attached:
                if "AdministratorAccess" in pol["PolicyName"]:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": uname,
                            "issue": "User has full administrative permissions attached",
                            "resource_id_type": "iam_user",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ----------------------------------------------------------------------
        # Final evaluation
        # ----------------------------------------------------------------------
        affected = len(resources_affected)

        return {
            "id": "SEC08-BP04",
            "check_name": "Enforce access control",
            "problem_statement": "Ensure strict access controls and least-privilege configurations across all data-related resources.",
            "severity_score": 85,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Review and correct access configurations, enforcing least-privilege, "
                "resource versioning, integrity controls, and secure queue and storage settings."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Enable S3 versioning, object lock, and public access blocks.",
                "2. Configure Dead Letter Queues and verify FIFO settings for SQS.",
                "3. Review IAM roles, inline policies, and attached policies for least privilege.",
                "4. Ensure EKS cluster roles and Lambda execution roles follow strict access boundaries.",
                "5. Regularly audit access control policies across your environment.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error running SEC08-BP04: {e}")
        return None


def check_sec09_bp01_secure_key_and_certificate_management(session):
    print(
        "Running SEC09-BP01 secure key and certificate management (no measurable AWS API checks)"
    )

    return {
        "id": "SEC09-BP01",
        "check_name": "Implement secure key and certificate management",
        "problem_statement": "Key and certificate management processes must follow best practices to maintain secure lifecycle operations.",
        "severity_score": 50,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Maintain strong governance for key and certificate lifecycle, including issuance, renewal, rotation, "
            "and revocation processes."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Use AWS Certificate Manager (ACM) for issuing and rotating certificates.",
            "2. Maintain clear ownership and lifecycle governance of all keys.",
            "3. Implement policies for regular inspection of certificate expirations.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_transit_key_cert_mgmt.html",
        "last_updated": datetime.now(IST).isoformat(),
    }


def check_sec09_bp02_enforce_encryption_in_transit(session):
    print("Running SEC09-BP02 encryption in transit checks")

    cloudfront = session.client("cloudfront")
    ec2 = session.client("ec2")
    s3 = session.client("s3")
    redshift = session.client("redshift")
    rds = session.client("rds")
    opensearch = session.client("opensearch")
    elasticache = session.client("elasticache")
    sqs = session.client("sqs")
    sts = session.client("sts")

    resources_affected = []
    total_scanned = 0

    aws_doc_link = "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_transit_encrypt.html"

    try:
        account_id = sts.get_caller_identity()["Account"]

        # ----------------------------------------------------------------------
        # CLOUDFRONT – viewer protocol HTTPS + TLS version
        # ----------------------------------------------------------------------
        distributions = cloudfront.list_distributions().get("DistributionList", {})
        items = distributions.get("Items", [])
        total_scanned += len(items)

        for dist in items:
            dist_id = dist["Id"]
            config = cloudfront.get_distribution_config(Id=dist_id)

            default_cache = config["DistributionConfig"]["DefaultCacheBehavior"]
            viewer_policy = default_cache["ViewerProtocolPolicy"]

            # viewerPolicyHttps
            if viewer_policy != "redirect-to-https":
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist_id,
                        "issue": "CloudFront distribution does not enforce HTTPS viewer policy",
                        "resource_id_type": "cloudfront",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            # Deprecated SSL protocols
            restrictions = config["DistributionConfig"].get("ViewerCertificate", {})
            if "MinimumProtocolVersion" in restrictions:
                proto = restrictions["MinimumProtocolVersion"]
                if "SSL" in proto or proto in ["TLSv1", "TLSv1_1"]:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": dist_id,
                            "issue": "CloudFront distribution uses deprecated SSL/TLS protocol",
                            "resource_id_type": "cloudfront",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ----------------------------------------------------------------------
        # SG Encryption In Transit (basic check: SG allowing insecure ports)
        # ----------------------------------------------------------------------
        security_groups = ec2.describe_security_groups().get("SecurityGroups", [])
        total_scanned += len(security_groups)

        for sg in security_groups:
            sgid = sg["GroupId"]
            for perm in sg.get("IpPermissions", []):
                if perm.get("FromPort") == 80:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": sgid,
                            "issue": "Security group allows unencrypted HTTP traffic (port 80)",
                            "resource_id_type": "security_group",
                            "region": (
                                sg["VpcId"].split(":")[3]
                                if "VpcId" in sg
                                else "unknown"
                            ),
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ----------------------------------------------------------------------
        # ELB insecure listener (HTTP or old SSL)
        # ----------------------------------------------------------------------
        elb = session.client("elbv2")
        lbs = elb.describe_load_balancers().get("LoadBalancers", [])
        total_scanned += len(lbs)

        for lb in lbs:
            listeners = elb.describe_listeners(
                LoadBalancerArn=lb["LoadBalancerArn"]
            ).get("Listeners", [])
            for l in listeners:
                if l["Protocol"] in ("HTTP", "SSL", "TLS") and l.get("Port") == 80:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": lb["LoadBalancerName"],
                            "issue": "Load balancer uses insecure listener configuration",
                            "resource_id_type": "elb",
                            "region": lb["AvailabilityZones"][0]["ZoneName"][:-1],
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        # ----------------------------------------------------------------------
        # S3 TLS enforcement
        # ----------------------------------------------------------------------
        buckets = s3.list_buckets().get("Buckets", [])
        total_scanned += len(buckets)

        for b in buckets:
            name = b["Name"]
            try:
                pol = s3.get_bucket_policy(Bucket=name)
                if "aws:SecureTransport" not in pol.get("Policy", ""):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": name,
                            "issue": "S3 bucket does not enforce TLS access",
                            "resource_id_type": "s3",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            except:
                # No policy → assume not enforced
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "S3 bucket missing secure transport enforcement",
                        "resource_id_type": "s3",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # REDSHIFT encryption in transit
        # ----------------------------------------------------------------------
        clusters = redshift.describe_clusters().get("Clusters", [])
        total_scanned += len(clusters)

        for c in clusters:
            if not c.get("Encrypted"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": c["ClusterIdentifier"],
                        "issue": "Redshift cluster lacks TLS encryption in transit",
                        "resource_id_type": "redshift",
                        "region": c["ClusterNamespaceArn"].split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # RDS PG/MSSQL transport encryption
        # ----------------------------------------------------------------------
        instances = rds.describe_db_instances().get("DBInstances", [])
        total_scanned += len(instances)

        for db in instances:
            if db["Engine"] in ["postgres", "sqlserver"] and not db.get(
                "IAMDatabaseAuthenticationEnabled", False
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": db["DBInstanceIdentifier"],
                        "issue": "RDS instance does not enforce transport encryption",
                        "resource_id_type": "rds",
                        "region": (
                            db["DBSubnetGroup"]["VpcId"].split(":")[3]
                            if "DBSubnetGroup" in db
                            else "unknown"
                        ),
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # OPENSEARCH encryption
        # ----------------------------------------------------------------------
        domains = opensearch.list_domain_names().get("DomainNames", [])
        total_scanned += len(domains)

        for domain in domains:
            name = domain["DomainName"]
            info = opensearch.describe_domain(DomainName=name)["DomainStatus"]

            if not info.get("NodeToNodeEncryptionOptions", {}).get("Enabled", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "OpenSearch domain lacks node-to-node encryption",
                        "resource_id_type": "opensearch",
                        "region": info["ARN"].split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            if not info.get("DomainEndpointOptions", {}).get("EnforceHTTPS", False):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": name,
                        "issue": "OpenSearch domain does not enforce TLS for endpoints",
                        "resource_id_type": "opensearch",
                        "region": info["ARN"].split(":")[3],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # ELASTICACHE encryption
        # ----------------------------------------------------------------------
        cache_clusters = elasticache.describe_cache_clusters().get("CacheClusters", [])
        total_scanned += len(cache_clusters)

        for c in cache_clusters:
            if not c.get("TransitEncryptionEnabled") or not c.get(
                "AtRestEncryptionEnabled"
            ):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": c["CacheClusterId"],
                        "issue": "ElastiCache cluster missing encryption in transit or at rest",
                        "resource_id_type": "elasticache",
                        "region": c["PreferredAvailabilityZone"][:-1],
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ----------------------------------------------------------------------
        # SQS encryption in transit (HTTPS enforced)
        # ----------------------------------------------------------------------
        queues = sqs.list_queues().get("QueueUrls", [])
        total_scanned += len(queues)

        for q in queues:
            if not q.startswith("https://"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": q,
                        "issue": "SQS queue endpoint is not accessed via TLS",
                        "resource_id_type": "sqs",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        # ------------------------------------------
        # Final summary
        # ------------------------------------------
        affected = len(resources_affected)

        return {
            "id": "SEC09-BP02",
            "check_name": "Enforce encryption in transit",
            "problem_statement": "Ensure all services enforce TLS encryption during data transmission.",
            "severity_score": 90,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": (
                "Enable TLS enforcement, disable outdated protocols, and configure secure listeners across "
                "all CloudFront, S3, EC2, ELB, RDS, Redshift, OpenSearch, and ElastiCache resources."
            ),
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Configure HTTPS-only policies and latest TLS versions.",
                "2. Remove insecure listeners (HTTP or deprecated TLS).",
                "3. Enforce aws:SecureTransport for S3.",
                "4. Enable encryption settings for RDS, Redshift, OpenSearch, and ElastiCache.",
            ],
            "aws_doc_link": aws_doc_link,
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error running SEC09-BP02: {e}")
        return None


def check_sec09_bp03_authenticate_network_communications(session):
    print(
        "Running SEC09-BP03 authenticate network communications (no measurable AWS API checks)"
    )

    return {
        "id": "SEC09-BP03",
        "check_name": "Authenticate network communications",
        "problem_statement": "Network communications must use strong authentication to ensure trusted connections.",
        "severity_score": 60,
        "severity_level": "Medium",
        "resources_affected": [],
        "status": "passed",
        "recommendation": (
            "Ensure all network paths use authenticated channels such as mTLS, SigV4, or identity-aware proxies."
        ),
        "additional_info": {"total_scanned": 0, "affected": 0},
        "remediation_steps": [
            "1. Implement mTLS for service-to-service authentication.",
            "2. Use SigV4 authentication for AWS-managed endpoints.",
            "3. Periodically review authentication posture.",
        ],
        "aws_doc_link": "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_transit_authentication.html",
        "last_updated": datetime.now(IST).isoformat(),
    }
