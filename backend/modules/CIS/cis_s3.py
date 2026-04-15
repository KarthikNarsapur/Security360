import boto3
from datetime import datetime, timezone, timedelta
import json

IST = timezone(timedelta(hours=5, minutes=30))


def check_s3_block_public_access(session):
    # [S3.1]
    print("Checking S3 block public access settings")

    s3control = session.client("s3control")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        response = s3control.get_public_access_block(AccountId=account_id)

        public_access_block = response.get("PublicAccessBlockConfiguration", {})

        required_settings = [
            ("BlockPublicAcls", "Block public ACLs"),
            ("IgnorePublicAcls", "Ignore public ACLs"),
            ("BlockPublicPolicy", "Block public bucket policies"),
            ("RestrictPublicBuckets", "Restrict public bucket policies"),
        ]

        missing_settings = []
        for setting, description in required_settings:
            if not public_access_block.get(setting, False):
                missing_settings.append(description)

        if missing_settings:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "issue": f"Missing S3 block public access settings: {', '.join(missing_settings)}",
                    "region": region,
                    "resource_type": "Account-level S3 Public Access Block",
                    "resource_identifier": f"Account ID {account_id}",
                    "details": {
                        "missing_settings": missing_settings,
                        "effect": "Buckets in this account may be publicly accessible due to missing block settings",
                    },
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = 1
        affected = len(resources_affected)

        return {
            "id": "S3.1",
            "check_name": "S3 Block Public Access",
            "problem_statement": "S3 general purpose buckets should have block public access settings enabled",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable all S3 block public access settings at the account level",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon S3 service",
                "2. Go to 'Block Public Access settings' for the account",
                "3. Click 'Edit'",
                "4. Enable all four block public access settings:",
                "   - Block public ACLs",
                "   - Ignore public ACLs",
                "   - Block public bucket policies",
                "   - Restrict public bucket policies",
                "5. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except Exception as e:
        if (
            e.response.get("Error", {}).get("Code")
            == "NoSuchPublicAccessBlockConfiguration"
        ):
            total_scanned = 1
            affected = len(resources_affected)
            resources_affected.append(
                {
                    "account_id": account_id,
                    "issue": "No S3 block public access configuration exists",
                    "region": region,
                    "resource_type": "Account-level S3 Public Access Block",
                    "resource_identifier": f"Account ID {account_id}",
                    "details": {
                        "effect": "All S3 buckets in this account might be exposed to public access",
                    },
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )
            return {
                "id": "S3.1",
                "check_name": "S3 Block Public Access",
                "problem_statement": "S3 general purpose buckets should have block public access settings enabled",
                "severity_score": 60,
                "severity_level": "Medium",
                "resources_affected": resources_affected,
                "status": "passed" if affected == 0 else "failed",
                "recommendation": "Enable all S3 block public access settings at the account level",
                "additional_info": {
                    "total_scanned": total_scanned,
                    "affected": affected,
                },
                "remediation_steps": [
                    "1. Navigate to Amazon S3 service",
                    "2. Go to 'Block Public Access settings' for the account",
                    "3. Click 'Edit'",
                    "4. Enable all four block public access settings:",
                    "   - Block public ACLs",
                    "   - Ignore public ACLs",
                    "   - Block public bucket policies",
                    "   - Restrict public bucket policies",
                    "5. Save changes",
                ],
                "last_updated": datetime.now(IST).isoformat(),
            }

        return None


def check_s3_ssl_requirement(session):
    # [S3.5]
    print("Checking S3 bucket SSL requirements")

    s3 = session.client("s3")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "{}")
                policy_json = json.loads(policy)

                has_ssl_requirement = False
                for statement in policy_json.get("Statement", []):
                    condition = statement.get("Condition", {})
                    secure_transport = condition.get("Bool", {}).get(
                        "aws:SecureTransport", ""
                    )
                    if (
                        isinstance(secure_transport, str)
                        and secure_transport.lower() == "true"
                    ):
                        has_ssl_requirement = True
                        break
                    if isinstance(secure_transport, bool) and secure_transport:
                        has_ssl_requirement = True
                        break

                if not has_ssl_requirement:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_type": "S3 Bucket",
                            "issue": "Bucket policy does not require SSL",
                            "region": region,
                            "details": {
                                "policy_enforces_ssl": False,
                                "effect": "Requests to this bucket may succeed without using SSL, risking data exposure",
                            },
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

            except s3.exceptions.from_code("NoSuchBucketPolicy"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": bucket_name,
                        "resource_type": "S3 Bucket",
                        "issue": "No bucket policy exists to enforce SSL",
                        "region": region,
                        "details": {
                            "policy_exists": False,
                            "effect": "No SSL enforcement possible without a bucket policy, leaving the bucket open to non-SSL requests",
                        },
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

            except Exception as e:
                print(f"Error checking bucket {bucket_name}: {e}")
                continue

        total_scanned = len(buckets)
        affected = len(resources_affected)

        return {
            "id": "S3.5",
            "check_name": "S3 SSL Requirement",
            "problem_statement": "S3 buckets should require requests to use SSL",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Add SSL requirement to S3 bucket policies",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon S3 service",
                "2. Select the bucket",
                "3. Go to 'Permissions' tab",
                "4. Click 'Bucket Policy'",
                "5. Add a statement with Condition:",
                "   'Bool': {'aws:SecureTransport': 'false'}",
                "   and Effect: 'Deny'",
                "6. Save the policy",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 SSL requirements: {e}")
        return None


def check_s3_bucket_public_access_block(session):
    # [S3.8]
    print("Checking S3 bucket-level block public access settings")

    s3 = session.client("s3")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                public_access_block = response.get("PublicAccessBlockConfiguration", {})

                required_settings = [
                    ("BlockPublicAcls", "Block public ACLs"),
                    ("IgnorePublicAcls", "Ignore public ACLs"),
                    ("BlockPublicPolicy", "Block public bucket policies"),
                    ("RestrictPublicBuckets", "Restrict public bucket policies"),
                ]

                missing_settings = []
                for setting, description in required_settings:
                    if not public_access_block.get(setting, False):
                        missing_settings.append(description)

                if missing_settings:
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_type": "S3 Bucket",
                            "issue": f"Missing bucket-level block public access settings: {', '.join(missing_settings)}",
                            "region": region,
                            "details": {
                                "missing_settings": missing_settings,
                                "impact": "Public access is not fully restricted at bucket level, increasing risk of data exposure",
                            },
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )
            
            except Exception as e:
                print(f"Error checking bucket {bucket_name}: {e}")
                continue

        total_scanned = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.8",
            "check_name": "S3 Bucket Public Access Block",
            "problem_statement": "S3 buckets should block public access at the bucket level",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable all block public access settings at the bucket level",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon S3 service",
                "2. Select the bucket",
                "3. Go to 'Permissions' tab",
                "4. Click 'Edit' for Block Public Access settings",
                "5. Enable all four settings:",
                "   - Block public ACLs",
                "   - Ignore public ACLs",
                "   - Block public bucket policies",
                "   - Restrict public bucket policies",
                "6. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        resources_affected.append(
            {
                "account_id": account_id,
                "resource_id": bucket_name,
                "resource_type": "S3 Bucket",
                "issue": "No bucket-level block public access configuration exists",
                "region": region,
                "details": {
                    "impact": "Bucket is vulnerable to public access due to missing block public access settings",
                },
                "last_updated": datetime.now(IST).isoformat(),
            }
        )
        total_scanned = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.8",
            "check_name": "S3 Bucket Public Access Block",
            "problem_statement": "S3 buckets should block public access at the bucket level",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable all block public access settings at the bucket level",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon S3 service",
                "2. Select the bucket",
                "3. Go to 'Permissions' tab",
                "4. Click 'Edit' for Block Public Access settings",
                "5. Enable all four settings:",
                "   - Block public ACLs",
                "   - Ignore public ACLs",
                "   - Block public bucket policies",
                "   - Restrict public bucket policies",
                "6. Save changes",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }


    except Exception as e:
        print(f"Error checking S3 bucket public access blocks: {e}")
        return None


def check_s3_mfa_delete(session):
    # [S3.20]
    print("Checking S3 bucket MFA delete configuration")

    s3 = session.client("s3")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)

                if versioning.get("Status") != "Enabled":
                    continue

                try:
                    lifecycle = s3.get_bucket_lifecycle_configuration(
                        Bucket=bucket_name
                    )
                    continue
                except:
                    pass

                if versioning.get("MFADelete") != "Enabled":
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": bucket_name,
                            "resource_type": "S3 Bucket",
                            "issue": "MFA delete not enabled for versioned bucket",
                            "region": region,
                            "details": {
                                "versioning_status": versioning.get(
                                    "Status", "Unknown"
                                ),
                                "mfa_delete_status": versioning.get(
                                    "MFADelete", "Disabled or Not Set"
                                ),
                                "impact": "Without MFA delete enabled, accidental or unauthorized deletion of objects or versions is easier",
                                "note": "MFA delete can only be enabled or disabled by the bucket owner using root account credentials",
                            },
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

            except Exception as e:
                print(f"Error checking bucket {bucket_name}: {e}")
                continue

        total_scanned = len(buckets)
        affected = len(resources_affected)
        return {
            "id": "S3.20",
            "check_name": "S3 MFA Delete",
            "problem_statement": "S3 versioned buckets should have MFA delete enabled",
            "severity_score": 30,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable MFA delete for versioned S3 buckets",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to Amazon S3 service",
                "2. Select the versioned bucket",
                "3. Go to 'Properties' tab",
                "4. Click 'Edit' for Bucket Versioning",
                "5. Enable 'MFA delete'",
                "6. Enter MFA code from your device",
                "7. Save changes",
                "Note: Requires bucket owner's root account credentials",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 MFA delete: {e}")
        return None


def check_s3_object_write_logging(session):
    # [S3.22]
    print("Checking S3 object-level write event logging in CloudTrail")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        trails = cloudtrail.list_trails().get("Trails", [])
        has_compliant_trail = False

        for trail in trails:
            trail_name = trail["Name"]
            trail_info = cloudtrail.get_trail(Name=trail_name).get("Trail", {})

            if trail_info.get("IsMultiRegionTrail", False):
                event_selectors = cloudtrail.get_event_selectors(
                    TrailName=trail_name
                ).get("EventSelectors", [])

                for selector in event_selectors:
                    if selector.get("IncludeManagementEvents", False):
                        data_resources = selector.get("DataResources", [])

                        for resource in data_resources:
                            if resource.get("Type") == "AWS::S3::Object":
                                values = resource.get("Values", [])
                                if any("arn:aws:s3" in val.lower() for val in values):
                                    if selector.get("ReadWriteType") in [
                                        "WriteOnly",
                                        "All",
                                    ]:
                                        has_compliant_trail = True
                                        break

        if not has_compliant_trail:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_type": "CloudTrail",
                    "issue": "No multi-region CloudTrail configured to log S3 object-level write events",
                    "region": region,
                    "details": {
                        "checked_trails_count": len(trails),
                        "requirement": "Trail must be multi-region and log AWS::S3::Object data events with WriteOnly or All ReadWriteType",
                        "impact": "Without these logs, write operations on S3 objects may go unmonitored, risking undetected unauthorized or accidental changes.",
                    },
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = len(trails)
        affected = len(resources_affected)

        return {
            "id": "S3.22",
            "check_name": "S3 Object Write Logging",
            "problem_statement": "S3 buckets should log object-level write events in CloudTrail",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Configure a multi-region CloudTrail to log S3 object write events",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to CloudTrail service",
                "2. Create or edit a multi-region trail",
                "3. Under 'Data events', add S3 as a data event type",
                "4. Select 'Write only' or 'All' for event type",
                "5. Specify S3 buckets to monitor (or all buckets)",
                "6. Save the trail configuration",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 object write logging: {e}")
        return None


def check_s3_object_read_logging(session):
    # [S3.23]
    print("Checking S3 object-level read event logging in CloudTrail")

    cloudtrail = session.client("cloudtrail")
    sts = session.client("sts")

    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        region = session.region_name

        trails = cloudtrail.list_trails().get("Trails", [])
        has_compliant_trail = False

        for trail in trails:
            trail_name = trail["Name"]
            trail_info = cloudtrail.get_trail(Name=trail_name).get("Trail", {})

            if trail_info.get("IsMultiRegionTrail", False):
                event_selectors = cloudtrail.get_event_selectors(
                    TrailName=trail_name
                ).get("EventSelectors", [])

                for selector in event_selectors:
                    if selector.get("IncludeManagementEvents", False):
                        data_resources = selector.get("DataResources", [])

                        for resource in data_resources:
                            if resource.get("Type") == "AWS::S3::Object":
                                values = resource.get("Values", [])
                                if any("arn:aws:s3" in val.lower() for val in values):
                                    if selector.get("ReadWriteType") in [
                                        "ReadOnly",
                                        "All",
                                    ]:
                                        has_compliant_trail = True
                                        break

        if not has_compliant_trail:
            resources_affected.append(
                {
                    "account_id": account_id,
                    "resource_type": "CloudTrail",
                    "issue": "No multi-region CloudTrail configured to log S3 object-level read events",
                    "region": region,
                    "details": {
                        "checked_trails_count": len(trails),
                        "requirement": "Trail must be multi-region and include AWS::S3::Object data events with ReadOnly or All ReadWriteType",
                        "impact": "Object read operations (e.g., downloads) from S3 may go unmonitored, increasing risk of data exfiltration without audit trail.",
                    },
                    "last_updated": datetime.now(IST).isoformat(),
                }
            )

        total_scanned = len(trails)
        affected = len(resources_affected)

        return {
            "id": "S3.23",
            "check_name": "S3 Object Read Logging",
            "problem_statement": "S3 buckets should log object-level read events in CloudTrail",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Configure a multi-region CloudTrail to log S3 object read events",
            "additional_info": {
                "total_scanned": total_scanned,
                "affected": affected,
            },
            "remediation_steps": [
                "1. Navigate to CloudTrail service",
                "2. Create or edit a multi-region trail",
                "3. Under 'Data events', add S3 as a data event type",
                "4. Select 'Read only' or 'All' for event type",
                "5. Specify S3 buckets to monitor (or all buckets)",
                "6. Save the trail configuration",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking S3 object read logging: {e}")
        return None
