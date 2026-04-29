def public_s3_buckets(session, scan_meta_data_global_services):
    print("public_s3_buckets")
    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    public = []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})

            if not all(
                [
                    config.get("BlockPublicAcls", True),
                    config.get("IgnorePublicAcls", True),
                    config.get("BlockPublicPolicy", True),
                    config.get("RestrictPublicBuckets", True),
                ]
            ):
                public.append(
                    {
                        "resource_name": bucket_name,
                        "creation_date": str(bucket.get("CreationDate")),
                        "public_access_block_configuration": [config],
                        # "region": session.region_name,
                        # "arn": f"arn:aws:s3:::{bucket_name}",
                    }
                )
        except Exception as e:
            if (
                hasattr(e, "response")
                and e.response.get("Error", {}).get("Code")
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                # except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                public.append(
                    {
                        "resource_name": bucket_name,
                        "creation_date": str(bucket.get("CreationDate")),
                        "public_access_block_configuration": "Not configured",
                        # "region": session.region_name,
                        # "arn": f"arn:aws:s3:::{bucket_name}",
                    }
                )
        except Exception:
            continue
    scan_meta_data_global_services["total_scanned"] = scan_meta_data_global_services["total_scanned"] + len(buckets)
    scan_meta_data_global_services["affected"] = scan_meta_data_global_services["affected"] + len(public)
    scan_meta_data_global_services["High"] = scan_meta_data_global_services["High"] + len(public)
    scan_meta_data_global_services["services_scanned"].append("S3")

    return {
        "check_name": "Publicly Accessible S3 Buckets",
        "service":"S3",
        "problem_statement": "S3 buckets without proper public access block configuration are publicly accessible.",
        "severity_score": 90,
        "severity_level": "High",
        "resources_affected": public,
        "recommendation": "Enable all public access block settings to restrict public access to buckets.",
        "additional_info": {"total_scanned": len(buckets), "affected": len(public)},
    }


def wildcard_principal_bucket_policies(session, scan_meta_data_global_services):
    print("wildcard_principal_bucket_policies")
    import json

    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]
    risky_buckets = []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "{}")
            policy = json.loads(policy_str)

            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", {})
                effect = stmt.get("Effect", "")

                # Skip Deny statements — they restrict access, not grant it
                if effect == "Deny":
                    continue

                has_wildcard = False
                if principal == "*":
                    has_wildcard = True
                elif isinstance(principal, dict):
                    for key, value in principal.items():
                        values = value if isinstance(value, list) else [value]
                        if "*" in values:
                            has_wildcard = True
                            break

                if has_wildcard:
                    # Check if there's a restrictive Condition
                    condition = stmt.get("Condition", {})
                    if not condition:
                        risky_buckets.append({
                            "resource_name": bucket_name,
                            "creation_date": str(bucket.get("CreationDate")),
                            "statement_effect": effect,
                            "statement_action": str(stmt.get("Action", "")),
                            "principal": str(principal),
                            "note": "Bucket policy grants access to Principal \"*\" without conditions.",
                        })
                        break

        except s3.exceptions.from_code("NoSuchBucketPolicy"):
            continue
        except Exception as e:
            if "NoSuchBucketPolicy" in str(e):
                continue
            print(f"Error checking bucket policy for {bucket_name}: {e}")
            continue

    scan_meta_data_global_services["total_scanned"] += len(buckets)
    scan_meta_data_global_services["affected"] += len(risky_buckets)
    scan_meta_data_global_services["High"] += len(risky_buckets)
    if "S3" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("S3")

    return {
        "check_name": "S3 Bucket Policies with Wildcard Principal",
        "service": "S3",
        "problem_statement": "S3 bucket policies grant access to Principal \"*\" (anyone) without restrictive conditions.",
        "severity_score": 90,
        "severity_level": "High",
        "resources_affected": risky_buckets,
        "recommendation": "Remove wildcard principals from bucket policies or add restrictive Conditions (e.g., aws:SourceVpc, aws:SourceAccount).",
        "additional_info": {"total_scanned": len(buckets), "affected": len(risky_buckets)},
    }


def cross_account_bucket_sharing(session, scan_meta_data_global_services):
    print("cross_account_bucket_sharing")
    import json
    import re

    s3 = session.client("s3")
    sts = session.client("sts")
    buckets = s3.list_buckets()["Buckets"]
    shared_buckets = []

    try:
        current_account_id = sts.get_caller_identity()["Account"]
    except Exception:
        current_account_id = ""

    account_id_pattern = re.compile(r"\d{12}")

    for bucket in buckets:
        bucket_name = bucket["Name"]
        external_accounts = set()

        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "{}")
            policy = json.loads(policy_str)

            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                principal = stmt.get("Principal", {})
                if principal == "*":
                    continue  # Already caught by wildcard check

                principals_to_check = []
                if isinstance(principal, dict):
                    for key, value in principal.items():
                        values = value if isinstance(value, list) else [value]
                        principals_to_check.extend(values)
                elif isinstance(principal, str):
                    principals_to_check.append(principal)

                for p in principals_to_check:
                    # Extract account IDs from ARNs like arn:aws:iam::123456789012:root
                    matches = account_id_pattern.findall(str(p))
                    for account_id in matches:
                        if account_id != current_account_id:
                            external_accounts.add(account_id)

        except Exception as e:
            if "NoSuchBucketPolicy" in str(e):
                continue
            print(f"Error checking cross-account sharing for {bucket_name}: {e}")
            continue

        if external_accounts:
            shared_buckets.append({
                "resource_name": bucket_name,
                "creation_date": str(bucket.get("CreationDate")),
                "external_accounts": list(external_accounts),
                "note": f"Bucket policy grants access to {len(external_accounts)} external account(s).",
            })

    scan_meta_data_global_services["total_scanned"] += len(buckets)
    scan_meta_data_global_services["affected"] += len(shared_buckets)
    scan_meta_data_global_services["Medium"] += len(shared_buckets)
    if "S3" not in scan_meta_data_global_services["services_scanned"]:
        scan_meta_data_global_services["services_scanned"].append("S3")

    return {
        "check_name": "S3 Buckets Shared with External Accounts",
        "service": "S3",
        "problem_statement": "S3 bucket policies grant access to AWS accounts outside the current account.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": shared_buckets,
        "recommendation": "Review cross-account bucket sharing. Remove access for unknown accounts and ensure shared accounts are authorized.",
        "additional_info": {"total_scanned": len(buckets), "affected": len(shared_buckets)},
    }
