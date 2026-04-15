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
