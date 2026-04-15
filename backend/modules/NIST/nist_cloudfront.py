import boto3
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def check_cloudfront_default_root_object(session):
    # [CloudFront.1]
    print("Checking CloudFront default root object configuration")

    cf = session.client("cloudfront")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        distributions = (
            cf.list_distributions().get("DistributionList", {}).get("Items", [])
        )

        for dist in distributions:
            dist_id = dist["Id"]
            config = cf.get_distribution_config(Id=dist_id)
            root_obj = config["DistributionConfig"].get("DefaultRootObject")
            if not root_obj:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist_id,
                        "resource_id_type": "CloudFrontDistribution",
                        "issue": "No DefaultRootObject configured for CloudFront distribution",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(distributions)
        affected = len(resources_affected)

        return {
            "id": "CloudFront.1",
            "check_name": "CloudFront default root object configured",
            "problem_statement": "CloudFront distributions should define a DefaultRootObject to avoid exposing directory listings or 403 errors.",
            "severity_score": 20,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Set DefaultRootObject (e.g., index.html) in the distribution configuration.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open the CloudFront console.",
                "2. Select the distribution.",
                "3. Choose 'Edit' and set Default Root Object (e.g., index.html).",
                "4. Save and deploy the distribution.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudFront default root object: {e}")
        return None


def check_cloudfront_viewer_policy_https(session):
    # [CloudFront.3]
    print("Checking CloudFront viewer policy HTTPS enforcement")

    cf = session.client("cloudfront")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        distributions = (
            cf.list_distributions().get("DistributionList", {}).get("Items", [])
        )

        for dist in distributions:
            dist_id = dist["Id"]
            config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
            behaviors = [config["DefaultCacheBehavior"]] + config.get(
                "CacheBehaviors", {}
            ).get("Items", [])
            for b in behaviors:
                viewer_policy = b.get("ViewerProtocolPolicy")
                if (
                    viewer_policy != "https-only"
                    and viewer_policy != "redirect-to-https"
                ):
                    resources_affected.append(
                        {
                            "account_id": account_id,
                            "resource_id": dist_id,
                            "resource_id_type": "CloudFrontDistribution",
                            "issue": f"ViewerProtocolPolicy set to '{viewer_policy}' (should enforce HTTPS).",
                            "region": "global",
                            "last_updated": datetime.now(IST).isoformat(),
                        }
                    )

        total_scanned = len(distributions)
        affected = len(resources_affected)

        return {
            "id": "CloudFront.3",
            "check_name": "CloudFront viewer policy enforces HTTPS",
            "problem_statement": "CloudFront distributions should enforce HTTPS for viewer connections.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Set ViewerProtocolPolicy to 'https-only' or 'redirect-to-https'.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Edit your CloudFront distribution behaviors.",
                "2. Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only'.",
                "3. Save and deploy changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudFront viewer HTTPS policy: {e}")
        return None


def check_cloudfront_origin_failover(session):
    # [CloudFront.4]
    print("Checking CloudFront origin failover configuration")

    cf = session.client("cloudfront")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        distributions = (
            cf.list_distributions().get("DistributionList", {}).get("Items", [])
        )

        for dist in distributions:
            dist_id = dist["Id"]
            config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
            origins = config.get("Origins", {}).get("Items", [])
            failover_found = any(
                "OriginGroup" in o or "OriginGroupId" in o for o in origins
            )
            if not failover_found:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist_id,
                        "resource_id_type": "CloudFrontDistribution",
                        "issue": "No origin failover configured",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(distributions)
        affected = len(resources_affected)
        return {
            "id": "CloudFront.4",
            "check_name": "CloudFront origin failover configured",
            "problem_statement": "Origin failover should be configured for high availability.",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Configure an origin group with primary and secondary origins.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Edit the CloudFront distribution origins.",
                "2. Create an origin group with primary and secondary origins.",
                "3. Save and deploy the distribution.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudFront origin failover: {e}")
        return None


def check_cloudfront_access_logging(session):
    # [CloudFront.5]
    print("Checking CloudFront access logging configuration")

    cf = session.client("cloudfront")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        distributions = (
            cf.list_distributions().get("DistributionList", {}).get("Items", [])
        )

        for dist in distributions:
            dist_id = dist["Id"]
            config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
            logging = config.get("Logging", {})
            if not logging.get("Enabled"):
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist_id,
                        "resource_id_type": "CloudFrontDistribution",
                        "issue": "Access logging not enabled",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(distributions)
        affected = len(resources_affected)
        return {
            "id": "CloudFront.5",
            "check_name": "CloudFront access logging enabled",
            "problem_statement": "Access logging should be enabled for CloudFront distributions.",
            "severity_score": 40,
            "severity_level": "Low",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Enable access logging for CloudFront distributions.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Edit your CloudFront distribution.",
                "2. Enable access logging and specify a target S3 bucket.",
                "3. Save and deploy changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudFront access logging: {e}")
        return None


def check_cloudfront_waf_association(session):
    # [CloudFront.6]
    print("Checking CloudFront WAF association")

    cf = session.client("cloudfront")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        distributions = (
            cf.list_distributions().get("DistributionList", {}).get("Items", [])
        )

        for dist in distributions:
            dist_id = dist["Id"]
            waf_id = dist.get("WebACLId")
            if not waf_id:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist_id,
                        "resource_id_type": "CloudFrontDistribution",
                        "issue": "No WAF associated with CloudFront distribution",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(distributions)
        affected = len(resources_affected)
        return {
            "id": "CloudFront.6",
            "check_name": "CloudFront WAF association",
            "problem_statement": "CloudFront distributions should have AWS WAF associated for request filtering.",
            "severity_score": 60,
            "severity_level": "Medium",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Associate AWS WAF with CloudFront distributions.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Open AWS WAF console.",
                "2. Create or select a WebACL.",
                "3. Associate it with the CloudFront distribution.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudFront WAF association: {e}")
        return None


def check_cloudfront_deprecated_ssl_protocol(session):
    # [CloudFront.10]
    print("Checking CloudFront deprecated SSL protocols")

    cf = session.client("cloudfront")
    sts = session.client("sts")
    resources_affected = []

    try:
        account_id = sts.get_caller_identity()["Account"]
        distributions = (
            cf.list_distributions().get("DistributionList", {}).get("Items", [])
        )

        deprecated_versions = ["TLSv1", "TLSv1.1"]

        for dist in distributions:
            dist_id = dist["Id"]
            config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
            viewer_cert = config.get("ViewerCertificate", {})
            min_version = viewer_cert.get("MinimumProtocolVersion", "")
            if min_version in deprecated_versions:
                resources_affected.append(
                    {
                        "account_id": account_id,
                        "resource_id": dist_id,
                        "resource_id_type": "CloudFrontDistribution",
                        "issue": f"Deprecated SSL protocol in use: {min_version}",
                        "region": "global",
                        "last_updated": datetime.now(IST).isoformat(),
                    }
                )

        total_scanned = len(distributions)
        affected = len(resources_affected)
        return {
            "id": "CloudFront.10",
            "check_name": "CloudFront deprecated SSL protocols",
            "problem_statement": "CloudFront distributions should not use deprecated SSL/TLS versions.",
            "severity_score": 70,
            "severity_level": "High",
            "resources_affected": resources_affected,
            "status": "passed" if affected == 0 else "failed",
            "recommendation": "Use TLSv1.2_2021 or higher for CloudFront distributions.",
            "additional_info": {"total_scanned": total_scanned, "affected": affected},
            "remediation_steps": [
                "1. Edit your CloudFront distribution.",
                "2. Under SSL/TLS settings, choose 'TLSv1.2_2021' or newer.",
                "3. Save and deploy changes.",
            ],
            "last_updated": datetime.now(IST).isoformat(),
        }

    except Exception as e:
        print(f"Error checking CloudFront deprecated SSL protocol: {e}")
        return None
