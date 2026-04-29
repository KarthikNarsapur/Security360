"""CloudFront security checks (4 checks)."""


def check_cloudfront_default_cert(session, scan_meta_data):
    print("check_cloudfront_default_cert")
    cf = session.client("cloudfront")
    resources = []
    items = cf.list_distributions().get("DistributionList", {}).get("Items", []) or []

    for dist in items:
        cert = dist.get("ViewerCertificate", {})
        if cert.get("CloudFrontDefaultCertificate", False):
            resources.append({
                "resource_name": dist.get("Id"),
                "domain": dist.get("DomainName"),
                "aliases": dist.get("Aliases", {}).get("Items", []),
                "issue": "Using default *.cloudfront.net SSL certificate.",
            })

    scan_meta_data["total_scanned"] += len(items)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Low"] += len(resources)
    if "CloudFront" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudFront")

    return {
        "check_name": "CloudFront Default SSL Certificate",
        "service": "CloudFront",
        "problem_statement": "CloudFront distributions use the default SSL certificate instead of a custom one.",
        "severity_score": 25, "severity_level": "Low",
        "resources_affected": resources,
        "recommendation": "Use a custom SSL certificate from ACM for branded domains.",
        "additional_info": {"total_scanned": len(items), "affected": len(resources)},
    }


def check_cloudfront_waf(session, scan_meta_data):
    print("check_cloudfront_waf")
    cf = session.client("cloudfront")
    resources = []
    items = cf.list_distributions().get("DistributionList", {}).get("Items", []) or []

    for dist in items:
        if not dist.get("WebACLId"):
            resources.append({
                "resource_name": dist.get("Id"),
                "domain": dist.get("DomainName"),
                "issue": "No WAF Web ACL associated.",
            })

    scan_meta_data["total_scanned"] += len(items)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "CloudFront" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudFront")

    return {
        "check_name": "CloudFront Without WAF",
        "service": "CloudFront",
        "problem_statement": "CloudFront distributions lack WAF protection against web attacks.",
        "severity_score": 60, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Associate a WAF Web ACL with all CloudFront distributions.",
        "additional_info": {"total_scanned": len(items), "affected": len(resources)},
    }


def check_cloudfront_min_tls(session, scan_meta_data):
    print("check_cloudfront_min_tls")
    cf = session.client("cloudfront")
    resources = []
    items = cf.list_distributions().get("DistributionList", {}).get("Items", []) or []
    weak_protocols = ["SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"]

    for dist in items:
        cert = dist.get("ViewerCertificate", {})
        min_proto = cert.get("MinimumProtocolVersion", "")
        if min_proto in weak_protocols:
            resources.append({
                "resource_name": dist.get("Id"),
                "domain": dist.get("DomainName"),
                "min_protocol": min_proto,
                "issue": f"Minimum TLS version is {min_proto} (should be TLSv1.2_2021+).",
            })

    scan_meta_data["total_scanned"] += len(items)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "CloudFront" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudFront")

    return {
        "check_name": "CloudFront Minimum TLS Version",
        "service": "CloudFront",
        "problem_statement": "CloudFront distributions allow TLS versions below 1.2.",
        "severity_score": 60, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Set minimum protocol version to TLSv1.2_2021 or higher.",
        "additional_info": {"total_scanned": len(items), "affected": len(resources)},
    }


def check_cloudfront_origin_protocol(session, scan_meta_data):
    print("check_cloudfront_origin_protocol")
    cf = session.client("cloudfront")
    resources = []
    items = cf.list_distributions().get("DistributionList", {}).get("Items", []) or []

    for dist in items:
        origins = dist.get("Origins", {}).get("Items", [])
        for origin in origins:
            custom = origin.get("CustomOriginConfig", {})
            if custom and custom.get("OriginProtocolPolicy") == "http-only":
                resources.append({
                    "resource_name": dist.get("Id"),
                    "domain": dist.get("DomainName"),
                    "origin_domain": origin.get("DomainName"),
                    "protocol_policy": "http-only",
                    "issue": "Origin uses HTTP-only protocol.",
                })

    scan_meta_data["total_scanned"] += len(items)
    scan_meta_data["affected"] += len(resources)
    scan_meta_data["Medium"] += len(resources)
    if "CloudFront" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CloudFront")

    return {
        "check_name": "CloudFront Origin Protocol Policy",
        "service": "CloudFront",
        "problem_statement": "CloudFront origins use HTTP-only, sending data unencrypted to the origin.",
        "severity_score": 65, "severity_level": "Medium",
        "resources_affected": resources,
        "recommendation": "Set origin protocol policy to 'https-only' or 'match-viewer'.",
        "additional_info": {"total_scanned": len(items), "affected": len(resources)},
    }
