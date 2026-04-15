from modules.Website.OWASP.owasp_checks import (
    owasp_https_not_enforced,
    owasp_ssl_tls_version,
    owasp_ssl_certificate_validity,
    owasp_security_headers_missing,
    owasp_cookies_not_secure,
    owasp_sensitive_data_in_url,
    owasp_open_redirect,
    owasp_directory_listing_enabled,
    owasp_cors_misconfiguration,
    owasp_error_messages_verbose,
)


def run_owasp_checks(url: str, scan_meta_data: dict) -> list:
    """
    Called by run_website_scan().
    Receives a URL string + scan_meta_data, returns list of check results.
    No AWS session needed — pure HTTP/TLS checks against the website.
    """
    results = []
    results.append(owasp_https_not_enforced(url, scan_meta_data))
    print("after 1st check: ", results)
    results.append(owasp_ssl_tls_version(url, scan_meta_data))
    results.append(owasp_ssl_certificate_validity(url, scan_meta_data))
    results.append(owasp_security_headers_missing(url, scan_meta_data))
    results.append(owasp_cookies_not_secure(url, scan_meta_data))
    results.append(owasp_sensitive_data_in_url(url, scan_meta_data))
    results.append(owasp_open_redirect(url, scan_meta_data))
    results.append(owasp_directory_listing_enabled(url, scan_meta_data))
    results.append(owasp_cors_misconfiguration(url, scan_meta_data))
    results.append(owasp_error_messages_verbose(url, scan_meta_data))
    return results


# ── Direct API entry point from main.py ──────────────────────────────────────
async def owasp_scan_function(data):
    from utils.website_scan import run_website_scan

    return run_website_scan(data)
