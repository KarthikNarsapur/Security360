import ssl
import socket
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

IST = timezone(timedelta(hours=5, minutes=30))


# Shared session — reuse TCP connection across all checks for the same URL
def _get_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "Sec360-Security-Scanner/1.0"})
    return session


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ─────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 2021 + Security Headers
# Input: website URL (string)
# Output: same check result dict as all other framework checks
# ─────────────────────────────────────────────────────────────────────────────


def owasp_https_not_enforced(url, scan_meta_data):
    """
    OWASP A02:2021 - Cryptographic Failures
    The site must redirect HTTP → HTTPS. If it serves content over plain
    HTTP, all data (including credentials/card data) is transmitted in cleartext.
    """
    print("owasp_https_not_enforced")
    non_compliant = []
    http_url = _normalize_url(url).replace("https://", "http://")

    try:
        response = requests.get(http_url, timeout=10, allow_redirects=True)
        final_url = response.url

        if not final_url.startswith("https://"):
            non_compliant.append(
                {
                    "resource_name": url,
                    "issue": "HTTP request did not redirect to HTTPS",
                    "final_url": final_url,
                    "status_code": response.status_code,
                    "note": "Site serves content over plain HTTP — all traffic is unencrypted",
                }
            )
        elif response.history:
            first = response.history[0]
            if first.status_code not in (301, 308):
                non_compliant.append(
                    {
                        "resource_name": url,
                        "issue": f"HTTP redirects with {first.status_code} instead of 301/308",
                        "note": "Use permanent redirect (301/308) to enforce HTTPS consistently",
                    }
                )
    except Exception as e:
        print(f"Error checking HTTPS enforcement for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Critical"] += len(non_compliant)
    if "HTTPS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("HTTPS")

    return {
        "check_name": "OWASP A02 - HTTPS Not Enforced",
        "service": "Transport Security",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A02-2021",
        "problem_statement": "The website does not enforce HTTPS. All data including credentials and session tokens is transmitted in plaintext, exposing users to man-in-the-middle attacks.",
        "severity_score": 95,
        "severity_level": "Critical",
        "resources_affected": non_compliant,
        "recommendation": "Configure permanent 301 redirect from HTTP to HTTPS on the web server. Enable HSTS header to prevent future HTTP access.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_ssl_tls_version(url, scan_meta_data):
    """
    OWASP A02:2021 - Cryptographic Failures
    TLS 1.0 and 1.1 are deprecated and insecure. Only TLS 1.2+ should be used.
    Finance sites must use TLS 1.2 minimum, TLS 1.3 recommended.
    """
    print("owasp_ssl_tls_version")
    non_compliant = []
    hostname = urlparse(_normalize_url(url)).hostname

    WEAK_PROTOCOLS = {
        ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None,
        ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
    }
    WEAK_NAMES = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()

                if any(weak in tls_version for weak in WEAK_NAMES):
                    non_compliant.append(
                        {
                            "resource_name": url,
                            "tls_version": tls_version,
                            "cipher": cipher[0] if cipher else "unknown",
                            "note": f"Weak TLS version {tls_version} — deprecated and vulnerable to POODLE/BEAST attacks",
                        }
                    )
    except ssl.SSLError as e:
        non_compliant.append(
            {
                "resource_name": url,
                "issue": f"SSL error: {str(e)}",
                "note": "SSL/TLS handshake failed — certificate or protocol issue",
            }
        )
    except Exception as e:
        print(f"Error checking TLS for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "TLS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("TLS")

    return {
        "check_name": "OWASP A02 - Weak TLS Version",
        "service": "TLS/SSL",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A02-TLS",
        "problem_statement": "The site supports deprecated TLS versions (1.0/1.1) which are vulnerable to known attacks (POODLE, BEAST). PCI-DSS and RBI also explicitly prohibit TLS versions below 1.2.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Disable TLS 1.0 and TLS 1.1 on the web server. Support only TLS 1.2 and TLS 1.3. Disable weak cipher suites (RC4, DES, 3DES).",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_ssl_certificate_validity(url, scan_meta_data):
    """
    OWASP A02:2021 - Cryptographic Failures
    Expired or self-signed certificates destroy trust and may expose
    users to MITM attacks. Finance sites must use valid CA-signed certs.
    """
    print("owasp_ssl_certificate_validity")
    non_compliant = []
    hostname = urlparse(_normalize_url(url)).hostname

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_str = cert.get("notAfter", "")

                if expire_str:
                    expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    days_left = (expire_date - now).days

                    if days_left < 0:
                        non_compliant.append(
                            {
                                "resource_name": url,
                                "expired_on": expire_str,
                                "days_overdue": abs(days_left),
                                "note": "SSL certificate has EXPIRED — browsers will show security warnings",
                            }
                        )
                    elif days_left < 30:
                        non_compliant.append(
                            {
                                "resource_name": url,
                                "expires_on": expire_str,
                                "days_remaining": days_left,
                                "note": f"SSL certificate expires in {days_left} days — renew immediately",
                            }
                        )

    except ssl.SSLCertVerificationError as e:
        non_compliant.append(
            {
                "resource_name": url,
                "issue": str(e),
                "note": "Certificate verification failed — possibly self-signed or wrong hostname",
            }
        )
    except Exception as e:
        print(f"Error checking SSL cert for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "SSL Certificate" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("SSL Certificate")

    return {
        "check_name": "OWASP A02 - SSL Certificate Validity",
        "service": "SSL Certificate",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A02-CERT",
        "problem_statement": "An expired or invalid SSL certificate breaks encrypted connections and exposes users to man-in-the-middle attacks. All financial sites must maintain valid certificates.",
        "severity_score": 90,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Renew the SSL certificate immediately. Use Let's Encrypt with auto-renewal or AWS Certificate Manager (ACM) which auto-renews for free.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_security_headers_missing(url, scan_meta_data):
    """
    OWASP A05:2021 - Security Misconfiguration
    Missing HTTP security headers are one of the most common and easily
    fixed vulnerabilities. Each missing header opens a specific attack vector.
    """
    print("owasp_security_headers_missing")
    non_compliant = []
    target = _normalize_url(url)

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": "Prevents HTTP downgrade attacks (HSTS)",
        "Content-Security-Policy": "Prevents XSS and data injection attacks",
        "X-Content-Type-Options": "Prevents MIME sniffing attacks",
        "X-Frame-Options": "Prevents clickjacking attacks",
        "Referrer-Policy": "Controls referrer info leakage",
        "Permissions-Policy": "Controls browser feature access (camera, mic etc.)",
    }

    try:
        session = _get_session()
        response = session.get(target, timeout=10, verify=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        missing = []

        for header, reason in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                missing.append({"header": header, "reason": reason})

        # Extra checks for misconfigured headers
        server_header = headers.get("server", "")
        if server_header and any(
            tech in server_header.lower() for tech in ["apache", "nginx", "iis", "php"]
        ):
            missing.append(
                {
                    "header": "Server (info leakage)",
                    "reason": f"Server header reveals technology: '{server_header}' — helps attackers fingerprint stack",
                }
            )

        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            missing.append(
                {
                    "header": "X-Powered-By (info leakage)",
                    "reason": f"X-Powered-By reveals: '{x_powered}' — remove this header",
                }
            )

        if missing:
            non_compliant.append(
                {
                    "resource_name": url,
                    "missing_or_misconfigured": missing,
                    "status_code": response.status_code,
                }
            )

    except Exception as e:
        print(f"Error checking security headers for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "HTTP Headers" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("HTTP Headers")

    return {
        "check_name": "OWASP A05 - Missing Security Headers",
        "service": "HTTP Headers",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A05-2021",
        "problem_statement": "Missing HTTP security headers leave users exposed to XSS, clickjacking, MIME sniffing, and information leakage attacks. These are free to fix and high impact.",
        "severity_score": 70,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Add all missing security headers in your web server config or application middleware. Use securityheaders.com to verify. Priority: HSTS > CSP > X-Content-Type-Options > X-Frame-Options.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_cookies_not_secure(url, scan_meta_data):
    """
    OWASP A02:2021 / A07:2021 - Cryptographic Failures / Auth Failures
    Session cookies without Secure + HttpOnly flags can be stolen via
    XSS or network sniffing. SameSite prevents CSRF attacks.
    """
    print("owasp_cookies_not_secure")
    non_compliant = []
    target = _normalize_url(url)

    try:
        session = _get_session()
        response = session.get(target, timeout=10)

        for cookie in response.cookies:
            issues = []

            if not cookie.secure:
                issues.append("Missing 'Secure' flag — cookie sent over HTTP")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(
                    "Missing 'HttpOnly' flag — cookie accessible via JavaScript (XSS risk)"
                )
            same_site = cookie.get_nonstandard_attr("SameSite", "")
            if not same_site or same_site.lower() == "none":
                issues.append("Missing/weak 'SameSite' — vulnerable to CSRF attacks")

            if issues:
                non_compliant.append(
                    {
                        "resource_name": url,
                        "cookie_name": cookie.name,
                        "issues": issues,
                        "note": "Insecure cookie configuration detected",
                    }
                )

    except Exception as e:
        print(f"Error checking cookies for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "Cookies" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Cookies")

    return {
        "check_name": "OWASP A07 - Insecure Cookie Configuration",
        "service": "Cookies",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A07-2021",
        "problem_statement": "Session cookies without Secure/HttpOnly/SameSite flags can be stolen via XSS or network attacks, allowing session hijacking on financial accounts.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Set Secure, HttpOnly, and SameSite=Strict (or Lax) on all cookies. For session cookies on financial apps, always use Secure + HttpOnly + SameSite=Strict.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_sensitive_data_in_url(url, scan_meta_data):
    """
    OWASP A02:2021 - Cryptographic Failures / Sensitive Data Exposure
    Sensitive data (tokens, session IDs, passwords) must never appear in URLs
    as they get logged in server logs, browser history, and referrer headers.
    """
    print("owasp_sensitive_data_in_url")
    non_compliant = []
    target = _normalize_url(url)

    SENSITIVE_PARAMS = [
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "secret",
        "auth",
        "session",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "otp",
        "access_token",
        "refresh_token",
    ]

    try:
        session = _get_session()
        response = session.get(target, timeout=10, allow_redirects=True)
        final_url = response.url.lower()

        found = [p for p in SENSITIVE_PARAMS if f"{p}=" in final_url]
        if found:
            non_compliant.append(
                {
                    "resource_name": url,
                    "sensitive_params_found": found,
                    "note": "Sensitive parameters detected in URL — will appear in logs and browser history",
                }
            )

    except Exception as e:
        print(f"Error checking URL for sensitive data {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "URL Security" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("URL Security")

    return {
        "check_name": "OWASP A02 - Sensitive Data Exposed in URL",
        "service": "URL Security",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A02-URL",
        "problem_statement": "Sensitive parameters (tokens, passwords, keys) detected in the URL. These are logged by servers, proxies, and browsers — exposing credentials to unintended parties.",
        "severity_score": 85,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Move all sensitive data to POST request bodies or HTTP headers. Never pass credentials, tokens, or card data as URL query parameters.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_open_redirect(url, scan_meta_data):
    """
    OWASP A01:2021 - Broken Access Control
    Open redirects allow attackers to redirect users to phishing/malware sites
    while appearing to come from a trusted domain. Common in login/logout flows.
    """
    print("owasp_open_redirect")
    non_compliant = []
    target = _normalize_url(url)

    TEST_PAYLOADS = [
        f"{target}?redirect=https://evil.com",
        f"{target}?url=https://evil.com",
        f"{target}?next=https://evil.com",
        f"{target}?return=https://evil.com",
        f"{target}?returnUrl=https://evil.com",
    ]

    try:
        session = _get_session()
        for payload_url in TEST_PAYLOADS:
            try:
                response = session.get(payload_url, timeout=8, allow_redirects=True)
                if "evil.com" in response.url:
                    non_compliant.append(
                        {
                            "resource_name": url,
                            "payload": payload_url,
                            "redirected_to": response.url,
                            "note": "Open redirect confirmed — attacker can redirect users to malicious sites",
                        }
                    )
                    break  # one confirmed is enough
            except Exception:
                continue

    except Exception as e:
        print(f"Error checking open redirects for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "Redirects" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Redirects")

    return {
        "check_name": "OWASP A01 - Open Redirect Vulnerability",
        "service": "Redirects",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A01-2021",
        "problem_statement": "Open redirect vulnerabilities allow attackers to craft links that appear to come from a trusted financial domain but redirect users to phishing sites.",
        "severity_score": 75,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Validate all redirect URLs against an allowlist of trusted domains. Reject or sanitize any redirect parameter pointing to external domains.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_directory_listing_enabled(url, scan_meta_data):
    """
    OWASP A05:2021 - Security Misconfiguration
    Directory listing exposes the file structure of the web server, leaking
    source files, config files, backups, and other sensitive information.
    """
    print("owasp_directory_listing_enabled")
    non_compliant = []
    target = _normalize_url(url)

    TEST_PATHS = ["/uploads/", "/backup/", "/files/", "/static/", "/assets/", "/logs/"]

    try:
        session = _get_session()
        for path in TEST_PATHS:
            test_url = target + path
            try:
                response = session.get(test_url, timeout=8)
                body = response.text.lower()

                if response.status_code == 200 and (
                    "index of /" in body
                    or "directory listing" in body
                    or "<title>index of" in body
                ):
                    non_compliant.append(
                        {
                            "resource_name": test_url,
                            "status_code": response.status_code,
                            "note": "Directory listing is enabled — file structure exposed",
                        }
                    )
            except Exception:
                continue

    except Exception as e:
        print(f"Error checking directory listing for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "Web Config" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Web Config")

    return {
        "check_name": "OWASP A05 - Directory Listing Enabled",
        "service": "Web Configuration",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A05-DIR",
        "problem_statement": "Directory listing is enabled on common paths, exposing the server's file structure. Attackers can find backup files, config files, and source code.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Disable directory listing in your web server config (Apache: Options -Indexes, Nginx: autoindex off). Return 403 or 404 for all directory paths.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_cors_misconfiguration(url, scan_meta_data):
    """
    OWASP A05:2021 - Security Misconfiguration
    Wildcard CORS (Access-Control-Allow-Origin: *) on APIs that handle
    financial data allows any website to make authenticated requests on
    behalf of the user — leading to data theft.
    """
    print("owasp_cors_misconfiguration")
    non_compliant = []
    target = _normalize_url(url)

    try:
        session = _get_session()
        response = session.get(
            target,
            timeout=10,
            headers={"Origin": "https://evil.com"},
        )

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            non_compliant.append(
                {
                    "resource_name": url,
                    "Access-Control-Allow-Origin": acao,
                    "Access-Control-Allow-Credentials": acac,
                    "note": "Critical: wildcard CORS with credentials=true — any site can make authenticated requests",
                }
            )
        elif acao == "https://evil.com":
            non_compliant.append(
                {
                    "resource_name": url,
                    "Access-Control-Allow-Origin": acao,
                    "note": "CORS reflects arbitrary Origin header — any attacker domain is trusted",
                }
            )
        elif acao == "*":
            non_compliant.append(
                {
                    "resource_name": url,
                    "Access-Control-Allow-Origin": acao,
                    "note": "Wildcard CORS — acceptable for public APIs but not for financial/authenticated endpoints",
                }
            )

    except Exception as e:
        print(f"Error checking CORS for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["High"] += len(non_compliant)
    if "CORS" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("CORS")

    return {
        "check_name": "OWASP A05 - CORS Misconfiguration",
        "service": "CORS",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A05-CORS",
        "problem_statement": "CORS misconfiguration allows unauthorized cross-origin requests to financial APIs. Combined with credentials=true, attackers can steal user data from any website.",
        "severity_score": 80,
        "severity_level": "High",
        "resources_affected": non_compliant,
        "recommendation": "Set Access-Control-Allow-Origin to an explicit allowlist of trusted domains. Never combine wildcard (*) with Access-Control-Allow-Credentials: true.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }


def owasp_error_messages_verbose(url, scan_meta_data):
    """
    OWASP A05:2021 - Security Misconfiguration
    Verbose error messages reveal stack traces, database types, file paths,
    and internal logic — giving attackers a detailed map of the application.
    """
    print("owasp_error_messages_verbose")
    non_compliant = []
    target = _normalize_url(url)

    TEST_PATHS = [
        "/doesnotexist12345",
        "/api/doesnotexist",
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/%00",
        "/admin",
    ]

    TECH_LEAKS = [
        "stack trace",
        "traceback",
        "exception in",
        "at line",
        "mysql_",
        "sqlstate",
        "ora-",
        "pg_query",
        "debug",
        "django",
        "laravel",
        "flask",
        "rails",
        "internal server error",
        "application error",
        "php warning",
        "php fatal",
        "undefined index",
    ]

    try:
        session = _get_session()
        for path in TEST_PATHS:
            test_url = target + path
            try:
                response = session.get(test_url, timeout=8)
                body = response.text.lower()

                leaks = [leak for leak in TECH_LEAKS if leak in body]
                if leaks:
                    non_compliant.append(
                        {
                            "resource_name": test_url,
                            "status_code": response.status_code,
                            "technology_leaked": leaks,
                            "note": "Verbose error message reveals internal technology details",
                        }
                    )
            except Exception:
                continue

    except Exception as e:
        print(f"Error checking error messages for {url}: {e}")

    scan_meta_data["total_scanned"] += 1
    scan_meta_data["affected"] += len(non_compliant)
    scan_meta_data["Medium"] += len(non_compliant)
    if "Error Handling" not in scan_meta_data["services_scanned"]:
        scan_meta_data["services_scanned"].append("Error Handling")

    return {
        "check_name": "OWASP A05 - Verbose Error Messages",
        "service": "Error Handling",
        "framework": "OWASP Top 10 2021",
        "control_id": "OWASP-A05-ERR",
        "problem_statement": "Error pages reveal stack traces, database types, framework versions, or file paths. This information helps attackers craft targeted exploits.",
        "severity_score": 65,
        "severity_level": "Medium",
        "resources_affected": non_compliant,
        "recommendation": "Configure custom error pages (404, 500) that show friendly messages only. Never expose stack traces in production. Disable debug mode. Log errors server-side only.",
        "additional_info": {"total_scanned": 1, "affected": len(non_compliant)},
    }
