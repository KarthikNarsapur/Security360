import json
from datetime import datetime, timezone, timedelta
from utils.upload_to_s3 import upload_to_s3, save_report

IST = timezone(timedelta(hours=5, minutes=30))


# ─────────────────────────────────────────────────────────────────────────────
# WEBSITE SCANNER REGISTRY
# Add new website-based frameworks here — same pattern as framework_scan.py
# ─────────────────────────────────────────────────────────────────────────────
def _get_website_registry():
    from modules.Website.OWASP.owasp_run_checks import run_owasp_checks

    return {
        "owasp": run_owasp_checks,
    }


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST MODEL expected from frontend:
#
#   {
#       "username": "parth",
#       "websites": ["https://example.com", "https://bank.com"],
#       "framework": "owasp"        # optional, defaults to "owasp"
#   }
# ─────────────────────────────────────────────────────────────────────────────
def run_website_scan(data) -> dict:
    try:
        # step 1: validate input
        if not data.username:
            return {"status": "error", "error_message": "Username is missing."}

        websites = getattr(data, "websites", [])
        if not websites or len(websites) == 0:
            return {
                "status": "error",
                "error_message": "Website list is missing or empty.",
            }

        framework = getattr(data, "framework", "owasp").lower().strip()
        registry = _get_website_registry()

        if framework not in registry:
            return {
                "status": "error",
                "error_message": f"Unknown framework '{framework}'. Available: {list(registry.keys())}",
            }

        run_checks_fn = registry[framework]
        username = data.username
        notifications = {"success": [], "error": []}
        all_results = []

        # step 2: loop through each website
        for website_url in websites:
            url = website_url.strip()
            print(f"Scanning website: {url}")

            try:
                scan_meta_data = _fresh_meta(framework)
                results = run_checks_fn(url, scan_meta_data)
                print("after scan: ", results)

                all_results.append(
                    {
                        "url": url,
                        "data": results,
                        "scan_meta_data": scan_meta_data,
                    }
                )

                notifications["success"].append(
                    f"{framework.upper()} scan successful: {url}"
                )

            except Exception as e:
                print(f"Error scanning {url}: {e}")
                notifications["error"].append(f"Scan failed for: {url}")
                continue

        if not all_results:
            return {
                "status": "error",
                "error_message": "All website scans failed.",
                "notifications": notifications,
            }

        # step 3: save report and upload to S3
        merged_meta = _merge_meta(all_results)
        try:
            saved_filename = save_report(
                account_id="website-scan",
                username=username,
                account_name="Website Security Scan",
                results=all_results,
                type="framework-website-owasp",
                scan_meta_data=[],
                security_services_scan=[],
                global_services_scan_results={},
                scan_meta_data_global_services=merged_meta,
                output_dir=f"scan-reports/{framework}/Website/{username}",
                regions=["global"],
            )
        except Exception as e:
            print(f"Error saving {framework} website report: {e}")
            notifications["error"].append("Report save failed")
            saved_filename = None

        # if saved_filename:
        #     try:
        #         upload_to_s3(
        #             file_name=saved_filename,
        #             folder_name=f"scan-reports/{framework}/{username}",
        #             s3_folder_name=f"aws-account-security-reports/{username}/{framework}",
        #         )
        #     except Exception as e:
        #         print(f"Error uploading {framework} report to S3: {e}")
        #         notifications["error"].append("S3 upload failed")

        return {
            "status": "ok",
            "framework": framework.upper(),
            "websites_scanned": len(all_results),
            "scan_meta_data": merged_meta,
            "notifications": notifications,
            "results": all_results,
        }

    except Exception as e:
        print(f"Unexpected error in run_website_scan: {e}")
        return {"status": "error", "error_message": "Unknown error occurred"}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _fresh_meta(framework: str) -> dict:
    return {
        "total_scanned": 0,
        "affected": 0,
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "services_scanned": [],
        "framework": framework.upper(),
        "scan_time": datetime.now(IST).isoformat(),
    }


def _merge_meta(all_results: list) -> dict:
    merged = _fresh_meta("merged")
    for result in all_results:
        meta = result.get("scan_meta_data", {})
        merged["total_scanned"] += meta.get("total_scanned", 0)
        merged["affected"] += meta.get("affected", 0)
        merged["Critical"] += meta.get("Critical", 0)
        merged["High"] += meta.get("High", 0)
        merged["Medium"] += meta.get("Medium", 0)
        merged["Low"] += meta.get("Low", 0)
        for svc in meta.get("services_scanned", []):
            if svc not in merged["services_scanned"]:
                merged["services_scanned"].append(svc)
    return merged
