import boto3
import os
import json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from fastapi import UploadFile, File
import base64
import mimetypes

IST = timezone(timedelta(hours=5, minutes=30))

from Model.model import ReportRequest

from Model.model import ContactFormModel


def save_report(
    account_id,
    username,
    account_name,
    results,
    type,
    output_dir="default_reports",
    regions=[],
    scan_meta_data={},
    security_services_scan={},
    global_services_scan_results={},
    scan_meta_data_global_services={},
):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%SZ")
    filename = f"{account_id}.json"
    report = {}
    if type == "summary":
        report = {
            "account_id": account_id,
            "timestamp": timestamp,
            "username": username,
            "account_name": account_name,
            "regions": regions,
            "scanned_meta_data": scan_meta_data,
            "security_services_scanned_data": security_services_scan,
            "global_services_scan_results": global_services_scan_results,
            "scan_meta_data_global_services": scan_meta_data_global_services,
            "results": results,
        }
    elif type == "threat_detection":
        report = {
            "account_id": account_id,
            "timestamp": timestamp,
            "username": username,
            "account_name": account_name,
            "regions": regions,
            "results": results,
        }
    elif type == "cis" or type == "iso42001" or type == "nist" or type == "awaf":
        report = {
            "account_id": account_id,
            "timestamp": timestamp,
            "username": username,
            "account_name": account_name,
            "regions": regions,
            "results": results,
        }
    elif type == "framework-website-owasp":
        report = {
            "account_id": account_id,
            "timestamp": timestamp,
            "username": username,
            "account_name": account_name,
            "regions": regions,
            "results": results,
        }
    else:
        report = {
            "account_id": account_id,
            "timestamp": timestamp,
            "username": username,
            "account_name": account_name,
            "regions": regions,
            "results": results,
        }
    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return filename


def upload_to_s3(file_name, s3_folder_name, folder_name="default_reports"):
    bucket_name = os.getenv("S3_BUCKET_NAME")

    if bucket_name:

        file_path = f"{folder_name}/{file_name}"
        s3 = boto3.client("s3")

        object_name = f"{s3_folder_name}/{os.path.basename(file_path)}"

        try:
            s3.upload_file(file_path, bucket_name, object_name)
            # if os.path.exists(file_path):
            #     os.remove(file_path)
            #     print(f"Local file {file_path} deleted")
            print(f"File uploaded to s3://{bucket_name}/{object_name}")
            return True
        except Exception as e:
            print(f"Failed to upload file to S3: {e}")
            return False
    else:
        print("S3 Bucket Name is not set")
        return False


def get_report_from_s3_function(data: ReportRequest):
    # with open("utils/sample.json", "r") as f:
    #     response_data = json.load(f)

    # return {
    #     "status": "ok",
    #     "data": response_data,
    # }

    bucket_name = os.getenv("S3_BUCKET_NAME")

    if not bucket_name:
        return {
            "status": "error",
            "error_message": "Configuration error: Report storage is not available.",
        }

    username = data.username
    account_id = data.account_id
    s3_folder_name = f"aws-account-security-reports/{username}"
    object_name = f"{s3_folder_name}/{account_id}.json"

    s3 = boto3.client("s3")

    def fetch_json_from_s3(key):
        try:
            resp = s3.get_object(Bucket=bucket_name, Key=key)
            content = resp["Body"].read().decode("utf-8")
            return json.loads(content)
        except ClientError as e:
            err_code = e.response["Error"]["Code"]
            if err_code == "NoSuchKey":
                return {
                    "status": "error",
                    "error_message": "No report available yet. Please initiate a scan first.",
                }
            elif err_code == "AccessDenied":
                return {
                    "status": "error",
                    "error_message": "Access denied to S3 report",
                }
            else:
                return {
                    "status": "error",
                    "error_message": "Failed to fetch report from S3",
                }
        except Exception:
            print("error: ", str(e))
            return {
                "status": "error",
                "error_message": "Unexpected error while retrieving report",
            }

    try:

        # threat detection report
        if data.type == "threat_detection":
            if data.is_sample:
                base_folder = "Sample_Reports/AWS_Threat_Detection"
                cloudtrail_key = f"{base_folder}/cloudtrail_sample_report.json"
                vpc_flow_logs_key = f"{base_folder}/vpc_flow_logs_sample_report.json"
            else:
                base_folder = f"AWS-Threat-Detection/{username}"
                cloudtrail_key = f"{base_folder}/Cloudtrail/{account_id}.json"
                vpc_flow_logs_key = f"{base_folder}/VPC_flow_logs/{account_id}.json"

            # print("cloudtrail_key: ", cloudtrail_key)
            # print("vpc_flow_logs_key: ", vpc_flow_logs_key)

            selected_types = data.threat_detection_scan_type or ["cloudtrail", "vpc"]

            response_data = {}

            if "cloudtrail" in selected_types:
                cloudtrail_data = fetch_json_from_s3(cloudtrail_key) or {}
                if cloudtrail_data.get("status", "") == "error":
                    cloudtrail_data["error_message"] = (
                        "CloudTrail: " + cloudtrail_data.get("error_message", "")
                    )
                response_data["cloudtrail_logs_findings"] = cloudtrail_data

            if "vpc" in selected_types:
                vpc_flow_logs_data = fetch_json_from_s3(vpc_flow_logs_key) or {}
                if vpc_flow_logs_data.get("status", "") == "error":
                    vpc_flow_logs_data["error_message"] = (
                        "VPC Flow Logs: " + vpc_flow_logs_data.get("error_message", "")
                    )
                response_data["VPC_flow_logs_findings"] = vpc_flow_logs_data

            return {
                "status": "ok",
                "data": response_data,
            }

        # summary report
        elif data.type == "summary":

            if data.is_sample:
                s3_folder_name = f"Sample_Reports/aws-account-security-reports"
                object_name = f"{s3_folder_name}/security_scan_sample_report.json"
            else:
                s3_folder_name = f"aws-account-security-reports/{username}"
                object_name = f"{s3_folder_name}/{account_id}.json"

            summary_data = fetch_json_from_s3(object_name) or {}
            if summary_data.get("status", "") == "error":
                return summary_data

            return {"status": "ok", "data": summary_data}

        # cis scan reports
        # Legacy standalone branches removed — now handled by the unified framework block below

        elif data.type in ("rbi", "sebi", "pcidss", "dpdp", "cis", "iso42001", "nist", "wafr", "owasp"):
            framework = data.type

            # Legacy S3 path mapping for frameworks that previously used different folder names
            LEGACY_PATHS = {
                "cis": ("CIS-rules", "cis_sample_report.json", "CIS_rules"),
                "nist": ("NIST-rules", "nist_sample_report.json", "NIST_rules"),
                "wafr": ("AWAF-rules", "awaf_sample_report.json", "AWAF_rules"),
                "iso42001": ("ISO42001-rules", "iso42001_sample_report.json", "ISO42001_rules"),
            }

            if data.is_sample:
                if framework in LEGACY_PATHS:
                    _, sample_file, sample_folder = LEGACY_PATHS[framework]
                    s3_folder_name = f"Sample_Reports/{sample_folder}"
                    object_name = f"{s3_folder_name}/{sample_file}"
                else:
                    s3_folder_name = f"Sample_Reports/{framework}_rules"
                    object_name = f"{s3_folder_name}/{framework}_sample_report.json"
            else:
                # Try new unified path first
                s3_folder_name = f"aws-account-security-reports/{username}/{framework}"
                object_name = f"{s3_folder_name}/{account_id}.json"

                fw_data = fetch_json_from_s3(object_name)
                # If not found in new path, try legacy path
                if (not fw_data or fw_data.get("status", "") == "error") and framework in LEGACY_PATHS:
                    legacy_folder, _, _ = LEGACY_PATHS[framework]
                    object_name = f"{legacy_folder}/{username}/{account_id}.json"

            fw_data = fetch_json_from_s3(object_name) or {}
            if fw_data.get("status", "") == "error":
                return fw_data

            return {"status": "ok", "data": fw_data}

        else:
            return {"status": "error", "error_message": "Invalid report type"}

    except UnicodeDecodeError:
        return {"status": "error", "error_message": "Report file is not readable"}
    except json.JSONDecodeError:
        return {"status": "error", "error_message": "Report file has invalid JSON"}
    except Exception as e:
        print("error: ", str(e))
        return {
            "status": "error",
            "error_message": "Unexpected error while retrieving report",
        }


def upload_profile_image_to_s3(upload_file: UploadFile, username: str):
    """
    Upload a profile image to S3 and return full URL
    """
    bucket_name = os.getenv("S3_BUCKET_NAME")
    region = os.getenv("BOTO3_REGION")
    if not bucket_name:
        return {"status": "error", "error_message": "S3 Bucket Name is not set"}

    s3 = boto3.client("s3")
    ext = "." + upload_file.filename.split(".")[-1]  # keep original extension
    object_name = f"Profile_Images/{username}/profile_photo{ext}"

    try:
        s3.put_object(Bucket=bucket_name, Key=object_name, Body=upload_file.file)
        s3_url = f"https://{bucket_name}.s3.{region}.amazonaws.com/{object_name}"
        return {"status": "ok", "url": s3_url}
    except Exception as e:
        print(f"Failed to upload profile image to S3: {e}")
        return {
            "status": "error",
            "error_message": "Failed to upload profile image to S3",
        }


def get_profile_image_from_s3(s3_key: str, bucket_name: str):
    """
    Fetches an image from S3 using boto3 and returns it as a base64 data URI.
    """

    s3 = boto3.client("s3")
    try:
        resp = s3.get_object(Bucket=bucket_name, Key=s3_key)
        image_bytes = resp["Body"].read()
        mime_type, _ = mimetypes.guess_type(s3_key)
        if not mime_type:
            mime_type = "image/jpeg"  # default fallback
        return f"data:{mime_type};base64," + base64.b64encode(image_bytes).decode()
    except ClientError as e:
        err_code = e.response["Error"]["Code"]
        print(f"S3 error ({err_code}): {e}")
        return ""
    except Exception as e:
        print(f"Unexpected error fetching image from S3: {e}")
        return ""


def save_contact_us_to_s3(data: ContactFormModel):
    """
    Save contact form submission to S3 as JSON
    """
    bucket_name = os.getenv("S3_BUCKET_NAME")
    if not bucket_name:
        print("S3 Bucket Name is not set")
        return False

    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"{data.name}_{timestamp}.json"
    file_path = f"tmp/{filename}"  # temporary local file

    # Prepare JSON data
    submission = {
        "name": data.name,
        "email": data.email,
        "phone": data.phone,
        "interest": data.interest,
        "company": data.company,
        "consent": data.consent,
        "message": data.message,
        "timestamp": timestamp,
    }

    # Save locally first
    with open(file_path, "w") as f:
        json.dump(submission, f, indent=2, default=str)

    # Upload to S3
    s3 = boto3.client("s3")
    folder_name = "Contact_US_Form_Responses"
    object_name = f"{folder_name}/{filename}"
    try:
        s3.upload_file(file_path, bucket_name, object_name)
        print(f"Contact submission saved to s3://{bucket_name}/{object_name}")
        if os.path.exists(file_path):
            os.remove(file_path)
        return True
    except Exception as e:
        print(f"Failed to upload contact submission to S3: {e}")
        return False
