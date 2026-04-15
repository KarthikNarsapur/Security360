import os
import json
import logging
from fastapi import Request
from utils.util import validate_ip_function
from Auth.controller import get_user_account_details_function
from Auth.model import GetUserDetailsModel


def admin_user_verification(request: Request):
    # Extract access token
    auth_header = request.headers.get("Authorization", "")
    access_token = auth_header.replace("Bearer ", "").strip()
    print("got access token: ", access_token)

    if not access_token:
        return {
            "status": "error",
            "error_message": "Missing or invalid Authorization token.",
        }

    # Validate user
    try:
        model = GetUserDetailsModel(access_token=access_token)
        user_result = get_user_account_details_function(model)

        if user_result.get("status") != "ok":
            return {"status": "error", "error_message": "User authentication failed."}

        user = user_result["response"]
        is_admin = user.get("is_admin", False)

        if not is_admin:
            return {
                "status": "error",
                "error_message": "Only admin users can add dashboards.",
            }

    except Exception as e:
        print("User validation failed: " + str(e))
        return {
            "status": "error",
            "error_message": "Unable to validate user credentials.",
        }


def get_site24x7_dashboard_list_function(request: Request):
    validate_ip_result = validate_ip_function(request)

    if not validate_ip_result.get("isAllowed", False):
        return {
            "status": "error",
            "error_message": "Access denied: Your IP is not allowed.",
            "ip": validate_ip_result.get("ip", ""),
        }

    try:
        json_path = os.path.join("utils", "site24x7_dashboards.json")
        with open(json_path, "r") as f:
            dashboards = json.load(f)

        return dashboards

    except Exception as e:
        logging.error(f"Failed to load dashboards: {str(e)}")
        return {"status": "error", "error_message": "Failed to load dashboards"}


def add_site24x7_dashboard_function(request: Request, new_dashboard: dict):
    validate_ip_result = validate_ip_function(request)

    if not validate_ip_result.get("isAllowed", False):
        return {"status": "error", "error_message": "Access denied."}
    
    # Extract access token
    auth_header = request.headers.get("Authorization", "")
    access_token = auth_header.replace("Bearer ", "").strip()
    
    invalid_tokens = ["", "undefined", "null", None]

    if access_token in invalid_tokens:
        return {
            "status": "error",
            "error_message": "Missing or invalid Authorization token.",
        }

    # Validate user
    try:
        model = GetUserDetailsModel(access_token=access_token)
        user_result = get_user_account_details_function(model)
    
        if user_result.get("status") != "ok":
            return {"status": "error", "error_message": "User authentication failed."}

        user = user_result["response"]
        is_admin = user.get("is_admin", False)

        if not is_admin:
            return {
                "status": "error",
                "error_message": "Only admin users can add dashboards.",
            }

    except Exception as e:
        print("User validation failed: " + str(e))
        return {
            "status": "error",
            "error_message": "Unable to validate user credentials.",
        }

    # Admin is verified
    
    try:
        json_path = os.path.join("utils", "site24x7_dashboards.json")

        with open(json_path, "r") as f:
            dashboards = json.load(f)

        # Extract values from new dashboard
        new_name = new_dashboard.get("clientName", "").strip().lower()
        new_url = new_dashboard.get("url", "").strip().lower()

        # Duplicate Check
        for d in dashboards:
            existing_name = d.get("clientName", "").strip().lower()
            existing_url = d.get("url", "").strip().lower()

            if existing_name == new_name:
                return {
                    "status": "error",
                    "error_message": f"Dashboard for client '{new_dashboard.get('clientName')}' already exists.",
                }

            if existing_url == new_url:
                return {
                    "status": "error",
                    "error_message": "Dashboard URL is already added.",
                }

        # No duplicate, Add new
        dashboards.append(new_dashboard)

        with open(json_path, "w") as f:
            json.dump(dashboards, f, indent=2)

        return {"status": "ok", "message": "Dashboard added successfully"}


    except Exception as e:
        print("Error adding Dashboard", str(e))
        return {"status": "error", "error_message": "Unable to save dashboard"}


def get_site24x7_settings_function(request: Request):
    validate_ip_result = validate_ip_function(request)

    if not validate_ip_result.get("isAllowed", False):
        return {"status": "error", "error_message": "Access denied"}

    try:
        json_path = os.path.join("utils", "site24x7_settings.json")
        with open(json_path, "r") as f:
            settings = json.load(f)

        return {"status": "ok", "settings": settings}

    except Exception as e:
        logging.error(f"Failed to load settings: {str(e)}")
        return {"status": "error", "error_message": "Failed to load settings"}


def update_site24x7_settings_function(request: Request, payload: dict):
    validate_ip_result = validate_ip_function(request)

    if not validate_ip_result.get("isAllowed", False):
        return {"status": "error", "error_message": "Access denied"}
    
    # Must be admin
    admin_user_verification(request=request)

    try:
        json_path = os.path.join("utils", "site24x7_settings.json")

        # --- 1. Load existing settings ---
        if os.path.exists(json_path):
            with open(json_path, "r") as f:
                settings = json.load(f)
        else:
            settings = {}

        # --- 2. Update only if payload has rotationSeconds ---
        if "rotationSeconds" in payload and payload["rotationSeconds"] is not None:
            settings["rotationSeconds"] = payload["rotationSeconds"]
        # else  KEEP OLD VALUE as it is

        # If still missing (first-time file), use default
        if "rotationSeconds" not in settings:
            settings["rotationSeconds"] = 60

        # --- 3. Save updated settings ---
        with open(json_path, "w") as f:
            json.dump(settings, f, indent=2)

        return {"status": "ok", "message": "Rotation time updated"}

    except Exception as e:
        logging.error(f"Failed to save settings: {str(e)}")
        return {"status": "error", "error_message": "Unable to save settings"}
