import os
import boto3
import json
from botocore.exceptions import ClientError

from utils.exceptions import handle_error
from db.model import (
    UserDataModel,
    DBKeysModel,
    RolesInfoModel,
    UpdateProfileModel,
)

from Auth.model import GetUserDetailsModel
from Model.model import UserNameModel, PDFReportModel

from fastapi import File, UploadFile
import base64

scan_type_mapping = {
    "basic": "BasicScanCount",
    "cloudtrail": "CloudTrailScanCount",
    "vpc-flow-logs": "VPCFlowLogsScanCount",
    "cis": "CISScanCount",
    # tool usage counts
    "argocd": "ArgoCDCount",
    "falco": "FalcoCount",
    "gatekeeper": "GatekeeperCount",
    "kured": "KuredCount",
    "headlamp": "HeadlampCount",
    # tool scan counts
    "kubescape": "KubescapeScanCount",
    "kubehunter": "KubeHunterScanCount",
}



def add_userdata_function(userdata: UserDataModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")

        response = dynamodb_client.put_item(
            TableName=table,
            Item={
                "Full_Name": {"S": userdata.full_name},
                "UserName": {"S": userdata.username},
                "Email": {"S": userdata.email},
                "Company": {"S": userdata.company},
                "Mobile_Number": {"S": userdata.mobile_number},
                "Role": {"S": userdata.role},
                "Roles_Info": {
                    "L": [
                        {
                            "M": {
                                "Role_ARN": {"S": role.role_arn},
                                "Account_ID": {"S": role.account_id},
                            }
                        }
                        for role in userdata.roles_info
                    ]
                },
                "Kubernetes_Roles_Info": {
                    "L": [
                        {
                            "M": {
                                "Role_ARN": {"S": role.role_arn},
                                "Account_ID": {"S": role.account_id},
                            }
                        }
                        for role in userdata.roles_info
                    ]
                },
                "Root_Account_ID": {"S": userdata.root_account_id},
                **{k: {"N": "0"} for k in scan_type_mapping.values()},
            },
            ConditionExpression="attribute_not_exists(UserName)",
            # S string L list M map
        )
        return {"status": "ok", "response": response}
    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def get_userdata_function(userdata: DBKeysModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")
        response = dynamodb_client.get_item(
            TableName=table,
            Key={
                "UserName": {"S": userdata.username},
            },
        )
        return {"status": "ok", "response": response}
    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def add_roleinfo_function(rolesinfo: RolesInfoModel):
    try:
        from Auth.controller import get_user_function

        get_user = GetUserDetailsModel(access_token=rolesinfo.access_token)
        user_response = get_user_function(get_user)

        if user_response["status"] != "ok":
            return {
                "status": "error",
                "error_message": "Invalid access token or user not found",
            }

        username = user_response["response"].get("Username", "")
        # print("got this username: ", username)
        if not username:
            return {
                "status": "error",
                "error_message": "Username not found in access token",
            }

        dynamodb_client = boto3.resource("dynamodb")
        table_name = os.getenv("USERDATA_TABLE_DYNAMODB")
        table = dynamodb_client.Table(table_name)

        existing_data = table.get_item(Key={"UserName": username})
        user_data = existing_data.get("Item", {})
        # print("User data: ", user_data)

        Role_Key = "Roles_Info"
        if rolesinfo.role_type == "eks":
            Role_Key = "Kubernetes_Roles_Info"
        print(Role_Key)

        updated_roles = user_data.get(Role_Key, []) + [
            role.model_dump() for role in rolesinfo.roles
        ]
        print("updated role: ", updated_roles)

        update_expression = f"SET {Role_Key} = :Roles_Info"
        expression_values = {":Roles_Info": updated_roles}

        table.update_item(
            Key={"UserName": username},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values,
        )

        return {"status": "ok"}
    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def update_roleinfo_function(rolesinfo: RolesInfoModel):
    try:
        from Auth.controller import get_user_function

        # Validate token & get username
        get_user = GetUserDetailsModel(access_token=rolesinfo.access_token)
        user_response = get_user_function(get_user)

        if user_response["status"] != "ok":
            return {
                "status": "error",
                "error_message": "Invalid access token or user not found",
            }

        username = user_response["response"].get("Username", "")
        if not username:
            return {
                "status": "error",
                "error_message": "Username not found in access token",
            }

        #  Initialize DynamoDB
        dynamodb_client = boto3.resource("dynamodb")
        table_name = os.getenv("USERDATA_TABLE_DYNAMODB")
        table = dynamodb_client.Table(table_name)

        #  Fetch user data
        existing_data = table.get_item(Key={"UserName": username})
        user_data = existing_data.get("Item", {})

        # Determine which key to update
        Role_Key = "Roles_Info"
        if rolesinfo.role_type == "eks":
            Role_Key = "Kubernetes_Roles_Info"

        existing_roles = user_data.get(Role_Key, [])
        if not existing_roles:
            return {
                "status": "error",
                "error_message": f"No existing roles found under {Role_Key}",
            }

        #  Update matching role(s)
        updated_roles = existing_roles.copy()
        updated_count = 0

        for update_role in rolesinfo.roles:
            for existing_role in updated_roles:
                if (
                    existing_role.get("role_arn") == update_role.role_arn
                    and existing_role.get("account_id") == update_role.account_id
                ):
                    # Update only changed fields
                    if update_role.account_name is not None:
                        existing_role["account_name"] = update_role.account_name
                    updated_count += 1

        if updated_count == 0:
            return {
                "status": "error",
                "error_message": "No matching role found to update",
            }

        #  Push updated list back to DynamoDB
        table.update_item(
            Key={"UserName": username},
            UpdateExpression=f"SET {Role_Key} = :Roles_Info",
            ExpressionAttributeValues={":Roles_Info": updated_roles},
        )

        return {"status": "ok", "message": f"Updated {updated_count} role(s)"}

    except ClientError as e:
        print(f"DynamoDB error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {"status": "error", "error_message": str(e)}


def get_user_profile_details_function(get_user: GetUserDetailsModel):

    from utils.upload_to_s3 import get_profile_image_from_s3

    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)

        congnito_response = cognito_client.get_user(AccessToken=get_user.access_token)
        # print("congnito_response: ", congnito_response)
        username = congnito_response.get("Username", "")

        user_attributes = {}
        for attr in congnito_response.get("UserAttributes", []):
            user_attributes[attr.get("Name")] = attr.get("Value")

        email = user_attributes.get("email", "")

        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")
        dynamodb_response = dynamodb_client.get_item(
            TableName=table,
            Key={
                "UserName": {"S": username},
            },
        )

        user_data = {}
        if "Item" in dynamodb_response:
            item = dynamodb_response["Item"]
            name = item.get("Full_Name", {}).get("S", "")
            company = item.get("Company", {}).get("S", "")
            profile_image = item.get("Profile_Image", {}).get("S", "")

            roles_info = []
            kubernetes_roles_info = []
            if "Roles_Info" in item and "L" in item["Roles_Info"]:
                for role in item["Roles_Info"]["L"]:
                    if "M" in role:
                        role_data = role["M"]
                        roles_info.append(
                            {
                                "account_id": role_data.get("account_id", {}).get(
                                    "S", ""
                                ),
                                "role_arn": role_data.get("role_arn", {}).get("S", ""),
                            }
                        )

            if "Kubernetes_Roles_Info" in item and "L" in item["Kubernetes_Roles_Info"]:
                for role in item["Kubernetes_Roles_Info"]["L"]:
                    if "M" in role:
                        role_data = role["M"]
                        kubernetes_roles_info.append(
                            {
                                "account_id": role_data.get("account_id", {}).get(
                                    "S", ""
                                ),
                                "role_arn": role_data.get("role_arn", {}).get("S", ""),
                            }
                        )

            user_data = {
                "company": company,
                "profileImage": profile_image,
                "roles_info": roles_info,
                "kubernetes_roles_info": kubernetes_roles_info,
            }

            # Convert profile image URL from S3 to base64
            if profile_image:
                bucket_name = os.getenv("S3_BUCKET_NAME")
                parts = profile_image.split("/")
                s3_key = "/".join(parts[-3:])
                profile_image_base64 = get_profile_image_from_s3(s3_key, bucket_name)
            else:
                profile_image_base64 = ""

            user_data["profileImage"] = profile_image_base64

        profile_details = {
            "full_name": name,
            "username": username,
            "email": email,
            "company": user_data.get("company", ""),
            "roles_info": user_data.get("roles_info", ""),
            "kubernetes_roles_info": user_data.get("kubernetes_roles_info", ""),
            "profileImage": user_data.get(
                "profileImage",
                "",
            ),
        }

        return {"status": "ok", "response": {"profileDetails": profile_details}}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def delete_role_data_function(role_data: RolesInfoModel):
    try:
        access_token = role_data.access_token
        roles_info = role_data.roles
        account_id = roles_info[0].account_id or ""
        role_arn = roles_info[0].role_arn or ""
        role_type = role_data.role_type or ""

        if (
            any(
                field == "" for field in [access_token, account_id, role_arn, role_type]
            )
            or not roles_info
            or not access_token
        ):
            return {"status": "error", "error_message": "Missing required fields"}

        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        cognito_response = cognito_client.get_user(AccessToken=access_token)
        username = cognito_response.get("Username", "")

        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table_name = os.getenv("USERDATA_TABLE_DYNAMODB")

        response = dynamodb_client.get_item(
            TableName=table_name, Key={"UserName": {"S": username}}
        )

        if "Item" not in response:
            return {"status": "error", "error_message": "User not found"}

        # Set key based on role_type
        Role_Key = "Roles_Info" if role_type == "infra" else "Kubernetes_Roles_Info"

        current_roles = []
        if Role_Key in response["Item"] and "L" in response["Item"][Role_Key]:
            for role in response["Item"][Role_Key]["L"]:
                if "M" in role:
                    role_data = role["M"]
                    role_entry = {
                        "account_id": role_data.get("account_id", {}).get("S", ""),
                        "role_arn": role_data.get("role_arn", {}).get("S", ""),
                    }
                    current_roles.append(role_entry)

        updated_roles = [
            role
            for role in current_roles
            if not (role["account_id"] == account_id and role["role_arn"] == role_arn)
        ]

        if len(current_roles) == len(updated_roles):
            return {
                "status": "error",
                "error_message": "Role not found",
            }

        updated_roles_ddb = [
            {
                "M": {
                    "account_id": {"S": role["account_id"]},
                    "role_arn": {"S": role["role_arn"]},
                }
            }
            for role in updated_roles
        ]

        dynamodb_client.update_item(
            TableName=table_name,
            Key={"UserName": {"S": username}},
            UpdateExpression=f"SET {Role_Key} = :roles",
            ExpressionAttributeValues={":roles": {"L": updated_roles_ddb}},
        )

        return {"status": "ok", "message": "Role deleted successfully"}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message, "status": "error"}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e), "status": "error"}


def get_eks_accounts_details_function(data: UserNameModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
        username = data.username

        s3_client = boto3.client("s3", region_name=BOTO3_REGION)

        # Get all objects in the user"s EKS-Scan-Reports folder
        prefix = f"EKS-Scan-Reports/{username}/"

        # <CHANGE> Building nested JSON structure instead of separate arrays
        nested_structure = {}

        # Get all objects recursively
        paginator = s3_client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix)

        for page in pages:
            if "Contents" in page:
                for obj in page["Contents"]:
                    key = obj["Key"]
                    # Remove the prefix to get relative path
                    relative_path = key.replace(prefix, "")

                    # Skip if it"s just the folder itself
                    if not relative_path or relative_path.endswith("/"):
                        continue

                    # Split the path: account_id/cluster_name/report_type/date/pdf_name
                    path_parts = relative_path.split("/")

                    if len(path_parts) >= 5:
                        account_id = path_parts[0]
                        cluster_name = path_parts[1]
                        report_type = path_parts[2]
                        date = path_parts[3]
                        pdf_name = path_parts[4]

                        # <CHANGE> Build nested structure: {accountid: {cluster: {reporttype: {date: [reports]}}}}
                        if account_id not in nested_structure:
                            nested_structure[account_id] = {}

                        if cluster_name not in nested_structure[account_id]:
                            nested_structure[account_id][cluster_name] = {}

                        if (
                            report_type
                            not in nested_structure[account_id][cluster_name]
                        ):
                            nested_structure[account_id][cluster_name][report_type] = {}

                        if (
                            date
                            not in nested_structure[account_id][cluster_name][
                                report_type
                            ]
                        ):
                            nested_structure[account_id][cluster_name][report_type][
                                date
                            ] = []

                        if (
                            pdf_name.endswith(".pdf") or pdf_name.endswith(".html")
                        ) and pdf_name not in nested_structure[account_id][
                            cluster_name
                        ][
                            report_type
                        ][
                            date
                        ]:
                            nested_structure[account_id][cluster_name][report_type][
                                date
                            ].append(pdf_name)

        return {"status": "ok", "response": nested_structure}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def get_pdf_report_function(data: PDFReportModel):
    """
    Get PDF report using presigned URL
    """

    try:
        username = data.username
        account = data.account
        cluster = data.cluster
        report_type = data.report_type
        date = data.date
        pdf_name = data.pdf_name

        # Validate required parameters
        if not all([username, account, cluster, report_type, date, pdf_name]):
            return {"success": False, "error": "Missing required parameters"}

        # Construct S3 key based on folder structure
        s3_key = f"EKS-Scan-Reports/{username}/{account}/{cluster}/{report_type}/{date}/{pdf_name}"

        # Initialize S3 client
        s3_client = boto3.client("s3")
        bucket_name = os.getenv("S3_BUCKET_NAME")

        # Check if file exists
        try:
            s3_client.head_object(Bucket=bucket_name, Key=s3_key)
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return {
                    "status": "error",
                    "error_message": f"PDF file not found: {pdf_name}",
                }
            else:
                print("Error checking file in S3: ", e.response["Error"]["Message"])
                return {
                    "status": "error",
                    "error_message": f"Could not fetch report",
                }
        # Generate presigned URL
        presigned_url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": s3_key},
            ExpiresIn=3600,  # 1 hour
        )

        return {
            "status": "ok",
            "pdfUrl": presigned_url,
            "fileName": pdf_name,
            "expiresIn": 3600,
        }

    except Exception as e:
        print(f"Error getting PDF report: {str(e)}")
        return {
            "status": "error",
            "error_message": "Internal server error while retrieving PDF report",
        }


def update_user_profile_function(
    update_data: UpdateProfileModel,
    profile_image: UploadFile = File(None),
):

    from utils.upload_to_s3 import upload_profile_image_to_s3

    try:
        username = update_data.username
        if not username:
            return {
                "status": "error",
                "error_message": "Username is required",
            }

        BOTO3_REGION = os.getenv("BOTO3_REGION")

        # Update DynamoDB attributes
        dynamodb_client = boto3.resource("dynamodb", region_name=BOTO3_REGION)
        table_name = os.getenv("USERDATA_TABLE_DYNAMODB")
        table = dynamodb_client.Table(table_name)

        update_expression_parts = []
        expression_values = {}

        if profile_image:

            upload_result = upload_profile_image_to_s3(
                upload_file=profile_image, username=username
            )
            if upload_result.get("status") == "ok":
                update_expression_parts.append("Profile_Image = :profile_image")
                expression_values[":profile_image"] = upload_result["url"]
            else:
                return {
                    "status": "error",
                    "error_message": upload_result.get("error_message"),
                }

        if update_data.company:
            update_expression_parts.append("Company = :company")
            expression_values[":company"] = update_data.company

        if update_data.full_name:
            update_expression_parts.append("Full_Name = :full_name")
            expression_values[":full_name"] = update_data.full_name

        if update_expression_parts:
            update_expression = "SET " + ", ".join(update_expression_parts)
            # print("update expression: ", update_expression)
            table.update_item(
                Key={"UserName": username},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
            )

        return {"status": "ok", "message": "Profile updated successfully"}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def increament_scan_count(username: str, scan_type: str):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")

        # step 1: decide attribute name based on scan type
        field_to_increment = scan_type_mapping.get(scan_type.lower())
        if not field_to_increment:
            return {"status": "error", "error_message": "Invalid scan type"}

        # step 2: update count in DynamoDB
        response = dynamodb_client.update_item(
            TableName=table,
            Key={
                "UserName": {"S": username},
            },
            UpdateExpression=f"ADD {field_to_increment} :inc",
            ExpressionAttributeValues={":inc": {"N": "1"}},
            ReturnValues="UPDATED_NEW",
        )

        return {"status": "ok", "response": response}

    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}


def check_scan_threshold(username: str, scan_type: str):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")

        # --- Step 1: Get IS_PRO status first ---
        pro_response = dynamodb_client.get_item(
            TableName=table,
            Key={"UserName": {"S": username}},
            ProjectionExpression="IS_PRO",
        )

        is_pro = pro_response.get("Item", {}).get("IS_PRO", {}).get("BOOL", False)

        if is_pro:  # Pro user -> always allowed
            return {"status": "ok", "message": f"{scan_type} scan allowed (Pro User)"}

        UNLIMITED_FREE_SCAN_TYPES = ["listnamespace"]
        # --- Step 2: Handle unlimited tool (listnamespace) ---
        if scan_type.lower() in UNLIMITED_FREE_SCAN_TYPES:
            return {"status": "ok", "message": "listnamespace allowed (unlimited)"}

        ONE_FREE_SCAN_TYPES = ["basic"]
        threshold = 1 if scan_type.lower() in ONE_FREE_SCAN_TYPES else 0

        field_to_check = scan_type_mapping.get(scan_type.lower())
        if not field_to_check:
            return {"status": "error", "error_message": "Invalid scan type"}

        # step 2: get current count from DynamoDB
        response = dynamodb_client.get_item(
            TableName=table,
            Key={"UserName": {"S": username}},
            ProjectionExpression=field_to_check,
        )

        current_count = int(
            response.get("Item", {}).get(field_to_check, {}).get("N", "0")
        )

        # step 3: check against threshold
        if current_count >= threshold:
            return {
                "status": "error",
                "error_message": f"Free scan limit reached — Contact Us for more details",
                "fail_type": "contact_us",
            }
        else:
            return {"status": "ok", "message": f"{scan_type} scan allowed"}

    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}
