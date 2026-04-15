import os
import boto3
from botocore.exceptions import ClientError

from Auth.model import (
    UserModel,
    ConfirmUserModel,
    ResendCodeUserModel,
    LoginUserModel,
    GetUserDetailsModel,
    ResetPasswordModel,
)
from Auth.utils import get_secret_hash
from utils.exceptions import handle_error

from db.model import UserDataModel


def get_all_users():
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        userpool_id = os.getenv("USER_POOL_ID")
        response = cognito_client.list_users(UserPoolId=userpool_id)
        return {"Users": response}
    except Exception as e:
        print(f"Error getting users: {e}")
        return {"status": "error", "error_message": str(e)}


def sign_up_function(user: UserModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")

        # Check if email already exists in DynamoDB
        response = dynamodb_client.scan(
            TableName=table,
            FilterExpression="Email = :email",
            ExpressionAttributeValues={":email": {"S": user.email}},
            ProjectionExpression="Email",
        )
        if response.get("Count", 0) > 0:
            return {"status": "error", "error_message": "Email already exists."}

        username = user.username
        password = user.password
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        secret_hash = get_secret_hash(username, client_id, client_secret)

        # Try signup
        try:
            response = cognito_client.sign_up(
                ClientId=client_id,
                SecretHash=secret_hash,
                Username=username,
                Password=password,
                UserAttributes=[
                    {"Name": "email", "Value": user.email},
                    {"Name": "name", "Value": user.full_name},
                ],
            )
            return {"status": "ok", "response": response}

        except cognito_client.exceptions.UsernameExistsException:
            try:
                # Fetch user details from Cognito
                user_info = cognito_client.admin_get_user(
                    UserPoolId=os.getenv("USER_POOL_ID"),
                    Username=username,
                )

                user_status = user_info.get("UserStatus", "")
                email_attr = next(
                    (
                        attr["Value"]
                        for attr in user_info["UserAttributes"]
                        if attr["Name"] == "email"
                    ),
                    None,
                )

                if user_status == "UNCONFIRMED" and email_attr == user.email:
                    # Resend verification code
                    resend_response = cognito_client.resend_confirmation_code(
                        ClientId=client_id,
                        SecretHash=secret_hash,
                        Username=username,
                    )
                    return {
                        "status": "unconfirmed",
                        "message": "User already exists but unconfirmed. Verification code resent.",
                        "response": resend_response,
                    }
                else:
                    return {
                        "status": "error",
                        "error_message": "Username already exists.",
                    }

            except cognito_client.exceptions.UserNotFoundException:
                return {"status": "error", "error_message": "Username already exists."}
            except cognito_client.exceptions.InvalidParameterException:
                return {"status": "error", "error_message": "Username already exists."}

    except ClientError as e:
        print(f"Error signing up user: {str(e)}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error signing up user: {str(e)}")
        return {"status": "error", "error_message": str(e)}


def confirm_user_function(confirm_user: ConfirmUserModel, user: UserDataModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        username = confirm_user.username
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        secret_hash = get_secret_hash(username, client_id, client_secret)
        response = cognito_client.confirm_sign_up(
            ClientId=client_id,
            SecretHash=secret_hash,
            Username=username,
            ConfirmationCode=confirm_user.confirmation_code,
        )
        from db.crud import add_userdata_function

        userdata = UserDataModel(
            full_name=user.full_name or "",
            username=user.username.lower() or "",
            email=user.email or "",
            company=user.company or "",
            mobile_number=user.mobile_number or "",
            role=user.role or "",
            roles_info=[],
            kubernetes_roles_info=[],
            root_account_id="",
        )

        add_response = add_userdata_function(userdata)
        if "error_message" in add_response:
            return {"status": "error", "error_message": add_response["error_message"]}

        return {"status": "ok", "response": response}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error signing up user: {e}")
        return {"status": "error", "error_message": str(e)}


def resend_code_function(resend_code_user: ResendCodeUserModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        username = resend_code_user.username
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        secret_hash = get_secret_hash(username, client_id, client_secret)
        response = cognito_client.resend_confirmation_code(
            ClientId=client_id, SecretHash=secret_hash, Username=username
        )
        return {"status": "ok", "response": response}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error signing up user: {e}")
        return {"status": "error", "error_message": str(e)}


def login_function(login_user: LoginUserModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        username = login_user.username
        password = login_user.password
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        secret_hash = get_secret_hash(username, client_id, client_secret)
        response = cognito_client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=client_id,
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": secret_hash,
            },
        )
        return {"status": "ok", "response": response}
    except ClientError as e:
        print(e)
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error signing up user: {e}")
        return {"status": "error", "error_message": str(e)}


def get_user_function(get_user: GetUserDetailsModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        response = cognito_client.get_user(AccessToken=get_user.access_token)
        return {"status": "ok", "response": response}
    except ClientError as e:

        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        print(
            f"error_code from here: {error_code} and error_message from here: {error_message}"
        )
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error getting user details: {e}")
        return {"status": "error", "error_message": str(e)}


def forgot_password_function(forgot_password: ResendCodeUserModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        username = forgot_password.username
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        secret_hash = get_secret_hash(username, client_id, client_secret)
        response = cognito_client.forgot_password(
            ClientId=client_id, SecretHash=secret_hash, Username=username
        )
        return {"status": "ok", "response": response}
    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        raw_message = e.response["Error"].get("Message", "")
        error_message = handle_error(error_code, raw_message)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error signing up user: {e}")
        return {"status": "error", "error_message": str(e)}


def reset_password_function(reset_password: ResetPasswordModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        username = reset_password.username
        password = reset_password.password
        confirmation_code = reset_password.confirmation_code
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")
        secret_hash = get_secret_hash(username, client_id, client_secret)
        response = cognito_client.confirm_forgot_password(
            ClientId=client_id,
            SecretHash=secret_hash,
            Username=username,
            ConfirmationCode=confirmation_code,
            Password=password,
        )
        return {"status": "ok", "response": response}
    except ClientError as e:
        print(f"error: {e}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error signing up user: {e}")
        return {"status": "error", "error_message": str(e)}


def get_user_account_details_function(get_user: GetUserDetailsModel):
    try:
        BOTO3_REGION = os.getenv("BOTO3_REGION")
        cognito_client = boto3.client("cognito-idp", region_name=BOTO3_REGION)
        congnito_response = cognito_client.get_user(AccessToken=get_user.access_token)
        username = congnito_response.get("Username", "")
        
        dynamodb_client = boto3.client("dynamodb", region_name=BOTO3_REGION)
        table = os.getenv("USERDATA_TABLE_DYNAMODB")
        dynamodb_response = dynamodb_client.get_item(
            TableName=table,
            Key={
                "UserName": {"S": username},
            },
        )
        roles_info_response = (
            dynamodb_response.get("Item", {}).get("Roles_Info", []).get("L", [])
        )
        kubernetes_roles_info_response = (
            dynamodb_response.get("Item", {})
            .get("Kubernetes_Roles_Info", [])
            .get("L", [])
        )

        full_name = dynamodb_response.get("Item", {}).get("Full_Name", {}).get("S", "")
        is_admin =  dynamodb_response.get("Item", {}).get("IS_ADMIN", {}).get("BOOL", False)
        
        # print("roles_info_response", roles_info_response)
        roles_info = []
        kubernetes_roles_info = []

        for account in roles_info_response:
            account_data = account.get("M", {})
            roles_info.append(
                {
                    "role_arn": account_data.get("role_arn", {}).get("S", ""),
                    "account_id": account_data.get("account_id", {}).get("S", ""),
                    "account_name": account_data.get("account_name", {}).get("S", ""),
                }
            )

        for account in kubernetes_roles_info_response:
            account_data = account.get("M", {})
            kubernetes_roles_info.append(
                {
                    "role_arn": account_data.get("role_arn", {}).get("S", ""),
                    "account_id": account_data.get("account_id", {}).get("S", ""),
                    "account_name": account_data.get("account_name", {}).get("S", ""),
                }
            )

        return {
            "status": "ok",
            "response": {
                "username": username,
                "account_details": roles_info,
                "eks_account_details": kubernetes_roles_info,
                "full_name": full_name,
                "is_admin": is_admin
            },
        }
    except ClientError as e:
        print("in except: ",str(e))
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "error_message": str(e)}
