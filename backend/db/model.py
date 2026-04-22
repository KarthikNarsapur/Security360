from pydantic import BaseModel
from typing import Optional, List


class RoleModel(BaseModel):
    role_arn: str
    account_id: str
    account_name: Optional[str] = ""
    # Azure Service Principal fields (used when role_type is "azure")
    tenant_id: Optional[str] = ""
    client_id: Optional[str] = ""
    client_secret: Optional[str] = ""


class UserDataModel(BaseModel):
    full_name: str
    username: str
    email: str
    roles_info: Optional[List[RoleModel]] = []
    kubernetes_roles_info: Optional[List[RoleModel]] = []
    root_account_id: Optional[str] = None
    company: Optional[str] = None
    mobile_number: str
    role: str


class DBKeysModel(BaseModel):
    username: str


class RolesInfoModel(BaseModel):
    roles: list[RoleModel]
    access_token: str
    role_type: str


class UpdateProfileModel(BaseModel):
    username: str
    full_name: Optional[str] = None
    company: Optional[str] = None
