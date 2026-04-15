from pydantic import BaseModel


class UserModel(BaseModel):
    full_name: str
    username: str
    password: str
    email: str


class ConfirmUserModel(BaseModel):
    username: str
    confirmation_code: str


class ResendCodeUserModel(BaseModel):
    username: str


class LoginUserModel(BaseModel):
    username: str
    password: str


class GetUserDetailsModel(BaseModel):
    access_token: str


class ResetPasswordModel(BaseModel):
    username: str
    password: str
    confirmation_code: str
