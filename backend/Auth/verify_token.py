# Auth/verify_token.py
import os
import requests
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

COGNITO_REGION = os.getenv("BOTO3_REGION")
COGNITO_USERPOOL_ID = os.getenv("USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("CLIENT_ID")

ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

bearer_scheme = HTTPBearer()
jwks = requests.get(JWKS_URL).json()


def verify_cognito_token(token: str):
    """Verify Cognito JWT Access Token"""
    try:
        headers = jwt.get_unverified_header(token)
        key = next((k for k in jwks["keys"] if k["kid"] == headers["kid"]), None)
        if not key:
            raise HTTPException(status_code=401, detail="Invalid token header")

        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=ISSUER,
        )
        return claims
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """FastAPI dependency to protect routes"""
    token = credentials.credentials
    claims = verify_cognito_token(token)
    print("claim: ", claims)
    return {
        "username": claims.get("username") or claims.get("cognito:username"),
        "email": claims.get("email"),
    }
