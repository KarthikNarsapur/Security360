# import os
# import requests
# from fastapi import Request
# from fastapi.responses import JSONResponse
# from jose import jwt, JWTError

# # AWS Cognito Configuration
# COGNITO_REGION = os.getenv("BOTO3_REGION")
# COGNITO_USERPOOL_ID = os.getenv("USER_POOL_ID")
# COGNITO_CLIENT_ID = os.getenv("CLIENT_ID")

# ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}"
# JWKS_URL = f"{ISSUER}/.well-known/jwks.json"


# # Helper Function: Load JWKS Keys Safely
# def load_jwks():
#     """Fetch JWKS (public keys) from Cognito for verifying JWTs."""
#     try:
#         response = requests.get(JWKS_URL, timeout=5)
#         response.raise_for_status()
#         print("JWKS keys loaded successfully.")
#         return response.json()
#     except Exception as e:
#         print(f"Warning: Failed to load JWKS keys: {e}")
#         return {"keys": []}


# # Load JWKS at startup
# # jwks = load_jwks()


# # Middleware: JWT Authentication
# class AuthMiddleware:
#     def __init__(self, app):
#         self.app = app
#         self.public_routes = [
#             "/api/login",
#             "/api/signup",
#             "/api/check",
#             "/api/forgotpassword",
#             "/api/resetpassword",
#             "/api/contact-us",
#             "/api/scan",
#         ]

#     async def __call__(self, scope, receive, send):

#         # Skip WebSocket and non-HTTP routes
#         if scope["type"] != "http":
#             await self.app(scope, receive, send)
#             return

#         request = Request(scope)
#         if request.method == "OPTIONS":
#             await self.app(scope, receive, send)
#             return

#         path = request.url.path
#         # Allow public routes without token
#         if any(path.startswith(route) for route in self.public_routes):
#             await self.app(scope, receive, send)
#             return

#         # Extract the Authorization header
#         auth_header = request.headers.get("authorization")
#         if not auth_header or not auth_header.startswith("Bearer "):
#             response = JSONResponse(
#                 {"error": "Missing or invalid Authorization header"},
#                 status_code=401,
#             )
#             await response(scope, receive, send)
#             return

#         token = auth_header.split(" ")[1]

#         # Ensure JWKS keys are available (reload if missing)
#         global jwks
#         if not jwks.get("keys"):
#             jwks = load_jwks()
#             if not jwks.get("keys"):
#                 response = JSONResponse(
#                     {"error": "Unable to verify token (JWKS unavailable)"},
#                     status_code=503,
#                 )
#                 await response(scope, receive, send)
#                 return

#         await self.app(scope, receive, send)

#         # Validate the JWT token
#         try:
#             await self.app(scope, receive, send)

#             headers = jwt.get_unverified_header(token)
#             key = next((k for k in jwks["keys"] if k["kid"] == headers["kid"]), None)
#             if not key:
#                 raise JWTError("Invalid token header (kid mismatch)")

#             payload = jwt.decode(
#                 token,
#                 key,
#                 algorithms=["RS256"],
#                 audience=COGNITO_CLIENT_ID,
#                 issuer=ISSUER,
#             )

#             # Attach user info to the request scope
#             scope["user"] = {
#                 "username": payload.get("username") or payload.get("cognito:username"),
#                 "email": payload.get("email"),
#             }

#         except JWTError as e:
#             response = JSONResponse(
#                 {"error": f"Invalid or expired token: {str(e)}"},
#                 status_code=401,
#             )
#             await response(scope, receive, send)
#             return

#         # Continue to next middleware or route
#         await self.app(scope, receive, send)
