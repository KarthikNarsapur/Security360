import os
import json
import logging
import ipaddress
from fastapi import Request

# ----------------- Logging Setup -----------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

ip_logger = logging.getLogger("ip_logger")
ip_logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(os.path.join(LOG_DIR, "ip_blocked.log"))
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))

if not ip_logger.handlers:
    ip_logger.addHandler(file_handler)
# -------------------------------------------------

raw_ips = os.getenv("ALLOWED_IPS", "")

# Convert CIDR strings into IPv4Network objects
ALLOWED_IPS = {
    ipaddress.ip_network(ip.strip(), strict=False)
    for ip in raw_ips.split(",")
    if ip.strip()
}


def is_ip_allowed(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in ALLOWED_IPS)
    except ValueError:
        return False


def get_client_ip(request: Request):
    # X-Forwarded-For header (for load balancers)
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    return request.client.host


def validate_ip_function(request: Request):
    #--------------------------------------
    # This is used for local development or testing purposes where IP validation might be bypassed.
    if os.getenv("ENVIRONMENT") == "LOCAL":
        return {"isAllowed": True, "ip": ""}
    #--------------------------------------
    
    ip = get_client_ip(request)
    
    allowed = is_ip_allowed(ip)
    if not allowed:
        logging.info(f"Unauthorized access attempt from IP: {ip}")

    return {"isAllowed": allowed, "ip": ip}
