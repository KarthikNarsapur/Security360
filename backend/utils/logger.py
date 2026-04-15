import logging
import os

ENV = os.getenv("ENV", "development")

LOG_LEVEL = logging.DEBUG if ENV == "development" else logging.INFO


logging.basicConfig(
    level=LOG_LEVEL, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)
logging.getLogger("boto3").setLevel(logging.WARNING)
logger = logging.getLogger("secops360")
