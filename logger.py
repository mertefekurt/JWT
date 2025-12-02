import logging
import sys
import os
from datetime import datetime

from config import settings


log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

level = getattr(logging, settings.log_level.upper(), logging.INFO)

logging.basicConfig(
    level=level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"{log_dir}/app.log"),
    ],
)

logger = logging.getLogger("jwt_api")


def log_request(method: str, path: str, status_code: int, process_time: float):
    logger.info(f"{method} {path} - Status: {status_code} - Time: {process_time:.4f}s")


def log_error(message: str, error: Exception = None):
    logger.error(f"{message} - Error: {str(error) if error else 'Unknown'}")


def log_auth_event(event_type: str, username: str, success: bool):
    status = "SUCCESS" if success else "FAILED"
    logger.info(f"AUTH {event_type} - User: {username} - Status: {status}")


def log_security_event(event: str, details: str = ""):
    logger.warning(f"SECURITY: {event} - {details}")

