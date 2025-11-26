import logging
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
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

