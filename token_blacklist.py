from datetime import datetime, timezone
from typing import Dict
from jose import jwt
from config import settings

blacklisted_tokens: Dict[str, datetime] = {}

def _utcnow():
    return datetime.now(timezone.utc)

def add_to_blacklist(token: str):
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm], options={"verify_exp": False})
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            blacklisted_tokens[token] = exp_datetime
        else:
            blacklisted_tokens[token] = _utcnow()
    except Exception:
        blacklisted_tokens[token] = _utcnow()

def is_token_blacklisted(token: str) -> bool:
    if token not in blacklisted_tokens:
        return False
    exp_time = blacklisted_tokens[token]
    if _utcnow() > exp_time:
        del blacklisted_tokens[token]
        return False
    return True

def remove_expired_tokens():
    current_time = _utcnow()
    expired_tokens = [token for token, exp_time in blacklisted_tokens.items() if current_time > exp_time]
    for token in expired_tokens:
        del blacklisted_tokens[token]
    return len(expired_tokens)

