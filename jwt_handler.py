from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from config import settings
from models import TokenData
from token_blacklist import is_token_blacklisted

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def _utcnow():
    return datetime.now(timezone.utc)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = _utcnow() + expires_delta
    else:
        expire = _utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = _utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def verify_token(token: str, token_type: str = "access") -> TokenData:
    if is_token_blacklisted(token):
        raise JWTError("Token has been revoked")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        payload_token_type = payload.get("type")
        if payload_token_type and payload_token_type != token_type:
            raise JWTError(f"Invalid token type. Expected {token_type}, got {payload_token_type}")
        username: str = payload.get("sub")
        if username is None:
            raise JWTError("Token invalid")
        token_data = TokenData(username=username)
        return token_data
    except JWTError:
        raise JWTError("Token invalid")

def verify_refresh_token(token: str) -> TokenData:
    return verify_token(token, token_type="refresh")

