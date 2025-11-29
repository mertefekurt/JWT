from pydantic_settings import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    secret_key: str = "ymy-secret-key-0234"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    database_url: Optional[str] = None
    cors_origins: List[str] = ["*"]
    trusted_hosts: List[str] = ["*"]
    
    class Config:
        env_file = ".env"

settings = Settings()

