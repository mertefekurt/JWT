from pydantic_settings import BaseSettings
from typing import Optional, List
import os


class Settings(BaseSettings):
    secret_key: str = "ymy-secret-key-0234"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    database_url: Optional[str] = None
    cors_origins: List[str] = ["*"]
    trusted_hosts: List[str] = ["*"]
    log_level: str = "INFO"
    app_name: str = "JWT Learning API"
    app_version: str = "1.0.0"
    environment: str = "development"

    class Config:
        env_file = ".env"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.environment == "production" and self.secret_key == "ymy-secret-key-0234":
            raise ValueError("secret_key must be set via environment variable in production")


settings = Settings()

