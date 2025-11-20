from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    secret_key: str = "ymy-secret-key-0234"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    database_url: Optional[str] = None
    
    class Config:
        env_file = ".env"

settings = Settings()

