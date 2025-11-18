from typing import Any, Dict, List, Optional, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "SecurityAI"
    API_V1_STR: str = "/api/v1"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = [
        "http://localhost:3000",  # React frontend
    ]

    # Authentication
    SECRET_KEY: str = "dev_secret_key_change_in_production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database (default to local SQLite for easy local dev; override in env for Postgres)
    DATABASE_URL: str = "sqlite+aiosqlite:///./securityai.db"
    
    # InfluxDB
    INFLUXDB_URL: str = "http://influxdb:8086"
    INFLUXDB_ORG: str = "securityai"
    INFLUXDB_BUCKET: str = "metrics"
    INFLUXDB_TOKEN: str = "my-super-secret-auth-token"
    
    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"
    
    # Redis
    REDIS_URL: str = "redis://redis:6379/0"
    
    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)


settings = Settings()