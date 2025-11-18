#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Configuration management for the SecurityAI ML Service.

This module provides centralized configuration management with
environment variable support, validation, and type safety.
"""

import os
from typing import Optional, List, Dict, Any
try:
    # Pydantic v1
    from pydantic import BaseSettings, validator  # type: ignore
    _PYDANTIC_V1 = True
except Exception:  # pragma: no cover
    # Pydantic v2
    from pydantic_settings import BaseSettings, SettingsConfigDict  # type: ignore
    from pydantic import field_validator as validator  # type: ignore
    _PYDANTIC_V1 = False
from enum import Enum


class LogLevel(str, Enum):
    """Available log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ModelType(str, Enum):
    """Available model types."""
    THREAT_DETECTION = "threat_detection"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Application settings
    app_name: str = "SecurityAI ML Service"
    app_version: str = "2.0.0"
    debug: bool = False
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8001
    workers: int = 1
    
    # Logging
    log_level: LogLevel = LogLevel.INFO
    log_format: str = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    
    # MLflow settings
    mlflow_tracking_uri: str = "http://localhost:5000"
    mlflow_experiment_name: str = "securityai-ml"
    
    # Model settings
    model_cache_size: int = 10
    model_timeout: float = 30.0
    batch_size_limit: int = 1000
    
    # Performance settings
    max_concurrent_requests: int = 100
    request_timeout: float = 60.0
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    # Database settings (optional)
    database_url: Optional[str] = None
    redis_url: Optional[str] = None
    
    # Security settings
    api_key_header: str = "X-API-Key"
    allowed_origins: List[str] = ["*"]
    
    # Model artifact paths
    model_storage_path: str = "./artifacts/saved"
    temp_model_path: str = "./artifacts/temp"
    
    @validator('mlflow_tracking_uri')
    def validate_mlflow_uri(cls, v):
        if not v.startswith(('http://', 'https://', 'file://')):
            raise ValueError('MLflow tracking URI must start with http://, https://, or file://')
        return v
    
    @validator('model_storage_path', 'temp_model_path')
    def validate_paths(cls, v):
        os.makedirs(v, exist_ok=True)
        return v
    
    if _PYDANTIC_V1:
        class Config:
            env_file = ".env"
            env_prefix = "SECURITYAI_"
            case_sensitive = False
    else:
        # Pydantic v2 settings configuration
        model_config = SettingsConfigDict(
            env_file=".env",
            env_prefix="SECURITYAI_",
            case_sensitive=False,
        )


# Global settings instance
settings = Settings()


# Model configuration
MODEL_CONFIGS = {
    ModelType.THREAT_DETECTION: {
        "name": "Threat Detection Model",
        "description": "Detects malicious activities and potential threats in network traffic and system logs",
        "input_features": [
            "source_ip", "destination_ip", "source_port", "destination_port",
            "protocol", "packet_count", "byte_count", "duration",
            "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg"
        ],
        "output_classes": ["benign", "malicious", "suspicious"],
        "model_params": {
            "n_estimators": 200,
            "max_depth": 15,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "random_state": 42
        }
    },
    ModelType.VULNERABILITY_ASSESSMENT: {
        "name": "Vulnerability Assessment Model",
        "description": "Assesses vulnerabilities in systems and applications, providing risk scores and severity levels",
        "input_features": [
            "age", "version", "patch_level", "complexity_score",
            "os_type", "service_type", "access_vector", "authentication_required",
            "confidentiality_impact", "integrity_impact", "availability_impact"
        ],
        "severity_thresholds": {
            "critical": 9.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.0
        },
        "model_params": {
            "n_estimators": 150,
            "learning_rate": 0.1,
            "max_depth": 8,
            "subsample": 0.8,
            "random_state": 42
        }
    }
}


# Performance thresholds
PERFORMANCE_THRESHOLDS = {
    "prediction_time_ms": 100,
    "batch_prediction_time_ms": 1000,
    "model_load_time_ms": 5000,
    "memory_usage_mb": 512
}


# Alert configurations
ALERT_CONFIGS = {
    "high_error_rate": {
        "threshold": 0.05,  # 5% error rate
        "window_minutes": 5
    },
    "slow_response": {
        "threshold_ms": 1000,
        "window_minutes": 5
    },
    "memory_usage": {
        "threshold_mb": 1024,
        "window_minutes": 1
    }
}