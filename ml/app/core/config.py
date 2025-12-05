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
    MALWARE_DETECTION = "malware_detection"
    ATTACK_PATH = "attack_path"
    MITRE_MAPPING = "mitre_mapping"
    UEBA = "ueba"
    FEDERATED_LEARNING = "federated_learning"
    EDR_TELEMETRY = "edr_telemetry"
    XDR_CORRELATION = "xdr_correlation"
    SOAR_ENGINE = "soar_engine"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    COMPLIANCE = "compliance"


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
        "description": "Classifies security events into threat categories (e.g., malware, exploit, lateral movement)",
        "module_path": "app.threat_classification.threat_classifier_prod",
        "factory_func": "get_threat_classifier"
    },
    ModelType.MALWARE_DETECTION: {
        "name": "Malware Detection Model",
        "description": "Detects malware based on static and behavioral features",
        "module_path": "app.malware_detection.malware_detector_prod",
        "factory_func": "get_malware_detector"
    },
    ModelType.ATTACK_PATH: {
        "name": "Attack Path Predictor",
        "description": "Predicts potential attack paths and lateral movement risks",
        "module_path": "app.attack_path.attack_path_predictor_prod",
        "factory_func": "get_attack_path_predictor"
    },
    ModelType.MITRE_MAPPING: {
        "name": "MITRE Technique Mapper",
        "description": "Maps security events to MITRE ATT&CK techniques",
        "module_path": "app.mitre_mapping.mitre_technique_mapper_prod",
        "factory_func": "get_mitre_mapper"
    },
    ModelType.UEBA: {
        "name": "UEBA Graph Detector",
        "description": "Detects anomalous user behavior using graph analysis",
        "module_path": "app.ueba.ueba_graph_detector_prod",
        "factory_func": "get_ueba_detector"
    },
    ModelType.FEDERATED_LEARNING: {
        "name": "Federated Learning System",
        "description": "Privacy-preserving collaborative learning",
        "module_path": "app.federated_learning.federated_learning_prod",
        "factory_func": "get_federated_learning"
    },
    ModelType.EDR_TELEMETRY: {
        "name": "EDR Telemetry Processor",
        "description": "Processes endpoint telemetry for suspicious patterns",
        "module_path": "app.edr_telemetry.edr_telemetry_processor_prod",
        "factory_func": "get_edr_telemetry_processor"
    },
    ModelType.XDR_CORRELATION: {
        "name": "XDR Correlation Engine",
        "description": "Correlates alerts across multiple sources",
        "module_path": "app.xdr_correlation.xdr_correlation_engine_prod",
        "factory_func": "get_xdr_engine"
    },
    ModelType.SOAR_ENGINE: {
        "name": "SOAR Orchestrator",
        "description": "Automated incident response and playbook execution",
        "module_path": "app.soar_engine.soar_orchestrator_prod",
        "factory_func": "get_soar_orchestrator"
    },
    ModelType.VULNERABILITY_ASSESSMENT: {
        "name": "Vulnerability Assessment Model",
        "description": "Assesses vulnerabilities in systems and applications",
        "module_path": "app.models.vulnerability_assessment",
        "factory_func": "VulnerabilityAssessmentModel"
    },
    ModelType.COMPLIANCE: {
        "name": "Compliance Assessment Model",
        "description": "Assesses system compliance against standards",
        "module_path": "app.compliance.compliance_model",
        "factory_func": "get_compliance_model"
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