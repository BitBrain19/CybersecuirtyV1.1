#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Comprehensive exception handling system for the SecurityAI ML Service.

This module provides:
- Custom exception classes
- Error recovery mechanisms
- Detailed error logging
- Circuit breaker pattern
- Retry logic with exponential backoff
"""

import time
import traceback
from typing import Dict, Any, Optional, Callable, Type, List
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from loguru import logger
import asyncio
from datetime import datetime, timedelta


class ErrorSeverity(str, Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(str, Enum):
    """Error categories for classification."""
    MODEL_ERROR = "model_error"
    DATA_ERROR = "data_error"
    SYSTEM_ERROR = "system_error"
    NETWORK_ERROR = "network_error"
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    RESOURCE_ERROR = "resource_error"


@dataclass
class ErrorContext:
    """Context information for errors."""
    timestamp: datetime
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    model_name: Optional[str] = None
    endpoint: Optional[str] = None
    input_data: Optional[Dict[str, Any]] = None
    system_info: Optional[Dict[str, Any]] = None


class SecurityAIException(Exception):
    """Base exception class for SecurityAI ML Service."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "UNKNOWN_ERROR",
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM_ERROR,
        context: Optional[ErrorContext] = None,
        recoverable: bool = True,
        user_message: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.severity = severity
        self.category = category
        self.context = context or ErrorContext(timestamp=datetime.now())
        self.recoverable = recoverable
        self.user_message = user_message or "An error occurred while processing your request."
        self.traceback_str = traceback.format_exc()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/API responses."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "user_message": self.user_message,
            "severity": self.severity.value,
            "category": self.category.value,
            "recoverable": self.recoverable,
            "timestamp": self.context.timestamp.isoformat(),
            "context": {
                "request_id": self.context.request_id,
                "model_name": self.context.model_name,
                "endpoint": self.context.endpoint
            }
        }


class ModelError(SecurityAIException):
    """Errors related to ML model operations."""
    
    def __init__(self, message: str, model_name: str = None, **kwargs):
        super().__init__(
            message=message,
            error_code="MODEL_ERROR",
            category=ErrorCategory.MODEL_ERROR,
            **kwargs
        )
        if model_name and self.context:
            self.context.model_name = model_name


class ModelNotFoundError(ModelError):
    """Model not found or not loaded."""
    
    def __init__(self, model_name: str, **kwargs):
        super().__init__(
            message=f"Model '{model_name}' not found or not loaded",
            error_code="MODEL_NOT_FOUND",
            model_name=model_name,
            recoverable=False,
            user_message=f"The requested model '{model_name}' is not available.",
            **kwargs
        )


class ModelLoadError(ModelError):
    """Error loading a model."""
    
    def __init__(self, model_name: str, reason: str = None, **kwargs):
        message = f"Failed to load model '{model_name}'"
        if reason:
            message += f": {reason}"
            
        super().__init__(
            message=message,
            error_code="MODEL_LOAD_ERROR",
            model_name=model_name,
            severity=ErrorSeverity.HIGH,
            user_message="The model is temporarily unavailable. Please try again later.",
            **kwargs
        )


class PredictionError(ModelError):
    """Error during model prediction."""
    
    def __init__(self, model_name: str, reason: str = None, **kwargs):
        message = f"Prediction failed for model '{model_name}'"
        if reason:
            message += f": {reason}"
            
        super().__init__(
            message=message,
            error_code="PREDICTION_ERROR",
            model_name=model_name,
            user_message="Unable to generate prediction. Please check your input data.",
            **kwargs
        )


class DataValidationError(SecurityAIException):
    """Data validation errors."""
    
    def __init__(self, message: str, field_name: str = None, **kwargs):
        super().__init__(
            message=message,
            error_code="DATA_VALIDATION_ERROR",
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.LOW,
            recoverable=False,
            user_message="Invalid input data provided.",
            **kwargs
        )
        self.field_name = field_name


class ResourceExhaustionError(SecurityAIException):
    """System resource exhaustion errors."""
    
    def __init__(self, resource_type: str, **kwargs):
        super().__init__(
            message=f"Resource exhaustion: {resource_type}",
            error_code="RESOURCE_EXHAUSTION",
            category=ErrorCategory.RESOURCE_ERROR,
            severity=ErrorSeverity.CRITICAL,
            user_message="Service temporarily unavailable due to high load.",
            **kwargs
        )


class CircuitBreakerError(SecurityAIException):
    """Circuit breaker is open."""
    
    def __init__(self, service_name: str, **kwargs):
        super().__init__(
            message=f"Circuit breaker open for service: {service_name}",
            error_code="CIRCUIT_BREAKER_OPEN",
            category=ErrorCategory.SYSTEM_ERROR,
            severity=ErrorSeverity.HIGH,
            recoverable=False,
            user_message="Service temporarily unavailable. Please try again later.",
            **kwargs
        )


class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Type[Exception] = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
        
    def __call__(self, func: Callable) -> Callable:
        """Decorator to apply circuit breaker to a function."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self._call(func, *args, **kwargs)
        return wrapper
        
    def _call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker logic."""
        if self.state == "open":
            if self._should_attempt_reset():
                self.state = "half-open"
            else:
                raise CircuitBreakerError(func.__name__)
                
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise
            
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit breaker."""
        return (
            self.last_failure_time and
            time.time() - self.last_failure_time >= self.recovery_timeout
        )
        
    def _on_success(self):
        """Handle successful execution."""
        self.failure_count = 0
        self.state = "closed"
        
    def _on_failure(self):
        """Handle failed execution."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """Decorator for retry logic with exponential backoff."""
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                    
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_retries:
                        logger.error(f"Function {func.__name__} failed after {max_retries} retries: {e}")
                        raise
                        
                    delay = min(base_delay * (exponential_base ** attempt), max_delay)
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}, retrying in {delay}s: {e}")
                    time.sleep(delay)
                    
            raise last_exception
            
        return wrapper
    return decorator


class ErrorHandler:
    """Centralized error handling and recovery system."""
    
    def __init__(self):
        self.error_counts = {}
        self.recovery_strategies = {}
        
    def register_recovery_strategy(
        self,
        error_type: Type[Exception],
        strategy: Callable[[Exception], Any]
    ):
        """Register a recovery strategy for a specific error type."""
        self.recovery_strategies[error_type] = strategy
        
    def handle_error(
        self,
        error: Exception,
        context: Optional[ErrorContext] = None
    ) -> Optional[Any]:
        """Handle an error with appropriate logging and recovery."""
        
        # Convert to SecurityAI exception if needed
        if not isinstance(error, SecurityAIException):
            error = SecurityAIException(
                message=str(error),
                context=context,
                severity=ErrorSeverity.MEDIUM
            )
            
        # Log the error
        self._log_error(error)
        
        # Update error counts
        error_key = f"{error.category.value}:{error.error_code}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        # Attempt recovery if strategy exists
        for error_type, strategy in self.recovery_strategies.items():
            if isinstance(error, error_type):
                try:
                    return strategy(error)
                except Exception as recovery_error:
                    logger.error(f"Recovery strategy failed: {recovery_error}")
                    
        # Re-raise if no recovery possible
        raise error
        
    def _log_error(self, error: SecurityAIException):
        """Log error with appropriate level based on severity."""
        error_dict = error.to_dict()
        
        if error.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"CRITICAL ERROR: {error.message}", extra=error_dict)
        elif error.severity == ErrorSeverity.HIGH:
            logger.error(f"HIGH SEVERITY: {error.message}", extra=error_dict)
        elif error.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"MEDIUM SEVERITY: {error.message}", extra=error_dict)
        else:
            logger.info(f"LOW SEVERITY: {error.message}", extra=error_dict)
            
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        total_errors = sum(self.error_counts.values())
        
        return {
            "total_errors": total_errors,
            "error_breakdown": dict(self.error_counts),
            "most_common_errors": sorted(
                self.error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }


# Global error handler instance
error_handler = ErrorHandler()


# Default recovery strategies
def model_load_recovery(error: ModelLoadError) -> None:
    """Recovery strategy for model loading errors."""
    logger.info(f"Attempting to recover from model load error: {error.message}")
    # Could implement model reloading, fallback model, etc.
    # For now, just log and re-raise
    raise error


def prediction_error_recovery(error: PredictionError) -> Dict[str, Any]:
    """Recovery strategy for prediction errors."""
    logger.info(f"Providing fallback response for prediction error: {error.message}")
    
    # Return a safe fallback response
    return {
        "prediction": "unknown",
        "confidence": 0.0,
        "fallback": True,
        "error_message": "Prediction service temporarily unavailable"
    }


# Register default recovery strategies
error_handler.register_recovery_strategy(ModelLoadError, model_load_recovery)
error_handler.register_recovery_strategy(PredictionError, prediction_error_recovery)


# Utility functions
def safe_execute(func: Callable, *args, **kwargs) -> tuple[Any, Optional[Exception]]:
    """Safely execute a function and return result and any exception."""
    try:
        result = func(*args, **kwargs)
        return result, None
    except Exception as e:
        return None, e


def create_error_context(
    request_id: str = None,
    model_name: str = None,
    endpoint: str = None,
    **kwargs
) -> ErrorContext:
    """Create an error context with common fields."""
    return ErrorContext(
        timestamp=datetime.now(),
        request_id=request_id,
        model_name=model_name,
        endpoint=endpoint,
        **kwargs
    )