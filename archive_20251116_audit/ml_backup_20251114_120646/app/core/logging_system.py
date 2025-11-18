#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Advanced logging and alerting system for the SecurityAI ML Service.

This module provides:
- Structured logging with context
- Performance tracking and metrics
- Real-time alerting
- Log aggregation and analysis
- Security event logging
- Audit trails
"""

import os
import sys
import json
import time
import asyncio
import threading
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from contextlib import contextmanager
from collections import defaultdict, deque
import traceback
import hashlib
from pathlib import Path

from loguru import logger
import structlog
from prometheus_client import Counter, Histogram, Gauge, Summary

from .config import settings
from .monitoring import metrics_collector


class LogLevel(Enum):
    """Log levels with numeric values."""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    SUCCESS = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LogContext:
    """Context information for structured logging."""
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    model_name: Optional[str] = None
    endpoint: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {k: v for k, v in asdict(self).items() if v is not None}
        if self.extra:
            result.update(self.extra)
        return result


@dataclass
class SecurityEvent:
    """Security-related event for audit logging."""
    event_type: str
    severity: AlertSeverity
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetric:
    """Performance metric data."""
    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)
    context: Optional[LogContext] = None


@dataclass
class Alert:
    """Alert data structure."""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "ml_service"
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


class StructuredLogger:
    """Enhanced structured logger with context management."""
    
    def __init__(self, name: str = "ml_service"):
        self.name = name
        self._context_stack = threading.local()
        self._setup_structlog()
        self._setup_loguru()
        
        # Metrics
        self.log_counter = Counter(
            'ml_service_logs_total',
            'Total number of log messages',
            ['level', 'logger', 'model']
        )
        
        self.error_counter = Counter(
            'ml_service_errors_total',
            'Total number of errors',
            ['error_type', 'model', 'endpoint']
        )
        
    def _setup_structlog(self):
        """Configure structlog for structured logging."""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        self.struct_logger = structlog.get_logger(self.name)
        
    def _setup_loguru(self):
        """Configure loguru for file and console logging."""
        # Remove default handler
        logger.remove()
        
        # Console handler with colors
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
                   "<level>{level: <8}</level> | "
                   "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                   "<level>{message}</level>",
            level=str(getattr(settings.log_level, 'value', settings.log_level)).upper(),
            colorize=True,
            backtrace=True,
            diagnose=True
        )
        
        # File handler for general logs
        log_dir = Path(getattr(settings, 'log_directory', './logs'))
        log_dir.mkdir(exist_ok=True)
        
        logger.add(
            log_dir / "ml_service.log",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
            level="DEBUG",
            rotation="100 MB",
            retention="30 days",
            compression="gz",
            backtrace=True,
            diagnose=True
        )
        
        # Structured JSON logs
        logger.add(
            log_dir / "ml_service_structured.jsonl",
            format="{message}",
            level="INFO",
            rotation="100 MB",
            retention="30 days",
            compression="gz",
            serialize=True
        )
        
        # Error-only logs
        logger.add(
            log_dir / "ml_service_errors.log",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
            level="ERROR",
            rotation="50 MB",
            retention="90 days",
            compression="gz",
            backtrace=True,
            diagnose=True
        )
        
        # Security audit logs
        logger.add(
            log_dir / "security_audit.log",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | SECURITY | {message}",
            level="INFO",
            rotation="50 MB",
            retention="365 days",
            compression="gz",
            filter=lambda record: record.get("extra", {}).get("security_event", False)
        )
        
    @property
    def context_stack(self) -> List[LogContext]:
        """Get the current context stack for this thread."""
        if not hasattr(self._context_stack, 'stack'):
            self._context_stack.stack = []
        return self._context_stack.stack
        
    @contextmanager
    def context(self, **kwargs):
        """Context manager for adding logging context."""
        ctx = LogContext(**kwargs)
        self.context_stack.append(ctx)
        try:
            yield ctx
        finally:
            if self.context_stack:
                self.context_stack.pop()
                
    def _get_current_context(self) -> Dict[str, Any]:
        """Get merged context from the context stack."""
        merged_context = {}
        for ctx in self.context_stack:
            merged_context.update(ctx.to_dict())
        return merged_context
        
    def _log_with_context(self, level: str, message: str, **kwargs):
        """Log message with current context."""
        context = self._get_current_context()
        context.update(kwargs)
        
        # Update metrics
        model_name = context.get('model_name', 'unknown')
        self.log_counter.labels(
            level=level.lower(),
            logger=self.name,
            model=model_name
        ).inc()
        
        # Log with loguru
        getattr(logger, level.lower())(message, **context)
        
        # Log with structlog for structured output
        getattr(self.struct_logger, level.lower())(message, **context)
        
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log_with_context("DEBUG", message, **kwargs)
        
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log_with_context("INFO", message, **kwargs)
        
    def success(self, message: str, **kwargs):
        """Log success message."""
        self._log_with_context("SUCCESS", message, **kwargs)
        
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self._log_with_context("WARNING", message, **kwargs)
        
    def error(self, message: str, error: Exception = None, **kwargs):
        """Log error message with optional exception."""
        if error:
            kwargs['error_type'] = type(error).__name__
            kwargs['error_message'] = str(error)
            kwargs['traceback'] = traceback.format_exc()
            
            # Update error metrics
            self.error_counter.labels(
                error_type=type(error).__name__,
                model=kwargs.get('model_name', 'unknown'),
                endpoint=kwargs.get('endpoint', 'unknown')
            ).inc()
            
        self._log_with_context("ERROR", message, **kwargs)
        
    def critical(self, message: str, error: Exception = None, **kwargs):
        """Log critical message."""
        if error:
            kwargs['error_type'] = type(error).__name__
            kwargs['error_message'] = str(error)
            kwargs['traceback'] = traceback.format_exc()
            
        self._log_with_context("CRITICAL", message, **kwargs)
        
    def security_event(self, event: SecurityEvent):
        """Log security event for audit trail."""
        event_data = asdict(event)
        event_data['timestamp'] = event.timestamp.isoformat()
        event_data['security_event'] = True
        
        logger.info(
            f"SECURITY EVENT: {event.event_type} - {event.description}",
            **event_data
        )
        
    def performance_metric(self, metric: PerformanceMetric):
        """Log performance metric."""
        metric_data = {
            'metric_name': metric.name,
            'metric_value': metric.value,
            'metric_unit': metric.unit,
            'metric_timestamp': metric.timestamp.isoformat(),
            'metric_tags': metric.tags,
            'performance_metric': True
        }
        
        if metric.context:
            metric_data.update(metric.context.to_dict())
            
        logger.info(f"PERFORMANCE: {metric.name} = {metric.value} {metric.unit}", **metric_data)
        

class AlertManager:
    """Manages alerts and notifications."""
    
    def __init__(self):
        self.alerts = {}
        self.alert_handlers = []
        self.alert_history = deque(maxlen=1000)
        self._lock = threading.RLock()
        
        # Metrics
        self.alert_counter = Counter(
            'ml_service_alerts_total',
            'Total number of alerts',
            ['severity', 'source']
        )
        
        self.active_alerts_gauge = Gauge(
            'ml_service_active_alerts',
            'Number of active alerts',
            ['severity']
        )
        
    def add_handler(self, handler: Callable[[Alert], None]):
        """Add an alert handler."""
        self.alert_handlers.append(handler)
        
    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        **kwargs
    ) -> Alert:
        """Create and process a new alert."""
        alert_id = self._generate_alert_id(title, description)
        
        alert = Alert(
            id=alert_id,
            title=title,
            description=description,
            severity=severity,
            **kwargs
        )
        
        with self._lock:
            # Check if alert already exists
            if alert_id in self.alerts:
                existing_alert = self.alerts[alert_id]
                if not existing_alert.resolved:
                    # Update existing alert
                    existing_alert.timestamp = alert.timestamp
                    existing_alert.metadata.update(alert.metadata)
                    return existing_alert
                    
            # Store new alert
            self.alerts[alert_id] = alert
            self.alert_history.append(alert)
            
            # Update metrics
            self.alert_counter.labels(
                severity=severity.value,
                source=alert.source
            ).inc()
            
            self._update_active_alerts_gauge()
            
        # Process alert through handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")
                
        return alert
        
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an active alert."""
        with self._lock:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                if not alert.resolved:
                    alert.resolved = True
                    alert.resolved_at = datetime.now()
                    self._update_active_alerts_gauge()
                    return True
            return False
            
    def get_active_alerts(self) -> List[Alert]:
        """Get all active (unresolved) alerts."""
        with self._lock:
            return [alert for alert in self.alerts.values() if not alert.resolved]
            
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with self._lock:
            active_alerts = self.get_active_alerts()
            
            stats = {
                "total_alerts": len(self.alerts),
                "active_alerts": len(active_alerts),
                "resolved_alerts": len(self.alerts) - len(active_alerts),
                "alerts_by_severity": defaultdict(int),
                "recent_alerts": []
            }
            
            # Count by severity
            for alert in active_alerts:
                stats["alerts_by_severity"][alert.severity.value] += 1
                
            # Recent alerts (last 10)
            recent = sorted(
                list(self.alert_history)[-10:],
                key=lambda a: a.timestamp,
                reverse=True
            )
            
            stats["recent_alerts"] = [
                {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "timestamp": alert.timestamp.isoformat(),
                    "resolved": alert.resolved
                }
                for alert in recent
            ]
            
            return stats
            
    def _generate_alert_id(self, title: str, description: str) -> str:
        """Generate a unique alert ID."""
        content = f"{title}:{description}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
        
    def _update_active_alerts_gauge(self):
        """Update the active alerts gauge metric."""
        active_by_severity = defaultdict(int)
        for alert in self.alerts.values():
            if not alert.resolved:
                active_by_severity[alert.severity.value] += 1
                
        for severity in AlertSeverity:
            self.active_alerts_gauge.labels(severity=severity.value).set(
                active_by_severity[severity.value]
            )


class PerformanceTracker:
    """Tracks and analyzes performance metrics."""
    
    def __init__(self, logger: StructuredLogger):
        self.logger = logger
        self.metrics = defaultdict(list)
        self._lock = threading.RLock()
        
        # Prometheus metrics
        self.request_duration = Histogram(
            'ml_service_request_duration_seconds',
            'Request duration in seconds',
            ['endpoint', 'model', 'status']
        )
        
        self.prediction_duration = Histogram(
            'ml_service_prediction_duration_seconds',
            'Prediction duration in seconds',
            ['model']
        )
        
    @contextmanager
    def track_request(self, endpoint: str, model: str = "unknown"):
        """Context manager to track request performance."""
        start_time = time.time()
        status = "success"
        
        try:
            yield
        except Exception as e:
            status = "error"
            raise
        finally:
            duration = time.time() - start_time
            
            # Update Prometheus metrics
            self.request_duration.labels(
                endpoint=endpoint,
                model=model,
                status=status
            ).observe(duration)
            
            # Log performance metric
            metric = PerformanceMetric(
                name="request_duration",
                value=duration * 1000,  # Convert to ms
                unit="ms",
                tags={"endpoint": endpoint, "model": model, "status": status}
            )
            
            self.logger.performance_metric(metric)
            
            # Store for analysis
            with self._lock:
                self.metrics[f"{endpoint}:{model}"].append(duration)
                
                # Keep only recent measurements
                if len(self.metrics[f"{endpoint}:{model}"]) > 1000:
                    self.metrics[f"{endpoint}:{model}"] = self.metrics[f"{endpoint}:{model}"][-1000:]
                    
    @contextmanager
    def track_prediction(self, model: str):
        """Context manager to track prediction performance."""
        start_time = time.time()
        
        try:
            yield
        finally:
            duration = time.time() - start_time
            
            # Update Prometheus metrics
            self.prediction_duration.labels(model=model).observe(duration)
            
            # Log performance metric
            metric = PerformanceMetric(
                name="prediction_duration",
                value=duration * 1000,  # Convert to ms
                unit="ms",
                tags={"model": model}
            )
            
            self.logger.performance_metric(metric)
            
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        with self._lock:
            stats = {}
            
            for key, durations in self.metrics.items():
                if durations:
                    stats[key] = {
                        "count": len(durations),
                        "avg_duration_ms": (sum(durations) / len(durations)) * 1000,
                        "min_duration_ms": min(durations) * 1000,
                        "max_duration_ms": max(durations) * 1000,
                        "p95_duration_ms": self._percentile(durations, 95) * 1000,
                        "p99_duration_ms": self._percentile(durations, 99) * 1000
                    }
                    
            return stats
            
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data."""
        if not data:
            return 0.0
            
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]


# Global instances
app_logger = StructuredLogger("ml_service")
alert_manager = AlertManager()
performance_tracker = PerformanceTracker(app_logger)


# Alert handlers
def console_alert_handler(alert: Alert):
    """Simple console alert handler."""
    color_map = {
        AlertSeverity.LOW: "blue",
        AlertSeverity.MEDIUM: "yellow",
        AlertSeverity.HIGH: "red",
        AlertSeverity.CRITICAL: "magenta"
    }
    
    logger.opt(colors=True).log(
        "WARNING" if alert.severity in [AlertSeverity.LOW, AlertSeverity.MEDIUM] else "ERROR",
        f"<{color_map[alert.severity]}>ALERT [{alert.severity.value.upper()}]</> {alert.title}: {alert.description}"
    )


# Register default alert handler
alert_manager.add_handler(console_alert_handler)


# Convenience functions
def log_security_event(
    event_type: str,
    description: str,
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    **kwargs
):
    """Log a security event."""
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        description=description,
        **kwargs
    )
    app_logger.security_event(event)
    
    # Create alert for high/critical security events
    if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
        alert_manager.create_alert(
            title=f"Security Event: {event_type}",
            description=description,
            severity=severity,
            tags={"type": "security", "event_type": event_type}
        )


def create_alert(
    title: str,
    description: str,
    severity: AlertSeverity,
    **kwargs
) -> Alert:
    """Create an alert."""
    return alert_manager.create_alert(title, description, severity, **kwargs)


@contextmanager
def log_context(**kwargs):
    """Context manager for logging context."""
    with app_logger.context(**kwargs):
        yield


@contextmanager
def track_performance(endpoint: str, model: str = "unknown"):
    """Context manager for performance tracking."""
    with performance_tracker.track_request(endpoint, model):
        yield