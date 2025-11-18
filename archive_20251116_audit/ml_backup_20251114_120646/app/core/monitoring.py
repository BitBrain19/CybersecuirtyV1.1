#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Advanced monitoring and metrics system for the SecurityAI ML Service.

This module provides comprehensive monitoring capabilities including:
- Performance metrics collection
- Health checks
- Alert management
- Resource monitoring
- Model performance tracking
"""

import time
import psutil
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from datetime import datetime, timedelta
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest
from loguru import logger
import asyncio
from contextlib import contextmanager


@dataclass
class MetricPoint:
    """A single metric data point."""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class Alert:
    """Alert configuration and state."""
    name: str
    condition: Callable[[List[MetricPoint]], bool]
    message: str
    severity: str = "warning"
    cooldown_minutes: int = 5
    last_triggered: Optional[datetime] = None
    is_active: bool = False


class MetricsCollector:
    """Advanced metrics collection and monitoring system."""
    
    def __init__(self):
        self.registry = CollectorRegistry()
        self._setup_metrics()
        self._metrics_history = defaultdict(lambda: deque(maxlen=1000))
        self._alerts = {}
        self._monitoring_active = False
        self._monitor_thread = None
        
    def _setup_metrics(self):
        """Initialize Prometheus metrics."""
        # Request metrics
        self.request_count = Counter(
            'ml_requests_total',
            'Total number of ML requests',
            ['model_name', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.request_duration = Histogram(
            'ml_request_duration_seconds',
            'Request duration in seconds',
            ['model_name', 'endpoint'],
            registry=self.registry
        )
        
        # Model performance metrics
        self.model_prediction_time = Histogram(
            'ml_model_prediction_seconds',
            'Model prediction time in seconds',
            ['model_name'],
            registry=self.registry
        )
        
        self.model_accuracy = Gauge(
            'ml_model_accuracy',
            'Model accuracy score',
            ['model_name'],
            registry=self.registry
        )
        
        # UEBA metrics
        self.user_risk_score = Gauge(
            'ml_user_risk_score',
            'User behavior risk score',
            ['user_id', 'department'],
            registry=self.registry
        )
        
        self.anomaly_count = Counter(
            'ml_anomalies_total',
            'Total number of detected anomalies',
            ['user_id', 'anomaly_type', 'severity'],
            registry=self.registry
        )
        
        self.baseline_deviation = Histogram(
            'ml_baseline_deviation',
            'Deviation from behavioral baseline',
            ['user_id', 'activity_type'],
            registry=self.registry
        )
        
        # System metrics
        self.memory_usage = Gauge(
            'ml_memory_usage_bytes',
            'Memory usage in bytes',
            registry=self.registry
        )
        
        self.cpu_usage = Gauge(
            'ml_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        # Error metrics
        self.error_count = Counter(
            'ml_errors_total',
            'Total number of errors',
            ['error_type', 'model_name'],
            registry=self.registry
        )
        
        # Model loading metrics
        self.model_load_time = Histogram(
            'ml_model_load_seconds',
            'Model loading time in seconds',
            ['model_name'],
            registry=self.registry
        )
        
        # UEBA metrics
        self.ueba_events_received = Counter(
            'ueba_events_received_total',
            'Total number of events received by UEBA service',
            registry=self.registry
        )
        
        self.ueba_events_processed = Counter(
            'ueba_events_processed_total',
            'Total number of events processed by UEBA service',
            registry=self.registry
        )
        
        self.ueba_events_dropped = Counter(
            'ueba_events_dropped_total',
            'Total number of events dropped by UEBA service',
            registry=self.registry
        )
        
        self.ueba_anomalies_detected = Counter(
            'ueba_anomalies_detected_total',
            'Total number of anomalies detected by UEBA service',
            ['entity_type', 'category', 'severity'],
            registry=self.registry
        )
        
        self.ueba_processing_time = Histogram(
            'ueba_processing_time_ms',
            'UEBA event processing time in milliseconds',
            registry=self.registry
        )
        
        self.ueba_processing_errors = Counter(
            'ueba_processing_errors_total',
            'Total number of errors in UEBA processing',
            registry=self.registry
        )
        
        self.ueba_queue_size = Gauge(
            'ueba_queue_size',
            'Current size of UEBA event queue',
            registry=self.registry
        )
        
    @contextmanager
    def track_request(self, model_name: str, endpoint: str):
        """Context manager to track request metrics."""
        start_time = time.time()
        status = "success"
        
        try:
            yield
        except Exception as e:
            status = "error"
            self.error_count.labels(
                error_type=type(e).__name__,
                model_name=model_name
            ).inc()
            raise
        finally:
            duration = time.time() - start_time
            self.request_count.labels(
                model_name=model_name,
                endpoint=endpoint,
                status=status
            ).inc()
            self.request_duration.labels(
                model_name=model_name,
                endpoint=endpoint
            ).observe(duration)
            
    @contextmanager
    def track_prediction(self, model_name: str):
        """Context manager to track prediction metrics."""
        start_time = time.time()
        
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.model_prediction_time.labels(model_name=model_name).observe(duration)
            
    @contextmanager
    def track_model_loading(self, model_name: str):
        """Context manager to track model loading metrics."""
        start_time = time.time()
        
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.model_load_time.labels(model_name=model_name).observe(duration)
            
    def record_model_accuracy(self, model_name: str, accuracy: float):
        """Record model accuracy metric."""
        self.model_accuracy.labels(model_name=model_name).set(accuracy)
        
    def record_custom_metric(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a custom metric point."""
        labels = labels or {}
        metric_point = MetricPoint(
            timestamp=datetime.now(),
            value=value,
            labels=labels
        )
        self._metrics_history[name].append(metric_point)
        
    def add_alert(self, alert: Alert):
        """Add an alert configuration."""
        self._alerts[alert.name] = alert
        logger.info(f"Added alert: {alert.name}")
        
    def start_monitoring(self, interval_seconds: int = 30):
        """Start the monitoring thread."""
        if self._monitoring_active:
            return
            
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info("Monitoring started")
        
    def stop_monitoring(self):
        """Stop the monitoring thread."""
        self._monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Monitoring stopped")
        
    def _monitor_loop(self, interval_seconds: int):
        """Main monitoring loop."""
        while self._monitoring_active:
            try:
                self._collect_system_metrics()
                self._check_alerts()
                time.sleep(interval_seconds)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval_seconds)
                
    def _collect_system_metrics(self):
        """Collect system-level metrics."""
        # Memory usage
        memory_info = psutil.virtual_memory()
        self.memory_usage.set(memory_info.used)
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        self.cpu_usage.set(cpu_percent)
        
        # Record custom metrics
        self.record_custom_metric("memory_usage_mb", memory_info.used / 1024 / 1024)
        self.record_custom_metric("cpu_usage_percent", cpu_percent)
        
    def _check_alerts(self):
        """Check alert conditions and trigger if necessary."""
        current_time = datetime.now()
        
        for alert_name, alert in self._alerts.items():
            try:
                # Skip if in cooldown period
                if (alert.last_triggered and 
                    current_time - alert.last_triggered < timedelta(minutes=alert.cooldown_minutes)):
                    continue
                    
                # Get recent metrics for this alert
                relevant_metrics = self._get_recent_metrics_for_alert(alert_name)
                
                # Check condition
                if alert.condition(relevant_metrics):
                    self._trigger_alert(alert)
                    
            except Exception as e:
                logger.error(f"Error checking alert {alert_name}: {e}")
                
    def _get_recent_metrics_for_alert(self, alert_name: str) -> List[MetricPoint]:
        """Get recent metrics relevant to an alert."""
        # This is a simplified implementation
        # In practice, you'd have more sophisticated metric selection
        recent_time = datetime.now() - timedelta(minutes=5)
        
        all_recent = []
        for metric_name, points in self._metrics_history.items():
            recent_points = [p for p in points if p.timestamp >= recent_time]
            all_recent.extend(recent_points)
            
        return all_recent
        
    def _trigger_alert(self, alert: Alert):
        """Trigger an alert."""
        alert.last_triggered = datetime.now()
        alert.is_active = True
        
        logger.warning(f"ALERT TRIGGERED: {alert.name} - {alert.message}")
        
        # Here you could integrate with external alerting systems
        # like Slack, PagerDuty, email, etc.
        
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of current metrics."""
        summary = {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "memory_usage_mb": psutil.virtual_memory().used / 1024 / 1024,
                "cpu_usage_percent": psutil.cpu_percent(),
                "disk_usage_percent": psutil.disk_usage('/').percent
            },
            "alerts": {
                "active_count": sum(1 for alert in self._alerts.values() if alert.is_active),
                "total_count": len(self._alerts)
            },
            "metrics_history_size": {name: len(points) for name, points in self._metrics_history.items()}
        }
        
        return summary
        
    def export_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format."""
        return generate_latest(self.registry).decode('utf-8')


class HealthChecker:
    """Comprehensive health checking system."""
    
    def __init__(self):
        self._checks = {}
        
    def add_check(self, name: str, check_func: Callable[[], bool], 
                  description: str = "", timeout: float = 5.0):
        """Add a health check."""
        self._checks[name] = {
            "func": check_func,
            "description": description,
            "timeout": timeout
        }
        
    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        overall_healthy = True
        
        for name, check_config in self._checks.items():
            try:
                # Run check with timeout
                check_result = await asyncio.wait_for(
                    asyncio.create_task(self._run_check(check_config["func"])),
                    timeout=check_config["timeout"]
                )
                
                results["checks"][name] = {
                    "status": "healthy" if check_result else "unhealthy",
                    "description": check_config["description"]
                }
                
                if not check_result:
                    overall_healthy = False
                    
            except asyncio.TimeoutError:
                results["checks"][name] = {
                    "status": "timeout",
                    "description": f"Check timed out after {check_config['timeout']}s"
                }
                overall_healthy = False
                
            except Exception as e:
                results["checks"][name] = {
                    "status": "error",
                    "description": f"Check failed: {str(e)}"
                }
                overall_healthy = False
                
        results["status"] = "healthy" if overall_healthy else "unhealthy"
        return results
        
    async def _run_check(self, check_func: Callable[[], bool]) -> bool:
        """Run a single health check."""
        if asyncio.iscoroutinefunction(check_func):
            return await check_func()
        else:
            return check_func()


# Global instances
metrics_collector = MetricsCollector()
health_checker = HealthChecker()


# Predefined alert conditions
def high_error_rate_condition(metrics: List[MetricPoint]) -> bool:
    """Check for high error rate."""
    if not metrics:
        return False
        
    error_metrics = [m for m in metrics if "error" in m.labels.get("status", "")]
    total_metrics = len(metrics)
    
    if total_metrics == 0:
        return False
        
    error_rate = len(error_metrics) / total_metrics
    return error_rate > 0.05  # 5% error rate threshold


def high_memory_usage_condition(metrics: List[MetricPoint]) -> bool:
    """Check for high memory usage."""
    memory_metrics = [m for m in metrics if "memory_usage_mb" in str(m.labels)]
    
    if not memory_metrics:
        return False
        
    latest_memory = max(memory_metrics, key=lambda x: x.timestamp)
    return latest_memory.value > 1024  # 1GB threshold


def slow_response_condition(metrics: List[MetricPoint]) -> bool:
    """Check for slow response times."""
    response_metrics = [m for m in metrics if "response_time" in str(m.labels)]
    
    if len(response_metrics) < 5:
        return False
        
    recent_metrics = sorted(response_metrics, key=lambda x: x.timestamp)[-5:]
    avg_response_time = sum(m.value for m in recent_metrics) / len(recent_metrics)
    
    return avg_response_time > 1000  # 1 second threshold


# Setup default alerts
default_alerts = [
    Alert(
        name="high_error_rate",
        condition=high_error_rate_condition,
        message="Error rate exceeded 5% threshold",
        severity="critical",
        cooldown_minutes=5
    ),
    Alert(
        name="high_memory_usage",
        condition=high_memory_usage_condition,
        message="Memory usage exceeded 1GB threshold",
        severity="warning",
        cooldown_minutes=10
    ),
    Alert(
        name="slow_response",
        condition=slow_response_condition,
        message="Average response time exceeded 1 second",
        severity="warning",
        cooldown_minutes=5
    )
]

# Add default alerts
for alert in default_alerts:
    metrics_collector.add_alert(alert)