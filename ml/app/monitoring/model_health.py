"""Model Health Monitoring System

This module provides comprehensive monitoring capabilities for ML models,
including performance tracking, drift detection, and automatic retraining triggers.
"""

import time
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from scipy import stats

from ..core.exceptions import MonitoringError
from ..core.config import get_config

logger = logging.getLogger(__name__)

@dataclass
class ModelMetrics:
    """Container for model performance metrics."""
    timestamp: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    prediction_count: int
    avg_confidence: float
    error_rate: float
    response_time: float
    drift_score: Optional[float] = None
    anomaly_rate: Optional[float] = None

@dataclass
class HealthStatus:
    """Model health status container."""
    model_name: str
    status: str  # 'healthy', 'degraded', 'critical'
    last_check: float
    issues: List[str]
    recommendations: List[str]
    needs_retraining: bool
    confidence_score: float

class ModelHealthMonitor:
    """Comprehensive model health monitoring system."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or get_config().get('monitoring', {})
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.health_status: Dict[str, HealthStatus] = {}
        self.drift_detectors: Dict[str, Any] = {}
        self.baseline_metrics: Dict[str, ModelMetrics] = {}
        self.alert_thresholds = self._load_alert_thresholds()
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Performance tracking
        self.prediction_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.error_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        
        logger.info("Model health monitor initialized")
    
    def _load_alert_thresholds(self) -> Dict[str, Dict[str, float]]:
        """Load alert thresholds from configuration."""
        return {
            'accuracy': {
                'warning': 0.85,
                'critical': 0.75
            },
            'precision': {
                'warning': 0.80,
                'critical': 0.70
            },
            'recall': {
                'warning': 0.80,
                'critical': 0.70
            },
            'f1_score': {
                'warning': 0.80,
                'critical': 0.70
            },
            'error_rate': {
                'warning': 0.05,
                'critical': 0.10
            },
            'response_time': {
                'warning': 1.0,  # seconds
                'critical': 2.0
            },
            'drift_score': {
                'warning': 0.3,
                'critical': 0.5
            },
            'confidence_drop': {
                'warning': 0.15,
                'critical': 0.25
            }
        }
    
    def start_monitoring(self, interval: int = 300) -> None:
        """Start continuous model health monitoring."""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Started model health monitoring with {interval}s interval")
    
    def stop_monitoring(self) -> None:
        """Stop continuous monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped model health monitoring")
    
    def _monitoring_loop(self, interval: int) -> None:
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                self._check_all_models()
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(interval)
    
    def record_prediction(self, model_name: str, prediction_time: float, 
                         confidence: float, error: bool = False) -> None:
        """Record a prediction for monitoring."""
        with self._lock:
            timestamp = time.time()
            
            # Record prediction timing and confidence
            self.prediction_windows[model_name].append({
                'timestamp': timestamp,
                'response_time': prediction_time,
                'confidence': confidence
            })
            
            # Record errors
            if error:
                self.error_windows[model_name].append(timestamp)
    
    def record_metrics(self, model_name: str, metrics: ModelMetrics) -> None:
        """Record model performance metrics."""
        with self._lock:
            self.metrics_history[model_name].append(metrics)
            
            # Set baseline if not exists
            if model_name not in self.baseline_metrics:
                self.baseline_metrics[model_name] = metrics
                logger.info(f"Set baseline metrics for {model_name}")
    
    def calculate_current_metrics(self, model_name: str) -> Optional[ModelMetrics]:
        """Calculate current metrics from recent predictions."""
        if model_name not in self.prediction_windows:
            return None
        
        predictions = list(self.prediction_windows[model_name])
        errors = list(self.error_windows[model_name])
        
        if not predictions:
            return None
        
        current_time = time.time()
        recent_predictions = [
            p for p in predictions 
            if current_time - p['timestamp'] <= 3600  # Last hour
        ]
        
        if not recent_predictions:
            return None
        
        # Calculate metrics
        avg_response_time = np.mean([p['response_time'] for p in recent_predictions])
        avg_confidence = np.mean([p['confidence'] for p in recent_predictions])
        
        # Error rate calculation
        recent_errors = [e for e in errors if current_time - e <= 3600]
        error_rate = len(recent_errors) / len(recent_predictions) if recent_predictions else 0
        
        return ModelMetrics(
            timestamp=current_time,
            accuracy=0.0,  # Would need ground truth for actual calculation
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            prediction_count=len(recent_predictions),
            avg_confidence=avg_confidence,
            error_rate=error_rate,
            response_time=avg_response_time
        )
    
    def detect_drift(self, model_name: str, current_data: np.ndarray, 
                    reference_data: Optional[np.ndarray] = None) -> float:
        """Detect data drift using statistical tests."""
        if reference_data is None:
            # Use historical data as reference
            if model_name not in self.drift_detectors:
                # Store current data as reference for future comparisons
                self.drift_detectors[model_name] = current_data
                return 0.0
            reference_data = self.drift_detectors[model_name]
        
        try:
            # Use Kolmogorov-Smirnov test for drift detection
            if current_data.ndim > 1:
                # For multivariate data, test each feature
                drift_scores = []
                for i in range(current_data.shape[1]):
                    if reference_data.shape[1] > i:
                        _, p_value = stats.ks_2samp(
                            reference_data[:, i], 
                            current_data[:, i]
                        )
                        drift_scores.append(1 - p_value)  # Convert p-value to drift score
                
                return np.mean(drift_scores) if drift_scores else 0.0
            else:
                # Univariate case
                _, p_value = stats.ks_2samp(reference_data, current_data)
                return 1 - p_value
        
        except Exception as e:
            logger.warning(f"Drift detection failed for {model_name}: {str(e)}")
            return 0.0
    
    def _check_all_models(self) -> None:
        """Check health of all monitored models."""
        for model_name in self.metrics_history.keys():
            try:
                self._check_model_health(model_name)
            except Exception as e:
                logger.error(f"Health check failed for {model_name}: {str(e)}")
    
    def _check_model_health(self, model_name: str) -> HealthStatus:
        """Perform comprehensive health check for a model."""
        current_metrics = self.calculate_current_metrics(model_name)
        if not current_metrics:
            return self._create_health_status(
                model_name, 'critical', 
                ['No recent predictions'], 
                ['Check model availability']
            )
        
        issues = []
        recommendations = []
        status = 'healthy'
        needs_retraining = False
        
        # Check performance metrics
        baseline = self.baseline_metrics.get(model_name)
        if baseline:
            # Check for performance degradation
            confidence_drop = baseline.avg_confidence - current_metrics.avg_confidence
            if confidence_drop > self.alert_thresholds['confidence_drop']['critical']:
                issues.append(f"Severe confidence drop: {confidence_drop:.3f}")
                recommendations.append("Consider model retraining")
                status = 'critical'
                needs_retraining = True
            elif confidence_drop > self.alert_thresholds['confidence_drop']['warning']:
                issues.append(f"Confidence drop detected: {confidence_drop:.3f}")
                recommendations.append("Monitor closely")
                status = 'degraded'
        
        # Check error rate
        if current_metrics.error_rate > self.alert_thresholds['error_rate']['critical']:
            issues.append(f"High error rate: {current_metrics.error_rate:.3f}")
            recommendations.append("Investigate error causes")
            status = 'critical'
        elif current_metrics.error_rate > self.alert_thresholds['error_rate']['warning']:
            issues.append(f"Elevated error rate: {current_metrics.error_rate:.3f}")
            status = 'degraded'
        
        # Check response time
        if current_metrics.response_time > self.alert_thresholds['response_time']['critical']:
            issues.append(f"Slow response time: {current_metrics.response_time:.3f}s")
            recommendations.append("Optimize model inference")
            status = 'critical'
        elif current_metrics.response_time > self.alert_thresholds['response_time']['warning']:
            issues.append(f"Elevated response time: {current_metrics.response_time:.3f}s")
            status = 'degraded'
        
        # Check drift if available
        if current_metrics.drift_score is not None:
            if current_metrics.drift_score > self.alert_thresholds['drift_score']['critical']:
                issues.append(f"Severe data drift: {current_metrics.drift_score:.3f}")
                recommendations.append("Retrain model with recent data")
                status = 'critical'
                needs_retraining = True
            elif current_metrics.drift_score > self.alert_thresholds['drift_score']['warning']:
                issues.append(f"Data drift detected: {current_metrics.drift_score:.3f}")
                recommendations.append("Consider retraining")
                status = 'degraded'
        
        # Calculate overall confidence score
        confidence_score = self._calculate_confidence_score(current_metrics, baseline)
        
        health_status = HealthStatus(
            model_name=model_name,
            status=status,
            last_check=time.time(),
            issues=issues,
            recommendations=recommendations,
            needs_retraining=needs_retraining,
            confidence_score=confidence_score
        )
        
        self.health_status[model_name] = health_status
        
        # Log significant issues
        if status != 'healthy':
            logger.warning(
                f"Model {model_name} health: {status}. "
                f"Issues: {', '.join(issues)}"
            )
        
        return health_status
    
    def _calculate_confidence_score(self, current: ModelMetrics, 
                                  baseline: Optional[ModelMetrics]) -> float:
        """Calculate overall confidence score for model health."""
        score = 1.0
        
        # Penalize high error rate
        score -= min(current.error_rate * 2, 0.5)
        
        # Penalize slow response time
        if current.response_time > 1.0:
            score -= min((current.response_time - 1.0) * 0.2, 0.3)
        
        # Consider confidence drop if baseline exists
        if baseline:
            confidence_drop = baseline.avg_confidence - current.avg_confidence
            score -= min(confidence_drop, 0.3)
        
        # Consider drift if available
        if current.drift_score is not None:
            score -= min(current.drift_score * 0.5, 0.4)
        
        return max(0.0, min(1.0, score))
    
    def _create_health_status(self, model_name: str, status: str, 
                            issues: List[str], recommendations: List[str]) -> HealthStatus:
        """Create a health status object."""
        return HealthStatus(
            model_name=model_name,
            status=status,
            last_check=time.time(),
            issues=issues,
            recommendations=recommendations,
            needs_retraining=status == 'critical',
            confidence_score=0.0 if status == 'critical' else 0.5
        )
    
    def get_health_report(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Get comprehensive health report."""
        if model_name:
            if model_name not in self.health_status:
                self._check_model_health(model_name)
            
            status = self.health_status.get(model_name)
            if not status:
                return {'error': f'No health data for model {model_name}'}
            
            return {
                'model': model_name,
                'status': asdict(status),
                'recent_metrics': list(self.metrics_history[model_name])[-10:] if model_name in self.metrics_history else []
            }
        else:
            # Return report for all models
            return {
                'models': {
                    name: asdict(status) 
                    for name, status in self.health_status.items()
                },
                'summary': {
                    'total_models': len(self.health_status),
                    'healthy': len([s for s in self.health_status.values() if s.status == 'healthy']),
                    'degraded': len([s for s in self.health_status.values() if s.status == 'degraded']),
                    'critical': len([s for s in self.health_status.values() if s.status == 'critical']),
                    'needs_retraining': [name for name, status in self.health_status.items() if status.needs_retraining]
                }
            }
    
    def should_retrain(self, model_name: str) -> Tuple[bool, List[str]]:
        """Determine if a model should be retrained."""
        if model_name not in self.health_status:
            self._check_model_health(model_name)
        
        status = self.health_status.get(model_name)
        if not status:
            return False, ['No health data available']
        
        return status.needs_retraining, status.recommendations
    
    def export_metrics(self, model_name: str, filepath: str) -> None:
        """Export model metrics to file."""
        if model_name not in self.metrics_history:
            raise MonitoringError(f"No metrics found for model {model_name}")
        
        metrics_data = {
            'model_name': model_name,
            'export_timestamp': time.time(),
            'metrics': [asdict(m) for m in self.metrics_history[model_name]],
            'health_status': asdict(self.health_status.get(model_name)) if model_name in self.health_status else None
        }
        
        with open(filepath, 'w') as f:
            json.dump(metrics_data, f, indent=2)
        
        logger.info(f"Exported metrics for {model_name} to {filepath}")

# Global monitor instance
_monitor_instance: Optional[ModelHealthMonitor] = None

def get_health_monitor() -> ModelHealthMonitor:
    """Get global health monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = ModelHealthMonitor()
    return _monitor_instance