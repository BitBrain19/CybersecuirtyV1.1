"""Automatic Model Retraining System

This module provides automated retraining capabilities for ML models
based on health monitoring triggers and performance degradation detection.
"""

import time
import logging
import threading
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from .model_health import ModelHealthMonitor, get_health_monitor
from ..core.exceptions import RetrainingError, ModelError
from ..core.config import get_config
from ..data.data_loader import DataLoader

logger = logging.getLogger(__name__)

@dataclass
class RetrainingConfig:
    """Configuration for automatic retraining."""
    min_samples: int = 1000
    validation_split: float = 0.2
    performance_threshold: float = 0.8
    max_retrain_attempts: int = 3
    retrain_interval_hours: int = 24
    backup_models: bool = True
    notification_enabled: bool = True
    auto_deploy: bool = False

@dataclass
class RetrainingJob:
    """Represents a retraining job."""
    model_name: str
    trigger_reason: str
    scheduled_time: float
    priority: int  # 1=high, 2=medium, 3=low
    config: RetrainingConfig
    attempts: int = 0
    status: str = 'pending'  # pending, running, completed, failed
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error_message: Optional[str] = None

class AutoRetrainer:
    """Automatic model retraining system."""
    
    def __init__(self, health_monitor: Optional[ModelHealthMonitor] = None):
        self.health_monitor = health_monitor or get_health_monitor()
        self.config = get_config().get('retraining', {})
        self.default_config = RetrainingConfig()
        
        # Job management
        self.job_queue: List[RetrainingJob] = []
        self.active_jobs: Dict[str, RetrainingJob] = {}
        self.completed_jobs: List[RetrainingJob] = []
        self.job_lock = threading.Lock()
        
        # Model registry
        self.model_registry: Dict[str, Any] = {}
        self.model_trainers: Dict[str, Callable] = {}
        self.data_loaders: Dict[str, DataLoader] = {}
        
        # Scheduling
        self.scheduler_active = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.executor = ThreadPoolExecutor(max_workers=2)
        
        # Performance tracking
        self.retraining_history: Dict[str, List[Dict]] = {}
        
        logger.info("Auto-retrainer initialized")
    
    def register_model(self, model_name: str, model_instance: Any, 
                      trainer_func: Callable, data_loader: DataLoader,
                      config: Optional[RetrainingConfig] = None) -> None:
        """Register a model for automatic retraining."""
        self.model_registry[model_name] = model_instance
        self.model_trainers[model_name] = trainer_func
        self.data_loaders[model_name] = data_loader
        
        if model_name not in self.retraining_history:
            self.retraining_history[model_name] = []
        
        logger.info(f"Registered model {model_name} for auto-retraining")
    
    def start_scheduler(self, check_interval: int = 300) -> None:
        """Start the automatic retraining scheduler."""
        if self.scheduler_active:
            logger.warning("Scheduler already active")
            return
        
        self.scheduler_active = True
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            args=(check_interval,),
            daemon=True
        )
        self.scheduler_thread.start()
        logger.info(f"Started retraining scheduler with {check_interval}s interval")
    
    def stop_scheduler(self) -> None:
        """Stop the automatic retraining scheduler."""
        self.scheduler_active = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=10)
        self.executor.shutdown(wait=True)
        logger.info("Stopped retraining scheduler")
    
    def _scheduler_loop(self, check_interval: int) -> None:
        """Main scheduler loop."""
        while self.scheduler_active:
            try:
                self._check_retraining_triggers()
                self._process_job_queue()
                time.sleep(check_interval)
            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}")
                time.sleep(check_interval)
    
    def _check_retraining_triggers(self) -> None:
        """Check all registered models for retraining triggers."""
        for model_name in self.model_registry.keys():
            try:
                should_retrain, reasons = self.health_monitor.should_retrain(model_name)
                
                if should_retrain:
                    # Check if already scheduled or running
                    if not self._is_job_active(model_name):
                        priority = self._determine_priority(reasons)
                        self._schedule_retraining(
                            model_name, 
                            f"Health monitor trigger: {', '.join(reasons)}",
                            priority
                        )
                
                # Check time-based triggers
                self._check_time_based_triggers(model_name)
                
            except Exception as e:
                logger.error(f"Error checking triggers for {model_name}: {str(e)}")
    
    def _check_time_based_triggers(self, model_name: str) -> None:
        """Check if model needs retraining based on time intervals."""
        history = self.retraining_history.get(model_name, [])
        if not history:
            return
        
        last_training = max(h['timestamp'] for h in history)
        config = self._get_model_config(model_name)
        
        hours_since_training = (time.time() - last_training) / 3600
        
        if hours_since_training >= config.retrain_interval_hours:
            if not self._is_job_active(model_name):
                self._schedule_retraining(
                    model_name,
                    f"Scheduled retraining ({hours_since_training:.1f}h since last training)",
                    priority=3  # Low priority for scheduled retraining
                )
    
    def _determine_priority(self, reasons: List[str]) -> int:
        """Determine job priority based on trigger reasons."""
        high_priority_keywords = ['critical', 'severe', 'drift', 'error']
        medium_priority_keywords = ['degraded', 'warning', 'confidence']
        
        reason_text = ' '.join(reasons).lower()
        
        if any(keyword in reason_text for keyword in high_priority_keywords):
            return 1  # High priority
        elif any(keyword in reason_text for keyword in medium_priority_keywords):
            return 2  # Medium priority
        else:
            return 3  # Low priority
    
    def _schedule_retraining(self, model_name: str, reason: str, priority: int = 2) -> None:
        """Schedule a retraining job."""
        config = self._get_model_config(model_name)
        
        job = RetrainingJob(
            model_name=model_name,
            trigger_reason=reason,
            scheduled_time=time.time(),
            priority=priority,
            config=config
        )
        
        with self.job_lock:
            self.job_queue.append(job)
            # Sort by priority (lower number = higher priority)
            self.job_queue.sort(key=lambda x: (x.priority, x.scheduled_time))
        
        logger.info(f"Scheduled retraining for {model_name}: {reason} (priority {priority})")
    
    def _process_job_queue(self) -> None:
        """Process pending retraining jobs."""
        with self.job_lock:
            if not self.job_queue:
                return
            
            # Check if we can start a new job
            if len(self.active_jobs) >= 2:  # Max 2 concurrent retraining jobs
                return
            
            job = self.job_queue.pop(0)
            self.active_jobs[job.model_name] = job
        
        # Start retraining in background
        future = self.executor.submit(self._execute_retraining, job)
        future.add_done_callback(lambda f: self._job_completed(job, f))
    
    def _execute_retraining(self, job: RetrainingJob) -> Dict[str, Any]:
        """Execute a retraining job."""
        job.status = 'running'
        job.start_time = time.time()
        job.attempts += 1
        
        logger.info(f"Starting retraining for {job.model_name} (attempt {job.attempts})")
        
        try:
            # Load fresh training data
            data_loader = self.data_loaders[job.model_name]
            training_data = data_loader.load_training_data()
            
            if len(training_data) < job.config.min_samples:
                raise RetrainingError(
                    f"Insufficient training data: {len(training_data)} < {job.config.min_samples}"
                )
            
            # Backup current model if configured
            if job.config.backup_models:
                self._backup_model(job.model_name)
            
            # Prepare data
            X, y = self._prepare_training_data(training_data)
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=job.config.validation_split, random_state=42
            )
            
            # Get trainer function and execute training
            trainer = self.model_trainers[job.model_name]
            new_model, training_metrics = trainer(X_train, y_train, X_val, y_val)
            
            # Validate new model performance
            validation_score = self._validate_model(new_model, X_val, y_val)
            
            if validation_score < job.config.performance_threshold:
                raise RetrainingError(
                    f"New model performance too low: {validation_score:.3f} < {job.config.performance_threshold}"
                )
            
            # Update model registry
            old_model = self.model_registry[job.model_name]
            self.model_registry[job.model_name] = new_model
            
            # Record training history
            training_record = {
                'timestamp': time.time(),
                'trigger_reason': job.trigger_reason,
                'validation_score': validation_score,
                'training_samples': len(X_train),
                'validation_samples': len(X_val),
                'training_time': time.time() - job.start_time,
                'metrics': training_metrics
            }
            
            self.retraining_history[job.model_name].append(training_record)
            
            job.status = 'completed'
            job.end_time = time.time()
            
            logger.info(
                f"Retraining completed for {job.model_name}. "
                f"Validation score: {validation_score:.3f}"
            )
            
            return {
                'success': True,
                'validation_score': validation_score,
                'training_record': training_record
            }
            
        except Exception as e:
            job.status = 'failed'
            job.end_time = time.time()
            job.error_message = str(e)
            
            logger.error(f"Retraining failed for {job.model_name}: {str(e)}")
            
            # Retry if attempts remaining
            if job.attempts < job.config.max_retrain_attempts:
                logger.info(f"Scheduling retry for {job.model_name} (attempt {job.attempts + 1})")
                job.status = 'pending'
                job.start_time = None
                job.end_time = None
                
                with self.job_lock:
                    self.job_queue.insert(0, job)  # High priority retry
            
            return {
                'success': False,
                'error': str(e),
                'attempts': job.attempts
            }
    
    def _job_completed(self, job: RetrainingJob, future) -> None:
        """Handle job completion."""
        with self.job_lock:
            if job.model_name in self.active_jobs:
                del self.active_jobs[job.model_name]
            
            if job.status in ['completed', 'failed']:
                self.completed_jobs.append(job)
                # Keep only last 100 completed jobs
                if len(self.completed_jobs) > 100:
                    self.completed_jobs = self.completed_jobs[-100:]
    
    def _prepare_training_data(self, raw_data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data from raw data."""
        # This is a placeholder - actual implementation would depend on data format
        # Assuming the last column is the target
        X = raw_data.iloc[:, :-1].values
        y = raw_data.iloc[:, -1].values
        return X, y
    
    def _validate_model(self, model: Any, X_val: np.ndarray, y_val: np.ndarray) -> float:
        """Validate model performance."""
        try:
            predictions = model.predict(X_val)
            
            # For regression tasks
            if hasattr(model, 'predict') and len(np.unique(y_val)) > 10:
                from sklearn.metrics import r2_score
                return r2_score(y_val, predictions)
            
            # For classification tasks
            else:
                return accuracy_score(y_val, predictions)
                
        except Exception as e:
            logger.error(f"Model validation failed: {str(e)}")
            return 0.0
    
    def _backup_model(self, model_name: str) -> None:
        """Create backup of current model."""
        try:
            import joblib
            
            model = self.model_registry[model_name]
            backup_path = Path(f"backups/{model_name}_{int(time.time())}.pkl")
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(model, backup_path)
            logger.info(f"Created model backup: {backup_path}")
            
        except Exception as e:
            logger.warning(f"Failed to backup model {model_name}: {str(e)}")
    
    def _get_model_config(self, model_name: str) -> RetrainingConfig:
        """Get retraining configuration for a model."""
        model_config = self.config.get(model_name, {})
        
        return RetrainingConfig(
            min_samples=model_config.get('min_samples', self.default_config.min_samples),
            validation_split=model_config.get('validation_split', self.default_config.validation_split),
            performance_threshold=model_config.get('performance_threshold', self.default_config.performance_threshold),
            max_retrain_attempts=model_config.get('max_retrain_attempts', self.default_config.max_retrain_attempts),
            retrain_interval_hours=model_config.get('retrain_interval_hours', self.default_config.retrain_interval_hours),
            backup_models=model_config.get('backup_models', self.default_config.backup_models),
            notification_enabled=model_config.get('notification_enabled', self.default_config.notification_enabled),
            auto_deploy=model_config.get('auto_deploy', self.default_config.auto_deploy)
        )
    
    def _is_job_active(self, model_name: str) -> bool:
        """Check if a job is active for the model."""
        with self.job_lock:
            # Check active jobs
            if model_name in self.active_jobs:
                return True
            
            # Check pending jobs
            return any(job.model_name == model_name for job in self.job_queue)
    
    def force_retrain(self, model_name: str, reason: str = "Manual trigger") -> bool:
        """Force immediate retraining of a model."""
        if model_name not in self.model_registry:
            logger.error(f"Model {model_name} not registered")
            return False
        
        self._schedule_retraining(model_name, reason, priority=1)
        logger.info(f"Forced retraining scheduled for {model_name}")
        return True
    
    def get_status(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Get retraining status."""
        with self.job_lock:
            if model_name:
                # Status for specific model
                active_job = self.active_jobs.get(model_name)
                pending_jobs = [j for j in self.job_queue if j.model_name == model_name]
                recent_jobs = [j for j in self.completed_jobs if j.model_name == model_name][-5:]
                
                return {
                    'model': model_name,
                    'active_job': active_job.__dict__ if active_job else None,
                    'pending_jobs': [j.__dict__ for j in pending_jobs],
                    'recent_jobs': [j.__dict__ for j in recent_jobs],
                    'training_history': self.retraining_history.get(model_name, [])
                }
            else:
                # Overall status
                return {
                    'scheduler_active': self.scheduler_active,
                    'registered_models': list(self.model_registry.keys()),
                    'active_jobs': {name: job.__dict__ for name, job in self.active_jobs.items()},
                    'pending_jobs': len(self.job_queue),
                    'completed_jobs': len(self.completed_jobs)
                }
    
    def get_training_history(self, model_name: str) -> List[Dict[str, Any]]:
        """Get training history for a model."""
        return self.retraining_history.get(model_name, [])

# Global retrainer instance
_retrainer_instance: Optional[AutoRetrainer] = None

def get_auto_retrainer() -> AutoRetrainer:
    """Get global auto-retrainer instance."""
    global _retrainer_instance
    if _retrainer_instance is None:
        _retrainer_instance = AutoRetrainer()
    return _retrainer_instance