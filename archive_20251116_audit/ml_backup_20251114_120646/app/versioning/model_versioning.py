"""Model Versioning and A/B Testing System

This module provides comprehensive model versioning, A/B testing,
and deployment management capabilities for production ML systems.
"""

import json
import pickle
import hashlib
import logging
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
import random
import statistics
from collections import defaultdict, deque
import numpy as np

from ..models.threat_detection import get_threat_detector
from ..models.vulnerability_assessment import get_vulnerability_assessor
from ..core.exceptions import VersioningError
from ..core.config import get_config
from ..core.error_handler import with_error_recovery, RecoveryStrategy, RecoveryAction
from ..benchmarking.performance_benchmark import get_model_benchmark, BenchmarkConfig

logger = logging.getLogger(__name__)

class ModelStatus(Enum):
    """Model deployment status."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"

class ABTestStatus(Enum):
    """A/B test status."""
    DRAFT = "draft"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class TrafficSplitStrategy(Enum):
    """Traffic splitting strategies."""
    RANDOM = "random"
    USER_HASH = "user_hash"
    GEOGRAPHIC = "geographic"
    TIME_BASED = "time_based"
    FEATURE_BASED = "feature_based"

@dataclass
class ModelVersion:
    """Model version metadata."""
    version_id: str
    model_name: str
    version_number: str
    status: ModelStatus
    created_at: datetime
    created_by: str
    description: str
    model_path: str
    config_path: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    checksum: Optional[str] = None
    size_bytes: Optional[int] = None
    dependencies: Dict[str, str] = field(default_factory=dict)
    deployment_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ABTestConfig:
    """A/B test configuration."""
    test_id: str
    name: str
    description: str
    control_version: str
    treatment_versions: List[str]
    traffic_split: Dict[str, float]  # version_id -> percentage
    split_strategy: TrafficSplitStrategy
    start_date: datetime
    end_date: datetime
    success_metrics: List[str]
    minimum_sample_size: int = 1000
    confidence_level: float = 0.95
    statistical_power: float = 0.8
    early_stopping_enabled: bool = True
    max_duration_days: int = 30
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ABTestResult:
    """A/B test result data."""
    test_id: str
    version_id: str
    timestamp: datetime
    user_id: Optional[str]
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]
    metrics: Dict[str, float]
    latency_ms: float
    success: bool
    error_message: Optional[str] = None

@dataclass
class ABTestSummary:
    """A/B test summary statistics."""
    test_id: str
    status: ABTestStatus
    start_date: datetime
    end_date: Optional[datetime]
    total_requests: int
    version_stats: Dict[str, Dict[str, Any]]
    statistical_significance: Dict[str, bool]
    confidence_intervals: Dict[str, Dict[str, Tuple[float, float]]]
    recommendations: List[str]
    winner: Optional[str] = None

class ModelRegistry:
    """Model version registry and management."""
    
    def __init__(self, registry_path: Optional[str] = None):
        self.config = get_config()
        self.registry_path = Path(registry_path or self.config.get('model_registry_path', './model_registry'))
        self.registry_path.mkdir(parents=True, exist_ok=True)
        
        # Version storage
        self.versions: Dict[str, ModelVersion] = {}
        self.version_lock = threading.Lock()
        
        # Load existing versions
        self._load_registry()
        
        logger.info(f"Model registry initialized at {self.registry_path}")
    
    def _load_registry(self) -> None:
        """Load existing model versions from registry."""
        registry_file = self.registry_path / 'registry.json'
        
        if registry_file.exists():
            try:
                with open(registry_file, 'r') as f:
                    data = json.load(f)
                
                for version_data in data.get('versions', []):
                    version = ModelVersion(
                        version_id=version_data['version_id'],
                        model_name=version_data['model_name'],
                        version_number=version_data['version_number'],
                        status=ModelStatus(version_data['status']),
                        created_at=datetime.fromisoformat(version_data['created_at']),
                        created_by=version_data['created_by'],
                        description=version_data['description'],
                        model_path=version_data['model_path'],
                        config_path=version_data['config_path'],
                        metrics=version_data.get('metrics', {}),
                        metadata=version_data.get('metadata', {}),
                        parent_version=version_data.get('parent_version'),
                        tags=version_data.get('tags', []),
                        checksum=version_data.get('checksum'),
                        size_bytes=version_data.get('size_bytes'),
                        dependencies=version_data.get('dependencies', {}),
                        deployment_config=version_data.get('deployment_config', {})
                    )
                    self.versions[version.version_id] = version
                
                logger.info(f"Loaded {len(self.versions)} model versions from registry")
                
            except Exception as e:
                logger.error(f"Failed to load registry: {str(e)}")
    
    def _save_registry(self) -> None:
        """Save model registry to disk."""
        registry_file = self.registry_path / 'registry.json'
        
        try:
            versions_data = []
            for version in self.versions.values():
                version_data = {
                    'version_id': version.version_id,
                    'model_name': version.model_name,
                    'version_number': version.version_number,
                    'status': version.status.value,
                    'created_at': version.created_at.isoformat(),
                    'created_by': version.created_by,
                    'description': version.description,
                    'model_path': version.model_path,
                    'config_path': version.config_path,
                    'metrics': version.metrics,
                    'metadata': version.metadata,
                    'parent_version': version.parent_version,
                    'tags': version.tags,
                    'checksum': version.checksum,
                    'size_bytes': version.size_bytes,
                    'dependencies': version.dependencies,
                    'deployment_config': version.deployment_config
                }
                versions_data.append(version_data)
            
            registry_data = {
                'last_updated': datetime.now().isoformat(),
                'versions': versions_data
            }
            
            with open(registry_file, 'w') as f:
                json.dump(registry_data, f, indent=2)
            
            logger.debug("Registry saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save registry: {str(e)}")
            raise VersioningError(f"Registry save failed: {str(e)}")
    
    @with_error_recovery("ModelRegistry", RecoveryStrategy(RecoveryAction.RETRY, max_attempts=2))
    def register_version(self, model_name: str, version_number: str, model_path: str,
                        config_path: str, created_by: str, description: str,
                        parent_version: Optional[str] = None, tags: Optional[List[str]] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> str:
        """Register a new model version."""
        version_id = f"{model_name}_v{version_number}_{int(datetime.now().timestamp())}"
        
        # Calculate checksum
        checksum = self._calculate_checksum(model_path)
        
        # Get file size
        size_bytes = Path(model_path).stat().st_size if Path(model_path).exists() else None
        
        # Create version object
        version = ModelVersion(
            version_id=version_id,
            model_name=model_name,
            version_number=version_number,
            status=ModelStatus.DEVELOPMENT,
            created_at=datetime.now(),
            created_by=created_by,
            description=description,
            model_path=model_path,
            config_path=config_path,
            parent_version=parent_version,
            tags=tags or [],
            metadata=metadata or {},
            checksum=checksum,
            size_bytes=size_bytes
        )
        
        # Store version
        with self.version_lock:
            self.versions[version_id] = version
            self._save_registry()
        
        logger.info(f"Registered model version {version_id}")
        return version_id
    
    def get_version(self, version_id: str) -> Optional[ModelVersion]:
        """Get model version by ID."""
        with self.version_lock:
            return self.versions.get(version_id)
    
    def list_versions(self, model_name: Optional[str] = None, 
                     status: Optional[ModelStatus] = None,
                     tags: Optional[List[str]] = None) -> List[ModelVersion]:
        """List model versions with optional filters."""
        with self.version_lock:
            versions = list(self.versions.values())
        
        # Apply filters
        if model_name:
            versions = [v for v in versions if v.model_name == model_name]
        
        if status:
            versions = [v for v in versions if v.status == status]
        
        if tags:
            versions = [v for v in versions if any(tag in v.tags for tag in tags)]
        
        # Sort by creation date (newest first)
        versions.sort(key=lambda x: x.created_at, reverse=True)
        
        return versions
    
    def get_latest_version(self, model_name: str, status: Optional[ModelStatus] = None) -> Optional[ModelVersion]:
        """Get the latest version of a model."""
        versions = self.list_versions(model_name, status)
        return versions[0] if versions else None
    
    def update_version_status(self, version_id: str, status: ModelStatus) -> bool:
        """Update version status."""
        with self.version_lock:
            if version_id in self.versions:
                self.versions[version_id].status = status
                self._save_registry()
                logger.info(f"Updated version {version_id} status to {status.value}")
                return True
        
        return False
    
    def add_version_metrics(self, version_id: str, metrics: Dict[str, Any]) -> bool:
        """Add performance metrics to a version."""
        with self.version_lock:
            if version_id in self.versions:
                self.versions[version_id].metrics.update(metrics)
                self._save_registry()
                logger.info(f"Added metrics to version {version_id}")
                return True
        
        return False
    
    def compare_versions(self, version_ids: List[str]) -> Dict[str, Any]:
        """Compare multiple model versions."""
        comparison = {
            'versions': {},
            'metrics_comparison': {},
            'recommendations': []
        }
        
        with self.version_lock:
            for version_id in version_ids:
                if version_id in self.versions:
                    version = self.versions[version_id]
                    comparison['versions'][version_id] = {
                        'version_number': version.version_number,
                        'status': version.status.value,
                        'created_at': version.created_at.isoformat(),
                        'metrics': version.metrics,
                        'size_bytes': version.size_bytes
                    }
        
        # Compare metrics
        all_metrics = set()
        for version_data in comparison['versions'].values():
            all_metrics.update(version_data['metrics'].keys())
        
        for metric in all_metrics:
            comparison['metrics_comparison'][metric] = {}
            for version_id, version_data in comparison['versions'].items():
                comparison['metrics_comparison'][metric][version_id] = version_data['metrics'].get(metric)
        
        return comparison
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate file checksum."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.warning(f"Failed to calculate checksum for {file_path}: {str(e)}")
            return ""
    
    def archive_version(self, version_id: str) -> bool:
        """Archive a model version."""
        return self.update_version_status(version_id, ModelStatus.ARCHIVED)
    
    def delete_version(self, version_id: str, force: bool = False) -> bool:
        """Delete a model version."""
        with self.version_lock:
            if version_id not in self.versions:
                return False
            
            version = self.versions[version_id]
            
            # Check if version is in production
            if version.status == ModelStatus.PRODUCTION and not force:
                raise VersioningError("Cannot delete production version without force=True")
            
            # Remove files if they exist
            try:
                if Path(version.model_path).exists():
                    Path(version.model_path).unlink()
                if Path(version.config_path).exists():
                    Path(version.config_path).unlink()
            except Exception as e:
                logger.warning(f"Failed to delete version files: {str(e)}")
            
            # Remove from registry
            del self.versions[version_id]
            self._save_registry()
            
            logger.info(f"Deleted version {version_id}")
            return True

class ABTestManager:
    """A/B testing manager for model versions."""
    
    def __init__(self, registry: ModelRegistry):
        self.registry = registry
        self.config = get_config()
        
        # Test storage
        self.active_tests: Dict[str, ABTestConfig] = {}
        self.test_results: Dict[str, List[ABTestResult]] = defaultdict(list)
        self.test_lock = threading.Lock()
        
        # Results storage path
        self.results_path = Path(self.config.get('ab_test_results_path', './ab_test_results'))
        self.results_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("A/B test manager initialized")
    
    @with_error_recovery("ABTestManager", RecoveryStrategy(RecoveryAction.RETRY, max_attempts=2))
    def create_test(self, name: str, description: str, control_version: str,
                   treatment_versions: List[str], traffic_split: Dict[str, float],
                   duration_days: int = 14, success_metrics: Optional[List[str]] = None,
                   split_strategy: TrafficSplitStrategy = TrafficSplitStrategy.RANDOM,
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """Create a new A/B test."""
        test_id = f"test_{int(datetime.now().timestamp())}_{hash(name) % 10000}"
        
        # Validate versions exist
        all_versions = [control_version] + treatment_versions
        for version_id in all_versions:
            if not self.registry.get_version(version_id):
                raise VersioningError(f"Version {version_id} not found in registry")
        
        # Validate traffic split
        if abs(sum(traffic_split.values()) - 1.0) > 0.01:
            raise VersioningError("Traffic split must sum to 1.0")
        
        # Create test configuration
        test_config = ABTestConfig(
            test_id=test_id,
            name=name,
            description=description,
            control_version=control_version,
            treatment_versions=treatment_versions,
            traffic_split=traffic_split,
            split_strategy=split_strategy,
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=duration_days),
            success_metrics=success_metrics or ['accuracy', 'latency'],
            metadata=metadata or {}
        )
        
        # Store test
        with self.test_lock:
            self.active_tests[test_id] = test_config
        
        logger.info(f"Created A/B test {test_id}: {name}")
        return test_id
    
    def get_version_for_request(self, test_id: str, user_id: Optional[str] = None,
                               request_data: Optional[Dict[str, Any]] = None) -> str:
        """Get model version for a request based on A/B test configuration."""
        with self.test_lock:
            if test_id not in self.active_tests:
                raise VersioningError(f"Test {test_id} not found")
            
            test_config = self.active_tests[test_id]
        
        # Check if test is active
        now = datetime.now()
        if now < test_config.start_date or now > test_config.end_date:
            return test_config.control_version
        
        # Determine version based on split strategy
        if test_config.split_strategy == TrafficSplitStrategy.RANDOM:
            return self._random_split(test_config)
        elif test_config.split_strategy == TrafficSplitStrategy.USER_HASH:
            return self._user_hash_split(test_config, user_id)
        else:
            # Default to random for unsupported strategies
            return self._random_split(test_config)
    
    def _random_split(self, test_config: ABTestConfig) -> str:
        """Random traffic splitting."""
        rand_val = random.random()
        cumulative = 0.0
        
        for version_id, percentage in test_config.traffic_split.items():
            cumulative += percentage
            if rand_val <= cumulative:
                return version_id
        
        # Fallback to control
        return test_config.control_version
    
    def _user_hash_split(self, test_config: ABTestConfig, user_id: Optional[str]) -> str:
        """User hash-based traffic splitting for consistent assignment."""
        if not user_id:
            return self._random_split(test_config)
        
        # Create deterministic hash
        hash_val = int(hashlib.md5(f"{test_config.test_id}_{user_id}".encode()).hexdigest(), 16)
        normalized_hash = (hash_val % 10000) / 10000.0
        
        cumulative = 0.0
        for version_id, percentage in test_config.traffic_split.items():
            cumulative += percentage
            if normalized_hash <= cumulative:
                return version_id
        
        return test_config.control_version
    
    def record_result(self, test_id: str, version_id: str, user_id: Optional[str],
                     request_data: Dict[str, Any], response_data: Dict[str, Any],
                     latency_ms: float, success: bool, metrics: Optional[Dict[str, float]] = None,
                     error_message: Optional[str] = None) -> None:
        """Record A/B test result."""
        result = ABTestResult(
            test_id=test_id,
            version_id=version_id,
            timestamp=datetime.now(),
            user_id=user_id,
            request_data=request_data,
            response_data=response_data,
            metrics=metrics or {},
            latency_ms=latency_ms,
            success=success,
            error_message=error_message
        )
        
        with self.test_lock:
            self.test_results[test_id].append(result)
        
        # Periodically save results to disk
        if len(self.test_results[test_id]) % 100 == 0:
            self._save_test_results(test_id)
    
    def get_test_summary(self, test_id: str) -> ABTestSummary:
        """Get comprehensive test summary with statistical analysis."""
        with self.test_lock:
            if test_id not in self.active_tests:
                raise VersioningError(f"Test {test_id} not found")
            
            test_config = self.active_tests[test_id]
            results = self.test_results[test_id]
        
        # Calculate statistics for each version
        version_stats = {}
        all_versions = [test_config.control_version] + test_config.treatment_versions
        
        for version_id in all_versions:
            version_results = [r for r in results if r.version_id == version_id]
            
            if version_results:
                latencies = [r.latency_ms for r in version_results]
                success_rate = sum(1 for r in version_results if r.success) / len(version_results)
                
                # Calculate metric averages
                metric_averages = {}
                for metric_name in test_config.success_metrics:
                    metric_values = [r.metrics.get(metric_name, 0) for r in version_results if metric_name in r.metrics]
                    if metric_values:
                        metric_averages[metric_name] = statistics.mean(metric_values)
                
                version_stats[version_id] = {
                    'sample_size': len(version_results),
                    'success_rate': success_rate,
                    'avg_latency_ms': statistics.mean(latencies),
                    'median_latency_ms': statistics.median(latencies),
                    'p95_latency_ms': np.percentile(latencies, 95),
                    'metric_averages': metric_averages
                }
            else:
                version_stats[version_id] = {
                    'sample_size': 0,
                    'success_rate': 0.0,
                    'avg_latency_ms': 0.0,
                    'median_latency_ms': 0.0,
                    'p95_latency_ms': 0.0,
                    'metric_averages': {}
                }
        
        # Determine test status
        now = datetime.now()
        if now < test_config.start_date:
            status = ABTestStatus.DRAFT
        elif now > test_config.end_date:
            status = ABTestStatus.COMPLETED
        else:
            status = ABTestStatus.RUNNING
        
        # Statistical significance testing (simplified)
        statistical_significance = {}
        confidence_intervals = {}
        
        control_stats = version_stats.get(test_config.control_version, {})
        control_sample_size = control_stats.get('sample_size', 0)
        
        for treatment_version in test_config.treatment_versions:
            treatment_stats = version_stats.get(treatment_version, {})
            treatment_sample_size = treatment_stats.get('sample_size', 0)
            
            # Simple significance test based on sample size
            min_sample_size = test_config.minimum_sample_size
            is_significant = (control_sample_size >= min_sample_size and 
                            treatment_sample_size >= min_sample_size)
            
            statistical_significance[treatment_version] = is_significant
            
            # Simplified confidence intervals (would need proper statistical calculation)
            confidence_intervals[treatment_version] = {
                'success_rate': (0.0, 1.0),  # Placeholder
                'latency': (0.0, 1000.0)     # Placeholder
            }
        
        # Generate recommendations
        recommendations = self._generate_recommendations(version_stats, test_config)
        
        # Determine winner
        winner = self._determine_winner(version_stats, test_config, statistical_significance)
        
        return ABTestSummary(
            test_id=test_id,
            status=status,
            start_date=test_config.start_date,
            end_date=test_config.end_date if status == ABTestStatus.COMPLETED else None,
            total_requests=len(results),
            version_stats=version_stats,
            statistical_significance=statistical_significance,
            confidence_intervals=confidence_intervals,
            recommendations=recommendations,
            winner=winner
        )
    
    def _generate_recommendations(self, version_stats: Dict[str, Dict[str, Any]], 
                                test_config: ABTestConfig) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        control_stats = version_stats.get(test_config.control_version, {})
        control_success_rate = control_stats.get('success_rate', 0)
        control_latency = control_stats.get('avg_latency_ms', 0)
        
        for treatment_version in test_config.treatment_versions:
            treatment_stats = version_stats.get(treatment_version, {})
            treatment_success_rate = treatment_stats.get('success_rate', 0)
            treatment_latency = treatment_stats.get('avg_latency_ms', 0)
            
            sample_size = treatment_stats.get('sample_size', 0)
            
            if sample_size < test_config.minimum_sample_size:
                recommendations.append(f"Increase sample size for {treatment_version} (current: {sample_size})")
            
            if treatment_success_rate > control_success_rate * 1.05:  # 5% improvement
                recommendations.append(f"{treatment_version} shows {((treatment_success_rate/control_success_rate - 1) * 100):.1f}% improvement in success rate")
            
            if treatment_latency < control_latency * 0.95:  # 5% improvement
                recommendations.append(f"{treatment_version} shows {((1 - treatment_latency/control_latency) * 100):.1f}% improvement in latency")
        
        return recommendations
    
    def _determine_winner(self, version_stats: Dict[str, Dict[str, Any]], 
                         test_config: ABTestConfig, 
                         statistical_significance: Dict[str, bool]) -> Optional[str]:
        """Determine the winning version based on success metrics."""
        control_stats = version_stats.get(test_config.control_version, {})
        control_success_rate = control_stats.get('success_rate', 0)
        
        best_version = test_config.control_version
        best_score = control_success_rate
        
        for treatment_version in test_config.treatment_versions:
            if not statistical_significance.get(treatment_version, False):
                continue  # Skip if not statistically significant
            
            treatment_stats = version_stats.get(treatment_version, {})
            treatment_success_rate = treatment_stats.get('success_rate', 0)
            
            if treatment_success_rate > best_score:
                best_version = treatment_version
                best_score = treatment_success_rate
        
        return best_version if best_score > control_success_rate else None
    
    def stop_test(self, test_id: str) -> ABTestSummary:
        """Stop an active A/B test."""
        with self.test_lock:
            if test_id not in self.active_tests:
                raise VersioningError(f"Test {test_id} not found")
            
            # Update end date to now
            self.active_tests[test_id].end_date = datetime.now()
        
        # Save final results
        self._save_test_results(test_id)
        
        # Generate final summary
        summary = self.get_test_summary(test_id)
        
        logger.info(f"Stopped A/B test {test_id}")
        return summary
    
    def _save_test_results(self, test_id: str) -> None:
        """Save test results to disk."""
        results_file = self.results_path / f"{test_id}_results.json"
        
        try:
            with self.test_lock:
                results = self.test_results[test_id]
            
            # Convert results to JSON-serializable format
            results_data = []
            for result in results:
                result_data = {
                    'test_id': result.test_id,
                    'version_id': result.version_id,
                    'timestamp': result.timestamp.isoformat(),
                    'user_id': result.user_id,
                    'request_data': result.request_data,
                    'response_data': result.response_data,
                    'metrics': result.metrics,
                    'latency_ms': result.latency_ms,
                    'success': result.success,
                    'error_message': result.error_message
                }
                results_data.append(result_data)
            
            with open(results_file, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            logger.debug(f"Saved {len(results_data)} test results to {results_file}")
            
        except Exception as e:
            logger.error(f"Failed to save test results: {str(e)}")
    
    def list_active_tests(self) -> List[ABTestConfig]:
        """List all active A/B tests."""
        with self.test_lock:
            return list(self.active_tests.values())
    
    def cleanup_old_tests(self, days: int = 90) -> int:
        """Clean up old test data."""
        cutoff_date = datetime.now() - timedelta(days=days)
        cleaned_count = 0
        
        with self.test_lock:
            tests_to_remove = []
            for test_id, test_config in self.active_tests.items():
                if test_config.end_date and test_config.end_date < cutoff_date:
                    tests_to_remove.append(test_id)
            
            for test_id in tests_to_remove:
                del self.active_tests[test_id]
                if test_id in self.test_results:
                    del self.test_results[test_id]
                cleaned_count += 1
        
        logger.info(f"Cleaned up {cleaned_count} old A/B tests")
        return cleaned_count

# Global instances
_model_registry: Optional[ModelRegistry] = None
_ab_test_manager: Optional[ABTestManager] = None

def get_model_registry(registry_path: Optional[str] = None) -> ModelRegistry:
    """Get global model registry instance."""
    global _model_registry
    if _model_registry is None:
        _model_registry = ModelRegistry(registry_path)
    return _model_registry

def get_ab_test_manager(registry: Optional[ModelRegistry] = None) -> ABTestManager:
    """Get global A/B test manager instance."""
    global _ab_test_manager
    if _ab_test_manager is None:
        registry = registry or get_model_registry()
        _ab_test_manager = ABTestManager(registry)
    return _ab_test_manager