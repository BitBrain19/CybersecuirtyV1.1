"""Comprehensive Model Performance Benchmarking System

This module provides tools for benchmarking, comparing, and analyzing
the performance of ML models across various metrics and scenarios.
"""

import time
import logging
import json
import pickle
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor
import psutil
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

from ..models.threat_detection import get_threat_detector
from ..models.vulnerability_assessment import get_vulnerability_assessor
from ..core.exceptions import BenchmarkingError
from ..core.config import get_config
from ..core.error_handler import with_error_recovery, RecoveryStrategy, RecoveryAction

logger = logging.getLogger(__name__)

class BenchmarkType(Enum):
    """Types of benchmarks."""
    PERFORMANCE = "performance"
    ACCURACY = "accuracy"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    MEMORY = "memory"
    STRESS = "stress"
    COMPARISON = "comparison"

class MetricType(Enum):
    """Performance metric types."""
    ACCURACY = "accuracy"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    ROC_AUC = "roc_auc"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    ERROR_RATE = "error_rate"

@dataclass
class BenchmarkConfig:
    """Benchmark configuration."""
    benchmark_type: BenchmarkType = BenchmarkType.PERFORMANCE
    iterations: int = 100
    warmup_iterations: int = 10
    batch_sizes: List[int] = field(default_factory=lambda: [1, 10, 50, 100])
    concurrent_users: List[int] = field(default_factory=lambda: [1, 5, 10, 20])
    timeout_seconds: int = 300
    memory_limit_mb: int = 2048
    collect_system_metrics: bool = True
    save_detailed_results: bool = True
    output_format: str = "json"  # json, csv, html

@dataclass
class PerformanceMetrics:
    """Performance metrics for a single test."""
    latency_ms: float
    throughput_rps: float
    memory_mb: float
    cpu_percent: float
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    roc_auc: Optional[float] = None
    error_rate: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""
    benchmark_id: str
    model_name: str
    benchmark_type: BenchmarkType
    config: BenchmarkConfig
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    metrics: List[PerformanceMetrics]
    summary_stats: Dict[str, Any]
    system_info: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

class SystemMonitor:
    """System resource monitoring."""
    
    def __init__(self):
        self.monitoring = False
        self.metrics: List[Dict[str, Any]] = []
        self.monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
    
    def start_monitoring(self, interval: float = 1.0) -> None:
        """Start system monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.metrics.clear()
        
        def monitor_loop():
            while self.monitoring:
                try:
                    cpu_percent = psutil.cpu_percent(interval=0.1)
                    memory = psutil.virtual_memory()
                    
                    with self._lock:
                        self.metrics.append({
                            'timestamp': datetime.now(),
                            'cpu_percent': cpu_percent,
                            'memory_percent': memory.percent,
                            'memory_used_mb': memory.used / (1024 * 1024),
                            'memory_available_mb': memory.available / (1024 * 1024)
                        })
                    
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Error in system monitoring: {str(e)}")
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Started system monitoring")
    
    def stop_monitoring(self) -> List[Dict[str, Any]]:
        """Stop system monitoring and return collected metrics."""
        if not self.monitoring:
            return []
        
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        
        with self._lock:
            metrics_copy = self.metrics.copy()
        
        logger.info(f"Stopped system monitoring, collected {len(metrics_copy)} data points")
        return metrics_copy
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics."""
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used_mb': memory.used / (1024 * 1024),
            'memory_available_mb': memory.available / (1024 * 1024)
        }

class ModelBenchmark:
    """Comprehensive model benchmarking system."""
    
    def __init__(self, config: Optional[BenchmarkConfig] = None):
        self.config = config or BenchmarkConfig()
        self.app_config = get_config()
        
        # Model instances
        self.threat_detector = get_threat_detector()
        self.vulnerability_assessor = get_vulnerability_assessor()
        
        # System monitoring
        self.system_monitor = SystemMonitor()
        
        # Results storage
        self.results: List[BenchmarkResult] = []
        self.results_lock = threading.Lock()
        
        # Output directory
        self.output_dir = Path(self.app_config.get('benchmark_output_dir', './benchmark_results'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Model benchmark system initialized")
    
    @with_error_recovery("ModelBenchmark", RecoveryStrategy(RecoveryAction.RETRY, max_attempts=2))
    def run_performance_benchmark(self, model_name: str, test_data: List[Dict[str, Any]], 
                                ground_truth: Optional[List[Any]] = None) -> BenchmarkResult:
        """Run comprehensive performance benchmark."""
        benchmark_id = f"perf_{model_name}_{int(time.time())}"
        start_time = datetime.now()
        
        logger.info(f"Starting performance benchmark {benchmark_id}")
        
        # Start system monitoring
        if self.config.collect_system_metrics:
            self.system_monitor.start_monitoring()
        
        try:
            # Get model instance
            model = self._get_model(model_name)
            
            # Warmup
            self._run_warmup(model, test_data[:self.config.warmup_iterations])
            
            # Run benchmark iterations
            metrics = []
            total_requests = 0
            successful_requests = 0
            failed_requests = 0
            errors = []
            
            for i in range(self.config.iterations):
                try:
                    # Select test sample
                    sample = test_data[i % len(test_data)]
                    
                    # Measure performance
                    start_mem = psutil.virtual_memory().used / (1024 * 1024)
                    start_cpu = psutil.cpu_percent()
                    start_latency = time.time()
                    
                    # Make prediction
                    result = model.predict(sample)
                    
                    end_latency = time.time()
                    end_cpu = psutil.cpu_percent()
                    end_mem = psutil.virtual_memory().used / (1024 * 1024)
                    
                    # Calculate metrics
                    latency_ms = (end_latency - start_latency) * 1000
                    throughput_rps = 1.0 / (end_latency - start_latency)
                    memory_mb = end_mem - start_mem
                    cpu_percent = end_cpu - start_cpu
                    
                    # Calculate accuracy metrics if ground truth available
                    accuracy_metrics = {}
                    if ground_truth and i < len(ground_truth):
                        accuracy_metrics = self._calculate_accuracy_metrics(
                            result, ground_truth[i % len(ground_truth)]
                        )
                    
                    # Create performance metrics
                    perf_metrics = PerformanceMetrics(
                        latency_ms=latency_ms,
                        throughput_rps=throughput_rps,
                        memory_mb=memory_mb,
                        cpu_percent=cpu_percent,
                        **accuracy_metrics
                    )
                    
                    metrics.append(perf_metrics)
                    successful_requests += 1
                    
                except Exception as e:
                    failed_requests += 1
                    errors.append(f"Iteration {i}: {str(e)}")
                    logger.error(f"Benchmark iteration {i} failed: {str(e)}")
                
                total_requests += 1
            
            # Stop system monitoring
            system_metrics = []
            if self.config.collect_system_metrics:
                system_metrics = self.system_monitor.stop_monitoring()
            
            # Calculate summary statistics
            summary_stats = self._calculate_summary_stats(metrics)
            
            # Get system info
            system_info = self._get_system_info(system_metrics)
            
            # Create benchmark result
            end_time = datetime.now()
            result = BenchmarkResult(
                benchmark_id=benchmark_id,
                model_name=model_name,
                benchmark_type=self.config.benchmark_type,
                config=self.config,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                metrics=metrics,
                summary_stats=summary_stats,
                system_info=system_info,
                errors=errors
            )
            
            # Store result
            with self.results_lock:
                self.results.append(result)
            
            # Save detailed results if configured
            if self.config.save_detailed_results:
                self._save_benchmark_result(result)
            
            logger.info(f"Completed performance benchmark {benchmark_id}")
            return result
            
        except Exception as e:
            # Stop monitoring on error
            if self.config.collect_system_metrics:
                self.system_monitor.stop_monitoring()
            
            logger.error(f"Performance benchmark failed: {str(e)}")
            raise BenchmarkingError(f"Benchmark failed: {str(e)}")
    
    def run_stress_test(self, model_name: str, test_data: List[Dict[str, Any]], 
                       duration_minutes: int = 10) -> BenchmarkResult:
        """Run stress test with sustained load."""
        benchmark_id = f"stress_{model_name}_{int(time.time())}"
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        logger.info(f"Starting stress test {benchmark_id} for {duration_minutes} minutes")
        
        # Start system monitoring
        if self.config.collect_system_metrics:
            self.system_monitor.start_monitoring(interval=0.5)
        
        try:
            model = self._get_model(model_name)
            
            # Run sustained load
            metrics = []
            total_requests = 0
            successful_requests = 0
            failed_requests = 0
            errors = []
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                while datetime.now() < end_time:
                    # Submit batch of requests
                    futures = []
                    for _ in range(10):  # Batch size
                        if datetime.now() >= end_time:
                            break
                        
                        sample = test_data[total_requests % len(test_data)]
                        future = executor.submit(self._measure_single_prediction, model, sample)
                        futures.append(future)
                        total_requests += 1
                    
                    # Collect results
                    for future in futures:
                        try:
                            perf_metrics = future.result(timeout=30)
                            metrics.append(perf_metrics)
                            successful_requests += 1
                        except Exception as e:
                            failed_requests += 1
                            errors.append(str(e))
                    
                    # Brief pause to prevent overwhelming
                    time.sleep(0.1)
            
            # Stop system monitoring
            system_metrics = []
            if self.config.collect_system_metrics:
                system_metrics = self.system_monitor.stop_monitoring()
            
            # Calculate summary statistics
            summary_stats = self._calculate_summary_stats(metrics)
            summary_stats['stress_test_duration_minutes'] = duration_minutes
            
            # Get system info
            system_info = self._get_system_info(system_metrics)
            
            # Create benchmark result
            actual_end_time = datetime.now()
            result = BenchmarkResult(
                benchmark_id=benchmark_id,
                model_name=model_name,
                benchmark_type=BenchmarkType.STRESS,
                config=self.config,
                start_time=start_time,
                end_time=actual_end_time,
                duration_seconds=(actual_end_time - start_time).total_seconds(),
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                metrics=metrics,
                summary_stats=summary_stats,
                system_info=system_info,
                errors=errors
            )
            
            # Store result
            with self.results_lock:
                self.results.append(result)
            
            if self.config.save_detailed_results:
                self._save_benchmark_result(result)
            
            logger.info(f"Completed stress test {benchmark_id}")
            return result
            
        except Exception as e:
            if self.config.collect_system_metrics:
                self.system_monitor.stop_monitoring()
            
            logger.error(f"Stress test failed: {str(e)}")
            raise BenchmarkingError(f"Stress test failed: {str(e)}")
    
    def compare_models(self, model_names: List[str], test_data: List[Dict[str, Any]], 
                      ground_truth: Optional[List[Any]] = None) -> Dict[str, BenchmarkResult]:
        """Compare performance of multiple models."""
        logger.info(f"Starting model comparison: {', '.join(model_names)}")
        
        results = {}
        
        for model_name in model_names:
            try:
                logger.info(f"Benchmarking {model_name}")
                result = self.run_performance_benchmark(model_name, test_data, ground_truth)
                results[model_name] = result
            except Exception as e:
                logger.error(f"Failed to benchmark {model_name}: {str(e)}")
                continue
        
        # Generate comparison report
        if len(results) > 1:
            self._generate_comparison_report(results)
        
        logger.info(f"Completed model comparison")
        return results
    
    def _get_model(self, model_name: str):
        """Get model instance by name."""
        if model_name == 'threat_detection':
            return self.threat_detector
        elif model_name == 'vulnerability_assessment':
            return self.vulnerability_assessor
        else:
            raise BenchmarkingError(f"Unknown model: {model_name}")
    
    def _run_warmup(self, model, warmup_data: List[Dict[str, Any]]) -> None:
        """Run warmup iterations."""
        logger.info(f"Running {len(warmup_data)} warmup iterations")
        
        for sample in warmup_data:
            try:
                model.predict(sample)
            except Exception as e:
                logger.warning(f"Warmup iteration failed: {str(e)}")
    
    def _measure_single_prediction(self, model, sample: Dict[str, Any]) -> PerformanceMetrics:
        """Measure performance of a single prediction."""
        start_mem = psutil.virtual_memory().used / (1024 * 1024)
        start_cpu = psutil.cpu_percent()
        start_time = time.time()
        
        try:
            result = model.predict(sample)
            success = True
        except Exception as e:
            result = None
            success = False
        
        end_time = time.time()
        end_cpu = psutil.cpu_percent()
        end_mem = psutil.virtual_memory().used / (1024 * 1024)
        
        latency_ms = (end_time - start_time) * 1000
        throughput_rps = 1.0 / (end_time - start_time) if success else 0.0
        memory_mb = end_mem - start_mem
        cpu_percent = end_cpu - start_cpu
        error_rate = 0.0 if success else 1.0
        
        return PerformanceMetrics(
            latency_ms=latency_ms,
            throughput_rps=throughput_rps,
            memory_mb=memory_mb,
            cpu_percent=cpu_percent,
            error_rate=error_rate
        )
    
    def _calculate_accuracy_metrics(self, prediction: Any, ground_truth: Any) -> Dict[str, float]:
        """Calculate accuracy metrics."""
        # This is a simplified implementation
        # In practice, you'd need to adapt this based on your specific prediction format
        try:
            if isinstance(prediction, dict) and 'prediction' in prediction:
                pred_value = prediction['prediction']
            else:
                pred_value = prediction
            
            # Simple accuracy calculation
            accuracy = 1.0 if pred_value == ground_truth else 0.0
            
            return {
                'accuracy': accuracy,
                'precision': accuracy,  # Simplified
                'recall': accuracy,     # Simplified
                'f1_score': accuracy    # Simplified
            }
        except Exception:
            return {}
    
    def _calculate_summary_stats(self, metrics: List[PerformanceMetrics]) -> Dict[str, Any]:
        """Calculate summary statistics from metrics."""
        if not metrics:
            return {}
        
        latencies = [m.latency_ms for m in metrics]
        throughputs = [m.throughput_rps for m in metrics]
        memory_usage = [m.memory_mb for m in metrics]
        cpu_usage = [m.cpu_percent for m in metrics]
        error_rates = [m.error_rate for m in metrics]
        
        # Filter out None values for accuracy metrics
        accuracies = [m.accuracy for m in metrics if m.accuracy is not None]
        precisions = [m.precision for m in metrics if m.precision is not None]
        recalls = [m.recall for m in metrics if m.recall is not None]
        f1_scores = [m.f1_score for m in metrics if m.f1_score is not None]
        
        stats = {
            'latency_stats': {
                'mean': statistics.mean(latencies),
                'median': statistics.median(latencies),
                'min': min(latencies),
                'max': max(latencies),
                'std': statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
                'p95': np.percentile(latencies, 95),
                'p99': np.percentile(latencies, 99)
            },
            'throughput_stats': {
                'mean': statistics.mean(throughputs),
                'median': statistics.median(throughputs),
                'min': min(throughputs),
                'max': max(throughputs)
            },
            'memory_stats': {
                'mean': statistics.mean(memory_usage),
                'max': max(memory_usage),
                'total': sum(memory_usage)
            },
            'cpu_stats': {
                'mean': statistics.mean(cpu_usage),
                'max': max(cpu_usage)
            },
            'error_rate': statistics.mean(error_rates)
        }
        
        # Add accuracy stats if available
        if accuracies:
            stats['accuracy_stats'] = {
                'mean': statistics.mean(accuracies),
                'min': min(accuracies),
                'max': max(accuracies)
            }
        
        if precisions:
            stats['precision_stats'] = {
                'mean': statistics.mean(precisions),
                'min': min(precisions),
                'max': max(precisions)
            }
        
        if recalls:
            stats['recall_stats'] = {
                'mean': statistics.mean(recalls),
                'min': min(recalls),
                'max': max(recalls)
            }
        
        if f1_scores:
            stats['f1_stats'] = {
                'mean': statistics.mean(f1_scores),
                'min': min(f1_scores),
                'max': max(f1_scores)
            }
        
        return stats
    
    def _get_system_info(self, system_metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get system information and metrics summary."""
        system_info = {
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'python_version': f"{psutil.sys.version_info.major}.{psutil.sys.version_info.minor}",
            'platform': psutil.platform.platform()
        }
        
        if system_metrics:
            cpu_values = [m['cpu_percent'] for m in system_metrics]
            memory_values = [m['memory_percent'] for m in system_metrics]
            
            system_info['monitoring_summary'] = {
                'cpu_usage': {
                    'mean': statistics.mean(cpu_values),
                    'max': max(cpu_values),
                    'min': min(cpu_values)
                },
                'memory_usage': {
                    'mean': statistics.mean(memory_values),
                    'max': max(memory_values),
                    'min': min(memory_values)
                },
                'monitoring_duration_seconds': len(system_metrics)
            }
        
        return system_info
    
    def _save_benchmark_result(self, result: BenchmarkResult) -> None:
        """Save benchmark result to file."""
        timestamp = result.start_time.strftime('%Y%m%d_%H%M%S')
        filename = f"{result.model_name}_{result.benchmark_type.value}_{timestamp}"
        
        if self.config.output_format == 'json':
            output_path = self.output_dir / f"{filename}.json"
            
            # Convert result to JSON-serializable format
            result_dict = {
                'benchmark_id': result.benchmark_id,
                'model_name': result.model_name,
                'benchmark_type': result.benchmark_type.value,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat(),
                'duration_seconds': result.duration_seconds,
                'total_requests': result.total_requests,
                'successful_requests': result.successful_requests,
                'failed_requests': result.failed_requests,
                'summary_stats': result.summary_stats,
                'system_info': result.system_info,
                'errors': result.errors
            }
            
            with open(output_path, 'w') as f:
                json.dump(result_dict, f, indent=2)
        
        elif self.config.output_format == 'csv':
            output_path = self.output_dir / f"{filename}.csv"
            
            # Convert metrics to DataFrame
            metrics_data = []
            for metric in result.metrics:
                metrics_data.append({
                    'timestamp': metric.timestamp.isoformat(),
                    'latency_ms': metric.latency_ms,
                    'throughput_rps': metric.throughput_rps,
                    'memory_mb': metric.memory_mb,
                    'cpu_percent': metric.cpu_percent,
                    'accuracy': metric.accuracy,
                    'precision': metric.precision,
                    'recall': metric.recall,
                    'f1_score': metric.f1_score,
                    'error_rate': metric.error_rate
                })
            
            df = pd.DataFrame(metrics_data)
            df.to_csv(output_path, index=False)
        
        logger.info(f"Saved benchmark result to {output_path}")
    
    def _generate_comparison_report(self, results: Dict[str, BenchmarkResult]) -> None:
        """Generate comparison report for multiple models."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = self.output_dir / f"comparison_report_{timestamp}.json"
        
        comparison_data = {
            'report_generated': datetime.now().isoformat(),
            'models_compared': list(results.keys()),
            'comparison_metrics': {}
        }
        
        # Compare key metrics
        for model_name, result in results.items():
            stats = result.summary_stats
            comparison_data['comparison_metrics'][model_name] = {
                'avg_latency_ms': stats.get('latency_stats', {}).get('mean', 0),
                'p95_latency_ms': stats.get('latency_stats', {}).get('p95', 0),
                'avg_throughput_rps': stats.get('throughput_stats', {}).get('mean', 0),
                'avg_memory_mb': stats.get('memory_stats', {}).get('mean', 0),
                'error_rate': stats.get('error_rate', 0),
                'success_rate': (result.successful_requests / result.total_requests) * 100,
                'total_requests': result.total_requests
            }
            
            # Add accuracy metrics if available
            if 'accuracy_stats' in stats:
                comparison_data['comparison_metrics'][model_name]['avg_accuracy'] = stats['accuracy_stats']['mean']
        
        with open(report_path, 'w') as f:
            json.dump(comparison_data, f, indent=2)
        
        logger.info(f"Generated comparison report: {report_path}")
    
    def get_benchmark_history(self, model_name: Optional[str] = None, 
                            days: int = 30) -> List[BenchmarkResult]:
        """Get benchmark history."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with self.results_lock:
            filtered_results = [
                result for result in self.results
                if result.start_time >= cutoff_date and
                (model_name is None or result.model_name == model_name)
            ]
        
        return filtered_results
    
    def get_performance_trends(self, model_name: str, days: int = 30) -> Dict[str, List[float]]:
        """Get performance trends over time."""
        history = self.get_benchmark_history(model_name, days)
        
        trends = {
            'timestamps': [],
            'avg_latency': [],
            'avg_throughput': [],
            'error_rates': [],
            'success_rates': []
        }
        
        for result in sorted(history, key=lambda x: x.start_time):
            trends['timestamps'].append(result.start_time.isoformat())
            
            stats = result.summary_stats
            trends['avg_latency'].append(stats.get('latency_stats', {}).get('mean', 0))
            trends['avg_throughput'].append(stats.get('throughput_stats', {}).get('mean', 0))
            trends['error_rates'].append(stats.get('error_rate', 0))
            trends['success_rates'].append((result.successful_requests / result.total_requests) * 100)
        
        return trends
    
    def cleanup_old_results(self, days: int = 90) -> int:
        """Clean up old benchmark results."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with self.results_lock:
            initial_count = len(self.results)
            self.results = [
                result for result in self.results
                if result.start_time >= cutoff_date
            ]
            cleaned_count = initial_count - len(self.results)
        
        logger.info(f"Cleaned up {cleaned_count} old benchmark results")
        return cleaned_count

# Global benchmark instance
_benchmark_instance: Optional[ModelBenchmark] = None

def get_model_benchmark(config: Optional[BenchmarkConfig] = None) -> ModelBenchmark:
    """Get global model benchmark instance."""
    global _benchmark_instance
    if _benchmark_instance is None:
        _benchmark_instance = ModelBenchmark(config)
    return _benchmark_instance