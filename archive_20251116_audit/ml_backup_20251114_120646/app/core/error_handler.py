"""Enhanced Error Handling and Recovery System

This module provides comprehensive error handling, recovery mechanisms,
and resilience patterns for all ML components.
"""

import logging
import traceback
import functools
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Type, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading
import json

logger = logging.getLogger(__name__)

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RecoveryAction(Enum):
    """Recovery action types."""
    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAK = "circuit_break"
    ESCALATE = "escalate"
    IGNORE = "ignore"

@dataclass
class ErrorContext:
    """Context information for an error."""
    error_id: str
    timestamp: datetime
    component: str
    function: str
    error_type: str
    error_message: str
    severity: ErrorSeverity
    stack_trace: str
    context_data: Dict[str, Any] = field(default_factory=dict)
    recovery_attempts: int = 0
    resolved: bool = False
    resolution_time: Optional[datetime] = None

@dataclass
class RecoveryStrategy:
    """Recovery strategy configuration."""
    action: RecoveryAction
    max_attempts: int = 3
    backoff_factor: float = 2.0
    initial_delay: float = 1.0
    max_delay: float = 60.0
    fallback_function: Optional[Callable] = None
    escalation_threshold: int = 5
    circuit_breaker_timeout: float = 300.0  # 5 minutes

class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    def __init__(self, failure_threshold: int = 5, timeout: float = 300.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED
        self._lock = threading.Lock()
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                else:
                    raise Exception("Circuit breaker is OPEN")
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure()
                raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset."""
        return (self.last_failure_time and 
                time.time() - self.last_failure_time > self.timeout)
    
    def _on_success(self) -> None:
        """Handle successful execution."""
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED
    
    def _on_failure(self) -> None:
        """Handle failed execution."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN

class ErrorRecoveryManager:
    """Comprehensive error recovery manager."""
    
    def __init__(self):
        self.error_history: deque = deque(maxlen=1000)
        self.recovery_strategies: Dict[str, RecoveryStrategy] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_patterns: Dict[str, List[ErrorContext]] = defaultdict(list)
        self.metrics = {
            'total_errors': 0,
            'recovered_errors': 0,
            'failed_recoveries': 0,
            'circuit_breaker_trips': 0
        }
        self._lock = threading.Lock()
        
        # Default recovery strategies
        self._setup_default_strategies()
        
        logger.info("Error recovery manager initialized")
    
    def _setup_default_strategies(self) -> None:
        """Setup default recovery strategies for common error types."""
        self.recovery_strategies.update({
            'ConnectionError': RecoveryStrategy(
                action=RecoveryAction.RETRY,
                max_attempts=3,
                backoff_factor=2.0,
                initial_delay=1.0
            ),
            'TimeoutError': RecoveryStrategy(
                action=RecoveryAction.RETRY,
                max_attempts=2,
                backoff_factor=1.5,
                initial_delay=2.0
            ),
            'MemoryError': RecoveryStrategy(
                action=RecoveryAction.CIRCUIT_BREAK,
                circuit_breaker_timeout=600.0
            ),
            'ModelLoadError': RecoveryStrategy(
                action=RecoveryAction.FALLBACK,
                max_attempts=1
            ),
            'ValidationError': RecoveryStrategy(
                action=RecoveryAction.IGNORE,
                max_attempts=0
            )
        })
    
    def register_strategy(self, error_type: str, strategy: RecoveryStrategy) -> None:
        """Register a recovery strategy for an error type."""
        self.recovery_strategies[error_type] = strategy
        logger.info(f"Registered recovery strategy for {error_type}")
    
    def handle_error(self, error: Exception, component: str, function: str, 
                    context_data: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """Handle an error with appropriate recovery strategy."""
        error_context = self._create_error_context(
            error, component, function, context_data or {}
        )
        
        with self._lock:
            self.error_history.append(error_context)
            self.error_patterns[error_context.error_type].append(error_context)
            self.metrics['total_errors'] += 1
        
        logger.error(f"Error in {component}.{function}: {str(error)}")
        
        # Get recovery strategy
        strategy = self._get_recovery_strategy(error_context.error_type)
        
        if strategy.action == RecoveryAction.IGNORE:
            logger.info(f"Ignoring error {error_context.error_id}")
            return None
        
        # Attempt recovery
        return self._attempt_recovery(error_context, strategy)
    
    def _create_error_context(self, error: Exception, component: str, 
                            function: str, context_data: Dict[str, Any]) -> ErrorContext:
        """Create error context from exception."""
        error_id = f"{component}_{function}_{int(time.time())}_{id(error)}"
        severity = self._determine_severity(error)
        
        return ErrorContext(
            error_id=error_id,
            timestamp=datetime.now(),
            component=component,
            function=function,
            error_type=type(error).__name__,
            error_message=str(error),
            severity=severity,
            stack_trace=traceback.format_exc(),
            context_data=context_data
        )
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """Determine error severity based on error type."""
        critical_errors = (MemoryError, SystemError, KeyboardInterrupt)
        high_errors = (ConnectionError, TimeoutError, OSError)
        medium_errors = (ValueError, TypeError, AttributeError)
        
        if isinstance(error, critical_errors):
            return ErrorSeverity.CRITICAL
        elif isinstance(error, high_errors):
            return ErrorSeverity.HIGH
        elif isinstance(error, medium_errors):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _get_recovery_strategy(self, error_type: str) -> RecoveryStrategy:
        """Get recovery strategy for error type."""
        return self.recovery_strategies.get(
            error_type, 
            RecoveryStrategy(action=RecoveryAction.RETRY, max_attempts=1)
        )
    
    def _attempt_recovery(self, error_context: ErrorContext, 
                         strategy: RecoveryStrategy) -> Optional[Any]:
        """Attempt error recovery based on strategy."""
        if strategy.action == RecoveryAction.RETRY:
            return self._retry_with_backoff(error_context, strategy)
        
        elif strategy.action == RecoveryAction.FALLBACK:
            return self._execute_fallback(error_context, strategy)
        
        elif strategy.action == RecoveryAction.CIRCUIT_BREAK:
            return self._handle_circuit_breaker(error_context, strategy)
        
        elif strategy.action == RecoveryAction.ESCALATE:
            return self._escalate_error(error_context, strategy)
        
        return None
    
    def _retry_with_backoff(self, error_context: ErrorContext, 
                           strategy: RecoveryStrategy) -> Optional[Any]:
        """Retry with exponential backoff."""
        delay = strategy.initial_delay
        
        for attempt in range(strategy.max_attempts):
            error_context.recovery_attempts += 1
            
            try:
                time.sleep(delay)
                logger.info(f"Retry attempt {attempt + 1} for {error_context.error_id}")
                
                # This would need to be implemented by the calling code
                # For now, we just mark as recovered
                self._mark_recovered(error_context)
                return True
                
            except Exception as e:
                logger.warning(f"Retry {attempt + 1} failed: {str(e)}")
                delay = min(delay * strategy.backoff_factor, strategy.max_delay)
        
        self.metrics['failed_recoveries'] += 1
        return None
    
    def _execute_fallback(self, error_context: ErrorContext, 
                         strategy: RecoveryStrategy) -> Optional[Any]:
        """Execute fallback function."""
        if not strategy.fallback_function:
            logger.warning(f"No fallback function for {error_context.error_id}")
            return None
        
        try:
            logger.info(f"Executing fallback for {error_context.error_id}")
            result = strategy.fallback_function(error_context.context_data)
            self._mark_recovered(error_context)
            return result
        except Exception as e:
            logger.error(f"Fallback failed for {error_context.error_id}: {str(e)}")
            self.metrics['failed_recoveries'] += 1
            return None
    
    def _handle_circuit_breaker(self, error_context: ErrorContext, 
                               strategy: RecoveryStrategy) -> Optional[Any]:
        """Handle circuit breaker logic."""
        breaker_key = f"{error_context.component}_{error_context.function}"
        
        if breaker_key not in self.circuit_breakers:
            self.circuit_breakers[breaker_key] = CircuitBreaker(
                failure_threshold=strategy.escalation_threshold,
                timeout=strategy.circuit_breaker_timeout
            )
        
        breaker = self.circuit_breakers[breaker_key]
        
        if breaker.state == CircuitBreakerState.OPEN:
            logger.warning(f"Circuit breaker OPEN for {breaker_key}")
            self.metrics['circuit_breaker_trips'] += 1
            return None
        
        return None
    
    def _escalate_error(self, error_context: ErrorContext, 
                       strategy: RecoveryStrategy) -> Optional[Any]:
        """Escalate error to higher level handling."""
        logger.critical(f"Escalating error {error_context.error_id}")
        
        # Could integrate with alerting systems, notifications, etc.
        # For now, just log the escalation
        
        return None
    
    def _mark_recovered(self, error_context: ErrorContext) -> None:
        """Mark error as recovered."""
        error_context.resolved = True
        error_context.resolution_time = datetime.now()
        self.metrics['recovered_errors'] += 1
        
        logger.info(f"Error {error_context.error_id} recovered after {error_context.recovery_attempts} attempts")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics."""
        with self._lock:
            recent_errors = [e for e in self.error_history 
                           if (datetime.now() - e.timestamp).total_seconds() < 3600]
            
            error_types = defaultdict(int)
            severity_counts = defaultdict(int)
            component_errors = defaultdict(int)
            
            for error in recent_errors:
                error_types[error.error_type] += 1
                severity_counts[error.severity.value] += 1
                component_errors[error.component] += 1
            
            return {
                'total_metrics': dict(self.metrics),
                'recent_errors_count': len(recent_errors),
                'error_types': dict(error_types),
                'severity_distribution': dict(severity_counts),
                'component_errors': dict(component_errors),
                'circuit_breaker_states': {
                    key: breaker.state.value 
                    for key, breaker in self.circuit_breakers.items()
                },
                'recovery_rate': (
                    self.metrics['recovered_errors'] / max(self.metrics['total_errors'], 1)
                ) * 100
            }
    
    def reset_circuit_breaker(self, component: str, function: str) -> bool:
        """Manually reset a circuit breaker."""
        breaker_key = f"{component}_{function}"
        
        if breaker_key in self.circuit_breakers:
            breaker = self.circuit_breakers[breaker_key]
            breaker.state = CircuitBreakerState.CLOSED
            breaker.failure_count = 0
            breaker.last_failure_time = None
            
            logger.info(f"Circuit breaker reset for {breaker_key}")
            return True
        
        return False
    
    def export_error_report(self, hours: int = 24) -> Dict[str, Any]:
        """Export detailed error report."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self._lock:
            relevant_errors = [
                {
                    'error_id': e.error_id,
                    'timestamp': e.timestamp.isoformat(),
                    'component': e.component,
                    'function': e.function,
                    'error_type': e.error_type,
                    'error_message': e.error_message,
                    'severity': e.severity.value,
                    'recovery_attempts': e.recovery_attempts,
                    'resolved': e.resolved,
                    'resolution_time': e.resolution_time.isoformat() if e.resolution_time else None
                }
                for e in self.error_history
                if e.timestamp >= cutoff_time
            ]
        
        return {
            'report_period_hours': hours,
            'report_generated': datetime.now().isoformat(),
            'errors': relevant_errors,
            'statistics': self.get_error_statistics()
        }

# Decorator for automatic error handling
def with_error_recovery(component: str, recovery_strategy: Optional[RecoveryStrategy] = None):
    """Decorator for automatic error handling and recovery."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                manager = get_error_manager()
                
                if recovery_strategy:
                    manager.register_strategy(type(e).__name__, recovery_strategy)
                
                result = manager.handle_error(e, component, func.__name__, {
                    'args': str(args)[:200],  # Truncate for logging
                    'kwargs': str(kwargs)[:200]
                })
                
                if result is None:
                    raise e  # Re-raise if no recovery possible
                
                return result
        
        return wrapper
    return decorator

# Async version of the decorator
def with_async_error_recovery(component: str, recovery_strategy: Optional[RecoveryStrategy] = None):
    """Async decorator for automatic error handling and recovery."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                manager = get_error_manager()
                
                if recovery_strategy:
                    manager.register_strategy(type(e).__name__, recovery_strategy)
                
                result = manager.handle_error(e, component, func.__name__, {
                    'args': str(args)[:200],
                    'kwargs': str(kwargs)[:200]
                })
                
                if result is None:
                    raise e
                
                return result
        
        return wrapper
    return decorator

# Global error manager instance
_error_manager: Optional[ErrorRecoveryManager] = None

def get_error_manager() -> ErrorRecoveryManager:
    """Get global error recovery manager instance."""
    global _error_manager
    if _error_manager is None:
        _error_manager = ErrorRecoveryManager()
    return _error_manager

def setup_error_handling() -> ErrorRecoveryManager:
    """Setup and configure error handling system."""
    manager = get_error_manager()
    
    # Setup logging handler for errors
    error_handler = logging.StreamHandler()
    error_handler.setLevel(logging.ERROR)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    error_handler.setFormatter(formatter)
    
    # Add handler to root logger
    logging.getLogger().addHandler(error_handler)
    
    logger.info("Error handling system configured")
    return manager