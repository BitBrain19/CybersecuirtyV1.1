#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Real-time threat detection streaming service.

This module provides:
- Continuous data stream processing
- Real-time threat detection
- Event-driven alerting
- Stream analytics and aggregation
- Adaptive threat scoring
- Integration with existing ML models
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Callable, AsyncGenerator
from datetime import datetime, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor

import numpy as np
from pydantic import BaseModel, Field

from ..core.config import settings
from ..core.logging_system import app_logger, create_alert, AlertSeverity, log_security_event
from ..core.model_manager import model_manager
from ..core.monitoring import metrics_collector
from ..core.exceptions import SecurityAIException, PredictionError


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StreamEventType(Enum):
    """Types of streaming events."""
    NETWORK_TRAFFIC = "network_traffic"
    SYSTEM_LOG = "system_log"
    USER_ACTIVITY = "user_activity"
    FILE_ACCESS = "file_access"
    PROCESS_EXECUTION = "process_execution"
    AUTHENTICATION = "authentication"


@dataclass
class StreamEvent:
    """Represents a single event in the data stream."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    event_type: StreamEventType = StreamEventType.NETWORK_TRAFFIC
    source: str = "unknown"
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatDetectionResult:
    """Result of threat detection analysis."""
    event_id: str
    threat_level: ThreatLevel
    confidence: float
    threat_type: str
    description: str
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    model_version: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


class StreamAnalytics:
    """Analytics and aggregation for streaming data."""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.event_buffer = deque(maxlen=window_size)
        self.threat_counts = defaultdict(int)
        self.source_stats = defaultdict(lambda: {"events": 0, "threats": 0})
        self.hourly_stats = defaultdict(lambda: {"events": 0, "threats": 0})
        self._lock = threading.Lock()
    
    def add_event(self, event: StreamEvent, threat_result: Optional[ThreatDetectionResult] = None):
        """Add event to analytics buffer."""
        with self._lock:
            self.event_buffer.append((event, threat_result))
            
            # Update source statistics
            self.source_stats[event.source]["events"] += 1
            if threat_result and threat_result.threat_level != ThreatLevel.LOW:
                self.source_stats[event.source]["threats"] += 1
                self.threat_counts[threat_result.threat_type] += 1
            
            # Update hourly statistics
            hour_key = event.timestamp.strftime("%Y-%m-%d-%H")
            self.hourly_stats[hour_key]["events"] += 1
            if threat_result and threat_result.threat_level != ThreatLevel.LOW:
                self.hourly_stats[hour_key]["threats"] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current analytics statistics."""
        with self._lock:
            total_events = len(self.event_buffer)
            total_threats = sum(1 for _, result in self.event_buffer 
                              if result and result.threat_level != ThreatLevel.LOW)
            
            return {
                "total_events": total_events,
                "total_threats": total_threats,
                "threat_rate": total_threats / max(total_events, 1),
                "threat_types": dict(self.threat_counts),
                "source_stats": dict(self.source_stats),
                "recent_events": total_events,
                "window_size": self.window_size
            }
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect anomalous patterns in the stream."""
        anomalies = []
        stats = self.get_statistics()
        
        # High threat rate anomaly
        if stats["threat_rate"] > 0.1:  # More than 10% threats
            anomalies.append({
                "type": "high_threat_rate",
                "severity": "high",
                "description": f"Threat rate is {stats['threat_rate']:.2%}, above normal threshold",
                "value": stats["threat_rate"]
            })
        
        # Source-based anomalies
        for source, source_stats in stats["source_stats"].items():
            if source_stats["events"] > 0:
                source_threat_rate = source_stats["threats"] / source_stats["events"]
                if source_threat_rate > 0.2:  # More than 20% threats from this source
                    anomalies.append({
                        "type": "suspicious_source",
                        "severity": "medium",
                        "description": f"Source {source} has high threat rate: {source_threat_rate:.2%}",
                        "source": source,
                        "value": source_threat_rate
                    })
        
        return anomalies


class AdaptiveThreatScorer:
    """Adaptive threat scoring based on historical patterns."""
    
    def __init__(self):
        self.baseline_scores = defaultdict(float)
        self.score_history = defaultdict(lambda: deque(maxlen=100))
        self.adaptation_rate = 0.1
        self._lock = threading.Lock()
    
    def update_baseline(self, threat_type: str, score: float):
        """Update baseline score for a threat type."""
        with self._lock:
            self.score_history[threat_type].append(score)
            
            # Calculate moving average
            if len(self.score_history[threat_type]) > 10:
                recent_avg = np.mean(list(self.score_history[threat_type])[-10:])
                self.baseline_scores[threat_type] = (
                    (1 - self.adaptation_rate) * self.baseline_scores[threat_type] +
                    self.adaptation_rate * recent_avg
                )
    
    def get_adaptive_score(self, threat_type: str, base_score: float) -> float:
        """Get adaptive score based on historical patterns."""
        with self._lock:
            baseline = self.baseline_scores.get(threat_type, 0.5)
            
            # Adjust score based on deviation from baseline
            if base_score > baseline * 1.5:  # Significantly higher than baseline
                return min(base_score * 1.2, 1.0)  # Boost score
            elif base_score < baseline * 0.5:  # Significantly lower than baseline
                return max(base_score * 0.8, 0.0)  # Reduce score
            
            return base_score


class RealTimeThreatDetector:
    """Real-time threat detection streaming service."""
    
    def __init__(self):
        self.is_running = False
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.result_callbacks: List[Callable[[ThreatDetectionResult], None]] = []
        self.analytics = StreamAnalytics()
        self.adaptive_scorer = AdaptiveThreatScorer()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.processing_stats = {
            "events_processed": 0,
            "threats_detected": 0,
            "processing_errors": 0,
            "avg_processing_time": 0.0
        }
        self._stats_lock = threading.Lock()
    
    async def start(self):
        """Start the real-time detection service."""
        if self.is_running:
            app_logger.warning("Real-time detector is already running")
            return
        
        self.is_running = True
        app_logger.info("Starting real-time threat detection service")
        
        # Start processing tasks
        tasks = [
            asyncio.create_task(self._process_events()),
            asyncio.create_task(self._monitor_performance()),
            asyncio.create_task(self._detect_anomalies())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            app_logger.error(f"Error in real-time detector: {e}", error=e)
        finally:
            self.is_running = False
    
    async def stop(self):
        """Stop the real-time detection service."""
        app_logger.info("Stopping real-time threat detection service")
        self.is_running = False
        self.executor.shutdown(wait=True)
    
    async def add_event(self, event: StreamEvent):
        """Add an event to the processing queue."""
        try:
            await self.event_queue.put(event)
            metrics_collector.stream_events_received.inc()
        except asyncio.QueueFull:
            app_logger.warning("Event queue is full, dropping event")
            metrics_collector.stream_events_dropped.inc()
    
    def add_result_callback(self, callback: Callable[[ThreatDetectionResult], None]):
        """Add a callback for threat detection results."""
        self.result_callbacks.append(callback)
    
    async def _process_events(self):
        """Main event processing loop."""
        while self.is_running:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Process event
                start_time = time.time()
                result = await self._analyze_event(event)
                processing_time = (time.time() - start_time) * 1000
                
                # Update statistics
                with self._stats_lock:
                    self.processing_stats["events_processed"] += 1
                    if result.threat_level != ThreatLevel.LOW:
                        self.processing_stats["threats_detected"] += 1
                    
                    # Update average processing time
                    current_avg = self.processing_stats["avg_processing_time"]
                    count = self.processing_stats["events_processed"]
                    self.processing_stats["avg_processing_time"] = (
                        (current_avg * (count - 1) + processing_time) / count
                    )
                
                # Add to analytics
                self.analytics.add_event(event, result)
                
                # Update adaptive scorer
                self.adaptive_scorer.update_baseline(result.threat_type, result.confidence)
                
                # Call result callbacks
                for callback in self.result_callbacks:
                    try:
                        callback(result)
                    except Exception as e:
                        app_logger.error(f"Error in result callback: {e}", error=e)
                
                # Update metrics
                metrics_collector.stream_events_processed.inc()
                metrics_collector.stream_processing_time.observe(processing_time / 1000)
                
                if result.threat_level != ThreatLevel.LOW:
                    metrics_collector.stream_threats_detected.labels(
                        threat_level=result.threat_level.value,
                        threat_type=result.threat_type
                    ).inc()
                
            except asyncio.TimeoutError:
                continue  # No events to process
            except Exception as e:
                app_logger.error(f"Error processing event: {e}", error=e)
                with self._stats_lock:
                    self.processing_stats["processing_errors"] += 1
    
    async def _analyze_event(self, event: StreamEvent) -> ThreatDetectionResult:
        """Analyze a single event for threats."""
        start_time = time.time()
        
        try:
            # Prepare features for ML model
            features = self._extract_features(event)
            
            # Get prediction from threat detection model
            prediction_result = await model_manager.predict(
                model_name="threat_detection",
                features=features,
                request_id=event.id
            )
            
            # Determine threat level and type
            threat_level, threat_type = self._classify_threat(
                prediction_result.prediction, 
                prediction_result.confidence
            )
            
            # Apply adaptive scoring
            adaptive_confidence = self.adaptive_scorer.get_adaptive_score(
                threat_type, prediction_result.confidence
            )
            
            # Generate description and recommendations
            description = self._generate_description(event, threat_type, adaptive_confidence)
            indicators = self._extract_indicators(event, threat_type)
            recommendations = self._generate_recommendations(threat_level, threat_type)
            
            processing_time = (time.time() - start_time) * 1000
            
            result = ThreatDetectionResult(
                event_id=event.id,
                threat_level=threat_level,
                confidence=adaptive_confidence,
                threat_type=threat_type,
                description=description,
                indicators=indicators,
                recommended_actions=recommendations,
                processing_time_ms=processing_time,
                model_version=prediction_result.model_version,
                metadata={
                    "event_type": event.event_type.value,
                    "source": event.source,
                    "original_confidence": prediction_result.confidence,
                    "adaptive_adjustment": adaptive_confidence - prediction_result.confidence
                }
            )
            
            # Log security events for high-severity threats
            if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                log_security_event(
                    event_type="threat_detected",
                    severity=threat_level.value,
                    description=description,
                    source_ip=event.data.get("source_ip", "unknown"),
                    user_id=event.data.get("user_id", "unknown"),
                    additional_data={
                        "threat_type": threat_type,
                        "confidence": adaptive_confidence,
                        "indicators": indicators
                    }
                )
                
                # Create alert for critical threats
                if threat_level == ThreatLevel.CRITICAL:
                    create_alert(
                        title=f"Critical Threat Detected: {threat_type}",
                        description=description,
                        severity=AlertSeverity.CRITICAL,
                        tags={
                            "threat_type": threat_type,
                            "source": event.source,
                            "confidence": str(adaptive_confidence)
                        }
                    )
            
            return result
            
        except Exception as e:
            app_logger.error(f"Error analyzing event {event.id}: {e}", error=e)
            
            # Return low-threat result for failed analysis
            return ThreatDetectionResult(
                event_id=event.id,
                threat_level=ThreatLevel.LOW,
                confidence=0.0,
                threat_type="analysis_error",
                description=f"Failed to analyze event: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                metadata={"error": str(e)}
            )
    
    def _extract_features(self, event: StreamEvent) -> Dict[str, Any]:
        """Extract features from event for ML model."""
        features = {
            "event_type": event.event_type.value,
            "source": event.source,
            "timestamp_hour": event.timestamp.hour,
            "timestamp_day_of_week": event.timestamp.weekday(),
        }
        
        # Add event-specific features
        if event.event_type == StreamEventType.NETWORK_TRAFFIC:
            features.update({
                "source_ip": event.data.get("source_ip", "0.0.0.0"),
                "destination_ip": event.data.get("destination_ip", "0.0.0.0"),
                "source_port": event.data.get("source_port", 0),
                "destination_port": event.data.get("destination_port", 0),
                "protocol": event.data.get("protocol", "unknown"),
                "packet_size": event.data.get("packet_size", 0),
                "flags": event.data.get("flags", "")
            })
        elif event.event_type == StreamEventType.AUTHENTICATION:
            features.update({
                "user_id": event.data.get("user_id", "unknown"),
                "auth_method": event.data.get("auth_method", "unknown"),
                "success": event.data.get("success", False),
                "source_ip": event.data.get("source_ip", "0.0.0.0")
            })
        
        # Add any additional data as features
        for key, value in event.data.items():
            if key not in features and isinstance(value, (int, float, str, bool)):
                features[key] = value
        
        return features
    
    def _classify_threat(self, prediction: Any, confidence: float) -> tuple[ThreatLevel, str]:
        """Classify threat level and type based on prediction."""
        # This is a simplified classification - in practice, this would be more sophisticated
        if isinstance(prediction, (int, float)):
            if prediction >= 0.9 and confidence >= 0.8:
                return ThreatLevel.CRITICAL, "high_confidence_threat"
            elif prediction >= 0.7 and confidence >= 0.6:
                return ThreatLevel.HIGH, "probable_threat"
            elif prediction >= 0.5 and confidence >= 0.4:
                return ThreatLevel.MEDIUM, "possible_threat"
            else:
                return ThreatLevel.LOW, "benign"
        elif isinstance(prediction, str):
            threat_mapping = {
                "malware": ThreatLevel.CRITICAL,
                "intrusion": ThreatLevel.HIGH,
                "suspicious": ThreatLevel.MEDIUM,
                "normal": ThreatLevel.LOW
            }
            return threat_mapping.get(prediction.lower(), ThreatLevel.LOW), prediction.lower()
        else:
            return ThreatLevel.LOW, "unknown"
    
    def _generate_description(self, event: StreamEvent, threat_type: str, confidence: float) -> str:
        """Generate human-readable threat description."""
        base_descriptions = {
            "high_confidence_threat": "High-confidence threat detected with strong indicators",
            "probable_threat": "Probable threat with multiple suspicious indicators",
            "possible_threat": "Possible threat requiring further investigation",
            "malware": "Malware activity detected",
            "intrusion": "Intrusion attempt identified",
            "suspicious": "Suspicious activity observed",
            "benign": "Normal activity, no threat detected"
        }
        
        base_desc = base_descriptions.get(threat_type, f"Threat type: {threat_type}")
        return f"{base_desc} (confidence: {confidence:.2%}) from {event.source}"
    
    def _extract_indicators(self, event: StreamEvent, threat_type: str) -> List[str]:
        """Extract threat indicators from event."""
        indicators = []
        
        if event.event_type == StreamEventType.NETWORK_TRAFFIC:
            if event.data.get("destination_port") in [22, 23, 3389]:  # SSH, Telnet, RDP
                indicators.append("Remote access port activity")
            if event.data.get("packet_size", 0) > 10000:
                indicators.append("Large packet size")
        
        if event.event_type == StreamEventType.AUTHENTICATION:
            if not event.data.get("success", True):
                indicators.append("Failed authentication attempt")
        
        # Add source-based indicators
        if "unknown" in event.source.lower():
            indicators.append("Unknown source")
        
        return indicators
    
    def _generate_recommendations(self, threat_level: ThreatLevel, threat_type: str) -> List[str]:
        """Generate recommended actions based on threat."""
        recommendations = []
        
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.extend([
                "Immediately isolate affected systems",
                "Activate incident response team",
                "Preserve forensic evidence",
                "Notify security operations center"
            ])
        elif threat_level == ThreatLevel.HIGH:
            recommendations.extend([
                "Investigate source and scope",
                "Implement additional monitoring",
                "Consider blocking suspicious sources",
                "Review security logs"
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Monitor for escalation",
                "Review related events",
                "Update threat intelligence"
            ])
        
        return recommendations
    
    async def _monitor_performance(self):
        """Monitor and report performance metrics."""
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                with self._stats_lock:
                    stats = self.processing_stats.copy()
                
                # Log performance metrics
                app_logger.info(
                    "Real-time detector performance",
                    events_processed=stats["events_processed"],
                    threats_detected=stats["threats_detected"],
                    processing_errors=stats["processing_errors"],
                    avg_processing_time_ms=stats["avg_processing_time"],
                    queue_size=self.event_queue.qsize()
                )
                
                # Check for performance issues
                if stats["avg_processing_time"] > 1000:  # More than 1 second
                    create_alert(
                        title="Slow Stream Processing",
                        description=f"Average processing time is {stats['avg_processing_time']:.1f}ms",
                        severity=AlertSeverity.MEDIUM,
                        tags={"component": "real_time_detector"}
                    )
                
                if self.event_queue.qsize() > 8000:  # Queue getting full
                    create_alert(
                        title="High Event Queue Size",
                        description=f"Event queue size is {self.event_queue.qsize()}",
                        severity=AlertSeverity.MEDIUM,
                        tags={"component": "real_time_detector"}
                    )
                
            except Exception as e:
                app_logger.error(f"Error in performance monitoring: {e}", error=e)
    
    async def _detect_anomalies(self):
        """Detect and report anomalies in the stream."""
        while self.is_running:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                anomalies = self.analytics.detect_anomalies()
                
                for anomaly in anomalies:
                    severity_mapping = {
                        "low": AlertSeverity.LOW,
                        "medium": AlertSeverity.MEDIUM,
                        "high": AlertSeverity.HIGH,
                        "critical": AlertSeverity.CRITICAL
                    }
                    
                    create_alert(
                        title=f"Stream Anomaly: {anomaly['type']}",
                        description=anomaly["description"],
                        severity=severity_mapping.get(anomaly["severity"], AlertSeverity.MEDIUM),
                        tags={
                            "component": "real_time_detector",
                            "anomaly_type": anomaly["type"]
                        }
                    )
                    
                    app_logger.warning(
                        f"Stream anomaly detected: {anomaly['type']}",
                        anomaly=anomaly
                    )
                
            except Exception as e:
                app_logger.error(f"Error in anomaly detection: {e}", error=e)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        with self._stats_lock:
            processing_stats = self.processing_stats.copy()
        
        analytics_stats = self.analytics.get_statistics()
        
        return {
            "processing": processing_stats,
            "analytics": analytics_stats,
            "queue_size": self.event_queue.qsize(),
            "is_running": self.is_running,
            "callbacks_registered": len(self.result_callbacks)
        }


# Global instance
real_time_detector = RealTimeThreatDetector()


# Convenience functions for external use
async def start_real_time_detection():
    """Start the real-time threat detection service."""
    await real_time_detector.start()


async def stop_real_time_detection():
    """Stop the real-time threat detection service."""
    await real_time_detector.stop()


async def submit_event(event_data: Dict[str, Any], event_type: StreamEventType = StreamEventType.NETWORK_TRAFFIC, source: str = "unknown"):
    """Submit an event for real-time analysis."""
    event = StreamEvent(
        event_type=event_type,
        source=source,
        data=event_data
    )
    await real_time_detector.add_event(event)


def add_threat_callback(callback: Callable[[ThreatDetectionResult], None]):
    """Add a callback for threat detection results."""
    real_time_detector.add_result_callback(callback)


def get_stream_statistics() -> Dict[str, Any]:
    """Get current streaming statistics."""
    return real_time_detector.get_statistics()