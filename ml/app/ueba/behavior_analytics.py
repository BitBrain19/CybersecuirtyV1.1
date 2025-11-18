#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
User and Entity Behavior Analytics (UEBA) module.

This module provides:
- User behavior profiling
- Entity behavior profiling
- Anomaly detection based on behavioral patterns
- Baseline establishment and deviation tracking
- Risk scoring for users and entities
- Integration with existing ML models
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple, Set
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
from ..core.exceptions import SecurityAIException
from ..streaming.real_time_detector import StreamEvent, ThreatLevel


class EntityType(Enum):
    """Types of entities tracked in UEBA."""
    USER = "user"
    DEVICE = "device"
    APPLICATION = "application"
    NETWORK = "network"
    RESOURCE = "resource"


class BehaviorCategory(Enum):
    """Categories of behavior patterns."""
    AUTHENTICATION = "authentication"
    ACCESS_PATTERN = "access_pattern"
    NETWORK_ACTIVITY = "network_activity"
    RESOURCE_USAGE = "resource_usage"
    DATA_TRANSFER = "data_transfer"
    COMMAND_EXECUTION = "command_execution"
    TEMPORAL_PATTERN = "temporal_pattern"
    LOCATION_PATTERN = "location_pattern"


@dataclass
class BehaviorEvent:
    """Represents a single behavior event for UEBA analysis."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    entity_id: str = ""
    entity_type: EntityType = EntityType.USER
    category: BehaviorCategory = BehaviorCategory.AUTHENTICATION
    action: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorProfile:
    """Profile of normal behavior for an entity."""
    entity_id: str
    entity_type: EntityType
    last_updated: datetime = field(default_factory=datetime.now)
    features: Dict[str, Any] = field(default_factory=dict)
    patterns: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    anomalies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BehaviorAnomaly:
    """Detected anomaly in entity behavior."""
    # Non-defaults must precede defaults for dataclass compatibility
    entity_id: str
    entity_type: EntityType
    category: BehaviorCategory
    severity: float  # 0.0 to 1.0
    description: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    evidence: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    related_events: List[str] = field(default_factory=list)


class BehaviorFeatureExtractor:
    """Extracts behavioral features from events."""
    
    def __init__(self):
        self.feature_extractors = {
            BehaviorCategory.AUTHENTICATION: self._extract_authentication_features,
            BehaviorCategory.ACCESS_PATTERN: self._extract_access_pattern_features,
            BehaviorCategory.NETWORK_ACTIVITY: self._extract_network_activity_features,
            BehaviorCategory.RESOURCE_USAGE: self._extract_resource_usage_features,
            BehaviorCategory.DATA_TRANSFER: self._extract_data_transfer_features,
            BehaviorCategory.COMMAND_EXECUTION: self._extract_command_execution_features,
            BehaviorCategory.TEMPORAL_PATTERN: self._extract_temporal_pattern_features,
            BehaviorCategory.LOCATION_PATTERN: self._extract_location_pattern_features,
        }
    
    def extract_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from a behavior event."""
        extractor = self.feature_extractors.get(event.category)
        if not extractor:
            app_logger.warning(f"No feature extractor for category: {event.category}")
            return {}
        
        try:
            return extractor(event)
        except Exception as e:
            app_logger.error(f"Error extracting features: {e}", error=e)
            return {}
    
    def _extract_authentication_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from authentication events."""
        features = {}
        ctx = event.context
        
        # Extract authentication method
        if "method" in ctx:
            features["auth_method"] = ctx["method"]
        
        # Extract success/failure
        if "success" in ctx:
            features["auth_success"] = ctx["success"]
        
        # Extract location information
        if "ip_address" in ctx:
            features["ip_address"] = ctx["ip_address"]
        if "location" in ctx:
            features["location"] = ctx["location"]
        
        # Extract device information
        if "device_id" in ctx:
            features["device_id"] = ctx["device_id"]
        if "user_agent" in ctx:
            features["user_agent"] = ctx["user_agent"]
        
        # Extract time features
        features["hour_of_day"] = event.timestamp.hour
        features["day_of_week"] = event.timestamp.weekday()
        
        return features
    
    def _extract_access_pattern_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from access pattern events."""
        features = {}
        ctx = event.context
        
        # Extract resource information
        if "resource_id" in ctx:
            features["resource_id"] = ctx["resource_id"]
        if "resource_type" in ctx:
            features["resource_type"] = ctx["resource_type"]
        
        # Extract access type
        if "access_type" in ctx:
            features["access_type"] = ctx["access_type"]
        
        # Extract time features
        features["hour_of_day"] = event.timestamp.hour
        features["day_of_week"] = event.timestamp.weekday()
        
        return features
    
    def _extract_network_activity_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from network activity events."""
        features = {}
        ctx = event.context
        
        # Extract network information
        if "source_ip" in ctx:
            features["source_ip"] = ctx["source_ip"]
        if "destination_ip" in ctx:
            features["destination_ip"] = ctx["destination_ip"]
        if "protocol" in ctx:
            features["protocol"] = ctx["protocol"]
        if "port" in ctx:
            features["port"] = ctx["port"]
        
        # Extract volume information
        if "bytes_sent" in ctx:
            features["bytes_sent"] = ctx["bytes_sent"]
        if "bytes_received" in ctx:
            features["bytes_received"] = ctx["bytes_received"]
        
        return features
    
    def _extract_resource_usage_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from resource usage events."""
        features = {}
        ctx = event.context
        
        # Extract resource metrics
        if "cpu_usage" in ctx:
            features["cpu_usage"] = ctx["cpu_usage"]
        if "memory_usage" in ctx:
            features["memory_usage"] = ctx["memory_usage"]
        if "disk_io" in ctx:
            features["disk_io"] = ctx["disk_io"]
        if "network_io" in ctx:
            features["network_io"] = ctx["network_io"]
        
        return features
    
    def _extract_data_transfer_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from data transfer events."""
        features = {}
        ctx = event.context
        
        # Extract transfer information
        if "source" in ctx:
            features["source"] = ctx["source"]
        if "destination" in ctx:
            features["destination"] = ctx["destination"]
        if "data_type" in ctx:
            features["data_type"] = ctx["data_type"]
        if "volume" in ctx:
            features["volume"] = ctx["volume"]
        
        return features
    
    def _extract_command_execution_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from command execution events."""
        features = {}
        ctx = event.context
        
        # Extract command information
        if "command" in ctx:
            features["command"] = ctx["command"]
        if "arguments" in ctx:
            features["arguments"] = ctx["arguments"]
        if "working_directory" in ctx:
            features["working_directory"] = ctx["working_directory"]
        if "exit_code" in ctx:
            features["exit_code"] = ctx["exit_code"]
        
        return features
    
    def _extract_temporal_pattern_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from temporal pattern events."""
        features = {}
        
        # Extract time features
        features["hour_of_day"] = event.timestamp.hour
        features["day_of_week"] = event.timestamp.weekday()
        features["is_weekend"] = event.timestamp.weekday() >= 5  # 5=Saturday, 6=Sunday
        features["is_business_hours"] = 9 <= event.timestamp.hour < 17  # 9 AM to 5 PM
        
        return features
    
    def _extract_location_pattern_features(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Extract features from location pattern events."""
        features = {}
        ctx = event.context
        
        # Extract location information
        if "ip_address" in ctx:
            features["ip_address"] = ctx["ip_address"]
        if "country" in ctx:
            features["country"] = ctx["country"]
        if "city" in ctx:
            features["city"] = ctx["city"]
        if "coordinates" in ctx:
            features["coordinates"] = ctx["coordinates"]
        
        return features


class BehaviorProfiler:
    """Builds and maintains behavior profiles for entities."""
    
    def __init__(self):
        self.profiles: Dict[str, BehaviorProfile] = {}
        self.feature_extractor = BehaviorFeatureExtractor()
        self.event_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._lock = threading.Lock()
    
    def get_profile(self, entity_id: str, entity_type: EntityType) -> BehaviorProfile:
        """Get or create a behavior profile for an entity."""
        profile_key = f"{entity_type.value}:{entity_id}"
        
        with self._lock:
            if profile_key not in self.profiles:
                self.profiles[profile_key] = BehaviorProfile(
                    entity_id=entity_id,
                    entity_type=entity_type
                )
            
            return self.profiles[profile_key]
    
    def update_profile(self, event: BehaviorEvent):
        """Update a behavior profile based on a new event."""
        profile = self.get_profile(event.entity_id, event.entity_type)
        profile_key = f"{event.entity_type.value}:{event.entity_id}"
        
        # Extract features
        features = self.feature_extractor.extract_features(event)
        
        # Add event to history
        with self._lock:
            self.event_history[profile_key].append((event, features))
            
            # Update profile features
            self._update_profile_features(profile, features, event.category)
            
            # Update profile patterns
            self._update_profile_patterns(profile, event.category)
            
            # Update last updated timestamp
            profile.last_updated = datetime.now()
    
    def _update_profile_features(self, profile: BehaviorProfile, features: Dict[str, Any], category: BehaviorCategory):
        """Update profile features with new event features."""
        category_key = category.value
        
        # Initialize category if not exists
        if category_key not in profile.features:
            profile.features[category_key] = {}
        
        # Update features
        for key, value in features.items():
            feature_key = f"{category_key}.{key}"
            
            # Handle different feature types differently
            if isinstance(value, (int, float)):
                # For numeric values, maintain running average
                if feature_key not in profile.features[category_key]:
                    profile.features[category_key][key] = {
                        "count": 1,
                        "mean": value,
                        "min": value,
                        "max": value,
                        "variance": 0.0
                    }
                else:
                    stats = profile.features[category_key][key]
                    old_mean = stats["mean"]
                    old_count = stats["count"]
                    new_count = old_count + 1
                    
                    # Update mean using Welford's online algorithm
                    new_mean = old_mean + (value - old_mean) / new_count
                    new_variance = stats["variance"] + (value - old_mean) * (value - new_mean)
                    
                    stats["count"] = new_count
                    stats["mean"] = new_mean
                    stats["min"] = min(stats["min"], value)
                    stats["max"] = max(stats["max"], value)
                    
                    if new_count > 1:
                        stats["variance"] = new_variance / (new_count - 1)
            
            elif isinstance(value, str):
                # For categorical values, maintain frequency counts
                if feature_key not in profile.features[category_key]:
                    profile.features[category_key][key] = {"values": {}}
                
                if "values" not in profile.features[category_key][key]:
                    profile.features[category_key][key]["values"] = {}
                
                values_dict = profile.features[category_key][key]["values"]
                values_dict[value] = values_dict.get(value, 0) + 1
            
            elif isinstance(value, bool):
                # For boolean values, track true/false counts
                if feature_key not in profile.features[category_key]:
                    profile.features[category_key][key] = {"true": 0, "false": 0}
                
                if value:
                    profile.features[category_key][key]["true"] += 1
                else:
                    profile.features[category_key][key]["false"] += 1
    
    def _update_profile_patterns(self, profile: BehaviorProfile, category: BehaviorCategory):
        """Update behavioral patterns in the profile."""
        category_key = category.value
        
        # Initialize category if not exists
        if category_key not in profile.patterns:
            profile.patterns[category_key] = {}
        
        # Get events for this entity
        profile_key = f"{profile.entity_type.value}:{profile.entity_id}"
        events = self.event_history.get(profile_key, [])
        
        # Skip if not enough events
        if len(events) < 10:
            return
        
        # Update temporal patterns
        if category == BehaviorCategory.TEMPORAL_PATTERN or category == BehaviorCategory.AUTHENTICATION:
            self._update_temporal_patterns(profile, category_key, events)
        
        # Update location patterns
        if category == BehaviorCategory.LOCATION_PATTERN or category == BehaviorCategory.AUTHENTICATION:
            self._update_location_patterns(profile, category_key, events)
    
    def _update_temporal_patterns(self, profile: BehaviorProfile, category_key: str, events):
        """Update temporal patterns in the profile."""
        # Initialize temporal patterns
        if "temporal" not in profile.patterns[category_key]:
            profile.patterns[category_key]["temporal"] = {
                "hour_distribution": [0] * 24,
                "day_distribution": [0] * 7,
                "business_hours_ratio": 0.0,
                "weekend_ratio": 0.0
            }
        
        # Count events by hour and day
        hour_counts = [0] * 24
        day_counts = [0] * 7
        business_hours_count = 0
        weekend_count = 0
        total_count = 0
        
        for event, _ in events:
            if not hasattr(event, "timestamp"):
                continue
                
            hour = event.timestamp.hour
            day = event.timestamp.weekday()
            
            hour_counts[hour] += 1
            day_counts[day] += 1
            
            if 9 <= hour < 17:  # 9 AM to 5 PM
                business_hours_count += 1
            
            if day >= 5:  # 5=Saturday, 6=Sunday
                weekend_count += 1
            
            total_count += 1
        
        if total_count > 0:
            # Update patterns
            profile.patterns[category_key]["temporal"]["hour_distribution"] = [
                count / total_count for count in hour_counts
            ]
            profile.patterns[category_key]["temporal"]["day_distribution"] = [
                count / total_count for count in day_counts
            ]
            profile.patterns[category_key]["temporal"]["business_hours_ratio"] = (
                business_hours_count / total_count
            )
            profile.patterns[category_key]["temporal"]["weekend_ratio"] = (
                weekend_count / total_count
            )
    
    def _update_location_patterns(self, profile: BehaviorProfile, category_key: str, events):
        """Update location patterns in the profile."""
        # Initialize location patterns
        if "location" not in profile.patterns[category_key]:
            profile.patterns[category_key]["location"] = {
                "ip_addresses": {},
                "countries": {},
                "cities": {}
            }
        
        # Count events by location
        ip_counts = {}
        country_counts = {}
        city_counts = {}
        
        for event, features in events:
            if "ip_address" in features:
                ip = features["ip_address"]
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            if "country" in features:
                country = features["country"]
                country_counts[country] = country_counts.get(country, 0) + 1
            
            if "city" in features:
                city = features["city"]
                city_counts[city] = city_counts.get(city, 0) + 1
        
        # Update patterns
        profile.patterns[category_key]["location"]["ip_addresses"] = ip_counts
        profile.patterns[category_key]["location"]["countries"] = country_counts
        profile.patterns[category_key]["location"]["cities"] = city_counts


class BehaviorAnomalyDetector:
    """Detects anomalies in entity behavior."""
    
    def __init__(self, profiler: BehaviorProfiler):
        self.profiler = profiler
        self.anomaly_thresholds = {
            BehaviorCategory.AUTHENTICATION: 0.8,
            BehaviorCategory.ACCESS_PATTERN: 0.7,
            BehaviorCategory.NETWORK_ACTIVITY: 0.75,
            BehaviorCategory.RESOURCE_USAGE: 0.85,
            BehaviorCategory.DATA_TRANSFER: 0.8,
            BehaviorCategory.COMMAND_EXECUTION: 0.75,
            BehaviorCategory.TEMPORAL_PATTERN: 0.9,
            BehaviorCategory.LOCATION_PATTERN: 0.85
        }
    
    def detect_anomalies(self, event: BehaviorEvent) -> List[BehaviorAnomaly]:
        """Detect anomalies in an event compared to the entity's profile."""
        profile = self.profiler.get_profile(event.entity_id, event.entity_type)
        features = self.profiler.feature_extractor.extract_features(event)
        anomalies = []
        
        # Skip if profile is too new (not enough data)
        profile_key = f"{event.entity_type.value}:{event.entity_id}"
        if len(self.profiler.event_history.get(profile_key, [])) < 10:
            return anomalies
        
        # Check for anomalies based on category
        if event.category == BehaviorCategory.AUTHENTICATION:
            auth_anomalies = self._detect_authentication_anomalies(event, profile, features)
            anomalies.extend(auth_anomalies)
        
        elif event.category == BehaviorCategory.ACCESS_PATTERN:
            access_anomalies = self._detect_access_pattern_anomalies(event, profile, features)
            anomalies.extend(access_anomalies)
        
        elif event.category == BehaviorCategory.NETWORK_ACTIVITY:
            network_anomalies = self._detect_network_activity_anomalies(event, profile, features)
            anomalies.extend(network_anomalies)
        
        elif event.category == BehaviorCategory.TEMPORAL_PATTERN:
            temporal_anomalies = self._detect_temporal_pattern_anomalies(event, profile, features)
            anomalies.extend(temporal_anomalies)
        
        elif event.category == BehaviorCategory.LOCATION_PATTERN:
            location_anomalies = self._detect_location_pattern_anomalies(event, profile, features)
            anomalies.extend(location_anomalies)
        
        # Update risk score if anomalies found
        if anomalies:
            self._update_risk_score(profile, anomalies)
        
        return anomalies
    
    def _detect_authentication_anomalies(self, event: BehaviorEvent, profile: BehaviorProfile, 
                                        features: Dict[str, Any]) -> List[BehaviorAnomaly]:
        """Detect anomalies in authentication events."""
        anomalies = []
        category_key = BehaviorCategory.AUTHENTICATION.value
        
        # Skip if no authentication features in profile
        if category_key not in profile.features:
            return anomalies
        
        # Check for unusual authentication method
        if "auth_method" in features:
            method = features["auth_method"]
            if "auth_method" in profile.features[category_key]:
                method_stats = profile.features[category_key]["auth_method"]
                if "values" in method_stats and method in method_stats["values"]:
                    # Calculate frequency of this method
                    total_auths = sum(method_stats["values"].values())
                    method_freq = method_stats["values"].get(method, 0) / total_auths
                    
                    # If method is rare (< 5% of authentications)
                    if method_freq < 0.05:
                        anomalies.append(BehaviorAnomaly(
                            entity_id=event.entity_id,
                            entity_type=event.entity_type,
                            category=event.category,
                            severity=0.7,
                            description=f"Unusual authentication method: {method}",
                            evidence={"method": method, "frequency": method_freq},
                            related_events=[event.id]
                        ))
        
        # Check for authentication outside normal hours
        if "hour_of_day" in features and "temporal" in profile.patterns.get(category_key, {}):
            hour = features["hour_of_day"]
            hour_dist = profile.patterns[category_key]["temporal"]["hour_distribution"]
            
            # If activity at this hour is rare (< 2% of authentications)
            if hour_dist[hour] < 0.02:
                anomalies.append(BehaviorAnomaly(
                    entity_id=event.entity_id,
                    entity_type=event.entity_type,
                    category=event.category,
                    severity=0.8,
                    description=f"Authentication at unusual hour: {hour}:00",
                    evidence={"hour": hour, "normal_distribution": hour_dist},
                    related_events=[event.id]
                ))
        
        # Check for authentication from unusual location
        if "ip_address" in features and "location" in profile.patterns.get(category_key, {}):
            ip = features["ip_address"]
            ip_addresses = profile.patterns[category_key]["location"]["ip_addresses"]
            
            # If IP has never been seen before
            if ip not in ip_addresses:
                anomalies.append(BehaviorAnomaly(
                    entity_id=event.entity_id,
                    entity_type=event.entity_type,
                    category=event.category,
                    severity=0.9,
                    description=f"Authentication from new IP address: {ip}",
                    evidence={"ip_address": ip},
                    related_events=[event.id]
                ))
        
        return anomalies
    
    def _detect_access_pattern_anomalies(self, event: BehaviorEvent, profile: BehaviorProfile, 
                                        features: Dict[str, Any]) -> List[BehaviorAnomaly]:
        """Detect anomalies in access pattern events."""
        anomalies = []
        category_key = BehaviorCategory.ACCESS_PATTERN.value
        
        # Skip if no access pattern features in profile
        if category_key not in profile.features:
            return anomalies
        
        # Check for access to unusual resource
        if "resource_id" in features:
            resource_id = features["resource_id"]
            if "resource_id" in profile.features[category_key]:
                resource_stats = profile.features[category_key]["resource_id"]
                if "values" in resource_stats and resource_id not in resource_stats["values"]:
                    anomalies.append(BehaviorAnomaly(
                        entity_id=event.entity_id,
                        entity_type=event.entity_type,
                        category=event.category,
                        severity=0.75,
                        description=f"Access to new resource: {resource_id}",
                        evidence={"resource_id": resource_id},
                        related_events=[event.id]
                    ))
        
        # Check for unusual access type
        if "access_type" in features:
            access_type = features["access_type"]
            if "access_type" in profile.features[category_key]:
                access_stats = profile.features[category_key]["access_type"]
                if "values" in access_stats:
                    # If this access type has never been used before
                    if access_type not in access_stats["values"]:
                        anomalies.append(BehaviorAnomaly(
                            entity_id=event.entity_id,
                            entity_type=event.entity_type,
                            category=event.category,
                            severity=0.8,
                            description=f"Unusual access type: {access_type}",
                            evidence={"access_type": access_type},
                            related_events=[event.id]
                        ))
        
        return anomalies
    
    def _detect_network_activity_anomalies(self, event: BehaviorEvent, profile: BehaviorProfile, 
                                          features: Dict[str, Any]) -> List[BehaviorAnomaly]:
        """Detect anomalies in network activity events."""
        anomalies = []
        category_key = BehaviorCategory.NETWORK_ACTIVITY.value
        
        # Skip if no network activity features in profile
        if category_key not in profile.features:
            return anomalies
        
        # Check for unusual destination
        if "destination_ip" in features:
            dest_ip = features["destination_ip"]
            if "destination_ip" in profile.features[category_key]:
                dest_stats = profile.features[category_key]["destination_ip"]
                if "values" in dest_stats and dest_ip not in dest_stats["values"]:
                    anomalies.append(BehaviorAnomaly(
                        entity_id=event.entity_id,
                        entity_type=event.entity_type,
                        category=event.category,
                        severity=0.7,
                        description=f"Connection to new destination: {dest_ip}",
                        evidence={"destination_ip": dest_ip},
                        related_events=[event.id]
                    ))
        
        # Check for unusual data volume
        if "bytes_sent" in features and "bytes_sent" in profile.features[category_key]:
            bytes_sent = features["bytes_sent"]
            stats = profile.features[category_key]["bytes_sent"]
            
            # If bytes sent is more than 3 standard deviations from mean
            if "mean" in stats and "variance" in stats:
                mean = stats["mean"]
                std_dev = np.sqrt(stats["variance"])
                
                if std_dev > 0 and (bytes_sent - mean) / std_dev > 3:
                    anomalies.append(BehaviorAnomaly(
                        entity_id=event.entity_id,
                        entity_type=event.entity_type,
                        category=event.category,
                        severity=0.85,
                        description=f"Unusually large data transfer: {bytes_sent} bytes",
                        evidence={
                            "bytes_sent": bytes_sent,
                            "mean": mean,
                            "std_dev": std_dev,
                            "z_score": (bytes_sent - mean) / std_dev
                        },
                        related_events=[event.id]
                    ))
        
        return anomalies
    
    def _detect_temporal_pattern_anomalies(self, event: BehaviorEvent, profile: BehaviorProfile, 
                                          features: Dict[str, Any]) -> List[BehaviorAnomaly]:
        """Detect anomalies in temporal patterns."""
        anomalies = []
        category_key = BehaviorCategory.TEMPORAL_PATTERN.value
        
        # Skip if no temporal patterns in profile
        if category_key not in profile.patterns or "temporal" not in profile.patterns[category_key]:
            return anomalies
        
        # Check for activity outside normal hours
        if "hour_of_day" in features:
            hour = features["hour_of_day"]
            hour_dist = profile.patterns[category_key]["temporal"]["hour_distribution"]
            
            # If activity at this hour is rare (< 1% of activity)
            if hour_dist[hour] < 0.01:
                anomalies.append(BehaviorAnomaly(
                    entity_id=event.entity_id,
                    entity_type=event.entity_type,
                    category=event.category,
                    severity=0.75,
                    description=f"Activity at unusual hour: {hour}:00",
                    evidence={"hour": hour, "normal_distribution": hour_dist},
                    related_events=[event.id]
                ))
        
        # Check for weekend activity for users who don't normally work weekends
        if "is_weekend" in features and features["is_weekend"]:
            weekend_ratio = profile.patterns[category_key]["temporal"]["weekend_ratio"]
            
            # If user rarely works on weekends (< 5% of activity)
            if weekend_ratio < 0.05:
                anomalies.append(BehaviorAnomaly(
                    entity_id=event.entity_id,
                    entity_type=event.entity_type,
                    category=event.category,
                    severity=0.8,
                    description="Unusual weekend activity",
                    evidence={"weekend_ratio": weekend_ratio},
                    related_events=[event.id]
                ))
        
        return anomalies
    
    def _detect_location_pattern_anomalies(self, event: BehaviorEvent, profile: BehaviorProfile, 
                                          features: Dict[str, Any]) -> List[BehaviorAnomaly]:
        """Detect anomalies in location patterns."""
        anomalies = []
        category_key = BehaviorCategory.LOCATION_PATTERN.value
        
        # Skip if no location patterns in profile
        if category_key not in profile.patterns or "location" not in profile.patterns[category_key]:
            return anomalies
        
        # Check for activity from new country
        if "country" in features:
            country = features["country"]
            countries = profile.patterns[category_key]["location"]["countries"]
            
            # If country has never been seen before
            if country not in countries:
                anomalies.append(BehaviorAnomaly(
                    entity_id=event.entity_id,
                    entity_type=event.entity_type,
                    category=event.category,
                    severity=0.9,
                    description=f"Activity from new country: {country}",
                    evidence={"country": country},
                    related_events=[event.id]
                ))
        
        # Check for activity from new city
        if "city" in features:
            city = features["city"]
            cities = profile.patterns[category_key]["location"]["cities"]
            
            # If city has never been seen before
            if city not in cities:
                anomalies.append(BehaviorAnomaly(
                    entity_id=event.entity_id,
                    entity_type=event.entity_type,
                    category=event.category,
                    severity=0.7,
                    description=f"Activity from new city: {city}",
                    evidence={"city": city},
                    related_events=[event.id]
                ))
        
        return anomalies
    
    def _update_risk_score(self, profile: BehaviorProfile, anomalies: List[BehaviorAnomaly]):
        """Update risk score based on detected anomalies."""
        # Calculate new risk score based on anomaly severities
        max_severity = max([a.severity for a in anomalies]) if anomalies else 0.0
        avg_severity = np.mean([a.severity for a in anomalies]) if anomalies else 0.0
        
        # Blend max and average with decay of old score
        old_score = profile.risk_score
        new_score = 0.7 * max_severity + 0.3 * avg_severity
        
        # Apply exponential decay to old score (half-life of ~24 hours)
        decay_factor = 0.97
        hours_since_update = (datetime.now() - profile.last_updated).total_seconds() / 3600
        decayed_old_score = old_score * (decay_factor ** hours_since_update)
        
        # Blend old and new scores
        profile.risk_score = max(0.8 * decayed_old_score, new_score)
        
        # Cap at 1.0
        profile.risk_score = min(profile.risk_score, 1.0)
        
        # Add anomalies to profile
        for anomaly in anomalies:
            profile.anomalies.append({
                "id": anomaly.id,
                "timestamp": anomaly.timestamp,
                "category": anomaly.category.value,
                "severity": anomaly.severity,
                "description": anomaly.description
            })
            
            # Keep only the 20 most recent anomalies
            if len(profile.anomalies) > 20:
                profile.anomalies.sort(key=lambda x: x["timestamp"], reverse=True)
                profile.anomalies = profile.anomalies[:20]


class UEBAService:
    """User and Entity Behavior Analytics service."""
    
    def __init__(self):
        self.is_running = False
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.profiler = BehaviorProfiler()
        self.anomaly_detector = BehaviorAnomalyDetector(self.profiler)
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._lock = threading.Lock()
    
    async def start(self):
        """Start the UEBA service."""
        if self.is_running:
            app_logger.warning("UEBA service is already running")
            return
        
        self.is_running = True
        app_logger.info("Starting User and Entity Behavior Analytics service")
        
        # Start processing tasks
        tasks = [
            asyncio.create_task(self._process_events()),
            asyncio.create_task(self._monitor_performance())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            app_logger.error(f"Error in UEBA service: {e}", error=e)
        finally:
            self.is_running = False
    
    async def stop(self):
        """Stop the UEBA service."""
        app_logger.info("Stopping User and Entity Behavior Analytics service")
        self.is_running = False
        self.executor.shutdown(wait=True)
    
    async def add_event(self, event: BehaviorEvent):
        """Add an event to the processing queue."""
        try:
            await self.event_queue.put(event)
            metrics_collector.ueba_events_received.inc()
        except asyncio.QueueFull:
            app_logger.warning("UEBA event queue is full, dropping event")
            metrics_collector.ueba_events_dropped.inc()
    
    async def _process_events(self):
        """Process events from the queue."""
        while self.is_running:
            try:
                # Get event from queue
                event = await self.event_queue.get()
                
                # Process event in thread pool
                start_time = time.time()
                await asyncio.get_event_loop().run_in_executor(
                    self.executor, self._process_single_event, event
                )
                
                # Update metrics
                processing_time = (time.time() - start_time) * 1000  # ms
                metrics_collector.ueba_processing_time.observe(processing_time)
                
                # Mark task as done
                self.event_queue.task_done()
            
            except Exception as e:
                app_logger.error(f"Error processing UEBA event: {e}", error=e)
                metrics_collector.ueba_processing_errors.inc()
    
    def _process_single_event(self, event: BehaviorEvent):
        """Process a single behavior event."""
        try:
            # Update profile with event
            self.profiler.update_profile(event)
            
            # Detect anomalies
            anomalies = self.anomaly_detector.detect_anomalies(event)
            
            # Handle detected anomalies
            if anomalies:
                self._handle_anomalies(event, anomalies)
            
            # Update metrics
            with self._lock:
                metrics_collector.ueba_events_processed.inc()
                if anomalies:
                    metrics_collector.ueba_anomalies_detected.inc(len(anomalies))
        
        except Exception as e:
            app_logger.error(f"Error in UEBA event processing: {e}", error=e)
            metrics_collector.ueba_processing_errors.inc()
    
    def _handle_anomalies(self, event: BehaviorEvent, anomalies: List[BehaviorAnomaly]):
        """Handle detected anomalies."""
        for anomaly in anomalies:
            # Log security event for high-severity anomalies
            if anomaly.severity >= 0.7:
                severity = AlertSeverity.MEDIUM
                if anomaly.severity >= 0.9:
                    severity = AlertSeverity.CRITICAL
                elif anomaly.severity >= 0.8:
                    severity = AlertSeverity.HIGH
                
                # Log security event
                log_security_event(
                    event_type="ueba_anomaly_detected",
                    severity=severity,
                    source=f"{event.entity_type.value}:{event.entity_id}",
                    details={
                        "anomaly_id": anomaly.id,
                        "description": anomaly.description,
                        "category": anomaly.category.value,
                        "severity": anomaly.severity,
                        "evidence": anomaly.evidence,
                        "context": anomaly.context,
                        "related_events": anomaly.related_events
                    }
                )
            
            # Create alert for critical anomalies
            if anomaly.severity >= 0.85:
                create_alert(
                    title=f"UEBA: {anomaly.description}",
                    description=f"Anomalous behavior detected for {event.entity_type.value} '{event.entity_id}'.",
                    severity=AlertSeverity.HIGH if anomaly.severity >= 0.9 else AlertSeverity.MEDIUM,
                    source=f"ueba:{event.entity_type.value}:{event.entity_id}",
                    tags={"type": "ueba_anomaly"},
                    metadata={
                        "anomaly_id": anomaly.id,
                        "entity_id": event.entity_id,
                        "entity_type": event.entity_type.value,
                        "category": anomaly.category.value,
                        "severity": anomaly.severity,
                        "description": anomaly.description,
                        "evidence": anomaly.evidence,
                        "context": anomaly.context,
                        "related_events": anomaly.related_events
                    }
                )
    
    async def _monitor_performance(self):
        """Monitor performance of the UEBA service."""
        while self.is_running:
            try:
                # Log queue size
                queue_size = self.event_queue.qsize()
                metrics_collector.ueba_queue_size.set(queue_size)
                
                if queue_size > 1000:
                    app_logger.warning(f"UEBA event queue is large: {queue_size} events")
                
                # Sleep for monitoring interval
                await asyncio.sleep(10)
            
            except Exception as e:
                app_logger.error(f"Error monitoring UEBA performance: {e}", error=e)
                await asyncio.sleep(30)  # Sleep longer on error


# Create singleton instance
ueba_service = UEBAService()