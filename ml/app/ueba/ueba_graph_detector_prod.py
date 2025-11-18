"""
UEBA Graph-Based Anomaly Detection
User and Entity Behavior Analytics using graph-relational models
Detects privilege escalation, insider threats, anomalous access patterns
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque
import threading

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.covariance import EllipticEnvelope

logger = logging.getLogger(__name__)


class UserRiskLevel(str, Enum):
    """User risk classifications"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnomalyType(str, Enum):
    """Types of detected anomalies"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    ANOMALOUS_ACCESS = "anomalous_access"
    UNUSUAL_SCHEDULE = "unusual_schedule"
    MASS_ACCESS = "mass_access"
    SUSPICIOUS_ELEVATION = "suspicious_elevation"


@dataclass
class UserProfile:
    """User behavior baseline"""
    user_id: str
    username: str
    
    # Behavioral baseline
    typical_hosts: Set[str] = field(default_factory=set)
    typical_times: Set[int] = field(default_factory=set)  # Hours of day
    typical_apps: Set[str] = field(default_factory=set)
    typical_access_level: int = 0  # 1-10 scale
    
    # Risk indicators
    privilege_level: int = 0  # 0=user, 1=admin, 2=system
    is_admin: bool = False
    is_service_account: bool = False
    
    # Statistics
    activity_count: int = 0
    last_activity: datetime = field(default_factory=datetime.now)
    
    # Baseline confidence
    baseline_established: bool = False
    baseline_activities_required: int = 100


@dataclass
class UserActivity:
    """User activity record"""
    activity_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    activity_type: str = ""  # login, file_access, resource_access, privilege_change, etc.
    
    timestamp: datetime = field(default_factory=datetime.now)
    source_host: str = ""
    target_host: str = ""
    target_resource: str = ""
    
    # Activity details
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Flags
    requires_authentication: bool = False
    is_interactive: bool = False


@dataclass
class AnomalyDetection:
    """Anomaly detection result"""
    anomaly_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.ANOMALOUS_ACCESS
    
    # Scoring
    anomaly_score: float = 0.0  # 0-1.0
    confidence: float = 0.0  # 0-1.0
    
    # Explanation
    indicators: List[str] = field(default_factory=list)
    description: str = ""
    
    # Risk assessment
    risk_level: UserRiskLevel = UserRiskLevel.LOW
    
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class GraphRelationship:
    """Relationship in entity graph"""
    source_id: str
    source_type: str  # user, resource, host, etc.
    target_id: str
    target_type: str
    relationship_type: str
    
    # Metrics
    frequency: int = 1
    last_interaction: datetime = field(default_factory=datetime.now)
    is_normal: bool = True


class UserEntityGraphBuilder:
    """Build relationship graph for UEBA"""
    
    def __init__(self):
        self.user_profiles = {}  # user_id -> UserProfile
        self.resources = {}  # resource_id -> resource metadata
        self.hosts = {}  # host_id -> host metadata
        self.relationships = defaultdict(list)  # (source, target) -> [relationships]
        self.lock = threading.RLock()
    
    def add_user(self, user_id: str, username: str, 
                 privilege_level: int = 0, is_admin: bool = False) -> UserProfile:
        """Add or get user profile"""
        with self.lock:
            if user_id not in self.user_profiles:
                profile = UserProfile(
                    user_id=user_id,
                    username=username,
                    privilege_level=privilege_level,
                    is_admin=is_admin
                )
                self.user_profiles[user_id] = profile
                logger.debug(f"Added user profile: {username}")
                return profile
            return self.user_profiles[user_id]
    
    def add_resource(self, resource_id: str, resource_type: str, 
                    sensitivity: int = 5) -> None:
        """Add resource (file, DB, etc.)"""
        with self.lock:
            self.resources[resource_id] = {
                "type": resource_type,
                "sensitivity": sensitivity,  # 1-10 scale
                "accessed_by": set()
            }
    
    def add_host(self, host_id: str, host_type: str) -> None:
        """Add host"""
        with self.lock:
            self.hosts[host_id] = {
                "type": host_type,
                "users_logged_in": set(),
                "risk_score": 0.0
            }
    
    def add_activity(self, user_id: str, activity: UserActivity) -> None:
        """Record user activity"""
        with self.lock:
            if user_id in self.user_profiles:
                profile = self.user_profiles[user_id]
                profile.activity_count += 1
                profile.last_activity = datetime.now()
                
                # Update behavioral baseline
                if activity.source_host:
                    profile.typical_hosts.add(activity.source_host)
                
                profile.typical_times.add(activity.timestamp.hour)
                
                if activity.target_resource:
                    profile.typical_apps.add(activity.target_resource)
                
                # Check baseline
                if profile.activity_count >= profile.baseline_activities_required:
                    profile.baseline_established = True
    
    def add_relationship(self, source_id: str, source_type: str,
                        target_id: str, target_type: str,
                        rel_type: str) -> None:
        """Add entity relationship"""
        with self.lock:
            key = (source_id, target_id)
            
            # Check if exists
            for rel in self.relationships[key]:
                if rel.relationship_type == rel_type:
                    rel.frequency += 1
                    rel.last_interaction = datetime.now()
                    return
            
            # Create new relationship
            rel = GraphRelationship(
                source_id=source_id,
                source_type=source_type,
                target_id=target_id,
                target_type=target_type,
                relationship_type=rel_type
            )
            self.relationships[key].append(rel)
    
    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile"""
        with self.lock:
            return self.user_profiles.get(user_id)
    
    def get_outbound_relationships(self, entity_id: str) -> List[GraphRelationship]:
        """Get relationships from entity"""
        with self.lock:
            result = []
            for (src, _), rels in self.relationships.items():
                if src == entity_id:
                    result.extend(rels)
            return result
    
    def get_inbound_relationships(self, entity_id: str) -> List[GraphRelationship]:
        """Get relationships to entity"""
        with self.lock:
            result = []
            for (_, tgt), rels in self.relationships.items():
                if tgt == entity_id:
                    result.extend(rels)
            return result


class BehavioralFeatureExtractor:
    """Extract features for anomaly detection"""
    
    def __init__(self, graph: UserEntityGraphBuilder):
        self.graph = graph
    
    def extract_features(self, user_id: str, activity: UserActivity) -> np.ndarray:
        """Extract 18 features for UEBA anomaly detection"""
        features = []
        profile = self.graph.get_user_profile(user_id)
        
        if not profile:
            return np.zeros(18, dtype=np.float32)
        
        # 1. Baseline deviation (0=matches, 1=deviates)
        if profile.baseline_established:
            host_match = 1.0 if activity.source_host in profile.typical_hosts else 0.0
            features.append(1.0 - host_match)
        else:
            features.append(0.5)
        
        # 2. Time anomaly (0-1.0)
        hour_match = 1.0 if activity.timestamp.hour in profile.typical_times else 0.0
        features.append(1.0 - hour_match)
        
        # 3. Privilege level change
        features.append(1.0 if profile.privilege_level > 0 and activity.activity_type == "privilege_change" else 0.0)
        
        # 4. New host access
        features.append(1.0 if activity.source_host not in profile.typical_hosts else 0.0)
        
        # 5. New resource access
        features.append(1.0 if activity.target_resource not in profile.typical_apps else 0.0)
        
        # 6. Sensitive resource access
        sensitive = activity.details.get("resource_sensitivity", 5)
        features.append(min(1.0, sensitive / 10.0))
        
        # 7. Rapid-fire access (batch)
        features.append(1.0 if activity.details.get("batch_access", False) else 0.0)
        
        # 8. Authentication type change
        auth_type = activity.details.get("auth_method", "normal")
        features.append(1.0 if auth_type in ["mfa_bypass", "compromised", "brute_force"] else 0.0)
        
        # 9. Geographic anomaly
        features.append(activity.details.get("geographic_anomaly", 0.0))
        
        # 10. Cross-domain access
        features.append(1.0 if activity.details.get("cross_domain", False) else 0.0)
        
        # 11-18. Additional context
        features.extend([
            1.0 if activity.activity_type == "lateral_movement" else 0.0,  # 11
            1.0 if activity.is_interactive else 0.0,  # 12
            1.0 if profile.is_admin else 0.5,  # 13
            1.0 if profile.is_service_account else 0.0,  # 14
            activity.details.get("data_volume", 0.0) / 1000.0,  # 15 (normalized)
            1.0 if activity.activity_type == "logout" else 0.0,  # 16
            profile.activity_count / 1000.0,  # 17 (activity rate)
            1.0 if activity.details.get("vpn_access", False) else 0.0,  # 18
        ])
        
        return np.array(features, dtype=np.float32)


class UEBAGraphAnomalyDetector:
    """Main UEBA anomaly detection engine"""
    
    def __init__(self):
        self.graph = UserEntityGraphBuilder()
        self.feature_extractor = BehavioralFeatureExtractor(self.graph)
        
        # ML models
        self.isolation_forest = IsolationForest(
            contamination=0.05, 
            random_state=42
        )
        self.elliptic_envelope = EllipticEnvelope(random_state=42)
        self.scaler = StandardScaler()
        
        self.models_trained = False
        self.activity_buffer = deque(maxlen=10000)
        self.detected_anomalies = deque(maxlen=1000)
        self.lock = threading.RLock()
    
    async def record_activity(self, user_id: str, activity: UserActivity) -> None:
        """Record user activity"""
        self.graph.add_activity(user_id, activity)
        
        with self.lock:
            self.activity_buffer.append((user_id, activity))
    
    async def detect_anomalies(self, user_id: str, activity: UserActivity) -> List[AnomalyDetection]:
        """Detect anomalies for activity"""
        anomalies = []
        
        # Feature extraction
        features = self.feature_extractor.extract_features(user_id, activity)
        
        # Rule-based detection
        rule_anomalies = self._rule_based_detection(user_id, activity)
        anomalies.extend(rule_anomalies)
        
        # ML-based detection
        if self.models_trained:
            ml_anomalies = self._ml_based_detection(user_id, features, activity)
            anomalies.extend(ml_anomalies)
        
        with self.lock:
            for anomaly in anomalies:
                self.detected_anomalies.append(anomaly)
        
        return anomalies
    
    def _rule_based_detection(self, user_id: str, activity: UserActivity) -> List[AnomalyDetection]:
        """Rule-based anomaly detection"""
        anomalies = []
        profile = self.graph.get_user_profile(user_id)
        
        if not profile:
            return anomalies
        
        # Privilege escalation
        if activity.activity_type == "privilege_change" and profile.privilege_level == 0:
            anomalies.append(AnomalyDetection(
                user_id=user_id,
                anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                anomaly_score=0.95,
                confidence=0.9,
                risk_level=UserRiskLevel.CRITICAL,
                indicators=["Non-admin user attempted privilege escalation", 
                           "Unexpected privilege level change"]
            ))
        
        # Lateral movement
        if activity.activity_type == "lateral_movement":
            anomalies.append(AnomalyDetection(
                user_id=user_id,
                anomaly_type=AnomalyType.LATERAL_MOVEMENT,
                anomaly_score=0.8,
                confidence=0.85,
                risk_level=UserRiskLevel.HIGH,
                indicators=["Cross-host movement detected",
                           "Potential lateral movement chain"]
            ))
        
        # Mass access (data exfiltration indicator)
        batch_count = activity.details.get("batch_access_count", 0)
        if batch_count > 50:
            anomalies.append(AnomalyDetection(
                user_id=user_id,
                anomaly_type=AnomalyType.DATA_EXFILTRATION,
                anomaly_score=0.85,
                confidence=0.8,
                risk_level=UserRiskLevel.HIGH,
                indicators=[f"Mass access pattern: {batch_count} resources in short time",
                           "Potential data exfiltration"]
            ))
        
        # Time anomaly (off-hours)
        hour = activity.timestamp.hour
        if hour < 2 or hour > 23:
            if profile.baseline_established and hour not in profile.typical_times:
                anomalies.append(AnomalyDetection(
                    user_id=user_id,
                    anomaly_type=AnomalyType.UNUSUAL_SCHEDULE,
                    anomaly_score=0.6,
                    confidence=0.7,
                    risk_level=UserRiskLevel.MEDIUM,
                    indicators=[f"Activity at unusual time: {hour}:00",
                               "Off-hours activity detected"]
                ))
        
        # New host
        if activity.source_host not in profile.typical_hosts:
            anomalies.append(AnomalyDetection(
                user_id=user_id,
                anomaly_type=AnomalyType.ANOMALOUS_ACCESS,
                anomaly_score=0.65,
                confidence=0.75,
                risk_level=UserRiskLevel.MEDIUM,
                indicators=[f"Access from new host: {activity.source_host}",
                           "New access pattern"]
            ))
        
        return anomalies
    
    def _ml_based_detection(self, user_id: str, features: np.ndarray, 
                           activity: UserActivity) -> List[AnomalyDetection]:
        """ML-based anomaly detection"""
        anomalies = []
        
        try:
            # Isolation Forest
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            if_score = self.isolation_forest.score_samples(features_scaled)[0]
            if_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            # Elliptic Envelope
            ee_score = self.elliptic_envelope.score_samples(features_scaled)[0]
            ee_anomaly = self.elliptic_envelope.predict(features_scaled)[0] == -1
            
            # Consensus
            if if_anomaly and ee_anomaly:
                score = min(1.0, abs(if_score) + abs(ee_score) / 2)
                
                anomalies.append(AnomalyDetection(
                    user_id=user_id,
                    anomaly_type=AnomalyType.ANOMALOUS_ACCESS,
                    anomaly_score=score,
                    confidence=0.8,
                    risk_level=UserRiskLevel.MEDIUM if score < 0.7 else UserRiskLevel.HIGH,
                    indicators=["ML model detected behavioral anomaly",
                               "Feature deviation from baseline"]
                ))
        except Exception as e:
            logger.debug(f"ML detection error: {e}")
        
        return anomalies
    
    async def train_models(self, min_samples: int = 100) -> Dict[str, float]:
        """Train anomaly detection models"""
        with self.lock:
            if len(self.activity_buffer) < min_samples:
                logger.info(f"Insufficient data: {len(self.activity_buffer)} < {min_samples}")
                return {"trained": False, "samples": len(self.activity_buffer)}
            
            # Extract features from buffer
            features_list = []
            for user_id, activity in self.activity_buffer:
                features = self.feature_extractor.extract_features(user_id, activity)
                features_list.append(features)
            
            X = np.array(features_list)
            X_scaled = self.scaler.fit_transform(X)
            
            # Train models
            self.isolation_forest.fit(X_scaled)
            self.elliptic_envelope.fit(X_scaled)
            self.models_trained = True
        
        logger.info("UEBA models trained successfully")
        return {"trained": True, "samples": len(self.activity_buffer)}
    
    async def detect_insider_threat(self, user_id: str) -> Optional[AnomalyDetection]:
        """Detect insider threat patterns"""
        profile = self.graph.get_user_profile(user_id)
        if not profile:
            return None
        
        # Insider threat indicators
        score = 0.0
        indicators = []
        
        # Long tenure, high privileges
        if profile.is_admin and profile.activity_count > 10000:
            score += 0.3
            indicators.append("High-privilege admin account")
        
        # Mass resource access
        outbound = self.graph.get_outbound_relationships(user_id)
        if len(outbound) > 50:
            score += 0.3
            indicators.append(f"Access to many resources: {len(outbound)}")
        
        # Off-hours activity
        recent_hour = datetime.now().hour
        if recent_hour not in profile.typical_times:
            score += 0.2
            indicators.append("Off-hours activity pattern")
        
        if score > 0.5:
            return AnomalyDetection(
                user_id=user_id,
                anomaly_type=AnomalyType.INSIDER_THREAT,
                anomaly_score=min(1.0, score),
                confidence=0.75,
                risk_level=UserRiskLevel.HIGH,
                indicators=indicators,
                description=f"Potential insider threat detected for {profile.username}"
            )
        
        return None
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get UEBA statistics"""
        with self.lock:
            num_users = len(self.graph.user_profiles)
            num_resources = len(self.graph.resources)
            num_hosts = len(self.graph.hosts)
            num_anomalies = len(self.detected_anomalies)
        
        return {
            "users_tracked": num_users,
            "resources_monitored": num_resources,
            "hosts_discovered": num_hosts,
            "anomalies_detected": num_anomalies,
            "models_trained": self.models_trained
        }


# Global instance
_ueba_instance = None


def get_ueba_detector() -> UEBAGraphAnomalyDetector:
    """Get or create UEBA detector"""
    global _ueba_instance
    if _ueba_instance is None:
        _ueba_instance = UEBAGraphAnomalyDetector()
    return _ueba_instance
