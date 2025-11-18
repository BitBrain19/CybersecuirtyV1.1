"""
XDR AI Correlation Engine
Multi-source log fusion and cross-layer detection
Evidence graph builder and alert deduplication
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DataSource(str, Enum):
    """Data sources for XDR"""
    EDR = "edr"
    SIEM = "siem"
    NETWORK = "network"
    EMAIL = "email"
    CLOUD = "cloud"
    DNS = "dns"
    FIREWALL = "firewall"
    PROXY = "proxy"


@dataclass
class AlertEvent:
    """Alert from any source"""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: DataSource = DataSource.EDR
    
    timestamp: datetime = field(default_factory=datetime.now)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    # Core information
    title: str = ""
    description: str = ""
    
    # Entity context
    source_host: str = ""
    source_user: str = ""
    target_resource: str = ""
    
    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # Tracking
    is_deduplicated: bool = False
    parent_incident_id: str = ""


@dataclass
class CorrelationEvidence:
    """Evidence linking related alerts"""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_ids: List[str] = field(default_factory=list)
    
    # Correlation metrics
    correlation_score: float = 0.0
    temporal_proximity: float = 0.0  # 0-1.0, how close in time
    entity_overlap: float = 0.0      # 0-1.0, how much entity overlap
    
    # Description
    correlation_type: str = ""  # e.g., "same_user", "same_host", "attack_chain"
    
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class IncidentGraph:
    """Graph of correlated alerts and evidence"""
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    alerts: List[AlertEvent] = field(default_factory=list)
    evidence_links: List[CorrelationEvidence] = field(default_factory=list)
    
    # Severity aggregation
    max_severity: AlertSeverity = AlertSeverity.LOW
    composite_severity: AlertSeverity = AlertSeverity.LOW
    
    # Timeline
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)
    
    # Metadata
    affected_entities: Set[str] = field(default_factory=set)
    attack_techniques: List[str] = field(default_factory=list)
    
    # Deduplication info
    is_duplicate_of: str = ""
    confidence: float = 0.0


class AlertDeduplicator:
    """Deduplicate similar alerts"""
    
    def __init__(self):
        self.alert_fingerprints = {}  # fingerprint -> original_alert
        self.similarity_threshold = 0.85
    
    def generate_fingerprint(self, alert: AlertEvent) -> str:
        """Generate fingerprint for alert"""
        # Normalize key fields
        key_parts = [
            alert.title.lower(),
            alert.source_host.lower(),
            alert.source_user.lower(),
            alert.source.value,
            str(alert.severity)
        ]
        
        import hashlib
        key_str = "|".join(key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def calculate_similarity(self, alert1: AlertEvent, alert2: AlertEvent) -> float:
        """Calculate alert similarity (0-1.0)"""
        score = 0.0
        
        # Title similarity
        if alert1.title.lower() == alert2.title.lower():
            score += 0.3
        
        # Host match
        if alert1.source_host == alert2.source_host:
            score += 0.2
        
        # User match
        if alert1.source_user == alert2.source_user:
            score += 0.2
        
        # Severity match
        if alert1.severity == alert2.severity:
            score += 0.1
        
        # Source match
        if alert1.source == alert2.source:
            score += 0.2
        
        return float(min(1.0, score))
    
    def is_duplicate(self, new_alert: AlertEvent, 
                     existing_alerts: List[AlertEvent]) -> Tuple[bool, Optional[AlertEvent]]:
        """Check if alert is duplicate"""
        for existing in existing_alerts:
            similarity = self.calculate_similarity(new_alert, existing)
            
            # Also check time proximity (within 5 minutes)
            time_diff = abs((new_alert.timestamp - existing.timestamp).total_seconds())
            
            if similarity > self.similarity_threshold and time_diff < 300:
                return True, existing
        
        return False, None


class CorrelationEngine:
    """Correlate alerts across sources"""
    
    def __init__(self):
        self.deduplicator = AlertDeduplicator()
        self.scaler = StandardScaler()
        self.classifier = None
        self.trained = False
    
    def extract_alert_features(self, alert: AlertEvent) -> np.ndarray:
        """Extract 15 features from alert"""
        features = []
        
        # 1. Severity encoding (0-1.0)
        severity_map = {
            AlertSeverity.CRITICAL: 1.0,
            AlertSeverity.HIGH: 0.75,
            AlertSeverity.MEDIUM: 0.5,
            AlertSeverity.LOW: 0.25,
            AlertSeverity.INFO: 0.1
        }
        features.append(severity_map.get(alert.severity, 0.5))
        
        # 2. Source type encoding
        source_risk = {
            DataSource.EDR: 0.9,
            DataSource.SIEM: 0.7,
            DataSource.NETWORK: 0.6,
            DataSource.EMAIL: 0.8,
            DataSource.CLOUD: 0.7,
            DataSource.DNS: 0.5,
            DataSource.FIREWALL: 0.6,
            DataSource.PROXY: 0.5
        }
        features.append(source_risk.get(alert.source, 0.5))
        
        # 3. Entity specificity
        entity_score = 0.0
        if alert.source_host:
            entity_score += 0.33
        if alert.source_user:
            entity_score += 0.33
        if alert.target_resource:
            entity_score += 0.34
        features.append(entity_score)
        
        # 4. Title suspicion
        title_score = self._score_title(alert.title)
        features.append(title_score)
        
        # 5. Hour of day (0-23)
        features.append(alert.timestamp.hour / 24.0)
        
        # 6. Day of week (0-6)
        features.append(alert.timestamp.weekday() / 7.0)
        
        # 7. Raw data richness
        raw_fields = len(alert.raw_data)
        features.append(min(1.0, raw_fields / 20.0))
        
        # 8-15. Additional features
        features.extend([
            1.0 if "attack" in alert.title.lower() else 0.0,
            1.0 if "malware" in alert.title.lower() else 0.0,
            1.0 if "exploit" in alert.title.lower() else 0.0,
            1.0 if "phishing" in alert.title.lower() else 0.0,
            1.0 if "privilege" in alert.title.lower() else 0.0,
            1.0 if "lateral" in alert.title.lower() else 0.0,
            1.0 if "exfiltration" in alert.title.lower() else 0.0,
            1.0 if "c2" in alert.title.lower() or "c&c" in alert.title.lower() else 0.0,
        ])
        
        return np.array(features, dtype=np.float32)
    
    def _score_title(self, title: str) -> float:
        """Score title for suspicion"""
        suspicious_keywords = [
            "malware", "attack", "exploit", "backdoor", "trojan",
            "ransomware", "phishing", "injection", "privilege",
            "lateral", "exfiltration", "c2", "payload"
        ]
        
        score = 0.0
        for keyword in suspicious_keywords:
            if keyword in title.lower():
                score += 0.1
        
        return float(min(1.0, score))
    
    def correlate_alerts(self, alert1: AlertEvent, alert2: AlertEvent) -> CorrelationEvidence:
        """Correlate two alerts"""
        # Temporal proximity
        time_diff = abs((alert1.timestamp - alert2.timestamp).total_seconds())
        temporal_proximity = max(0.0, 1.0 - (time_diff / 3600.0))  # 1 hour window
        
        # Entity overlap
        entities1 = {alert1.source_host, alert1.source_user, alert1.target_resource}
        entities2 = {alert2.source_host, alert2.source_user, alert2.target_resource}
        
        common_entities = len(entities1 & entities2)
        total_entities = len(entities1 | entities2)
        entity_overlap = common_entities / total_entities if total_entities > 0 else 0.0
        
        # Correlation score
        correlation_score = (temporal_proximity * 0.4 + entity_overlap * 0.6)
        
        # Determine correlation type
        correlation_type = self._determine_correlation_type(alert1, alert2)
        
        return CorrelationEvidence(
            alert_ids=[alert1.alert_id, alert2.alert_id],
            correlation_score=float(correlation_score),
            temporal_proximity=float(temporal_proximity),
            entity_overlap=float(entity_overlap),
            correlation_type=correlation_type
        )
    
    def _determine_correlation_type(self, alert1: AlertEvent, alert2: AlertEvent) -> str:
        """Determine type of correlation"""
        if alert1.source_host == alert2.source_host:
            return "same_host"
        elif alert1.source_user == alert2.source_user:
            return "same_user"
        elif alert1.target_resource == alert2.target_resource:
            return "same_resource"
        else:
            return "potential_attack_chain"
    
    def train_correlation_model(self, alerts: List[AlertEvent]):
        """Train alert correlation classifier"""
        if len(alerts) < 10:
            logger.warning("Insufficient alerts for training")
            return
        
        # Extract features
        X = np.array([self.extract_alert_features(a) for a in alerts])
        
        # Create labels (correlated=1, isolated=0)
        y = np.array([1 if len(a.title) > 20 else 0 for a in alerts])
        
        # Normalize
        X_scaled = self.scaler.fit_transform(X)
        
        # Train
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.classifier.fit(X_scaled, y)
        self.trained = True
        
        logger.info("Alert correlation model trained")


class XDRCorrelationEngine:
    """Main XDR correlation engine"""
    
    def __init__(self):
        self.correlation_engine = CorrelationEngine()
        self.deduplicator = AlertDeduplicator()
        
        self.alert_buffer = deque(maxlen=50000)
        self.incidents = {}  # incident_id -> IncidentGraph
        self.incident_queue = deque()
        
        self.lock = threading.RLock()
    
    async def ingest_alert(self, alert: AlertEvent) -> Tuple[bool, Optional[str]]:
        """Ingest alert from any source"""
        with self.lock:
            # Check for duplicates
            is_dup, original = self.deduplicator.is_duplicate(
                alert, list(self.alert_buffer)[-100:]  # Check last 100
            )
            
            if is_dup and original:
                alert.is_deduplicated = True
                alert.parent_incident_id = original.alert_id
                logger.debug(f"Alert {alert.alert_id} deduplicated")
                return False, original.alert_id
            
            self.alert_buffer.append(alert)
            logger.info(f"Ingested alert from {alert.source.value}: {alert.title}")
        
        return True, alert.alert_id
    
    async def correlate_and_incident(self, time_window: int = 300) -> List[IncidentGraph]:
        """Correlate alerts and build incidents"""
        incidents = []
        
        with self.lock:
            # Get recent alerts
            now = datetime.now()
            recent_alerts = [a for a in self.alert_buffer
                           if (now - a.timestamp).total_seconds() < time_window]
        
        if len(recent_alerts) < 2:
            return incidents
        
        # Group into incident graphs
        processed = set()
        
        for i, alert1 in enumerate(recent_alerts):
            if alert1.alert_id in processed:
                continue
            
            # Create new incident
            incident = IncidentGraph()
            incident.alerts.append(alert1)
            incident.max_severity = alert1.severity
            incident.start_time = alert1.timestamp
            incident.affected_entities.add(alert1.source_host)
            incident.affected_entities.add(alert1.source_user)
            
            processed.add(alert1.alert_id)
            
            # Find correlated alerts
            for j, alert2 in enumerate(recent_alerts[i+1:], i+1):
                if alert2.alert_id in processed:
                    continue
                
                evidence = self.correlation_engine.correlate_alerts(alert1, alert2)
                
                if evidence.correlation_score > 0.6:
                    incident.alerts.append(alert2)
                    incident.evidence_links.append(evidence)
                    incident.affected_entities.add(alert2.source_host)
                    incident.affected_entities.add(alert2.source_user)
                    
                    # Update severity
                    if alert2.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
                        incident.max_severity = alert2.severity
                    
                    incident.end_time = max(incident.end_time, alert2.timestamp)
                    processed.add(alert2.alert_id)
            
            # Calculate composite severity
            incident.composite_severity = self._calculate_composite_severity(incident)
            incident.confidence = len(incident.evidence_links) / (len(incident.alerts) + 1)
            
            incidents.append(incident)
            
            with self.lock:
                self.incidents[incident.incident_id] = incident
        
        logger.info(f"Correlated {len(recent_alerts)} alerts into {len(incidents)} incidents")
        return incidents
    
    def _calculate_composite_severity(self, incident: IncidentGraph) -> AlertSeverity:
        """Calculate incident severity from alerts"""
        severity_scores = {
            AlertSeverity.CRITICAL: 5,
            AlertSeverity.HIGH: 4,
            AlertSeverity.MEDIUM: 3,
            AlertSeverity.LOW: 2,
            AlertSeverity.INFO: 1
        }
        
        # Get max score
        max_score = max(
            (severity_scores.get(a.severity, 0) for a in incident.alerts),
            default=0
        )
        
        # Boost for multiple alerts of same source
        if len(incident.alerts) > 3:
            max_score = min(5, max_score + 1)
        
        # Convert back to enum
        for severity, score in severity_scores.items():
            if score >= max_score:
                return severity
        
        return AlertSeverity.MEDIUM
    
    async def build_evidence_graph(self, incident: IncidentGraph) -> Dict[str, Any]:
        """Build detailed evidence graph"""
        graph = {
            "incident_id": incident.incident_id,
            "alerts": len(incident.alerts),
            "evidence_links": len(incident.evidence_links),
            "affected_entities": list(incident.affected_entities),
            "timeline": {
                "start": incident.start_time.isoformat(),
                "end": incident.end_time.isoformat(),
                "duration_seconds": (incident.end_time - incident.start_time).total_seconds()
            },
            "severity": incident.composite_severity.value,
            "confidence": incident.confidence,
            "alert_sequence": []
        }
        
        # Build alert sequence
        sorted_alerts = sorted(incident.alerts, key=lambda a: a.timestamp)
        for alert in sorted_alerts:
            graph["alert_sequence"].append({
                "timestamp": alert.timestamp.isoformat(),
                "source": alert.source.value,
                "severity": alert.severity.value,
                "title": alert.title,
                "entities": {
                    "host": alert.source_host,
                    "user": alert.source_user,
                    "resource": alert.target_resource
                }
            })
        
        return graph
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get XDR engine statistics"""
        with self.lock:
            num_alerts = len(self.alert_buffer)
            num_incidents = len(self.incidents)
            num_dedup = sum(1 for a in self.alert_buffer if a.is_deduplicated)
        
        return {
            "alerts_processed": num_alerts,
            "incidents_detected": num_incidents,
            "alerts_deduplicated": num_dedup,
            "buffer_size": len(self.alert_buffer)
        }


# Global instance
_xdr_instance = None


def get_xdr_engine() -> XDRCorrelationEngine:
    """Get or create XDR engine"""
    global _xdr_instance
    if _xdr_instance is None:
        _xdr_instance = XDRCorrelationEngine()
    return _xdr_instance
