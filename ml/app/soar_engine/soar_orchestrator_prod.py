"""
AI-Driven SOAR Engine
ML-powered security orchestration and automated response
Playbook automation, action ranking, threat triage, root-cause analysis
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
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    """SOAR action types"""
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_USER = "quarantine_user"
    REVOKE_SESSION = "revoke_session"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    ESCALATE_INCIDENT = "escalate_incident"
    NOTIFY_SOC = "notify_soc"
    CAPTURE_MEMORY = "capture_memory"
    SNAPSHOT_DISK = "snapshot_disk"
    COLLECT_ARTIFACTS = "collect_artifacts"


class ActionPriority(str, Enum):
    """Action execution priority"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TriageLevel(str, Enum):
    """Incident triage levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PlaybookAction:
    """Action in a playbook"""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType = ActionType.NOTIFY_SOC
    
    # Parameters
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Execution
    status: str = "pending"  # pending, executing, success, failed
    confidence: float = 0.0  # Confidence in this action (0-1.0)
    
    # Timing
    created_at: datetime = field(default_factory=datetime.now)
    executed_at: Optional[datetime] = None
    
    # Outcome
    result: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""


@dataclass
class SecurityPlaybook:
    """Security playbook for automated response"""
    playbook_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    
    # Trigger
    trigger_type: str = ""  # e.g., "ransomware_detected", "privilege_escalation"
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Actions
    actions: List[PlaybookAction] = field(default_factory=list)
    
    # Metadata
    enabled: bool = True
    priority: ActionPriority = ActionPriority.MEDIUM
    
    # Performance
    success_rate: float = 0.0
    avg_execution_time: float = 0.0  # seconds
    
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class IncidentResponse:
    """Response to security incident"""
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    
    # Triage
    triage_level: TriageLevel = TriageLevel.MEDIUM
    triage_reasoning: str = ""
    
    # Root cause
    root_cause_hypothesis: str = ""
    root_cause_confidence: float = 0.0
    
    # Automated actions
    suggested_actions: List[PlaybookAction] = field(default_factory=list)
    executed_actions: List[PlaybookAction] = field(default_factory=list)
    
    # Results
    containment_status: str = "not_started"  # not_started, in_progress, contained, failed
    eradication_status: str = "pending"
    
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class IncidentContext:
    """Context for incident analysis"""
    incident_id: str
    incident_type: str
    severity: str
    
    # Entities involved
    affected_hosts: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    
    # Intelligence
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Evidence
    evidence_count: int = 0
    correlation_score: float = 0.0


class ActionRankingEngine:
    """ML-based action ranking"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.classifier = GradientBoostingClassifier(n_estimators=100)
        self.trained = False
    
    def extract_action_features(self, action: PlaybookAction, 
                               context: IncidentContext) -> np.ndarray:
        """Extract 16 features for action ranking"""
        features = []
        
        # 1. Action type severity
        severity_map = {
            ActionType.ISOLATE_HOST: 0.9,
            ActionType.DISABLE_ACCOUNT: 0.85,
            ActionType.KILL_PROCESS: 0.8,
            ActionType.BLOCK_IP: 0.7,
            ActionType.REVOKE_SESSION: 0.75,
            ActionType.QUARANTINE_USER: 0.8,
            ActionType.CAPTURE_MEMORY: 0.6,
            ActionType.ESCALATE_INCIDENT: 0.5,
            ActionType.NOTIFY_SOC: 0.3,
        }
        features.append(severity_map.get(action.action_type, 0.5))
        
        # 2. Incident severity
        severity_levels = {
            "critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1
        }
        features.append(severity_levels.get(context.severity, 0.5))
        
        # 3. Action confidence
        features.append(action.confidence)
        
        # 4. Evidence quality
        features.append(min(1.0, context.evidence_count / 10.0))
        
        # 5. Correlation strength
        features.append(context.correlation_score)
        
        # 6. Number of affected hosts (normalized)
        features.append(min(1.0, len(context.affected_hosts) / 10.0))
        
        # 7. Number of affected users
        features.append(min(1.0, len(context.affected_users) / 10.0))
        
        # 8. MITRE technique count
        features.append(min(1.0, len(context.mitre_techniques) / 10.0))
        
        # 9. Reversibility of action
        reversible_actions = {
            ActionType.NOTIFY_SOC, ActionType.ESCALATE_INCIDENT,
            ActionType.CAPTURE_MEMORY, ActionType.COLLECT_ARTIFACTS
        }
        features.append(1.0 if action.action_type in reversible_actions else 0.5)
        
        # 10. Speed impact
        speed_scores = {
            ActionType.NOTIFY_SOC: 0.1,
            ActionType.BLOCK_IP: 0.9,
            ActionType.ISOLATE_HOST: 0.95,
            ActionType.KILL_PROCESS: 0.8,
        }
        features.append(speed_scores.get(action.action_type, 0.5))
        
        # 11-16. Additional context features
        features.extend([
            1.0 if "ransomware" in context.incident_type.lower() else 0.0,
            1.0 if "lateral_movement" in context.mitre_techniques else 0.0,
            1.0 if "persistence" in context.incident_type.lower() else 0.0,
            1.0 if "exfiltration" in context.incident_type.lower() else 0.0,
            1.0 if len(context.affected_hosts) > 5 else 0.0,
            1.0 if context.correlation_score > 0.8 else 0.0,
        ])
        
        return np.array(features, dtype=np.float32)
    
    def rank_actions(self, actions: List[PlaybookAction],
                    context: IncidentContext) -> List[Tuple[PlaybookAction, float]]:
        """Rank actions by priority"""
        scores = []
        
        for action in actions:
            features = self.extract_action_features(action, context)
            
            # Get ML score if trained
            ml_score = 0.5
            if self.trained:
                try:
                    X_scaled = self.scaler.transform(features.reshape(1, -1))
                    ml_score = self.classifier.predict_proba(X_scaled)[0][1]
                except:
                    pass
            
            # Combine with action confidence
            final_score = (action.confidence * 0.4 + ml_score * 0.6)
            scores.append((action, float(final_score)))
        
        # Sort by score
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores
    
    def train(self, actions: List[PlaybookAction], outcomes: List[int]):
        """Train action ranking model"""
        if len(actions) < 10:
            return
        
        # Create dummy contexts
        contexts = [IncidentContext(
            incident_id=str(i),
            incident_type="security_incident",
            severity="high"
        ) for i in range(len(actions))]
        
        X = np.array([self.extract_action_features(a, c) 
                     for a, c in zip(actions, contexts)])
        y = np.array(outcomes)
        
        X_scaled = self.scaler.fit_transform(X)
        self.classifier.fit(X_scaled, y)
        self.trained = True
        logger.info("Action ranking model trained")


class RootCauseAnalyzer:
    """Analyze and determine root cause of incidents"""
    
    def __init__(self):
        self.cache = {}
    
    def analyze_root_cause(self, context: IncidentContext) -> Tuple[str, float]:
        """Determine root cause of incident"""
        hypotheses = []
        
        # Analyze MITRE techniques
        if "T1566" in context.mitre_techniques:  # Phishing
            hypotheses.append(("Phishing/Social Engineering", 0.9))
        
        if "T1110" in context.mitre_techniques:  # Brute Force
            hypotheses.append(("Weak Credentials/Brute Force", 0.85))
        
        if "T1548" in context.mitre_techniques:  # Privilege Escalation
            hypotheses.append(("Privilege Escalation Exploit", 0.8))
        
        if "T1570" in context.mitre_techniques:  # Lateral Movement
            hypotheses.append(("Lateral Movement Post-Compromise", 0.75))
        
        # Analyze indicators
        if any("malware" in ind.lower() for ind in context.indicators):
            hypotheses.append(("Malware Infection", 0.85))
        
        if any("c2" in ind.lower() or "c&c" in ind.lower() for ind in context.indicators):
            hypotheses.append(("C2 Communication/Compromise", 0.9))
        
        # Analyze affected resources
        if len(context.affected_hosts) > 3:
            hypotheses.append(("Lateral Movement/Worm", 0.8))
        
        if any("database" in res.lower() for res in context.affected_resources):
            hypotheses.append(("Database Compromise", 0.85))
        
        # Pick most likely
        if hypotheses:
            hypotheses.sort(key=lambda x: x[1], reverse=True)
            return hypotheses[0]
        
        return "Unknown/Insufficient Data", 0.3
    
    def generate_investigation_paths(self, context: IncidentContext) -> List[str]:
        """Suggest investigation paths"""
        paths = []
        
        # Investigate entry point
        paths.append("Identify initial compromise vector (phishing, exploit, brute force)")
        
        # Investigate scope
        paths.append("Determine full scope of compromise (all affected systems/users)")
        
        # Investigate lateral movement
        if len(context.affected_hosts) > 1:
            paths.append("Trace lateral movement path and identify persistence mechanisms")
        
        # Investigate data access
        if any("exfiltration" in t for t in context.mitre_techniques):
            paths.append("Identify accessed/exfiltrated data and establish breach timeline")
        
        # Timeline reconstruction
        paths.append("Construct complete timeline of attacker activities")
        
        return paths


class PlaybookLibrary:
    """Library of response playbooks"""
    
    def __init__(self):
        self.playbooks = {}
        self._initialize_default_playbooks()
    
    def _initialize_default_playbooks(self):
        """Initialize default playbooks"""
        
        # Ransomware response
        ransomware_pb = SecurityPlaybook(
            name="Ransomware Response",
            description="Automated response to ransomware detection",
            trigger_type="ransomware_detected",
            enabled=True,
            priority=ActionPriority.CRITICAL
        )
        ransomware_pb.actions = [
            PlaybookAction(action_type=ActionType.ISOLATE_HOST, confidence=0.95),
            PlaybookAction(action_type=ActionType.CAPTURE_MEMORY, confidence=0.85),
            PlaybookAction(action_type=ActionType.ESCALATE_INCIDENT, confidence=1.0),
            PlaybookAction(action_type=ActionType.NOTIFY_SOC, confidence=1.0),
        ]
        self.playbooks["ransomware"] = ransomware_pb
        
        # Privilege escalation response
        privesc_pb = SecurityPlaybook(
            name="Privilege Escalation Response",
            description="Response to privilege escalation attempts",
            trigger_type="privilege_escalation",
            enabled=True,
            priority=ActionPriority.HIGH
        )
        privesc_pb.actions = [
            PlaybookAction(action_type=ActionType.REVOKE_SESSION, confidence=0.9),
            PlaybookAction(action_type=ActionType.COLLECT_ARTIFACTS, confidence=0.8),
            PlaybookAction(action_type=ActionType.ESCALATE_INCIDENT, confidence=0.95),
        ]
        self.playbooks["privesc"] = privesc_pb
        
        # Lateral movement response
        lateral_pb = SecurityPlaybook(
            name="Lateral Movement Response",
            description="Response to detected lateral movement",
            trigger_type="lateral_movement",
            enabled=True,
            priority=ActionPriority.HIGH
        )
        lateral_pb.actions = [
            PlaybookAction(action_type=ActionType.BLOCK_IP, confidence=0.85),
            PlaybookAction(action_type=ActionType.REVOKE_SESSION, confidence=0.8),
            PlaybookAction(action_type=ActionType.COLLECT_ARTIFACTS, confidence=0.75),
        ]
        self.playbooks["lateral"] = lateral_pb
        
        # 4. Phishing / Credential Compromise Response
        phishing_pb = SecurityPlaybook(
            name="Phishing Response",
            description="Response to phishing or credential compromise",
            trigger_type="phishing",
            enabled=True,
            priority=ActionPriority.HIGH
        )
        phishing_pb.actions = [
            PlaybookAction(action_type=ActionType.DISABLE_ACCOUNT, confidence=0.95),
            PlaybookAction(action_type=ActionType.REVOKE_SESSION, confidence=0.95),
            PlaybookAction(action_type=ActionType.NOTIFY_SOC, confidence=1.0),
        ]
        self.playbooks["phishing"] = phishing_pb

        # 5. Data Exfiltration Response
        exfil_pb = SecurityPlaybook(
            name="Data Exfiltration Response",
            description="Response to detected data exfiltration",
            trigger_type="exfiltration",
            enabled=True,
            priority=ActionPriority.CRITICAL
        )
        exfil_pb.actions = [
            PlaybookAction(action_type=ActionType.BLOCK_IP, confidence=0.9),
            PlaybookAction(action_type=ActionType.ISOLATE_HOST, confidence=0.95),
            PlaybookAction(action_type=ActionType.DISABLE_ACCOUNT, confidence=0.85),
            PlaybookAction(action_type=ActionType.NOTIFY_SOC, confidence=1.0),
        ]
        self.playbooks["exfiltration"] = exfil_pb

        # 6. C2 / Botnet Response
        c2_pb = SecurityPlaybook(
            name="C2 Communication Response",
            description="Response to Command & Control traffic",
            trigger_type="c2_communication",
            enabled=True,
            priority=ActionPriority.CRITICAL
        )
        c2_pb.actions = [
            PlaybookAction(action_type=ActionType.BLOCK_IP, confidence=0.95),
            PlaybookAction(action_type=ActionType.KILL_PROCESS, confidence=0.9),
            PlaybookAction(action_type=ActionType.CAPTURE_MEMORY, confidence=0.8),
            PlaybookAction(action_type=ActionType.COLLECT_ARTIFACTS, confidence=0.8),
        ]
        self.playbooks["c2"] = c2_pb

        # 7. Brute Force Response
        brute_pb = SecurityPlaybook(
            name="Brute Force Response",
            description="Response to brute force attacks",
            trigger_type="brute_force",
            enabled=True,
            priority=ActionPriority.MEDIUM
        )
        brute_pb.actions = [
            PlaybookAction(action_type=ActionType.BLOCK_IP, confidence=0.9),
            PlaybookAction(action_type=ActionType.DISABLE_ACCOUNT, confidence=0.7), # Temporary lock usually
        ]
        self.playbooks["brute_force"] = brute_pb

        # 8. Insider Threat Response
        insider_pb = SecurityPlaybook(
            name="Insider Threat Response",
            description="Response to potential insider threats",
            trigger_type="insider_threat",
            enabled=True,
            priority=ActionPriority.HIGH
        )
        insider_pb.actions = [
            PlaybookAction(action_type=ActionType.NOTIFY_SOC, confidence=1.0),
            PlaybookAction(action_type=ActionType.SNAPSHOT_DISK, confidence=0.9),
            PlaybookAction(action_type=ActionType.COLLECT_ARTIFACTS, confidence=0.85),
            # No automated blocking for insiders usually, to avoid tipping them off or disrupting legit work
        ]
        self.playbooks["insider_threat"] = insider_pb
    
    def get_playbook(self, trigger_type: str) -> Optional[SecurityPlaybook]:
        """Get playbook by trigger"""
        for pb in self.playbooks.values():
            if trigger_type in pb.trigger_type:
                return pb
        return None
    
    def get_all_enabled(self) -> List[SecurityPlaybook]:
        """Get all enabled playbooks"""
        return [pb for pb in self.playbooks.values() if pb.enabled]


class SOAROrchestrator:
    """Main SOAR orchestration engine"""
    
    def __init__(self):
        self.playbook_library = PlaybookLibrary()
        self.action_ranker = ActionRankingEngine()
        self.root_cause_analyzer = RootCauseAnalyzer()
        
        self.incidents = {}  # incident_id -> IncidentResponse
        self.executed_actions = deque(maxlen=10000)
        
        self.lock = threading.RLock()
    
    async def process_incident(self, incident: IncidentContext) -> IncidentResponse:
        """Process security incident end-to-end"""
        response = IncidentResponse(incident_id=incident.incident_id)
        
        # Triage
        response.triage_level = self._triage_incident(incident)
        response.triage_reasoning = f"Severity: {incident.severity}, Evidence: {incident.evidence_count}"
        
        # Root cause
        root_cause, confidence = self.root_cause_analyzer.analyze_root_cause(incident)
        response.root_cause_hypothesis = root_cause
        response.root_cause_confidence = confidence
        
        # Get applicable playbooks
        playbooks = [self.playbook_library.get_playbook(incident.incident_type)]
        playbooks = [pb for pb in playbooks if pb]
        
        # Generate suggested actions
        all_actions = []
        for pb in playbooks:
            all_actions.extend(pb.actions)
        
        # Rank actions
        ranked = self.action_ranker.rank_actions(all_actions, incident)
        response.suggested_actions = [action for action, _ in ranked[:5]]
        
        # Execute high-confidence actions
        for action, score in ranked:
            if score > 0.7 and response.triage_level in [TriageLevel.CRITICAL, TriageLevel.HIGH]:
                await self._execute_action(action)
                response.executed_actions.append(action)
        
        with self.lock:
            self.incidents[response.incident_id] = response
        
        logger.info(f"Processed incident {incident.incident_id}: "
                   f"Triage={response.triage_level.value}, "
                   f"Actions={len(response.executed_actions)}")
        
        return response
    
    def _triage_incident(self, context: IncidentContext) -> TriageLevel:
        """Triage incident severity"""
        severity_map = {
            "critical": TriageLevel.CRITICAL,
            "high": TriageLevel.HIGH,
            "medium": TriageLevel.MEDIUM,
            "low": TriageLevel.LOW,
            "info": TriageLevel.INFO
        }
        
        level = severity_map.get(context.severity, TriageLevel.MEDIUM)
        
        # Boost for multi-host incidents
        if len(context.affected_hosts) > 5:
            if level == TriageLevel.MEDIUM:
                level = TriageLevel.HIGH
            elif level == TriageLevel.HIGH:
                level = TriageLevel.CRITICAL
        
        return level
    
    async def _execute_action(self, action: PlaybookAction) -> None:
        """Execute action"""
        action.status = "executing"
        action.executed_at = datetime.now()
        
        try:
            # Simulate execution
            await asyncio.sleep(0.1)
            
            action.status = "success"
            action.result = {"status": "executed"}
            
            with self.lock:
                self.executed_actions.append(action)
            
            logger.info(f"Executed action: {action.action_type.value}")
            
        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            logger.error(f"Action execution failed: {e}")
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get SOAR statistics"""
        with self.lock:
            num_incidents = len(self.incidents)
            num_actions = len(self.executed_actions)
            success_rate = sum(
                1 for a in self.executed_actions if a.status == "success"
            ) / max(1, len(self.executed_actions))
        
        return {
            "incidents_processed": num_incidents,
            "actions_executed": num_actions,
            "success_rate": success_rate,
            "playbooks_available": len(self.playbook_library.playbooks)
        }


# Global instance
_soar_instance = None


def get_soar_orchestrator() -> SOAROrchestrator:
    """Get or create SOAR orchestrator"""
    global _soar_instance
    if _soar_instance is None:
        _soar_instance = SOAROrchestrator()
    return _soar_instance
