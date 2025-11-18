"""
Auto-Healing Infrastructure Module
Automated response to security incidents with safe rollback capabilities
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RemediationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class IsolationLevel(Enum):
    SOFT = "soft"  # Network isolation only
    HARD = "hard"  # Network + storage isolation
    COMPLETE = "complete"  # Full VM disconnection


@dataclass
class QuarantinePolicy:
    """Defines VM quarantine behavior"""
    isolation_level: IsolationLevel
    preserve_logs: bool = True
    allow_root_access: bool = False
    network_retention: int = 3600  # seconds
    forensics_enabled: bool = True


@dataclass
class VMSnapshot:
    """Represents VM snapshot for rollback"""
    snapshot_id: str
    vm_id: str
    timestamp: datetime
    disk_size_gb: float
    memory_state: Optional[bytes] = None
    description: str = ""
    is_valid: bool = True
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class UserDisableAction:
    """User account disablement record"""
    action_id: str
    user_id: str
    username: str
    timestamp: datetime
    reason: str
    severity: str
    revoked_sessions: List[str] = field(default_factory=list)
    disabled_mfa: bool = False
    vpn_disconnected: bool = False
    was_active: bool = True


@dataclass
class NetworkSegment:
    """Network segment definition"""
    segment_id: str
    name: str
    cidr_block: str
    allowed_outbound: List[str] = field(default_factory=list)
    threat_level: str = "normal"  # normal, elevated, critical
    isolated: bool = False


@dataclass
class RemediationAction:
    """Single remediation action"""
    action_id: str
    action_type: str  # quarantine_vm, rollback_snapshot, disable_user, segment_network
    target: str  # VM ID, User ID, or network segment
    severity: str  # low, medium, high, critical
    timestamp: datetime
    status: RemediationStatus = RemediationStatus.PENDING
    details: Dict = field(default_factory=dict)
    reversible: bool = True
    rollback_action_id: Optional[str] = None
    estimated_impact: str = ""


class VMQuarantineManager:
    """Manages VM isolation and quarantine"""
    
    def __init__(self):
        self.quarantined_vms: Dict[str, Dict] = {}
        self.policies: Dict[str, QuarantinePolicy] = {}
        self.network_rules: Dict[str, List[Dict]] = {}
    
    def quarantine_vm(
        self,
        vm_id: str,
        policy: QuarantinePolicy,
        reason: str
    ) -> Dict:
        """Quarantine a VM with specified policy"""
        
        quarantine = {
            'vm_id': vm_id,
            'timestamp': datetime.now().isoformat(),
            'policy': {
                'isolation_level': policy.isolation_level.value,
                'preserve_logs': policy.preserve_logs,
                'forensics_enabled': policy.forensics_enabled
            },
            'reason': reason,
            'status': 'quarantined'
        }
        
        self.quarantined_vms[vm_id] = quarantine
        
        # Apply network isolation
        self._apply_network_isolation(vm_id, policy.isolation_level)
        
        # Preserve forensics
        if policy.forensics_enabled:
            self._capture_forensics(vm_id)
        
        logger.info(f"VM {vm_id} quarantined with {policy.isolation_level.value} isolation")
        
        return quarantine
    
    def _apply_network_isolation(self, vm_id: str, level: IsolationLevel):
        """Apply network isolation based on level"""
        
        if level == IsolationLevel.SOFT:
            # Allow only monitoring traffic
            rules = [
                {'protocol': 'tcp', 'port': 5985, 'action': 'allow'},  # WinRM monitoring
                {'protocol': 'tcp', 'port': 22, 'action': 'allow'},    # SSH monitoring
                {'protocol': '*', 'port': '*', 'action': 'deny'}       # Everything else
            ]
        elif level == IsolationLevel.HARD:
            # Strict isolation, forensics only
            rules = [
                {'protocol': 'tcp', 'port': 3389, 'action': 'allow'},  # RDP for forensics
                {'protocol': 'tcp', 'port': 5985, 'action': 'allow'},  # WinRM
                {'protocol': '*', 'port': '*', 'action': 'deny'}
            ]
        else:  # COMPLETE
            # Full disconnection
            rules = [
                {'protocol': '*', 'port': '*', 'action': 'deny'}
            ]
        
        self.network_rules[vm_id] = rules
    
    def _capture_forensics(self, vm_id: str):
        """Capture forensics snapshot"""
        logger.info(f"Capturing forensics for VM {vm_id}")
    
    def release_quarantine(self, vm_id: str) -> bool:
        """Release VM from quarantine"""
        
        if vm_id in self.quarantined_vms:
            self.quarantined_vms.pop(vm_id)
            if vm_id in self.network_rules:
                self.network_rules.pop(vm_id)
            logger.info(f"VM {vm_id} released from quarantine")
            return True
        return False
    
    def get_quarantined_vms(self) -> List[str]:
        """Get list of all quarantined VMs"""
        return list(self.quarantined_vms.keys())


class SnapshotRollbackEngine:
    """Manages VM snapshot rollback"""
    
    def __init__(self):
        self.snapshots: Dict[str, List[VMSnapshot]] = {}
        self.rollback_history: Dict[str, List[Dict]] = {}
    
    def create_snapshot(
        self,
        vm_id: str,
        disk_size_gb: float = 100.0,
        description: str = ""
    ) -> VMSnapshot:
        """Create VM snapshot"""
        
        snapshot_id = f"snap_{vm_id}_{datetime.now().timestamp()}"
        snapshot = VMSnapshot(
            snapshot_id=snapshot_id,
            vm_id=vm_id,
            timestamp=datetime.now(),
            disk_size_gb=disk_size_gb,
            description=description or f"Snapshot of {vm_id}"
        )
        
        if vm_id not in self.snapshots:
            self.snapshots[vm_id] = []
        
        self.snapshots[vm_id].append(snapshot)
        logger.info(f"Snapshot {snapshot_id} created for VM {vm_id}")
        
        return snapshot
    
    def list_snapshots(self, vm_id: str) -> List[VMSnapshot]:
        """List all snapshots for VM"""
        return self.snapshots.get(vm_id, [])
    
    def rollback_to_snapshot(
        self,
        vm_id: str,
        snapshot_id: str,
        verify: bool = True
    ) -> Dict:
        """Rollback VM to previous snapshot"""
        
        if vm_id not in self.snapshots:
            return {'success': False, 'error': 'No snapshots found'}
        
        # Find snapshot
        target_snapshot = None
        for snap in self.snapshots[vm_id]:
            if snap.snapshot_id == snapshot_id:
                target_snapshot = snap
                break
        
        if not target_snapshot:
            return {'success': False, 'error': 'Snapshot not found'}
        
        if not target_snapshot.is_valid:
            return {'success': False, 'error': 'Snapshot is invalid'}
        
        # Perform rollback
        rollback_record = {
            'rollback_id': f"rollback_{vm_id}_{datetime.now().timestamp()}",
            'vm_id': vm_id,
            'from_snapshot': snapshot_id,
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'verification': verify,
            'data_loss_seconds': (datetime.now() - target_snapshot.timestamp).total_seconds()
        }
        
        if vm_id not in self.rollback_history:
            self.rollback_history[vm_id] = []
        
        self.rollback_history[vm_id].append(rollback_record)
        
        logger.info(f"VM {vm_id} rolled back to snapshot {snapshot_id}")
        
        return {
            'success': True,
            'rollback_id': rollback_record['rollback_id'],
            'data_loss_seconds': rollback_record['data_loss_seconds']
        }
    
    def get_rollback_history(self, vm_id: str) -> List[Dict]:
        """Get rollback history for VM"""
        return self.rollback_history.get(vm_id, [])


class UserDisableAutomation:
    """Automated user account disablement"""
    
    def __init__(self):
        self.disabled_users: Dict[str, UserDisableAction] = {}
        self.session_tracker: Dict[str, List[str]] = {}
    
    def disable_user(
        self,
        user_id: str,
        username: str,
        reason: str,
        severity: str = "high"
    ) -> UserDisableAction:
        """Disable user account"""
        
        action = UserDisableAction(
            action_id=f"disable_{user_id}_{datetime.now().timestamp()}",
            user_id=user_id,
            username=username,
            timestamp=datetime.now(),
            reason=reason,
            severity=severity
        )
        
        # Revoke active sessions
        if user_id in self.session_tracker:
            action.revoked_sessions = self.session_tracker[user_id].copy()
            self.session_tracker[user_id] = []
        
        # Disable MFA
        action.disabled_mfa = True
        
        # Disconnect VPN
        action.vpn_disconnected = True
        
        self.disabled_users[user_id] = action
        
        logger.info(f"User {username} ({user_id}) disabled: {reason}")
        
        return action
    
    def track_session(self, user_id: str, session_id: str):
        """Track user session"""
        if user_id not in self.session_tracker:
            self.session_tracker[user_id] = []
        self.session_tracker[user_id].append(session_id)
    
    def reenable_user(self, user_id: str) -> bool:
        """Re-enable user account"""
        
        if user_id in self.disabled_users:
            self.disabled_users.pop(user_id)
            logger.info(f"User {user_id} re-enabled")
            return True
        return False
    
    def get_disabled_users(self) -> Dict[str, UserDisableAction]:
        """Get all disabled users"""
        return self.disabled_users.copy()


class NetworkSegmentationController:
    """Manages network microsegmentation"""
    
    def __init__(self):
        self.segments: Dict[str, NetworkSegment] = {}
        self.isolation_rules: Dict[str, List[Dict]] = {}
    
    def create_segment(
        self,
        segment_id: str,
        name: str,
        cidr_block: str
    ) -> NetworkSegment:
        """Create network segment"""
        
        segment = NetworkSegment(
            segment_id=segment_id,
            name=name,
            cidr_block=cidr_block
        )
        
        self.segments[segment_id] = segment
        logger.info(f"Network segment {name} created: {cidr_block}")
        
        return segment
    
    def isolate_segment(
        self,
        segment_id: str,
        threat_level: str = "critical"
    ) -> Dict:
        """Isolate network segment"""
        
        if segment_id not in self.segments:
            return {'success': False, 'error': 'Segment not found'}
        
        segment = self.segments[segment_id]
        segment.isolated = True
        segment.threat_level = threat_level
        
        # Create isolation rules
        rules = [
            {'source': segment.cidr_block, 'destination': 'any', 'action': 'deny'},
            {'source': 'any', 'destination': segment.cidr_block, 'action': 'deny'},
            {'source': segment.cidr_block, 'destination': '0.0.0.0/0', 'action': 'deny'},
        ]
        
        self.isolation_rules[segment_id] = rules
        
        logger.info(f"Network segment {segment.name} isolated at {threat_level} level")
        
        return {
            'success': True,
            'segment_id': segment_id,
            'rules_applied': len(rules),
            'threat_level': threat_level
        }
    
    def restore_segment(self, segment_id: str) -> bool:
        """Restore network segment to normal"""
        
        if segment_id not in self.segments:
            return False
        
        segment = self.segments[segment_id]
        segment.isolated = False
        segment.threat_level = "normal"
        
        if segment_id in self.isolation_rules:
            self.isolation_rules.pop(segment_id)
        
        logger.info(f"Network segment {segment.name} restored")
        return True
    
    def get_isolated_segments(self) -> List[NetworkSegment]:
        """Get all isolated segments"""
        return [s for s in self.segments.values() if s.isolated]


class AutoHealingOrchestrator:
    """Coordinates all auto-healing actions"""
    
    def __init__(self):
        self.vm_quarantine = VMQuarantineManager()
        self.snapshot_rollback = SnapshotRollbackEngine()
        self.user_disable = UserDisableAutomation()
        self.network_segmentation = NetworkSegmentationController()
        
        self.actions: Dict[str, RemediationAction] = {}
        self.action_history: List[RemediationAction] = []
    
    def execute_remediation_plan(
        self,
        incident_id: str,
        severity: str,
        affected_hosts: List[str],
        affected_users: List[Dict],
        affected_networks: List[str]
    ) -> Dict:
        """Execute comprehensive remediation plan"""
        
        plan = {
            'plan_id': f"plan_{incident_id}",
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'actions': []
        }
        
        # 1. Quarantine affected VMs
        for host_id in affected_hosts:
            policy = QuarantinePolicy(
                isolation_level=IsolationLevel.HARD if severity == "critical" else IsolationLevel.SOFT,
                forensics_enabled=True
            )
            
            quarantine = self.vm_quarantine.quarantine_vm(
                host_id,
                policy,
                f"Security incident {incident_id}"
            )
            
            action = RemediationAction(
                action_id=f"action_quarantine_{host_id}",
                action_type="quarantine_vm",
                target=host_id,
                severity=severity,
                timestamp=datetime.now(),
                status=RemediationStatus.COMPLETED,
                details=quarantine,
                reversible=True
            )
            
            self.actions[action.action_id] = action
            plan['actions'].append(action.action_id)
        
        # 2. Disable compromised users
        for user in affected_users:
            disable_action = self.user_disable.disable_user(
                user['user_id'],
                user['username'],
                f"Account compromised in incident {incident_id}",
                severity
            )
            
            action = RemediationAction(
                action_id=f"action_disable_{user['user_id']}",
                action_type="disable_user",
                target=user['user_id'],
                severity=severity,
                timestamp=datetime.now(),
                status=RemediationStatus.COMPLETED,
                details={
                    'username': user['username'],
                    'sessions_revoked': len(disable_action.revoked_sessions),
                    'mfa_disabled': disable_action.disabled_mfa,
                    'vpn_disconnected': disable_action.vpn_disconnected
                },
                reversible=True
            )
            
            self.actions[action.action_id] = action
            plan['actions'].append(action.action_id)
        
        # 3. Isolate affected network segments
        for network in affected_networks:
            isolation = self.network_segmentation.isolate_segment(
                network,
                threat_level="critical" if severity == "critical" else "elevated"
            )
            
            action = RemediationAction(
                action_id=f"action_segment_{network}",
                action_type="segment_network",
                target=network,
                severity=severity,
                timestamp=datetime.now(),
                status=RemediationStatus.COMPLETED,
                details=isolation,
                reversible=True
            )
            
            self.actions[action.action_id] = action
            plan['actions'].append(action.action_id)
        
        self.action_history.append(action)
        
        return plan
    
    def rollback_remediation(self, action_id: str) -> bool:
        """Rollback specific remediation action"""
        
        if action_id not in self.actions:
            return False
        
        action = self.actions[action_id]
        
        try:
            if action.action_type == "quarantine_vm":
                self.vm_quarantine.release_quarantine(action.target)
            elif action.action_type == "disable_user":
                self.user_disable.reenable_user(action.target)
            elif action.action_type == "segment_network":
                self.network_segmentation.restore_segment(action.target)
            
            action.status = RemediationStatus.ROLLED_BACK
            logger.info(f"Action {action_id} rolled back")
            return True
        except Exception as e:
            logger.error(f"Rollback failed for {action_id}: {e}")
            action.status = RemediationStatus.FAILED
            return False
    
    def get_remediation_status(self) -> Dict:
        """Get current remediation status"""
        
        return {
            'quarantined_vms': self.vm_quarantine.get_quarantined_vms(),
            'disabled_users': list(self.user_disable.get_disabled_users().keys()),
            'isolated_segments': [s.name for s in self.network_segmentation.get_isolated_segments()],
            'total_actions': len(self.actions),
            'completed_actions': sum(1 for a in self.actions.values() if a.status == RemediationStatus.COMPLETED),
            'rolled_back_actions': sum(1 for a in self.actions.values() if a.status == RemediationStatus.ROLLED_BACK)
        }


# Global instance
_orchestrator: Optional[AutoHealingOrchestrator] = None


def get_auto_healing_orchestrator() -> AutoHealingOrchestrator:
    """Get or create global orchestrator"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AutoHealingOrchestrator()
    return _orchestrator


# Example usage
if __name__ == "__main__":
    orchestrator = get_auto_healing_orchestrator()
    
    # Execute remediation for critical incident
    plan = orchestrator.execute_remediation_plan(
        incident_id="INC-2024-001",
        severity="critical",
        affected_hosts=["vm-001", "vm-002"],
        affected_users=[
            {'user_id': "user123", 'username': "john.doe"},
            {'user_id': "user456", 'username': "jane.smith"}
        ],
        affected_networks=["seg-001", "seg-002"]
    )
    
    print(f"Remediation plan executed: {plan['plan_id']}")
    print(f"Status: {orchestrator.get_remediation_status()}")
