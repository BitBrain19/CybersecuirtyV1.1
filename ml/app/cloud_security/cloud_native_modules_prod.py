"""
Cloud-Native Security Modules
AWS CloudTrail/GuardDuty, Azure Defender/Sentinel, GCP SCC analyzers
"""

import asyncio
import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import base64
import hashlib

logger = logging.getLogger(__name__)


class CloudProvider(str, Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class MisconfigurationSeverity(str, Enum):
    """Misconfig severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CloudSecurityFinding:
    """Cloud security finding"""
    finding_id: str
    cloud_provider: CloudProvider
    resource_id: str
    resource_type: str
    severity: MisconfigurationSeverity
    finding_type: str
    title: str
    description: str
    recommendation: str
    timestamp: datetime = field(default_factory=datetime.now)
    remediation_status: str = "open"


@dataclass
class MisconfigurationIssue:
    """Misconfiguration detection result"""
    issue_id: str
    resource_id: str
    config_item: str
    expected_value: Any
    actual_value: Any
    severity: MisconfigurationSeverity
    control_id: str  # CIS benchmark or similar
    remediation_steps: List[str]


class CloudTrailAnalyzer:
    """Analyzer for AWS CloudTrail events"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.findings = []
        self.suspicious_patterns = {
            'root_login': {'count_threshold': 1, 'description': 'Root account login detected'},
            'disabled_mfa': {'count_threshold': 1, 'description': 'MFA disabled on account'},
            'policy_change': {'count_threshold': 5, 'description': 'Multiple policy changes'},
            'unauthorized_api_calls': {'count_threshold': 10, 'description': 'Unauthorized API calls'},
            'ec2_termination': {'count_threshold': 5, 'description': 'Multiple EC2 terminations'},
            's3_bucket_acl_change': {'count_threshold': 1, 'description': 'S3 bucket ACL modified'},
            'iam_policy_attached': {'count_threshold': 10, 'description': 'Multiple IAM policies attached'},
        }
    
    def analyze_event(self, event: Dict[str, Any]) -> List[CloudSecurityFinding]:
        """Analyze CloudTrail event for security issues"""
        findings = []
        
        with self._lock:
            event_name = event.get('eventName', '')
            source_ip = event.get('sourceIPAddress', '')
            user_agent = event.get('userAgent', '')
            principal_id = event.get('requestParameters', {}).get('principalId', '')
            
            # Root login detection
            if event_name == 'ConsoleLogin' and principal_id == 'root':
                findings.append(CloudSecurityFinding(
                    finding_id=f"root_login_{datetime.now().timestamp()}",
                    cloud_provider=CloudProvider.AWS,
                    resource_id='root_account',
                    resource_type='IAM',
                    severity=MisconfigurationSeverity.CRITICAL,
                    finding_type='UnauthorizedAccess',
                    title='Root Account Console Login',
                    description='Root account logged in to console',
                    recommendation='Use IAM users for console access, enable MFA on root'
                ))
            
            # Disabled MFA detection
            if event_name == 'DeactivateMFADevice':
                findings.append(CloudSecurityFinding(
                    finding_id=f"mfa_disabled_{datetime.now().timestamp()}",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=principal_id,
                    resource_type='IAM',
                    severity=MisconfigurationSeverity.HIGH,
                    finding_type='AccessManagement',
                    title='MFA Device Deactivated',
                    description=f'MFA disabled for user {principal_id}',
                    recommendation='Re-enable MFA immediately'
                ))
            
            # S3 bucket public access
            if 'S3' in event_name and 'PutBucketAcl' in event_name:
                acl = event.get('requestParameters', {}).get('Acl', '')
                if acl in ['public-read', 'public-read-write']:
                    findings.append(CloudSecurityFinding(
                        finding_id=f"s3_public_{datetime.now().timestamp()}",
                        cloud_provider=CloudProvider.AWS,
                        resource_id=event.get('requestParameters', {}).get('bucketName', 'unknown'),
                        resource_type='S3',
                        severity=MisconfigurationSeverity.CRITICAL,
                        finding_type='UnauthorizedAccess',
                        title='S3 Bucket Made Public',
                        description=f'S3 bucket set to {acl}',
                        recommendation='Set bucket to private, use signed URLs'
                    ))
            
            # Suspicious IP
            if source_ip.startswith('0.') or source_ip.startswith('10.') and not any(
                c.isalpha() for c in user_agent
            ):
                findings.append(CloudSecurityFinding(
                    finding_id=f"suspicious_ip_{datetime.now().timestamp()}",
                    cloud_provider=CloudProvider.AWS,
                    resource_id=source_ip,
                    resource_type='Network',
                    severity=MisconfigurationSeverity.MEDIUM,
                    finding_type='SuspiciousActivity',
                    title='API Call from Suspicious IP',
                    description=f'API call from {source_ip}',
                    recommendation='Verify IP and user'
                ))
        
        return findings
    
    def detect_privilege_escalation_chain(self, events: List[Dict[str, Any]]) -> List[Tuple[str, List[str]]]:
        """Detect privilege escalation attack chains"""
        chains = []
        
        with self._lock:
            # Pattern: Assume role -> modify policy -> attach policy
            event_sequence = []
            for event in sorted(events, key=lambda e: e.get('eventTime', '')):
                event_sequence.append(event.get('eventName', ''))
            
            # Check for escalation patterns
            escalation_patterns = [
                ['AssumeRole', 'PutUserPolicy', 'AttachUserPolicy'],
                ['CreateAccessKey', 'GetUser', 'CreateLoginProfile'],
                ['CreateRole', 'PutRolePolicy', 'AttachRolePolicy'],
            ]
            
            for pattern in escalation_patterns:
                if all(evt in event_sequence for evt in pattern):
                    chains.append((
                        f"privilege_escalation_{datetime.now().timestamp()}",
                        pattern
                    ))
        
        return chains


class GuardDutyAnalyzer:
    """Analyzer for AWS GuardDuty findings"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.finding_counts = defaultdict(int)
    
    def analyze_finding(self, finding: Dict[str, Any]) -> CloudSecurityFinding:
        """Convert GuardDuty finding to standardized format"""
        with self._lock:
            finding_type = finding.get('type', '')
            severity = finding.get('severity', 0)
            
            # Map severity score to our enum
            if severity >= 7.0:
                sev = MisconfigurationSeverity.CRITICAL
            elif severity >= 5.0:
                sev = MisconfigurationSeverity.HIGH
            elif severity >= 3.0:
                sev = MisconfigurationSeverity.MEDIUM
            elif severity >= 1.0:
                sev = MisconfigurationSeverity.LOW
            else:
                sev = MisconfigurationSeverity.INFO
            
            self.finding_counts[finding_type] += 1
            
            return CloudSecurityFinding(
                finding_id=finding.get('id', f"guardduty_{datetime.now().timestamp()}"),
                cloud_provider=CloudProvider.AWS,
                resource_id=finding.get('resource', {}).get('instanceDetails', {}).get('instanceId', 'unknown'),
                resource_type='EC2',
                severity=sev,
                finding_type=finding_type,
                title=finding_type,
                description=finding.get('description', ''),
                recommendation=f'Review and remediate {finding_type}'
            )


class AzureDefenderAnalyzer:
    """Analyzer for Azure Defender + Sentinel logs"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.alert_counts = defaultdict(int)
    
    def analyze_security_alert(self, alert: Dict[str, Any]) -> CloudSecurityFinding:
        """Analyze Azure Defender security alert"""
        with self._lock:
            alert_type = alert.get('alertType', '')
            confidence = alert.get('confidence', 0)
            
            # Map confidence to severity
            if confidence >= 0.8:
                sev = MisconfigurationSeverity.CRITICAL
            elif confidence >= 0.6:
                sev = MisconfigurationSeverity.HIGH
            elif confidence >= 0.4:
                sev = MisconfigurationSeverity.MEDIUM
            else:
                sev = MisconfigurationSeverity.LOW
            
            self.alert_counts[alert_type] += 1
            
            return CloudSecurityFinding(
                finding_id=alert.get('alertId', f"defender_{datetime.now().timestamp()}"),
                cloud_provider=CloudProvider.AZURE,
                resource_id=alert.get('resourceId', 'unknown'),
                resource_type=alert.get('resourceType', 'VM'),
                severity=sev,
                finding_type=alert_type,
                title=alert.get('alertName', alert_type),
                description=alert.get('description', ''),
                recommendation=alert.get('remediationSteps', 'Review alert manually')
            )
    
    def detect_lateral_movement_azure(self, events: List[Dict[str, Any]]) -> List[CloudSecurityFinding]:
        """Detect lateral movement in Azure environment"""
        findings = []
        
        with self._lock:
            # Look for cross-VM authentication patterns
            vm_auth_map = defaultdict(list)
            
            for event in events:
                source_vm = event.get('sourceVM', '')
                dest_vm = event.get('destinationVM', '')
                event_type = event.get('eventType', '')
                
                if source_vm and dest_vm and source_vm != dest_vm:
                    vm_auth_map[source_vm].append({
                        'destination': dest_vm,
                        'type': event_type,
                        'timestamp': event.get('timestamp', '')
                    })
            
            # Detect anomalous lateral movement
            for source_vm, destinations in vm_auth_map.items():
                if len(destinations) > 5:  # More than 5 lateral connections
                    findings.append(CloudSecurityFinding(
                        finding_id=f"lateral_movement_{datetime.now().timestamp()}",
                        cloud_provider=CloudProvider.AZURE,
                        resource_id=source_vm,
                        resource_type='VM',
                        severity=MisconfigurationSeverity.HIGH,
                        finding_type='LateralMovement',
                        title=f'Lateral Movement Detected from {source_vm}',
                        description=f'Suspicious lateral movement to {len(destinations)} VMs',
                        recommendation='Isolate VM and investigate access'
                    ))
        
        return findings


class GCPSecurityCommandCenterAnalyzer:
    """Analyzer for GCP Security Command Center (SCC) findings"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.cis_findings = []
    
    def analyze_scc_finding(self, finding: Dict[str, Any]) -> CloudSecurityFinding:
        """Analyze GCP SCC finding"""
        with self._lock:
            severity_map = {
                'CRITICAL': MisconfigurationSeverity.CRITICAL,
                'HIGH': MisconfigurationSeverity.HIGH,
                'MEDIUM': MisconfigurationSeverity.MEDIUM,
                'LOW': MisconfigurationSeverity.LOW,
            }
            
            severity = severity_map.get(finding.get('severity', 'MEDIUM'), MisconfigurationSeverity.MEDIUM)
            
            return CloudSecurityFinding(
                finding_id=finding.get('name', f"scc_{datetime.now().timestamp()}"),
                cloud_provider=CloudProvider.GCP,
                resource_id=finding.get('resourceName', 'unknown'),
                resource_type=finding.get('resourceType', 'unknown'),
                severity=severity,
                finding_type=finding.get('category', 'unknown'),
                title=finding.get('title', ''),
                description=finding.get('description', ''),
                recommendation=finding.get('recommendation', 'Review finding manually')
            )
    
    def detect_cis_benchmark_violations(self, config: Dict[str, Any]) -> List[MisconfigurationIssue]:
        """Detect CIS benchmark violations in GCP"""
        issues = []
        
        with self._lock:
            # CIS Google Cloud Platform Foundation Benchmark
            
            # 1.1 Ensure that Cloud Audit Logs is enabled
            if not config.get('audit_logs_enabled'):
                issues.append(MisconfigurationIssue(
                    issue_id=f"cis_1_1_{datetime.now().timestamp()}",
                    resource_id=config.get('project_id', 'unknown'),
                    config_item='Cloud Audit Logs',
                    expected_value=True,
                    actual_value=config.get('audit_logs_enabled', False),
                    severity=MisconfigurationSeverity.HIGH,
                    control_id='CIS 1.1',
                    remediation_steps=['Enable Cloud Audit Logs', 'Configure retention policy']
                ))
            
            # 1.2 Ensure VPC Flow Logs is enabled
            if not config.get('vpc_flow_logs_enabled'):
                issues.append(MisconfigurationIssue(
                    issue_id=f"cis_1_2_{datetime.now().timestamp()}",
                    resource_id=config.get('network_id', 'unknown'),
                    config_item='VPC Flow Logs',
                    expected_value=True,
                    actual_value=config.get('vpc_flow_logs_enabled', False),
                    severity=MisconfigurationSeverity.MEDIUM,
                    control_id='CIS 1.2',
                    remediation_steps=['Enable VPC Flow Logs', 'Set aggregation interval']
                ))
            
            # 2.1 Ensure that Cloud Storage bucket is not anonymously/publicly accessible
            if config.get('bucket_public_access'):
                issues.append(MisconfigurationIssue(
                    issue_id=f"cis_2_1_{datetime.now().timestamp()}",
                    resource_id=config.get('bucket_name', 'unknown'),
                    config_item='Bucket Public Access',
                    expected_value=False,
                    actual_value=True,
                    severity=MisconfigurationSeverity.CRITICAL,
                    control_id='CIS 2.1',
                    remediation_steps=['Remove public access', 'Use signed URLs', 'Enable uniform bucket-level access']
                ))
            
            # 3.1 Ensure that KMS encryption key rotation is enabled
            if not config.get('kms_key_rotation_enabled'):
                issues.append(MisconfigurationIssue(
                    issue_id=f"cis_3_1_{datetime.now().timestamp()}",
                    resource_id=config.get('kms_key_id', 'unknown'),
                    config_item='KMS Key Rotation',
                    expected_value=True,
                    actual_value=config.get('kms_key_rotation_enabled', False),
                    severity=MisconfigurationSeverity.MEDIUM,
                    control_id='CIS 3.1',
                    remediation_steps=['Enable automatic key rotation', 'Set rotation period']
                ))
        
        self.cis_findings.extend(issues)
        return issues


class UniversalMisconfigurationDetector:
    """Universal cloud misconfiguration detector"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.issues = []
    
    def detect_common_misconfigurations(self, config: Dict[str, Any]) -> List[MisconfigurationIssue]:
        """Detect common misconfigurations across clouds"""
        with self._lock:
            issues = []
            
            # Authentication & Access
            if config.get('mfa_required') is False:
                issues.append(MisconfigurationIssue(
                    issue_id=f"mfa_disabled_{datetime.now().timestamp()}",
                    resource_id=config.get('resource_id', 'unknown'),
                    config_item='MFA',
                    expected_value=True,
                    actual_value=False,
                    severity=MisconfigurationSeverity.HIGH,
                    control_id='AUTH-001',
                    remediation_steps=['Enable MFA for all users', 'Test MFA process']
                ))
            
            # Encryption
            if config.get('encryption_enabled') is False:
                issues.append(MisconfigurationIssue(
                    issue_id=f"encryption_disabled_{datetime.now().timestamp()}",
                    resource_id=config.get('resource_id', 'unknown'),
                    config_item='Encryption',
                    expected_value=True,
                    actual_value=False,
                    severity=MisconfigurationSeverity.CRITICAL,
                    control_id='ENC-001',
                    remediation_steps=['Enable encryption at rest', 'Enable encryption in transit', 'Manage encryption keys']
                ))
            
            # Logging
            if config.get('logging_enabled') is False:
                issues.append(MisconfigurationIssue(
                    issue_id=f"logging_disabled_{datetime.now().timestamp()}",
                    resource_id=config.get('resource_id', 'unknown'),
                    config_item='Logging',
                    expected_value=True,
                    actual_value=False,
                    severity=MisconfigurationSeverity.HIGH,
                    control_id='LOG-001',
                    remediation_steps=['Enable activity logging', 'Configure log retention', 'Set up log analysis']
                ))
            
            # Network Isolation
            if config.get('public_accessible') and not config.get('waf_enabled'):
                issues.append(MisconfigurationIssue(
                    issue_id=f"no_waf_{datetime.now().timestamp()}",
                    resource_id=config.get('resource_id', 'unknown'),
                    config_item='WAF',
                    expected_value=True,
                    actual_value=False,
                    severity=MisconfigurationSeverity.HIGH,
                    control_id='NET-001',
                    remediation_steps=['Enable WAF', 'Configure WAF rules', 'Enable logging']
                ))
            
            # Compliance
            if config.get('compliance_tags') is None or len(config.get('compliance_tags', [])) == 0:
                issues.append(MisconfigurationIssue(
                    issue_id=f"missing_compliance_tags_{datetime.now().timestamp()}",
                    resource_id=config.get('resource_id', 'unknown'),
                    config_item='Compliance Tags',
                    expected_value=['env', 'owner', 'data_classification'],
                    actual_value=config.get('compliance_tags', []),
                    severity=MisconfigurationSeverity.MEDIUM,
                    control_id='COMPLIANCE-001',
                    remediation_steps=['Add required tags', 'Document tag standards']
                ))
            
            self.issues.extend(issues)
            return issues
    
    def get_remediation_plan(self, issues: List[MisconfigurationIssue]) -> Dict[str, List[str]]:
        """Get prioritized remediation plan"""
        plan = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for issue in issues:
            priority = issue.severity.value
            if priority in plan:
                plan[priority].append(f"{issue.control_id}: {issue.config_item}")
        
        return plan


@dataclass
class CloudSecurityMetrics:
    """Cloud security metrics"""
    total_findings: int = 0
    critical_issues: int = 0
    remediated_issues: int = 0
    open_issues: int = 0
    mean_time_to_remediate_hours: float = 0.0
    compliance_score: float = 0.0


# Global instances
_cloudtrail_analyzer: Optional[CloudTrailAnalyzer] = None
_guardduty_analyzer: Optional[GuardDutyAnalyzer] = None
_azure_analyzer: Optional[AzureDefenderAnalyzer] = None
_gcp_analyzer: Optional[GCPSecurityCommandCenterAnalyzer] = None
_universal_detector: Optional[UniversalMisconfigurationDetector] = None


def get_cloudtrail_analyzer() -> CloudTrailAnalyzer:
    global _cloudtrail_analyzer
    if _cloudtrail_analyzer is None:
        _cloudtrail_analyzer = CloudTrailAnalyzer()
    return _cloudtrail_analyzer


def get_guardduty_analyzer() -> GuardDutyAnalyzer:
    global _guardduty_analyzer
    if _guardduty_analyzer is None:
        _guardduty_analyzer = GuardDutyAnalyzer()
    return _guardduty_analyzer


def get_azure_analyzer() -> AzureDefenderAnalyzer:
    global _azure_analyzer
    if _azure_analyzer is None:
        _azure_analyzer = AzureDefenderAnalyzer()
    return _azure_analyzer


def get_gcp_analyzer() -> GCPSecurityCommandCenterAnalyzer:
    global _gcp_analyzer
    if _gcp_analyzer is None:
        _gcp_analyzer = GCPSecurityCommandCenterAnalyzer()
    return _gcp_analyzer


def get_universal_detector() -> UniversalMisconfigurationDetector:
    global _universal_detector
    if _universal_detector is None:
        _universal_detector = UniversalMisconfigurationDetector()
    return _universal_detector


if __name__ == "__main__":
    logger.info("Cloud-Native Security Modules initialized")
