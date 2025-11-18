"""Advanced data validation and preprocessing for ML models."""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Union, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field, validator
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
from sklearn.impute import SimpleImputer, KNNImputer
from sklearn.feature_selection import SelectKBest, f_classif
import joblib

from ..core.config import settings
from ..core.logging_system import get_logger
from ..core.monitoring import metrics_collector
from ..core.exceptions import ValidationError, SecurityAIException


logger = get_logger(__name__)


class ValidationSeverity(Enum):
    """Validation issue severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class DataType(Enum):
    """Supported data types for validation."""
    NETWORK_TRAFFIC = "network_traffic"
    SYSTEM_LOG = "system_log"
    USER_BEHAVIOR = "user_behavior"
    FILE_ANALYSIS = "file_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    THREAT_INTELLIGENCE = "threat_intelligence"


@dataclass
class ValidationIssue:
    """Represents a data validation issue."""
    field_name: str
    issue_type: str
    severity: ValidationSeverity
    message: str
    suggested_fix: Optional[str] = None
    raw_value: Any = None
    expected_type: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of data validation."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    cleaned_data: Optional[Dict[str, Any]] = None
    confidence_score: float = 1.0
    processing_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class NetworkTrafficSchema(BaseModel):
    """Schema for network traffic data."""
    source_ip: str = Field(..., regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    dest_ip: str = Field(..., regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    source_port: int = Field(..., ge=1, le=65535)
    dest_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., regex=r'^(TCP|UDP|ICMP)$')
    packet_size: int = Field(..., ge=0)
    timestamp: datetime
    flags: Optional[str] = None
    payload_size: Optional[int] = Field(None, ge=0)
    
    @validator('source_ip', 'dest_ip')
    def validate_ip(cls, v):
        parts = v.split('.')
        if len(parts) != 4:
            raise ValueError('Invalid IP format')
        for part in parts:
            if not (0 <= int(part) <= 255):
                raise ValueError('Invalid IP range')
        return v


class SystemLogSchema(BaseModel):
    """Schema for system log data."""
    timestamp: datetime
    log_level: str = Field(..., regex=r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    source: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    process_id: Optional[int] = Field(None, ge=1)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    event_id: Optional[str] = None


class UserBehaviorSchema(BaseModel):
    """Schema for user behavior data."""
    user_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    timestamp: datetime
    resource: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)


class DataCleaner:
    """Handles data cleaning and preprocessing."""
    
    def __init__(self):
        self.scalers = {}
        self.imputers = {}
        self.encoders = {}
        
    def clean_network_traffic(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean network traffic data."""
        cleaned = data.copy()
        
        # Normalize IP addresses
        for ip_field in ['source_ip', 'dest_ip']:
            if ip_field in cleaned:
                cleaned[ip_field] = self._normalize_ip(cleaned[ip_field])
        
        # Normalize protocol
        if 'protocol' in cleaned:
            cleaned['protocol'] = cleaned['protocol'].upper()
        
        # Handle missing values
        if 'payload_size' not in cleaned or cleaned['payload_size'] is None:
            cleaned['payload_size'] = 0
        
        # Add derived features
        cleaned['is_internal_traffic'] = self._is_internal_traffic(
            cleaned.get('source_ip'), cleaned.get('dest_ip')
        )
        cleaned['port_category'] = self._categorize_port(cleaned.get('dest_port'))
        
        return cleaned
    
    def clean_system_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean system log data."""
        cleaned = data.copy()
        
        # Normalize log level
        if 'log_level' in cleaned:
            cleaned['log_level'] = cleaned['log_level'].upper()
        
        # Clean message text
        if 'message' in cleaned:
            cleaned['message'] = self._clean_log_message(cleaned['message'])
        
        # Extract structured data from message
        if 'message' in cleaned:
            extracted = self._extract_log_patterns(cleaned['message'])
            cleaned.update(extracted)
        
        return cleaned
    
    def clean_user_behavior(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean user behavior data."""
        cleaned = data.copy()
        
        # Normalize action
        if 'action' in cleaned:
            cleaned['action'] = cleaned['action'].lower().strip()
        
        # Parse user agent
        if 'user_agent' in cleaned and cleaned['user_agent']:
            parsed_ua = self._parse_user_agent(cleaned['user_agent'])
            cleaned.update(parsed_ua)
        
        # Calculate session duration if possible
        if 'session_start' in cleaned and 'timestamp' in cleaned:
            duration = (cleaned['timestamp'] - cleaned['session_start']).total_seconds()
            cleaned['session_duration'] = duration
        
        return cleaned
    
    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address format."""
        try:
            parts = ip.split('.')
            return '.'.join(str(int(part)) for part in parts)
        except:
            return ip
    
    def _is_internal_traffic(self, source_ip: str, dest_ip: str) -> bool:
        """Check if traffic is internal."""
        if not source_ip or not dest_ip:
            return False
        
        internal_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255')
        ]
        
        def ip_to_int(ip):
            parts = ip.split('.')
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        
        try:
            src_int = ip_to_int(source_ip)
            dst_int = ip_to_int(dest_ip)
            
            for start, end in internal_ranges:
                start_int = ip_to_int(start)
                end_int = ip_to_int(end)
                if start_int <= src_int <= end_int and start_int <= dst_int <= end_int:
                    return True
        except:
            pass
        
        return False
    
    def _categorize_port(self, port: int) -> str:
        """Categorize port number."""
        if not port:
            return "unknown"
        
        if port < 1024:
            return "system"
        elif port < 49152:
            return "registered"
        else:
            return "dynamic"
    
    def _clean_log_message(self, message: str) -> str:
        """Clean log message text."""
        # Remove excessive whitespace
        cleaned = re.sub(r'\s+', ' ', message.strip())
        
        # Remove sensitive information patterns
        patterns = [
            r'password[=:]\s*\S+',
            r'token[=:]\s*\S+',
            r'key[=:]\s*\S+',
            r'secret[=:]\s*\S+'
        ]
        
        for pattern in patterns:
            cleaned = re.sub(pattern, '[REDACTED]', cleaned, flags=re.IGNORECASE)
        
        return cleaned
    
    def _extract_log_patterns(self, message: str) -> Dict[str, Any]:
        """Extract structured data from log messages."""
        extracted = {}
        
        # Extract IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, message)
        if ips:
            extracted['extracted_ips'] = ips
        
        # Extract URLs
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, message)
        if urls:
            extracted['extracted_urls'] = urls
        
        # Extract file paths
        path_pattern = r'[/\\][^\s]*\.[a-zA-Z0-9]+'
        paths = re.findall(path_pattern, message)
        if paths:
            extracted['extracted_paths'] = paths
        
        return extracted
    
    def _parse_user_agent(self, user_agent: str) -> Dict[str, str]:
        """Parse user agent string."""
        parsed = {
            'browser_family': 'unknown',
            'os_family': 'unknown',
            'device_family': 'unknown'
        }
        
        # Simple user agent parsing (in production, use a proper library)
        if 'Chrome' in user_agent:
            parsed['browser_family'] = 'Chrome'
        elif 'Firefox' in user_agent:
            parsed['browser_family'] = 'Firefox'
        elif 'Safari' in user_agent:
            parsed['browser_family'] = 'Safari'
        
        if 'Windows' in user_agent:
            parsed['os_family'] = 'Windows'
        elif 'Mac' in user_agent:
            parsed['os_family'] = 'macOS'
        elif 'Linux' in user_agent:
            parsed['os_family'] = 'Linux'
        
        return parsed


class DataValidator:
    """Main data validation class."""
    
    def __init__(self):
        self.schemas = {
            DataType.NETWORK_TRAFFIC: NetworkTrafficSchema,
            DataType.SYSTEM_LOG: SystemLogSchema,
            DataType.USER_BEHAVIOR: UserBehaviorSchema
        }
        self.cleaner = DataCleaner()
        self.validation_stats = {
            'total_validations': 0,
            'successful_validations': 0,
            'failed_validations': 0,
            'issues_by_type': {},
            'processing_times': []
        }
    
    def validate_data(self, data: Dict[str, Any], data_type: DataType, 
                     auto_clean: bool = True) -> ValidationResult:
        """Validate data against schema and business rules."""
        start_time = datetime.now()
        
        try:
            self.validation_stats['total_validations'] += 1
            
            issues = []
            cleaned_data = data.copy() if auto_clean else None
            
            # Schema validation
            schema_issues = self._validate_schema(data, data_type)
            issues.extend(schema_issues)
            
            # Business rule validation
            business_issues = self._validate_business_rules(data, data_type)
            issues.extend(business_issues)
            
            # Data quality checks
            quality_issues = self._validate_data_quality(data, data_type)
            issues.extend(quality_issues)
            
            # Security checks
            security_issues = self._validate_security(data, data_type)
            issues.extend(security_issues)
            
            # Auto-clean data if requested and no critical issues
            if auto_clean and not any(issue.severity == ValidationSeverity.CRITICAL for issue in issues):
                cleaned_data = self._clean_data(data, data_type)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(issues)
            
            # Determine if data is valid
            is_valid = not any(issue.severity in [ValidationSeverity.ERROR, ValidationSeverity.CRITICAL] 
                             for issue in issues)
            
            if is_valid:
                self.validation_stats['successful_validations'] += 1
            else:
                self.validation_stats['failed_validations'] += 1
            
            # Update issue statistics
            for issue in issues:
                issue_type = f"{issue.issue_type}_{issue.severity.value}"
                self.validation_stats['issues_by_type'][issue_type] = \
                    self.validation_stats['issues_by_type'].get(issue_type, 0) + 1
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.validation_stats['processing_times'].append(processing_time)
            
            # Record metrics
            metrics_collector.record_validation_result(
                data_type.value, is_valid, len(issues), processing_time
            )
            
            return ValidationResult(
                is_valid=is_valid,
                issues=issues,
                cleaned_data=cleaned_data,
                confidence_score=confidence_score,
                processing_time_ms=processing_time,
                metadata={
                    'data_type': data_type.value,
                    'auto_cleaned': auto_clean and cleaned_data is not None,
                    'validation_timestamp': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f"Validation failed for {data_type.value}: {str(e)}", error=e)
            self.validation_stats['failed_validations'] += 1
            
            return ValidationResult(
                is_valid=False,
                issues=[ValidationIssue(
                    field_name="validation_error",
                    issue_type="system_error",
                    severity=ValidationSeverity.CRITICAL,
                    message=f"Validation system error: {str(e)}"
                )],
                processing_time_ms=(datetime.now() - start_time).total_seconds() * 1000
            )
    
    def _validate_schema(self, data: Dict[str, Any], data_type: DataType) -> List[ValidationIssue]:
        """Validate data against Pydantic schema."""
        issues = []
        
        if data_type not in self.schemas:
            issues.append(ValidationIssue(
                field_name="data_type",
                issue_type="unsupported_type",
                severity=ValidationSeverity.ERROR,
                message=f"Unsupported data type: {data_type.value}"
            ))
            return issues
        
        schema_class = self.schemas[data_type]
        
        try:
            schema_class(**data)
        except Exception as e:
            # Parse validation errors
            error_details = str(e)
            issues.append(ValidationIssue(
                field_name="schema_validation",
                issue_type="schema_error",
                severity=ValidationSeverity.ERROR,
                message=f"Schema validation failed: {error_details}",
                suggested_fix="Check data format and required fields"
            ))
        
        return issues
    
    def _validate_business_rules(self, data: Dict[str, Any], data_type: DataType) -> List[ValidationIssue]:
        """Validate business-specific rules."""
        issues = []
        
        if data_type == DataType.NETWORK_TRAFFIC:
            issues.extend(self._validate_network_traffic_rules(data))
        elif data_type == DataType.SYSTEM_LOG:
            issues.extend(self._validate_system_log_rules(data))
        elif data_type == DataType.USER_BEHAVIOR:
            issues.extend(self._validate_user_behavior_rules(data))
        
        return issues
    
    def _validate_network_traffic_rules(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate network traffic business rules."""
        issues = []
        
        # Check for suspicious port combinations
        source_port = data.get('source_port')
        dest_port = data.get('dest_port')
        
        if source_port and dest_port and source_port == dest_port:
            issues.append(ValidationIssue(
                field_name="port_combination",
                issue_type="suspicious_ports",
                severity=ValidationSeverity.WARNING,
                message="Source and destination ports are identical",
                suggested_fix="Verify if this is expected behavior"
            ))
        
        # Check packet size
        packet_size = data.get('packet_size', 0)
        if packet_size > 65535:
            issues.append(ValidationIssue(
                field_name="packet_size",
                issue_type="invalid_size",
                severity=ValidationSeverity.ERROR,
                message="Packet size exceeds maximum allowed",
                raw_value=packet_size
            ))
        
        return issues
    
    def _validate_system_log_rules(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate system log business rules."""
        issues = []
        
        # Check for suspicious patterns in log messages
        message = data.get('message', '')
        
        suspicious_patterns = [
            (r'failed.*login.*attempt', 'potential_brute_force'),
            (r'privilege.*escalation', 'privilege_escalation'),
            (r'unauthorized.*access', 'unauthorized_access'),
            (r'malware.*detected', 'malware_detection')
        ]
        
        for pattern, issue_type in suspicious_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                issues.append(ValidationIssue(
                    field_name="message",
                    issue_type=issue_type,
                    severity=ValidationSeverity.WARNING,
                    message=f"Suspicious pattern detected: {issue_type}",
                    suggested_fix="Review log context for security implications"
                ))
        
        return issues
    
    def _validate_user_behavior_rules(self, data: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate user behavior business rules."""
        issues = []
        
        # Check for high-risk actions
        action = data.get('action', '').lower()
        high_risk_actions = ['delete', 'modify_permissions', 'access_sensitive', 'admin_action']
        
        if any(risk_action in action for risk_action in high_risk_actions):
            issues.append(ValidationIssue(
                field_name="action",
                issue_type="high_risk_action",
                severity=ValidationSeverity.WARNING,
                message=f"High-risk action detected: {action}",
                suggested_fix="Verify user authorization for this action"
            ))
        
        # Check risk score
        risk_score = data.get('risk_score')
        if risk_score and risk_score > 0.8:
            issues.append(ValidationIssue(
                field_name="risk_score",
                issue_type="high_risk_score",
                severity=ValidationSeverity.WARNING,
                message=f"High risk score: {risk_score}",
                raw_value=risk_score
            ))
        
        return issues
    
    def _validate_data_quality(self, data: Dict[str, Any], data_type: DataType) -> List[ValidationIssue]:
        """Validate data quality metrics."""
        issues = []
        
        # Check for missing critical fields
        critical_fields = self._get_critical_fields(data_type)
        for field in critical_fields:
            if field not in data or data[field] is None or data[field] == '':
                issues.append(ValidationIssue(
                    field_name=field,
                    issue_type="missing_critical_field",
                    severity=ValidationSeverity.ERROR,
                    message=f"Critical field '{field}' is missing or empty",
                    suggested_fix=f"Provide a valid value for {field}"
                ))
        
        # Check data freshness
        timestamp_field = 'timestamp'
        if timestamp_field in data:
            timestamp = data[timestamp_field]
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    issues.append(ValidationIssue(
                        field_name=timestamp_field,
                        issue_type="invalid_timestamp",
                        severity=ValidationSeverity.ERROR,
                        message="Invalid timestamp format",
                        raw_value=data[timestamp_field]
                    ))
                    return issues
            
            if isinstance(timestamp, datetime):
                age = datetime.now() - timestamp.replace(tzinfo=None)
                if age > timedelta(hours=24):
                    issues.append(ValidationIssue(
                        field_name=timestamp_field,
                        issue_type="stale_data",
                        severity=ValidationSeverity.WARNING,
                        message=f"Data is {age.total_seconds() / 3600:.1f} hours old",
                        suggested_fix="Verify if old data is acceptable for analysis"
                    ))
        
        return issues
    
    def _validate_security(self, data: Dict[str, Any], data_type: DataType) -> List[ValidationIssue]:
        """Validate security-related aspects."""
        issues = []
        
        # Check for potential injection attacks in string fields
        string_fields = [k for k, v in data.items() if isinstance(v, str)]
        
        injection_patterns = [
            (r'<script.*?>.*?</script>', 'xss_attempt'),
            (r'union.*select', 'sql_injection'),
            (r'\.\./', 'path_traversal'),
            (r'javascript:', 'javascript_injection')
        ]
        
        for field in string_fields:
            value = data[field]
            for pattern, issue_type in injection_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append(ValidationIssue(
                        field_name=field,
                        issue_type=issue_type,
                        severity=ValidationSeverity.CRITICAL,
                        message=f"Potential security threat detected in {field}",
                        raw_value=value[:100],  # Truncate for safety
                        suggested_fix="Sanitize input and investigate source"
                    ))
        
        return issues
    
    def _get_critical_fields(self, data_type: DataType) -> List[str]:
        """Get list of critical fields for each data type."""
        critical_fields_map = {
            DataType.NETWORK_TRAFFIC: ['source_ip', 'dest_ip', 'protocol', 'timestamp'],
            DataType.SYSTEM_LOG: ['timestamp', 'log_level', 'message'],
            DataType.USER_BEHAVIOR: ['user_id', 'action', 'timestamp']
        }
        return critical_fields_map.get(data_type, [])
    
    def _clean_data(self, data: Dict[str, Any], data_type: DataType) -> Dict[str, Any]:
        """Clean data based on type."""
        if data_type == DataType.NETWORK_TRAFFIC:
            return self.cleaner.clean_network_traffic(data)
        elif data_type == DataType.SYSTEM_LOG:
            return self.cleaner.clean_system_log(data)
        elif data_type == DataType.USER_BEHAVIOR:
            return self.cleaner.clean_user_behavior(data)
        else:
            return data
    
    def _calculate_confidence_score(self, issues: List[ValidationIssue]) -> float:
        """Calculate confidence score based on validation issues."""
        if not issues:
            return 1.0
        
        severity_weights = {
            ValidationSeverity.INFO: 0.0,
            ValidationSeverity.WARNING: 0.1,
            ValidationSeverity.ERROR: 0.3,
            ValidationSeverity.CRITICAL: 0.5
        }
        
        total_penalty = sum(severity_weights.get(issue.severity, 0.0) for issue in issues)
        confidence = max(0.0, 1.0 - total_penalty)
        
        return round(confidence, 3)
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation statistics."""
        stats = self.validation_stats.copy()
        
        if stats['processing_times']:
            stats['avg_processing_time_ms'] = np.mean(stats['processing_times'])
            stats['max_processing_time_ms'] = np.max(stats['processing_times'])
            stats['min_processing_time_ms'] = np.min(stats['processing_times'])
        
        if stats['total_validations'] > 0:
            stats['success_rate'] = stats['successful_validations'] / stats['total_validations']
        else:
            stats['success_rate'] = 0.0
        
        return stats


# Global validator instance
data_validator = DataValidator()


def validate_input_data(data: Dict[str, Any], data_type: str, 
                       auto_clean: bool = True) -> ValidationResult:
    """Convenience function for data validation."""
    try:
        dt = DataType(data_type.lower())
        return data_validator.validate_data(data, dt, auto_clean)
    except ValueError:
        return ValidationResult(
            is_valid=False,
            issues=[ValidationIssue(
                field_name="data_type",
                issue_type="invalid_type",
                severity=ValidationSeverity.ERROR,
                message=f"Invalid data type: {data_type}"
            )]
        )


def get_validation_stats() -> Dict[str, Any]:
    """Get validation statistics."""
    return data_validator.get_validation_statistics()