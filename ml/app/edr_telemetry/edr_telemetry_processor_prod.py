"""
EDR Telemetry Modeling and Normalization
Process tree building, command-line parsing, event profiling
Real EDR telemetry ingestion and analysis
"""

import asyncio
import json
import logging
import uuid
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque
import threading

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class ProcessEventType(str, Enum):
    """EDR process event types"""
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    THREAD_CREATE = "thread_create"
    IMAGE_LOAD = "image_load"
    FILE_CREATE = "file_create"
    REGISTRY_EVENT = "registry_event"
    NETWORK_CONNECTION = "network_connection"
    MEMORY_ACCESS = "memory_access"


@dataclass
class ProcessNode:
    """Node in process tree"""
    process_id: int
    parent_process_id: int
    process_name: str
    command_line: str
    
    user: str = ""
    image_path: str = ""
    
    # Timing
    create_time: datetime = field(default_factory=datetime.now)
    terminate_time: Optional[datetime] = None
    
    # Children
    children: List['ProcessNode'] = field(default_factory=list)
    
    # Telemetry
    file_operations: List[Dict[str, Any]] = field(default_factory=list)
    registry_operations: List[Dict[str, Any]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    image_loads: List[str] = field(default_factory=list)


@dataclass
class TelemetryEvent:
    """EDR telemetry event"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: ProcessEventType = ProcessEventType.PROCESS_CREATE
    
    timestamp: datetime = field(default_factory=datetime.now)
    source_host: str = ""
    
    # Process context
    process_id: int = 0
    parent_process_id: int = 0
    process_name: str = ""
    command_line: str = ""
    user: str = ""
    
    # Event-specific data
    details: Dict[str, Any] = field(default_factory=dict)
    raw_event: str = ""


@dataclass
class ProcessProfile:
    """Normalized process profile"""
    process_hash: str  # Hash of normalized process
    process_name: str
    
    # Command line analysis
    command_line_hash: str
    is_obfuscated: bool = False
    obfuscation_score: float = 0.0
    
    # Behavior profile
    typical_parent_processes: Set[str] = field(default_factory=set)
    typical_users: Set[str] = field(default_factory=set)
    typical_image_paths: Set[str] = field(default_factory=set)
    
    # File operations
    file_operations_count: int = 0
    critical_file_accesses: int = 0
    
    # Registry operations
    registry_operations_count: int = 0
    persistence_registry_writes: int = 0
    
    # Network operations
    network_connections_count: int = 0
    outbound_connections: int = 0
    c2_indicators: int = 0
    
    # Risk scoring
    base_risk_score: float = 0.0


class CommandLineParser:
    """Parse and analyze command lines"""
    
    # Common legitimate patterns
    LEGITIMATE_PATTERNS = {
        r'c:\\(?:windows|program files)',
        r'\.exe\s+\/[a-z]',
        r'powershell\s+-',
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        r'\.exe\s*\|',
        r'cmd\s+\/c',
        r'powershell.*-enc',
        r'rundll32.*\.dll',
        r'regsvcs.*\.exe',
        r'mshta.*vbs',
        r'bitsadmin.*transfer',
        r'certutil.*-decode',
        r'\\x[0-9a-f]{2}',  # Hex encoding
    }
    
    def __init__(self):
        self.parser_cache = {}
    
    def parse_command_line(self, cmd_line: str) -> Dict[str, Any]:
        """Parse command line"""
        if cmd_line in self.parser_cache:
            return self.parser_cache[cmd_line]
        
        result = {
            "original": cmd_line,
            "normalized": self._normalize(cmd_line),
            "hash": self._hash_command(cmd_line),
            "is_obfuscated": self._detect_obfuscation(cmd_line),
            "suspicious_patterns": self._find_suspicious_patterns(cmd_line),
            "arguments": self._extract_arguments(cmd_line),
            "suspicious_score": 0.0
        }
        
        # Calculate suspicion score
        result["suspicious_score"] = self._calculate_suspicion_score(result)
        
        self.parser_cache[cmd_line] = result
        return result
    
    def _normalize(self, cmd_line: str) -> str:
        """Normalize command line"""
        # Remove encoding
        normalized = cmd_line.replace("\\x", "").replace("\\", "")
        # Remove quotes
        normalized = normalized.replace("'", "").replace('"', '')
        # Convert to lowercase
        normalized = normalized.lower()
        # Remove excessive spaces
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized
    
    def _hash_command(self, cmd_line: str) -> str:
        """Hash command line"""
        import hashlib
        normalized = self._normalize(cmd_line)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def _detect_obfuscation(self, cmd_line: str) -> bool:
        """Detect command line obfuscation"""
        indicators = 0
        
        # Hex/encoding indicators
        if re.search(r'\\x[0-9a-f]{2}', cmd_line, re.I):
            indicators += 1
        if "base64" in cmd_line.lower():
            indicators += 1
        
        # Excessive special characters
        special_chars = len([c for c in cmd_line if c in "^%*|&"])
        if special_chars > 5:
            indicators += 1
        
        # PowerShell obfuscation
        if "-enc" in cmd_line.lower() or "-e" in cmd_line.lower():
            indicators += 1
        
        return indicators >= 2
    
    def _find_suspicious_patterns(self, cmd_line: str) -> List[str]:
        """Find suspicious patterns"""
        suspicious = []
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmd_line, re.I):
                suspicious.append(pattern)
        
        return suspicious
    
    def _extract_arguments(self, cmd_line: str) -> List[str]:
        """Extract arguments"""
        # Simple split
        parts = cmd_line.split()
        if len(parts) > 1:
            return parts[1:]
        return []
    
    def _calculate_suspicion_score(self, parsed: Dict[str, Any]) -> float:
        """Calculate command line suspicion score"""
        score = 0.0
        
        if parsed["is_obfuscated"]:
            score += 0.5
        
        score += len(parsed["suspicious_patterns"]) * 0.15
        
        return float(min(1.0, score))


class ProcessTreeBuilder:
    """Build process tree from telemetry"""
    
    def __init__(self):
        self.processes = {}  # pid -> ProcessNode
        self.roots = []  # Root processes
        self.lock = threading.RLock()
        self.cmd_parser = CommandLineParser()
    
    def add_process(self, event: TelemetryEvent) -> ProcessNode:
        """Add process to tree"""
        with self.lock:
            pid = event.process_id
            ppid = event.parent_process_id
            
            # Check if exists
            if pid in self.processes:
                node = self.processes[pid]
                return node
            
            # Create node
            node = ProcessNode(
                process_id=pid,
                parent_process_id=ppid,
                process_name=event.process_name,
                command_line=event.command_line,
                user=event.user,
                image_path=event.details.get("image_path", ""),
                create_time=event.timestamp
            )
            
            self.processes[pid] = node
            
            # Add to parent's children
            if ppid in self.processes:
                self.processes[ppid].children.append(node)
            else:
                self.roots.append(node)
            
            logger.debug(f"Added process {pid} ({event.process_name})")
            return node
    
    def record_file_operation(self, pid: int, operation: Dict[str, Any]) -> None:
        """Record file operation"""
        with self.lock:
            if pid in self.processes:
                self.processes[pid].file_operations.append(operation)
    
    def record_registry_operation(self, pid: int, operation: Dict[str, Any]) -> None:
        """Record registry operation"""
        with self.lock:
            if pid in self.processes:
                self.processes[pid].registry_operations.append(operation)
    
    def record_network_connection(self, pid: int, connection: Dict[str, Any]) -> None:
        """Record network connection"""
        with self.lock:
            if pid in self.processes:
                self.processes[pid].network_connections.append(connection)
    
    def record_image_load(self, pid: int, image_path: str) -> None:
        """Record DLL/image load"""
        with self.lock:
            if pid in self.processes:
                self.processes[pid].image_loads.append(image_path)
    
    def get_process_tree_depth(self, node: ProcessNode, depth: int = 0) -> int:
        """Get tree depth from node"""
        if not node.children:
            return depth
        return max(self.get_process_tree_depth(child, depth + 1) 
                  for child in node.children)
    
    def get_process_tree(self) -> str:
        """Get ASCII process tree"""
        lines = []
        for root in self.roots:
            lines.append(self._build_tree_string(root))
        return "\n".join(lines)
    
    def _build_tree_string(self, node: ProcessNode, prefix: str = "") -> str:
        """Recursively build tree string"""
        lines = [f"{prefix}{node.process_name} ({node.process_id})"]
        for child in node.children:
            lines.append(self._build_tree_string(child, prefix + "  "))
        return "\n".join(lines)


class EventNormalizer:
    """Normalize EDR events from different sources"""
    
    def __init__(self):
        self.normalizer_cache = {}
        self.cmd_parser = CommandLineParser()
    
    def normalize_event(self, event: TelemetryEvent) -> Dict[str, Any]:
        """Normalize event to canonical format"""
        normalized = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "source_host": event.source_host,
            "process": {
                "id": event.process_id,
                "parent_id": event.parent_process_id,
                "name": event.process_name,
                "user": event.user,
                "image_path": event.details.get("image_path", "")
            }
        }
        
        # Parse command line
        if event.command_line:
            normalized["command_line"] = self.cmd_parser.parse_command_line(
                event.command_line
            )
        
        # Normalize event details
        normalized["details"] = self._normalize_details(
            event.event_type, event.details
        )
        
        return normalized
    
    def _normalize_details(self, event_type: ProcessEventType, 
                          details: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize event-specific details"""
        if event_type == ProcessEventType.FILE_CREATE:
            return {
                "file_path": details.get("file_path", "").lower(),
                "operation": details.get("operation", ""),
                "desired_access": details.get("desired_access", "")
            }
        elif event_type == ProcessEventType.REGISTRY_EVENT:
            return {
                "registry_path": details.get("registry_path", "").lower(),
                "operation": details.get("operation", ""),
                "value": details.get("value", "")
            }
        elif event_type == ProcessEventType.NETWORK_CONNECTION:
            return {
                "protocol": details.get("protocol", "").lower(),
                "source_ip": details.get("source_ip", ""),
                "dest_ip": details.get("dest_ip", ""),
                "dest_port": details.get("dest_port", 0)
            }
        
        return details


class EDRTelemetryProcessor:
    """Main EDR telemetry processor"""
    
    def __init__(self):
        self.tree_builder = ProcessTreeBuilder()
        self.normalizer = EventNormalizer()
        self.cmd_parser = CommandLineParser()
        
        self.event_buffer = deque(maxlen=100000)
        self.process_profiles = {}  # process_hash -> ProcessProfile
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.05)
        
        self.lock = threading.RLock()
    
    async def ingest_event(self, event: TelemetryEvent) -> Dict[str, Any]:
        """Ingest EDR telemetry event"""
        # Normalize
        normalized = self.normalizer.normalize_event(event)
        
        # Update process tree
        if event.event_type == ProcessEventType.PROCESS_CREATE:
            self.tree_builder.add_process(event)
        elif event.event_type == ProcessEventType.FILE_CREATE:
            self.tree_builder.record_file_operation(
                event.process_id,
                normalized["details"]
            )
        elif event.event_type == ProcessEventType.REGISTRY_EVENT:
            self.tree_builder.record_registry_operation(
                event.process_id,
                normalized["details"]
            )
        elif event.event_type == ProcessEventType.NETWORK_CONNECTION:
            self.tree_builder.record_network_connection(
                event.process_id,
                normalized["details"]
            )
        
        with self.lock:
            self.event_buffer.append(normalized)
        
        logger.debug(f"Ingested {event.event_type.value} event")
        return normalized
    
    def profile_process(self, process_node: ProcessNode) -> ProcessProfile:
        """Create profile for process"""
        cmd_parsed = self.cmd_parser.parse_command_line(process_node.command_line)
        
        profile = ProcessProfile(
            process_hash=cmd_parsed["hash"],
            process_name=process_node.process_name,
            command_line_hash=cmd_parsed["hash"],
            is_obfuscated=cmd_parsed["is_obfuscated"],
            obfuscation_score=cmd_parsed["suspicious_score"],
            typical_parent_processes={f"{process_node.parent_process_id}"},
            typical_users={process_node.user},
            typical_image_paths={process_node.image_path},
            file_operations_count=len(process_node.file_operations),
            registry_operations_count=len(process_node.registry_operations),
            network_connections_count=len(process_node.network_connections)
        )
        
        # Analyze operations
        profile = self._analyze_operations(profile, process_node)
        
        # Calculate risk
        profile.base_risk_score = self._calculate_risk_score(profile)
        
        return profile
    
    def _analyze_operations(self, profile: ProcessProfile, 
                           node: ProcessNode) -> ProcessProfile:
        """Analyze process operations"""
        # File operations
        critical_files = {
            "system32", "drivers", "windows", "config", "sam"
        }
        for op in node.file_operations:
            file_path = op.get("file_path", "").lower()
            if any(cf in file_path for cf in critical_files):
                profile.critical_file_accesses += 1
        
        # Registry operations
        persistence_keys = {
            "run", "runonce", "startup", "shell", "services"
        }
        for op in node.registry_operations:
            reg_path = op.get("registry_path", "").lower()
            if any(pk in reg_path for pk in persistence_keys):
                profile.persistence_registry_writes += 1
        
        # Network operations
        c2_ports = {4444, 5555, 6666, 7777, 8888}
        for conn in node.network_connections:
            port = conn.get("dest_port", 0)
            if port in c2_ports:
                profile.c2_indicators += 1
            profile.outbound_connections += 1
        
        return profile
    
    def _calculate_risk_score(self, profile: ProcessProfile) -> float:
        """Calculate process risk score"""
        score = 0.0
        
        # Obfuscation
        score += profile.obfuscation_score * 0.3
        
        # Critical file access
        score += min(0.3, profile.critical_file_accesses * 0.1)
        
        # Persistence mechanisms
        score += min(0.2, profile.persistence_registry_writes * 0.05)
        
        # C2 indicators
        score += min(0.2, profile.c2_indicators * 0.1)
        
        return float(min(1.0, score))
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        with self.lock:
            num_events = len(self.event_buffer)
            num_processes = len(self.tree_builder.processes)
            num_profiles = len(self.process_profiles)
            tree_depth = max(
                (self.tree_builder.get_process_tree_depth(root) 
                 for root in self.tree_builder.roots),
                default=0
            )
        
        return {
            "events_ingested": num_events,
            "unique_processes": num_processes,
            "process_profiles": num_profiles,
            "process_tree_depth": tree_depth,
            "event_buffer_size": len(self.event_buffer)
        }


# Global instance
_edr_processor_instance = None


def get_edr_telemetry_processor() -> EDRTelemetryProcessor:
    """Get or create EDR processor"""
    global _edr_processor_instance
    if _edr_processor_instance is None:
        _edr_processor_instance = EDRTelemetryProcessor()
    return _edr_processor_instance
