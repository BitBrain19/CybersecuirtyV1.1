"""
Graph-Based Attack Path Prediction Model
Analyzes host-user-process-connection relationships
Predicts and scores lateral movement chains
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque
import threading

import numpy as np
try:
    import networkx as nx
except ImportError:
    nx = None
    logging.warning("NetworkX not available - using simplified graph")

logger = logging.getLogger(__name__)


class EntityType(str, Enum):
    """Entity types in attack graph"""
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    NETWORK_CONNECTION = "network_connection"
    RESOURCE = "resource"


class EdgeType(str, Enum):
    """Relationship types"""
    EXECUTED_ON = "executed_on"  # Process -> Host
    EXECUTED_BY = "executed_by"  # Process -> User
    CONNECTS_TO = "connects_to"  # Connection -> Host
    ACCESSES = "accesses"  # User -> Resource
    CREATED_BY = "created_by"  # Resource -> Process
    LATERAL_MOVE = "lateral_move"  # Host -> Host


@dataclass
class GraphNode:
    """Graph node representing entity"""
    node_id: str
    entity_type: EntityType
    label: str
    
    # Risk scoring
    risk_score: float = 0.0
    compromise_probability: float = 0.0
    
    # Attributes
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    # Discovery
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    

@dataclass
class GraphEdge:
    """Graph edge representing relationship"""
    source_id: str
    target_id: str
    edge_type: EdgeType
    
    # Scoring
    strength: float = 1.0  # 0-1.0
    frequency: int = 1
    
    # Temporal
    first_observed: datetime = field(default_factory=datetime.now)
    last_observed: datetime = field(default_factory=datetime.now)


@dataclass
class AttackPath:
    """Represents an attack path/chain"""
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    
    # Scoring
    path_risk_score: float = 0.0
    lateral_movement_likelihood: float = 0.0
    
    # Description
    description: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    
    timestamp: datetime = field(default_factory=datetime.now)


class AttackGraphBuilder:
    """Build attack graph from events"""
    
    def __init__(self):
        if nx:
            self.graph = nx.DiGraph()
        else:
            self.graph = None  # Fallback to manual management
        
        self.nodes = {}  # node_id -> GraphNode
        self.edges = defaultdict(list)  # (source, target) -> [GraphEdge]
        self.lock = threading.RLock()
    
    def add_node(self, node_id: str, entity_type: EntityType, label: str, 
                 attributes: Dict[str, Any] = None) -> GraphNode:
        """Add node to graph"""
        attributes = attributes or {}
        
        with self.lock:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                node.last_seen = datetime.now()
                return node
            
            node = GraphNode(
                node_id=node_id,
                entity_type=entity_type,
                label=label,
                attributes=attributes
            )
            self.nodes[node_id] = node
            
            if self.graph:
                self.graph.add_node(node_id, type=entity_type.value, label=label)
            
            logger.debug(f"Added node: {node_id} ({entity_type.value})")
            return node
    
    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType,
                 strength: float = 1.0) -> GraphEdge:
        """Add edge to graph"""
        with self.lock:
            key = (source_id, target_id)
            
            # Check if edge exists
            for edge in self.edges[key]:
                if edge.edge_type == edge_type:
                    edge.frequency += 1
                    edge.last_observed = datetime.now()
                    edge.strength = min(1.0, edge.strength + 0.1)
                    return edge
            
            # Create new edge
            edge = GraphEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                strength=strength
            )
            self.edges[key].append(edge)
            
            if self.graph:
                self.graph.add_edge(source_id, target_id, 
                                   type=edge_type.value, weight=strength)
            
            logger.debug(f"Added edge: {source_id} --[{edge_type.value}]--> {target_id}")
            return edge
    
    def update_node_risk(self, node_id: str, risk_score: float) -> None:
        """Update node risk score"""
        with self.lock:
            if node_id in self.nodes:
                self.nodes[node_id].risk_score = max(0, min(1, risk_score))
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by ID"""
        with self.lock:
            return self.nodes.get(node_id)
    
    def get_edges_from(self, source_id: str) -> List[GraphEdge]:
        """Get all outgoing edges"""
        with self.lock:
            result = []
            for (src, _), edges in self.edges.items():
                if src == source_id:
                    result.extend(edges)
            return result
    
    def get_edges_to(self, target_id: str) -> List[GraphEdge]:
        """Get all incoming edges"""
        with self.lock:
            result = []
            for (_, tgt), edges in self.edges.items():
                if tgt == target_id:
                    result.extend(edges)
            return result


class PathFinder:
    """Find and score attack paths"""
    
    def __init__(self, graph_builder: AttackGraphBuilder):
        self.graph_builder = graph_builder
    
    def find_paths(self, source_id: str, max_hops: int = 5) -> List[AttackPath]:
        """Find attack paths from source"""
        paths = []
        visited = set()
        
        # BFS to find paths
        queue = [(source_id, [source_id], [])]
        
        while queue:
            current_id, node_path, edge_path = queue.pop(0)
            
            if len(node_path) > max_hops:
                continue
            
            current_node = self.graph_builder.get_node(current_id)
            if not current_node:
                continue
            
            # Convert path to AttackPath
            if len(node_path) > 1:
                attack_path = self._build_attack_path(node_path, edge_path)
                paths.append(attack_path)
            
            # Explore neighbors
            for edge in self.graph_builder.get_edges_from(current_id):
                next_id = edge.target_id
                
                # Avoid cycles, limit exploration
                if next_id not in node_path or len(node_path) < 3:
                    new_node_path = node_path + [next_id]
                    new_edge_path = edge_path + [edge]
                    queue.append((next_id, new_node_path, new_edge_path))
        
        # Sort by risk
        paths.sort(key=lambda p: p.path_risk_score, reverse=True)
        return paths[:10]  # Top 10 paths
    
    def _build_attack_path(self, node_ids: List[str], edges: List[GraphEdge]) -> AttackPath:
        """Build AttackPath from node/edge sequence"""
        nodes = []
        for node_id in node_ids:
            node = self.graph_builder.get_node(node_id)
            if node:
                nodes.append(node)
        
        # Score path
        path_risk = self._score_path(nodes, edges)
        
        # Detect lateral movement
        lateral_movement = self._detect_lateral_movement(nodes)
        
        # Map to MITRE techniques
        mitre_techniques = self._map_mitre_techniques(nodes, edges)
        
        return AttackPath(
            nodes=nodes,
            edges=edges,
            path_risk_score=path_risk,
            lateral_movement_likelihood=lateral_movement,
            description=self._generate_description(nodes),
            mitre_techniques=mitre_techniques
        )
    
    def _score_path(self, nodes: List[GraphNode], edges: List[GraphEdge]) -> float:
        """Score attack path risk"""
        if not nodes:
            return 0.0
        
        # Node risk component
        node_risk = np.mean([n.risk_score for n in nodes]) if nodes else 0
        
        # Edge strength component
        edge_strength = np.mean([e.strength for e in edges]) if edges else 1.0
        
        # Path length component (longer = more work for attacker)
        length_score = 1.0 - (len(nodes) - 1) * 0.1
        
        # Combined score
        path_risk = (node_risk * 0.4 + edge_strength * 0.4 + length_score * 0.2)
        return float(min(1.0, path_risk))
    
    def _detect_lateral_movement(self, nodes: List[GraphNode]) -> float:
        """Detect lateral movement likelihood"""
        if len(nodes) < 2:
            return 0.0
        
        # Count host-to-host transitions
        host_transitions = 0
        for i in range(len(nodes) - 1):
            if (nodes[i].entity_type == EntityType.HOST and 
                nodes[i+1].entity_type == EntityType.HOST):
                host_transitions += 1
        
        likelihood = min(1.0, host_transitions * 0.3)
        return float(likelihood)
    
    def _map_mitre_techniques(self, nodes: List[GraphNode], edges: List[GraphEdge]) -> List[str]:
        """Map to MITRE ATT&CK techniques"""
        techniques = set()
        
        # Analyze path components
        for node in nodes:
            if node.entity_type == EntityType.PROCESS:
                if "powershell" in str(node.label).lower():
                    techniques.add("T1086")  # PowerShell
                if "cmd" in str(node.label).lower():
                    techniques.add("T1059")  # Command Line Interface
            
            elif node.entity_type == EntityType.USER:
                techniques.add("T1078")  # Valid Accounts
        
        # Analyze edge types
        for edge in edges:
            if edge.edge_type == EdgeType.LATERAL_MOVE:
                techniques.add("T1570")  # Lateral Movement
            elif edge.edge_type == EdgeType.EXECUTED_BY:
                techniques.add("T1204")  # User Execution
        
        return list(techniques)
    
    def _generate_description(self, nodes: List[GraphNode]) -> str:
        """Generate natural description"""
        if not nodes:
            return ""
        
        parts = []
        for i, node in enumerate(nodes):
            if i == 0:
                parts.append(f"Starting from {node.label} ({node.entity_type.value})")
            else:
                parts.append(f"Moving to {node.label}")
        
        return " → ".join(parts)


class AttackPathPredictor:
    """Main attack path prediction system"""
    
    def __init__(self):
        self.graph = AttackGraphBuilder()
        self.path_finder = PathFinder(self.graph)
        self.detected_paths = deque(maxlen=1000)
        self.lock = threading.RLock()
    
    async def record_process_execution(self, host_id: str, user_id: str, 
                                       process_name: str, pid: int) -> None:
        """Record process execution in graph"""
        # Add nodes
        host_node = self.graph.add_node(
            host_id, EntityType.HOST, host_id, {"type": "endpoint"}
        )
        user_node = self.graph.add_node(
            user_id, EntityType.USER, user_id, {"type": "account"}
        )
        process_id = f"proc_{pid}_{process_name}"
        process_node = self.graph.add_node(
            process_id, EntityType.PROCESS, process_name, {"pid": pid}
        )
        
        # Add edges
        self.graph.add_edge(process_id, host_id, EdgeType.EXECUTED_ON)
        self.graph.add_edge(process_id, user_id, EdgeType.EXECUTED_BY)
    
    async def record_network_connection(self, source_host: str, dest_host: str,
                                        dest_port: int) -> None:
        """Record network connection"""
        conn_id = f"conn_{source_host}_{dest_host}_{dest_port}"
        
        source_node = self.graph.add_node(
            source_host, EntityType.HOST, source_host, {"type": "endpoint"}
        )
        dest_node = self.graph.add_node(
            dest_host, EntityType.HOST, dest_host, {"type": "endpoint"}
        )
        
        # Add connection node and edges
        self.graph.add_node(conn_id, EntityType.NETWORK_CONNECTION, 
                           f"Conn to {dest_host}:{dest_port}",
                           {"port": dest_port})
        
        self.graph.add_edge(source_host, conn_id, EdgeType.CONNECTS_TO)
        self.graph.add_edge(conn_id, dest_host, EdgeType.CONNECTS_TO)
    
    async def predict_attack_paths(self, source_id: str = None) -> List[AttackPath]:
        """Predict attack paths"""
        sources = [source_id] if source_id else list(self.graph.nodes.keys())
        
        all_paths = []
        for source in sources[:5]:  # Limit to 5 sources
            paths = self.path_finder.find_paths(source)
            all_paths.extend(paths)
        
        # Sort by risk
        all_paths.sort(key=lambda p: p.path_risk_score, reverse=True)
        
        with self.lock:
            for path in all_paths[:10]:
                self.detected_paths.append(path)
        
        return all_paths[:10]  # Top 10 paths
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get attack graph statistics"""
        with self.lock:
            num_nodes = len(self.graph.nodes)
            num_edges = sum(len(edges) for edges in self.graph.edges.values())
            num_hosts = sum(
                1 for n in self.graph.nodes.values()
                if n.entity_type == EntityType.HOST
            )
            num_users = sum(
                1 for n in self.graph.nodes.values()
                if n.entity_type == EntityType.USER
            )
        
        return {
            "graph_nodes": num_nodes,
            "graph_edges": num_edges,
            "hosts_discovered": num_hosts,
            "users_discovered": num_users,
            "attack_paths_found": len(self.detected_paths)
        }


# Global instance
_predictor_instance = None


def get_attack_path_predictor() -> AttackPathPredictor:
    """Get or create predictor"""
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = AttackPathPredictor()
    return _predictor_instance
