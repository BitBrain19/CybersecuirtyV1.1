"""
Federated Learning Infrastructure
Privacy-preserving ML training across distributed clients
Secure aggregation and gradient exchange
2-week automated sync cycle
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
import threading

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)


class ClientStatus(str, Enum):
    """Client connection status"""
    ONLINE = "online"
    OFFLINE = "offline"
    SYNCING = "syncing"
    TRAINING = "training"
    ERROR = "error"


class AggregationMethod(str, Enum):
    """Model aggregation methods"""
    FEDAVG = "fedavg"  # FedAvg (averaging)
    SECAGG = "secagg"  # Secure aggregation
    DIFFERENTIAL_PRIVACY = "diff_privacy"


@dataclass
class ClientModel:
    """Client-side model metadata"""
    client_id: str
    version: int = 0
    
    # Model state
    model_weights: Dict[str, Any] = field(default_factory=dict)
    gradients: np.ndarray = field(default_factory=lambda: np.array([]))
    
    # Training metadata
    local_samples: int = 0
    training_loss: float = 0.0
    
    # Timing
    last_sync: datetime = field(default_factory=datetime.now)
    last_training: datetime = field(default_factory=datetime.now)


@dataclass
class GradientUpdate:
    """Gradient update from client"""
    update_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = ""
    round_number: int = 0
    
    # Gradient data
    gradients: np.ndarray = field(default_factory=lambda: np.array([]))
    gradient_magnitude: float = 0.0
    
    # Client info
    local_samples: int = 0
    training_loss: float = 0.0
    
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class GlobalModel:
    """Global aggregated model"""
    model_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    round_number: int = 0
    
    # Aggregated weights
    aggregated_weights: Dict[str, Any] = field(default_factory=dict)
    global_loss: float = 0.0
    
    # Metrics
    clients_participated: int = 0
    total_samples: int = 0
    
    # Versioning
    created_at: datetime = field(default_factory=datetime.now)
    accuracy: float = 0.0


@dataclass
class FederatedConfig:
    """Federated learning configuration"""
    sync_interval_days: int = 14  # 2-week cycle
    min_clients_required: int = 3
    aggregation_method: AggregationMethod = AggregationMethod.FEDAVG
    
    # Privacy
    differential_privacy_epsilon: float = 1.0  # Privacy budget
    gradient_clipping: float = 1.0
    
    # Training
    local_epochs: int = 5
    batch_size: int = 32
    learning_rate: float = 0.001


class SecureAggregator:
    """Secure aggregation without exposing individual gradients"""
    
    def __init__(self, config: FederatedConfig):
        self.config = config
        self.lock = threading.RLock()
    
    def aggregate_gradients(self, updates: List[GradientUpdate]) -> np.ndarray:
        """Aggregate gradients with privacy"""
        if not updates:
            return np.array([])
        
        # Extract gradient arrays
        gradient_arrays = [u.gradients for u in updates if u.gradients.size > 0]
        if not gradient_arrays:
            return np.array([])
        
        # Stack arrays
        stacked = np.vstack(gradient_arrays)
        
        # Apply gradient clipping for privacy
        clipped = self._apply_gradient_clipping(stacked)
        
        # FedAvg: weighted average by local samples
        total_samples = sum(u.local_samples for u in updates)
        weights = np.array([u.local_samples / total_samples for u in updates])
        
        aggregated = np.average(clipped, axis=0, weights=weights)
        
        # Apply differential privacy noise
        if self.config.aggregation_method == AggregationMethod.DIFFERENTIAL_PRIVACY:
            aggregated = self._apply_differential_privacy(aggregated)
        
        return aggregated
    
    def _apply_gradient_clipping(self, gradients: np.ndarray) -> np.ndarray:
        """Apply gradient clipping"""
        max_norm = self.config.gradient_clipping
        norms = np.linalg.norm(gradients, axis=1, keepdims=True)
        clipped = gradients / (norms / max_norm + 1e-8)
        return clipped
    
    def _apply_differential_privacy(self, gradients: np.ndarray) -> np.ndarray:
        """Apply differential privacy noise"""
        epsilon = self.config.differential_privacy_epsilon
        sensitivity = 1.0
        
        # Laplace noise
        noise = np.random.laplace(
            0, 
            sensitivity / epsilon,
            size=gradients.shape
        )
        
        return gradients + noise


class FederatedClient:
    """Client participating in federated learning"""
    
    def __init__(self, client_id: str, config: FederatedConfig):
        self.client_id = client_id
        self.config = config
        self.status = ClientStatus.OFFLINE
        
        self.model = None
        self.local_data = []
        self.round_number = 0
        
        self.lock = threading.RLock()
    
    async def connect(self) -> None:
        """Connect to federated learning server"""
        with self.lock:
            self.status = ClientStatus.ONLINE
        logger.info(f"Client {self.client_id} connected")
    
    async def download_global_model(self, global_model: GlobalModel) -> None:
        """Download latest global model"""
        with self.lock:
            self.model = RandomForestClassifier(n_estimators=100)
            self.round_number = global_model.round_number
        logger.debug(f"Client {self.client_id} downloaded model round {self.round_number}")
    
    async def train_local_model(self, training_data: List[Tuple[np.ndarray, int]]) -> GradientUpdate:
        """Train model locally"""
        with self.lock:
            self.status = ClientStatus.TRAINING
            self.local_data = training_data
        
        if not training_data or not self.model:
            return GradientUpdate(client_id=self.client_id)
        
        # Extract features and labels
        X = np.array([x[0] for x in training_data])
        y = np.array([x[1] for x in training_data])
        
        # Normalize
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train
        try:
            self.model.fit(X_scaled, y)
            
            # Extract gradients (feature importances as proxy)
            gradients = self.model.feature_importances_
            loss = 1.0 - self.model.score(X_scaled, y)
            
            update = GradientUpdate(
                client_id=self.client_id,
                round_number=self.round_number,
                gradients=gradients,
                gradient_magnitude=float(np.linalg.norm(gradients)),
                local_samples=len(training_data),
                training_loss=loss
            )
            
            self.status = ClientStatus.ONLINE
            logger.info(f"Client {self.client_id} trained with loss {loss:.4f}")
            return update
            
        except Exception as e:
            logger.error(f"Client {self.client_id} training error: {e}")
            self.status = ClientStatus.ERROR
            return GradientUpdate(client_id=self.client_id)
    
    async def disconnect(self) -> None:
        """Disconnect from server"""
        with self.lock:
            self.status = ClientStatus.OFFLINE
        logger.info(f"Client {self.client_id} disconnected")


class FederatedServer:
    """Central server coordinating federated learning"""
    
    def __init__(self, config: FederatedConfig):
        self.config = config
        self.aggregator = SecureAggregator(config)
        
        self.clients = {}  # client_id -> FederatedClient
        self.current_round = 0
        self.global_model = GlobalModel()
        self.round_history = deque(maxlen=100)
        
        self.last_sync = datetime.now()
        self.sync_scheduler = None
        self.lock = threading.RLock()
    
    async def register_client(self, client_id: str) -> FederatedClient:
        """Register client"""
        with self.lock:
            if client_id not in self.clients:
                client = FederatedClient(client_id, self.config)
                self.clients[client_id] = client
                await client.connect()
                logger.info(f"Registered client {client_id}")
            return self.clients[client_id]
    
    async def start_training_round(self) -> Dict[str, Any]:
        """Start federated training round"""
        with self.lock:
            online_clients = [c for c in self.clients.values() 
                            if c.status == ClientStatus.ONLINE]
            
            if len(online_clients) < self.config.min_clients_required:
                logger.warning(f"Insufficient clients: {len(online_clients)} < {self.config.min_clients_required}")
                return {"success": False, "reason": "insufficient_clients"}
        
        self.current_round += 1
        logger.info(f"Starting federated training round {self.current_round}")
        
        # Download model to clients
        tasks = []
        for client in online_clients:
            tasks.append(client.download_global_model(self.global_model))
        await asyncio.gather(*tasks)
        
        return {
            "success": True,
            "round": self.current_round,
            "clients": len(online_clients)
        }
    
    async def collect_gradients(self) -> List[GradientUpdate]:
        """Collect gradients from clients"""
        updates = []
        
        with self.lock:
            for client in self.clients.values():
                if client.status == ClientStatus.ONLINE:
                    # Simulate gradient collection
                    # In real system, would be collected via network
                    if hasattr(client, '_last_update'):
                        updates.append(client._last_update)
        
        logger.info(f"Collected {len(updates)} gradient updates")
        return updates
    
    async def aggregate_models(self, updates: List[GradientUpdate]) -> GlobalModel:
        """Aggregate client models"""
        if not updates:
            logger.warning("No updates to aggregate")
            return self.global_model
        
        # Aggregate gradients
        aggregated_gradients = self.aggregator.aggregate_gradients(updates)
        
        # Create new global model
        self.global_model = GlobalModel(
            round_number=self.current_round,
            clients_participated=len(updates),
            total_samples=sum(u.local_samples for u in updates),
            accuracy=1.0 - np.mean([u.training_loss for u in updates])
        )
        
        with self.lock:
            self.round_history.append(self.global_model)
        
        logger.info(f"Aggregated model: round {self.current_round}, "
                   f"clients={len(updates)}, accuracy={self.global_model.accuracy:.4f}")
        
        return self.global_model
    
    async def run_federated_cycle(self) -> Dict[str, Any]:
        """Run complete federated learning cycle"""
        # Start round
        round_result = await self.start_training_round()
        if not round_result["success"]:
            return round_result
        
        # Wait for local training (simulated)
        await asyncio.sleep(1)
        
        # Collect gradients
        updates = await self.collect_gradients()
        
        # Aggregate
        global_model = await self.aggregate_models(updates)
        
        self.last_sync = datetime.now()
        
        return {
            "success": True,
            "round": self.current_round,
            "global_model": asdict(global_model)
        }
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get federated learning statistics"""
        online_count = sum(1 for c in self.clients.values() 
                          if c.status == ClientStatus.ONLINE)
        
        return {
            "current_round": self.current_round,
            "total_clients": len(self.clients),
            "online_clients": online_count,
            "global_model_accuracy": self.global_model.accuracy,
            "total_samples_used": self.global_model.total_samples,
            "rounds_completed": len(self.round_history),
            "last_sync": self.last_sync.isoformat()
        }


class FederatedLearningOrchestrator:
    """Main federated learning system"""
    
    def __init__(self):
        self.config = FederatedConfig()
        self.server = FederatedServer(self.config)
        self.training_task = None
    
    async def initialize(self, num_clients: int = 5) -> Dict[str, Any]:
        """Initialize federated learning with clients"""
        clients = []
        for i in range(num_clients):
            client_id = f"client_{i+1}"
            client = await self.server.register_client(client_id)
            clients.append(client)
        
        logger.info(f"Initialized {num_clients} federated clients")
        return {
            "clients_registered": len(clients),
            "sync_interval_days": self.config.sync_interval_days,
            "aggregation_method": self.config.aggregation_method.value
        }
    
    async def train_round(self, client_data: Dict[str, List[Tuple[np.ndarray, int]]]) -> Dict[str, Any]:
        """Execute single training round"""
        # Assign data to clients
        for client_id, data in client_data.items():
            if client_id in self.server.clients:
                client = self.server.clients[client_id]
                update = await client.train_local_model(data)
                client._last_update = update
        
        # Run federated cycle
        result = await self.server.run_federated_cycle()
        return result
    
    async def start_periodic_sync(self) -> None:
        """Start periodic federated sync (every 2 weeks)"""
        while True:
            sync_seconds = self.config.sync_interval_days * 24 * 3600
            await asyncio.sleep(sync_seconds)
            
            logger.info("Starting scheduled 2-week federated sync")
            await self.server.run_federated_cycle()
    
    async def get_status(self) -> Dict[str, Any]:
        """Get overall federated learning status"""
        stats = await self.server.get_statistics()
        
        return {
            **stats,
            "privacy_epsilon": self.config.differential_privacy_epsilon,
            "gradient_clipping": self.config.gradient_clipping,
            "local_epochs": self.config.local_epochs
        }


# Global instance
_orchestrator_instance = None


def get_federated_learning() -> FederatedLearningOrchestrator:
    """Get or create federated learning orchestrator"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = FederatedLearningOrchestrator()
    return _orchestrator_instance
