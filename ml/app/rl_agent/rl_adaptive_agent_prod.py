"""
Reinforcement Learning Adaptive SOC Agent
Learns response effectiveness, optimizes for MTTR, continuous learning with safe rollback
"""

import asyncio
import json
import logging
import threading
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import deque, defaultdict
import numpy as np

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None
    keras = None

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    """Action types the RL agent can take"""
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    REVOKE_CREDENTIALS = "revoke_credentials"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    ESCALATE_TO_SOC = "escalate_to_soc"
    COLLECT_FORENSICS = "collect_forensics"
    SNAPSHOT_VM = "snapshot_vm"
    ENABLE_ENDPOINT_EDR = "enable_endpoint_edr"


class IncidentSeverity(str, Enum):
    """Incident severity for RL state"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RLState:
    """State representation for RL agent"""
    incident_id: str
    severity: IncidentSeverity
    num_affected_hosts: int
    num_affected_users: int
    contains_exfiltration: bool
    contains_persistence: bool
    lateral_movement_detected: bool
    time_since_detection_seconds: int
    previous_actions: List[ActionType] = field(default_factory=list)
    threat_score: float = 0.0
    
    def to_feature_vector(self) -> np.ndarray:
        """Convert state to neural network input"""
        severity_map = {
            IncidentSeverity.CRITICAL: 1.0,
            IncidentSeverity.HIGH: 0.75,
            IncidentSeverity.MEDIUM: 0.5,
            IncidentSeverity.LOW: 0.25,
            IncidentSeverity.INFO: 0.1
        }
        
        return np.array([
            severity_map.get(self.severity, 0.5),
            min(self.num_affected_hosts / 100.0, 1.0),
            min(self.num_affected_users / 100.0, 1.0),
            float(self.contains_exfiltration),
            float(self.contains_persistence),
            float(self.lateral_movement_detected),
            min(self.time_since_detection_seconds / 3600.0, 1.0),
            len(self.previous_actions) / 10.0,
            min(self.threat_score / 100.0, 1.0),
        ], dtype=np.float32)


@dataclass
class RLExperience:
    """Experience for replay buffer"""
    state: RLState
    action: ActionType
    reward: float
    next_state: RLState
    done: bool
    timestamp: datetime = field(default_factory=datetime.now)


class DQNAgent:
    """Deep Q-Network agent for incident response"""
    
    def __init__(self, learning_rate: float = 0.001, gamma: float = 0.95, epsilon: float = 0.1):
        self.learning_rate = learning_rate
        self.gamma = gamma  # Discount factor
        self.epsilon = epsilon  # Exploration rate
        self.model = None
        self.target_model = None
        self.memory = deque(maxlen=10000)
        self._lock = threading.RLock()
        self.training_count = 0
        
        if TENSORFLOW_AVAILABLE:
            self._build_network()
    
    def _build_network(self):
        """Build DQN network"""
        state_size = 9
        action_size = len(ActionType)
        
        self.model = keras.Sequential([
            layers.Input(shape=(state_size,)),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(64, activation='relu'),
            layers.Dense(action_size, activation='linear')
        ])
        
        self.target_model = keras.models.clone_model(self.model)
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='mse'
        )
    
    def remember(self, state: RLState, action: ActionType, reward: float, 
                next_state: RLState, done: bool):
        """Store experience in replay buffer"""
        with self._lock:
            experience = RLExperience(state, action, reward, next_state, done)
            self.memory.append(experience)
    
    def select_action(self, state: RLState, training: bool = True) -> ActionType:
        """Select action using epsilon-greedy strategy"""
        if not TENSORFLOW_AVAILABLE or self.model is None:
            return random.choice(list(ActionType))
        
        with self._lock:
            # Exploration
            if training and random.random() < self.epsilon:
                return random.choice(list(ActionType))
            
            # Exploitation
            state_vector = state.to_feature_vector().reshape(1, -1)
            q_values = self.model.predict(state_vector, verbose=0)[0]
            best_action_idx = np.argmax(q_values)
            
            return list(ActionType)[best_action_idx]
    
    def replay(self, batch_size: int = 32):
        """Train network on batch of experiences"""
        if not TENSORFLOW_AVAILABLE or self.model is None or len(self.memory) < batch_size:
            return
        
        with self._lock:
            batch = random.sample(list(self.memory), batch_size)
            
            states = np.array([exp.state.to_feature_vector() for exp in batch])
            actions = np.array([list(ActionType).index(exp.action) for exp in batch])
            rewards = np.array([exp.reward for exp in batch])
            next_states = np.array([exp.next_state.to_feature_vector() for exp in batch])
            dones = np.array([exp.done for exp in batch])
            
            # Predict Q-values
            targets = self.model.predict(states, verbose=0)
            next_q_values = self.target_model.predict(next_states, verbose=0)
            
            for i in range(batch_size):
                if dones[i]:
                    targets[i][actions[i]] = rewards[i]
                else:
                    targets[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q_values[i])
            
            self.model.fit(states, targets, epochs=1, verbose=0)
            self.training_count += 1
            
            # Update target network periodically
            if self.training_count % 100 == 0:
                self.target_model.set_weights(self.model.get_weights())
    
    def decay_epsilon(self, decay_rate: float = 0.995):
        """Decay exploration rate"""
        self.epsilon *= decay_rate
        self.epsilon = max(self.epsilon, 0.01)


@dataclass
class ActionOutcome:
    """Outcome of an action"""
    action: ActionType
    success: bool
    mttr_reduction_seconds: int  # Mean time to respond/remediate
    lateral_movement_stopped: bool
    data_exfiltration_stopped: bool
    false_positive_risk: float  # 0-1
    side_effects: List[str] = field(default_factory=list)


class RewardCalculator:
    """Calculates rewards for RL agent"""
    
    @staticmethod
    def calculate_reward(outcome: ActionOutcome, 
                        prev_state: RLState,
                        current_state: RLState) -> float:
        """Calculate reward based on action outcome"""
        reward = 0.0
        
        # Success bonus
        if outcome.success:
            reward += 10.0
        else:
            reward -= 5.0
        
        # MTTR improvement (main goal)
        reward += outcome.mttr_reduction_seconds / 100.0  # Scale down
        
        # Containment bonuses
        if outcome.lateral_movement_stopped:
            reward += 15.0
        
        if outcome.data_exfiltration_stopped:
            reward += 20.0
        
        # Penalize risky actions
        reward -= outcome.false_positive_risk * 10.0
        
        # Penalize side effects
        reward -= len(outcome.side_effects) * 2.0
        
        # Penalize impacting more systems than necessary
        if current_state.num_affected_hosts > prev_state.num_affected_hosts * 1.5:
            reward -= 10.0
        
        return float(reward)


class ActionSafetyValidator:
    """Validates actions for safety before execution"""
    
    def __init__(self):
        self.rollback_history = deque(maxlen=100)
        self._lock = threading.RLock()
    
    def validate_action(self, action: ActionType, state: RLState) -> Tuple[bool, str]:
        """Validate if action is safe to execute"""
        with self._lock:
            # ISOLATE_HOST requires at least some context
            if action == ActionType.ISOLATE_HOST:
                if state.severity == IncidentSeverity.INFO:
                    return False, "Too low severity for host isolation"
                if state.num_affected_hosts > 50:
                    return False, "Would affect too many hosts"
            
            # REVOKE_CREDENTIALS is drastic
            if action == ActionType.REVOKE_CREDENTIALS:
                if state.severity not in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                    return False, "Insufficient severity for credential revocation"
                if state.num_affected_users > 20:
                    return False, "Would affect too many users"
            
            # KILL_PROCESS requires strong indicators
            if action == ActionType.KILL_PROCESS:
                if state.threat_score < 0.7:
                    return False, "Threat score too low for process termination"
            
            # Always allow escalation and collection actions
            if action in [ActionType.ESCALATE_TO_SOC, ActionType.COLLECT_FORENSICS]:
                return True, "Always safe"
            
            return True, "Action validated"
    
    def can_rollback(self, action: ActionType) -> bool:
        """Check if action is reversible"""
        reversible_actions = {
            ActionType.ISOLATE_HOST,
            ActionType.BLOCK_IP,
            ActionType.DISABLE_USER,
        }
        return action in reversible_actions
    
    def create_rollback_checkpoint(self, action: ActionType, target: str) -> str:
        """Create rollback checkpoint before action"""
        checkpoint_id = f"ckpt_{action.value}_{target}_{datetime.now().timestamp()}"
        
        with self._lock:
            self.rollback_history.append({
                'checkpoint_id': checkpoint_id,
                'action': action.value,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            })
        
        return checkpoint_id
    
    def rollback_action(self, checkpoint_id: str) -> bool:
        """Attempt to rollback action"""
        with self._lock:
            for checkpoint in self.rollback_history:
                if checkpoint['checkpoint_id'] == checkpoint_id:
                    checkpoint['status'] = 'rolled_back'
                    logger.info(f"Rolled back action: {checkpoint}")
                    return True
        
        return False


@dataclass
class RLAgentPerformanceMetrics:
    """Performance metrics for RL agent"""
    total_incidents_handled: int = 0
    successful_remediations: int = 0
    false_positive_actions: int = 0
    avg_mttr_seconds: float = 0.0
    avg_reward_per_episode: float = 0.0
    learned_policies: Dict[str, float] = field(default_factory=dict)


class AdaptiveSOCAgent:
    """Main adaptive SOC agent combining DQN + safety validation"""
    
    def __init__(self):
        self.dqn_agent = DQNAgent()
        self.safety_validator = ActionSafetyValidator()
        self.reward_calculator = RewardCalculator()
        self.metrics = RLAgentPerformanceMetrics()
        self.episode_count = 0
        self.action_history: Dict[str, List[ActionOutcome]] = defaultdict(list)
        self._lock = threading.RLock()
    
    async def handle_incident(self, state: RLState) -> Tuple[ActionType, str]:
        """Handle incident with RL agent"""
        with self._lock:
            self.episode_count += 1
            
            # Select action
            action = self.dqn_agent.select_action(state, training=True)
            
            # Validate action safety
            is_safe, reason = self.safety_validator.validate_action(action, state)
            
            if not is_safe:
                logger.warning(f"Action {action.value} rejected: {reason}")
                # Fall back to safe action
                action = ActionType.ESCALATE_TO_SOC
            
            # Create rollback checkpoint if needed
            if self.safety_validator.can_rollback(action):
                checkpoint = self.safety_validator.create_rollback_checkpoint(
                    action, state.incident_id
                )
                logger.info(f"Created rollback checkpoint: {checkpoint}")
            
            return action, reason
    
    async def execute_action(self, action: ActionType, 
                            state: RLState,
                            target: str) -> ActionOutcome:
        """Execute action and record outcome"""
        outcome = ActionOutcome(
            action=action,
            success=random.random() > 0.1,  # 90% success rate
            mttr_reduction_seconds=int(random.uniform(60, 600)),
            lateral_movement_stopped=random.random() > 0.3,
            data_exfiltration_stopped=random.random() > 0.4,
            false_positive_risk=random.uniform(0.0, 0.2),
            side_effects=[]
        )
        
        with self._lock:
            self.action_history[target].append(outcome)
            self.metrics.total_incidents_handled += 1
            
            if outcome.success:
                self.metrics.successful_remediations += 1
            
            # Track false positives
            if not outcome.success and outcome.false_positive_risk > 0.5:
                self.metrics.false_positive_actions += 1
        
        return outcome
    
    async def learn_from_episode(self, state: RLState, action: ActionType,
                                outcome: ActionOutcome, next_state: RLState):
        """Learn from episode"""
        # Calculate reward
        reward = self.reward_calculator.calculate_reward(outcome, state, next_state)
        
        # Store experience
        done = outcome.success and (next_state.threat_score < 20.0)
        self.dqn_agent.remember(state, action, reward, next_state, done)
        
        # Train network
        if len(self.dqn_agent.memory) > 32:
            self.dqn_agent.replay(batch_size=32)
        
        # Decay epsilon
        if self.episode_count % 10 == 0:
            self.dqn_agent.decay_epsilon()
        
        # Update metrics
        with self._lock:
            self.metrics.avg_reward_per_episode = (
                (self.metrics.avg_reward_per_episode * (self.episode_count - 1) + reward) /
                self.episode_count
            )
    
    def get_learned_policy(self) -> Dict[str, Any]:
        """Get current learned policy for analysis"""
        with self._lock:
            policy = {
                'episode_count': self.episode_count,
                'avg_reward': self.metrics.avg_reward_per_episode,
                'success_rate': (
                    self.metrics.successful_remediations / 
                    max(1, self.metrics.total_incidents_handled) * 100
                ),
                'false_positive_rate': (
                    self.metrics.false_positive_actions /
                    max(1, self.metrics.total_incidents_handled) * 100
                ),
                'avg_mttr': self.metrics.avg_mttr_seconds,
                'epsilon': self.dqn_agent.epsilon,
                'training_iterations': self.dqn_agent.training_count
            }
            return policy
    
    def save_agent(self, path: Union[str, Path]):
        """Save trained agent"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            if TENSORFLOW_AVAILABLE and self.dqn_agent.model:
                self.dqn_agent.model.save(str(path / "dqn_model.h5"))
                self.dqn_agent.target_model.save(str(path / "target_model.h5"))
            
            # Save metrics
            with open(path / "metrics.json", 'w') as f:
                json.dump(asdict(self.metrics), f, indent=2)
            
            logger.info(f"Agent saved to {path}")
    
    def load_agent(self, path: Union[str, Path]):
        """Load previously trained agent"""
        path = Path(path)
        
        with self._lock:
            if TENSORFLOW_AVAILABLE and (path / "dqn_model.h5").exists():
                self.dqn_agent.model = keras.models.load_model(str(path / "dqn_model.h5"))
                self.dqn_agent.target_model = keras.models.load_model(str(path / "target_model.h5"))
            
            # Load metrics
            if (path / "metrics.json").exists():
                with open(path / "metrics.json") as f:
                    data = json.load(f)
                    # Restore metrics
            
            logger.info(f"Agent loaded from {path}")


# Global instance
_adaptive_soc_agent: Optional[AdaptiveSOCAgent] = None


def get_adaptive_soc_agent() -> AdaptiveSOCAgent:
    """Get or create global adaptive SOC agent"""
    global _adaptive_soc_agent
    if _adaptive_soc_agent is None:
        _adaptive_soc_agent = AdaptiveSOCAgent()
    return _adaptive_soc_agent


from typing import Union

if __name__ == "__main__":
    logger.info("RL Adaptive SOC Agent initialized")
