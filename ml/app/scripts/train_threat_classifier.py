"""
Training Script for Threat Classification Model
Classifies security events into threat categories (malware, exploit, lateral movement, etc.)
"""

import os
import sys
import json
import argparse
import glob
import time
from datetime import datetime
from typing import List, Dict, Any
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.threat_classification.threat_classifier_prod import (
    ThreatClassifierModel,
    SecurityEvent,
    ThreatCategory
)


def generate_synthetic_security_events(n: int = 1000) -> List[SecurityEvent]:
    """Generate synthetic security events for training"""
    import random
    
    events = []
    
    # Define patterns for each threat category
    threat_patterns = {
        ThreatCategory.MALWARE: {
            "event_types": ["process_creation", "file_write", "registry_modify"],
            "sources": ["endpoint", "edr"],
            "indicators": ["suspicious_process", "unsigned_binary", "temp_execution"]
        },
        ThreatCategory.EXPLOIT: {
            "event_types": ["vulnerability_exploit", "buffer_overflow", "code_injection"],
            "sources": ["ids", "firewall", "endpoint"],
            "indicators": ["shellcode", "heap_spray", "rop_chain"]
        },
        ThreatCategory.LATERAL_MOVEMENT: {
            "event_types": ["smb_connection", "rdp_session", "psexec"],
            "sources": ["network", "endpoint"],
            "indicators": ["admin_share", "remote_execution", "credential_reuse"]
        },
        ThreatCategory.PRIVILEGE_ESCALATION: {
            "event_types": ["token_manipulation", "service_creation", "dll_injection"],
            "sources": ["endpoint", "edr"],
            "indicators": ["elevated_privileges", "bypass_uac", "kernel_exploit"]
        },
        ThreatCategory.CREDENTIAL_ACCESS: {
            "event_types": ["lsass_access", "credential_dumping", "keylogging"],
            "sources": ["endpoint", "edr"],
            "indicators": ["mimikatz", "password_spray", "hash_dump"]
        },
        ThreatCategory.DATA_EXFILTRATION: {
            "event_types": ["large_upload", "dns_tunneling", "ftp_transfer"],
            "sources": ["network", "firewall", "proxy"],
            "indicators": ["unusual_traffic", "encrypted_channel", "data_staging"]
        },
        ThreatCategory.COMMAND_CONTROL: {
            "event_types": ["beacon_traffic", "c2_communication", "callback"],
            "sources": ["network", "firewall"],
            "indicators": ["periodic_connection", "known_c2_ip", "encoded_traffic"]
        },
        ThreatCategory.PERSISTENCE: {
            "event_types": ["scheduled_task", "registry_run_key", "service_install"],
            "sources": ["endpoint", "edr"],
            "indicators": ["autostart", "boot_persistence", "hidden_service"]
        }
    }
    
    categories = list(threat_patterns.keys())
    
    for i in range(n):
        # 70% threats, 30% benign
        is_threat = random.random() < 0.7
        
        if is_threat:
            category = random.choice(categories)
            pattern = threat_patterns[category]
            
            event = SecurityEvent(
                source_type=random.choice(pattern["sources"]),
                source_id=f"sensor_{random.randint(1, 100):03d}",
                event_type=random.choice(pattern["event_types"]),
                event_data={
                    "severity": random.choice(["high", "medium", "low"]),
                    "indicator": random.choice(pattern["indicators"]),
                    "process": f"process_{i}",
                    "user": f"user_{random.randint(1, 50)}",
                    "ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "port": random.randint(1024, 65535),
                    "protocol": random.choice(["tcp", "udp", "icmp"]),
                    "bytes_sent": random.randint(100, 1000000),
                    "bytes_received": random.randint(100, 1000000),
                },
                raw_log=f"[{category.value}] Detected {random.choice(pattern['indicators'])}",
                threat_category=category,
                is_threat=True,
                confidence=random.uniform(0.6, 0.99),
                host_id=f"host_{random.randint(1, 200):03d}",
                user_id=f"user_{random.randint(1, 50)}",
                context={
                    "mitre_technique": f"T{random.randint(1000, 1600)}",
                    "kill_chain_phase": random.choice(["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command_control", "actions"]),
                }
            )
        else:
            # Benign event
            event = SecurityEvent(
                source_type=random.choice(["endpoint", "network", "application"]),
                source_id=f"sensor_{random.randint(1, 100):03d}",
                event_type=random.choice(["user_login", "file_access", "network_connection", "process_start"]),
                event_data={
                    "severity": "info",
                    "process": random.choice(["chrome.exe", "outlook.exe", "teams.exe", "excel.exe"]),
                    "user": f"user_{random.randint(1, 50)}",
                    "ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "port": random.choice([80, 443, 3389, 445]),
                    "protocol": "tcp",
                },
                raw_log="Normal user activity",
                threat_category=None,
                is_threat=False,
                confidence=0.0,
                host_id=f"host_{random.randint(1, 200):03d}",
                user_id=f"user_{random.randint(1, 50)}",
                context={}
            )
        
        events.append(event)
    
    return events


def load_security_events_from_dir(data_dir: str) -> List[SecurityEvent]:
    """Load security events from JSONL files"""
    events = []
    
    if not os.path.exists(data_dir):
        return events
    
    jsonl_files = glob.glob(os.path.join(data_dir, "*.jsonl"))
    
    for fpath in jsonl_files:
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    
                    # Convert to SecurityEvent
                    event = SecurityEvent(
                        source_type=data.get("source_type", ""),
                        source_id=data.get("source_id", ""),
                        event_type=data.get("event_type", ""),
                        event_data=data.get("event_data", {}),
                        raw_log=data.get("raw_log", ""),
                        threat_category=ThreatCategory(data["threat_category"]) if data.get("threat_category") else None,
                        is_threat=data.get("is_threat", False),
                        confidence=data.get("confidence", 0.0),
                        host_id=data.get("host_id", ""),
                        user_id=data.get("user_id", ""),
                        context=data.get("context", {})
                    )
                    events.append(event)
        except Exception as e:
            print(f"Error reading file {fpath}: {e}")
    
    return events


def train_threat_classifier(data_dir: str = None, output_dir: str = None):
    """Train threat classification model"""
    start = time.time()
    
    # Resolve output directory
    if output_dir:
        storage_dir = output_dir
    else:
        storage_dir = os.path.join(os.path.dirname(__file__), "..", "..", "artifacts", "saved")
    
    os.makedirs(storage_dir, exist_ok=True)
    
    print("=" * 60)
    print("Training Threat Classification Model")
    print("=" * 60)
    
    # Load or generate data
    events = []
    if data_dir:
        print(f"Loading data from: {data_dir}")
        events = load_security_events_from_dir(data_dir)
    
    if not events:
        print("No data found, generating synthetic samples...")
        events = generate_synthetic_security_events(n=1000)
    
    print(f"Total events: {len(events)}")
    print(f"Threat events: {sum(1 for e in events if e.is_threat)}")
    print(f"Benign events: {sum(1 for e in events if not e.is_threat)}")
    
    # Count by category
    threat_events = [e for e in events if e.threat_category]
    if threat_events:
        print("\nThreat Category Distribution:")
        from collections import Counter
        category_counts = Counter(e.threat_category.value for e in threat_events)
        for category, count in category_counts.most_common():
            print(f"  {category}: {count}")
    
    # Train model
    print("\nTraining model...")
    model = ThreatClassifierModel()
    metrics = model.train(events)
    
    print("\nTraining Results:")
    print(f"  Accuracy:  {metrics.accuracy:.2%}")
    print(f"  Precision: {metrics.precision:.2%}")
    print(f"  Recall:    {metrics.recall:.2%}")
    print(f"  F1 Score:  {metrics.f1:.2%}")
    print(f"  Dataset:   {metrics.dataset_size} events")
    
    # Save model
    model_path = os.path.join(storage_dir, "threat_classifier_latest.pkl")
    print(f"\nSaving model to: {model_path}")
    model.save_model(model_path)
    
    duration = time.time() - start
    
    result = {
        "model_path": os.path.abspath(model_path),
        "training_time_seconds": duration,
        "metrics": {
            "accuracy": metrics.accuracy,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
        },
        "samples": {
            "total": len(events),
            "threats": sum(1 for e in events if e.is_threat),
            "benign": sum(1 for e in events if not e.is_threat)
        },
        "trained_at": datetime.now().isoformat()
    }
    
    # Save results
    results_path = os.path.join(storage_dir, "threat_classifier_training_results.json")
    with open(results_path, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"\nTraining completed in {duration:.2f}s")
    print(f"Results saved to: {results_path}")
    print("=" * 60)
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Threat Classification Model")
    parser.add_argument("--data-dir", type=str, help="Directory containing security event data (JSONL)")
    parser.add_argument("--output-dir", type=str, help="Directory to save trained model")
    args = parser.parse_args()
    
    results = train_threat_classifier(data_dir=args.data_dir, output_dir=args.output_dir)
    print("\nFinal Results:")
    print(json.dumps(results, indent=2))
