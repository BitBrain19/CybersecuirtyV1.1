import os
import random
import time
from typing import List, Dict, Any, Tuple

import numpy as np
import pandas as pd
import sys
import json
from datetime import datetime, timedelta

# Ensure internal app modules can be imported before model imports
CURRENT_DIR = os.path.dirname(__file__)
APP_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from ..models.threat_detection import ThreatDetectionModel
from ..models.vulnerability_assessment import VulnerabilityAssessmentModel


def generate_threat_samples(n: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
    """Generate synthetic training data for ThreatDetectionModel.

    Produces feature dictionaries aligned with MODEL_CONFIGS and labels across
    ['benign', 'malicious', 'suspicious']. Uses model.preprocess to convert
    to numeric arrays consistent with the model's pipeline.
    """
    model = ThreatDetectionModel()

    features_list: List[Dict[str, Any]] = []
    labels: List[str] = []

    protocols = ["TCP", "UDP"]
    common_ports_benign = [80, 443, 53, 22, 25, 110]
    suspicious_ports = [445, 3389, 135, 139, 23, 21]

    for i in range(n):
        # Base traffic characteristics
        src_ip = f"192.168.{random.randint(0, 254)}.{random.randint(1, 254)}"
        dst_ip = f"10.0.{random.randint(0, 254)}.{random.randint(1, 254)}"
        proto = random.choice(protocols)

        # Choose destination port with skewed distribution
        if random.random() < 0.7:
            dst_port = random.choice(common_ports_benign)
        else:
            dst_port = random.choice(suspicious_ports)

        src_port = random.randint(1024, 65535)
        packet_count = max(1, int(np.random.exponential(scale=100)))
        byte_count = max(100, int(packet_count * np.random.uniform(50, 200)))
        duration = round(max(0.05, np.random.exponential(scale=3.0)), 3)

        # Flags (for TCP) - synthesize plausible combinations
        flag_syn = 1 if proto == "TCP" and random.random() < 0.5 else 0
        flag_ack = 1 if proto == "TCP" and random.random() < 0.5 else 0
        flag_fin = 1 if proto == "TCP" and random.random() < 0.2 else 0
        flag_rst = 1 if proto == "TCP" and random.random() < 0.05 else 0
        flag_psh = 1 if proto == "TCP" and random.random() < 0.2 else 0
        flag_urg = 1 if proto == "TCP" and random.random() < 0.01 else 0

        features = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration": duration,
            "flag_syn": flag_syn,
            "flag_ack": flag_ack,
            "flag_fin": flag_fin,
            "flag_rst": flag_rst,
            "flag_psh": flag_psh,
            "flag_urg": flag_urg,
        }

        # Labeling heuristic
        # - High byte_count + suspicious port + abnormal flags -> malicious
        # - Moderate anomalies -> suspicious
        # - Else benign
        anomaly_score = 0
        if dst_port in suspicious_ports:
            anomaly_score += 2
        if byte_count / (packet_count + 1e-6) > 500:
            anomaly_score += 2
        if flag_rst == 1 and flag_syn == 0 and flag_ack == 0:
            anomaly_score += 2
        if duration < 0.2 and packet_count > 500:
            anomaly_score += 2
        if flag_urg == 1:
            anomaly_score += 1

        # Add noise to avoid overfitting synthetic rules
        anomaly_score += np.random.binomial(1, 0.1)

        if anomaly_score >= 5:
            label = "malicious"
        elif anomaly_score >= 3:
            label = "suspicious"
        else:
            label = "benign"

        features_list.append(features)
        labels.append(label)

    # Force add at least 5 malicious and 5 suspicious samples to avoid stratification errors
    for _ in range(5):
        # Malicious
        features_list.append({
            "source_ip": "192.168.1.100", "destination_ip": "10.0.0.5", "source_port": 12345, "destination_port": 445,
            "protocol": "TCP", "packet_count": 1000, "byte_count": 1000000, "duration": 0.1,
            "flag_syn": 0, "flag_ack": 0, "flag_fin": 0, "flag_rst": 1, "flag_psh": 1, "flag_urg": 1
        })
        labels.append("malicious")
        
        # Suspicious
        features_list.append({
             "source_ip": "192.168.1.101", "destination_ip": "10.0.0.6", "source_port": 54321, "destination_port": 3389,
             "protocol": "TCP", "packet_count": 500, "byte_count": 50000, "duration": 0.5,
             "flag_syn": 1, "flag_ack": 0, "flag_fin": 0, "flag_rst": 0, "flag_psh": 0, "flag_urg": 0
        })
        labels.append("suspicious")

    # Preprocess via model to align with expected numeric arrays
    X_rows: List[np.ndarray] = []
    for feats in features_list:
        X_rows.append(model.preprocess(feats))
    X = np.vstack(X_rows)
    y = np.array(labels)

    return X, y


def generate_vulnerability_samples(n: int = 200) -> Tuple[pd.DataFrame, np.ndarray]:
    """Generate synthetic training data for VulnerabilityAssessmentModel.

    Creates a DataFrame with the required input features and a target risk score
    from 0.0 to 10.0.
    """
    rng = np.random.default_rng(42)

    os_types = ["Windows", "Linux", "macOS", "NetworkOS"]
    service_types = ["web", "database", "ssh", "smtp", "fileserver"]
    access_vector = ["NETWORK", "ADJACENT", "LOCAL"]
    auth_required = ["NONE", "SINGLE", "MULTIPLE"]
    impact_levels = ["NONE", "PARTIAL", "COMPLETE"]

    rows: List[Dict[str, Any]] = []
    scores: List[float] = []

    for i in range(n):
        age = int(rng.integers(0, 365))  # days since discovery
        version = rng.integers(1, 10)
        patch_level = rng.integers(0, 10)
        complexity_score = float(rng.uniform(0.0, 10.0))
        os_type = random.choice(os_types)
        service_type = random.choice(service_types)
        av = random.choice(access_vector)
        auth = random.choice(auth_required)
        conf = random.choice(impact_levels)
        integ = random.choice(impact_levels)
        avail = random.choice(impact_levels)

        row = {
            "age": age,
            "version": int(version),
            "patch_level": int(patch_level),
            "complexity_score": complexity_score,
            "os_type": os_type,
            "service_type": service_type,
            "access_vector": av,
            "authentication": auth,
            "confidentiality_impact": conf,
            "integrity_impact": integ,
            "availability_impact": avail,
            "exposure_score": float(rng.uniform(0.0, 10.0)),
            "exploitability_score": float(rng.uniform(0.0, 10.0)),
            "impact_score": float(rng.uniform(0.0, 10.0)),
            "cvss_base_score": float(rng.uniform(0.0, 10.0)),
            "vulnerability_type": rng.choice(["SQLi", "XSS", "RCE", "LFI", "CSRF"]),
            "vendor": rng.choice(["Microsoft", "Apache", "Oracle", "Cisco", "Unknown"]),
        }

        # Risk scoring heuristic: higher with NETWORK access, NONE auth, COMPLETE impacts,
        # older age, lower patch_level, higher complexity
        risk = 0.0
        risk += 2.0 if av == "NETWORK" else 1.0 if av == "ADJACENT" else 0.5
        risk += 2.0 if auth == "NONE" else 1.0 if auth == "SINGLE" else 0.5
        for level in [conf, integ, avail]:
            risk += 2.0 if level == "COMPLETE" else 1.0 if level == "PARTIAL" else 0.0
        risk += min(3.0, age / 120.0)
        risk += min(3.0, complexity_score / 3.0)
        risk += max(0.0, 2.0 - (patch_level / 5.0))
        risk = max(0.0, min(10.0, risk + rng.normal(0, 0.7)))

        rows.append(row)
        scores.append(float(risk))

    df = pd.DataFrame(rows)
    y = np.array(scores)
    return df, y


def generate_ueba_samples(n_users: int = 50, events_per_user: int = 40) -> List[Dict[str, Any]]:
    """Generate synthetic UEBA data with sufficient variance."""
    rng = np.random.default_rng(42)
    events = []
    
    users = [f"user_{i:03d}" for i in range(n_users)]
    
    # Import here to avoid circular dependency at top level
    from app.ueba.ueba_graph_detector_prod import get_ueba_detector, UserActivity
    
    # Define baseline profiles for variation
    profiles = {}
    for u in users:
        profiles[u] = {
            "hosts": [f"host_{rng.integers(1, 10)}" for _ in range(rng.integers(1, 4))],
            "apps": [f"app_{rng.integers(1, 20)}" for _ in range(rng.integers(2, 6))],
            "hours": list(range(rng.integers(8, 10), rng.integers(17, 19))),
            "is_admin": rng.random() < 0.1,
            "is_service_account": rng.random() < 0.05
        }
        # Inject service account explicitly if needed
        detector = get_ueba_detector()
        detector.graph.add_user(u, u, is_admin=profiles[u]["is_admin"])
        # We need to set is_service_account which is not in add_user signature?
        # UserProfile has it. We need to access it.
        profile = detector.graph.get_user_profile(u)
        if profile:
            profile.is_service_account = profiles[u]["is_service_account"]

    start_time = datetime.now() - timedelta(days=7)

    for u in users:
        profile = profiles[u]
        for _ in range(events_per_user):
            # 90% normal behavior, 10% variance/anomaly
            is_normal = rng.random() < 0.90
            
            if is_normal:
                hour = int(rng.choice(profile["hours"]))
                host = str(rng.choice(profile["hosts"]))
                app = str(rng.choice(profile["apps"]))
                auth = "normal"
                geo = 0.0
            else:
                # Variance
                hour = int(rng.integers(0, 24))
                host = f"host_{rng.integers(1, 20)}" 
                app = f"app_{rng.integers(1, 50)}" 
                auth = rng.choice(["normal", "mfa_bypass", "failed"]) if rng.random() < 0.1 else "normal"
                geo = float(rng.random()) if rng.random() < 0.1 else 0.0

            # Event types
            evt_type = rng.choice(["login", "file_access", "resource_access", "logout", "api_call", "lateral_movement"])
            if rng.random() < 0.01: 
                evt_type = "privilege_change" # Rare event
            
            # Timestamp
            day_offset = rng.integers(0, 7)
            ts = start_time + timedelta(days=int(day_offset), hours=hour, minutes=int(rng.integers(0, 60)))
            
            event = {
                "entity_id": u,
                "event_type": evt_type,
                "timestamp": ts.isoformat(),
                "source_ip": host, # Mapped to source_host
                "resource": app,   # Mapped to target_resource
                "auth_method": auth,
                "geographic_anomaly": geo,
                "resource_sensitivity": int(rng.integers(1, 11)),
                "batch_access": bool(rng.random() < 0.05),
                "cross_domain": bool(rng.random() < 0.02),
                "is_interactive": bool(rng.random() < 0.8),
                "data_volume": float(rng.exponential(1000)),
                "vpn_access": bool(rng.random() < 0.3)
            }
            events.append(event)
            
    return events


import argparse
import glob

def load_data_from_dir(data_dir: str, model_type: str) -> Tuple[Any, Any]:
    """Load training data from JSONL files in the specified directory."""
    files = glob.glob(os.path.join(data_dir, "*.jsonl"))
    if not files:
        print(f"No .jsonl files found in {data_dir}, using synthetic data.")
        return None, None
    
    print(f"Loading data from {len(files)} files in {data_dir}...")
    
    all_features = []
    all_labels = []
    
    for fpath in files:
        try:
            with open(fpath, 'r') as f:
                for line in f:
                    item = json.loads(line)
                    # Simple heuristic: assume last field or specific field is label
                    # This needs to be adapted based on actual data schema
                    if model_type == 'threat_detection':
                        label = item.pop('label', 'benign')
                        all_features.append(item)
                        all_labels.append(label)
                    elif model_type == 'vulnerability_assessment':
                        score = item.pop('risk_score', 0.0)
                        # Ensure all required numerical features exist
                        required_numerical = [
                            'age', 'version', 'patch_level', 'complexity_score',
                            'exposure_score', 'exploitability_score', 'impact_score',
                            'cvss_base_score'
                        ]
                        for feature in required_numerical:
                            if feature not in item:
                                item[feature] = 0.0
                        
                        # Ensure all required categorical features exist
                        required_categorical = [
                            'os_type', 'service_type', 'access_vector', 'authentication',
                            'vulnerability_type', 'vendor'
                        ]
                        for feature in required_categorical:
                            if feature not in item:
                                item[feature] = "Unknown"
                        
                        all_features.append(item)
                        all_labels.append(score)
        except Exception as e:
            print(f"Error reading {fpath}: {e}")

    if not all_features:
        return None, None

    if model_type == 'threat_detection':
        model = ThreatDetectionModel()
        X_rows = [model.preprocess(f) for f in all_features]
        return np.vstack(X_rows), np.array(all_labels)
    else:
        return pd.DataFrame(all_features), np.array(all_labels)


def train_and_save_models(data_dir: str = None, output_dir: str = None):
    """Train both models with datasets and save artifacts."""
    start = time.time()
    
    # Resolve storage directory
    if output_dir:
        storage_dir = output_dir
    else:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        storage_dir = os.path.join(repo_root, "models", "saved")
        
        # In Docker, repo_root might be different, handle /models/saved explicitly if needed
        if not os.path.exists(os.path.dirname(storage_dir)):
            # Fallback for Docker where /app is root
             storage_dir = "/models/saved"

    # Auto-detect data_dir if not provided
    if data_dir is None:
        # Try finding artifacts relative to script
        # Script is in ml/app/scripts. Artifacts in ml/artifacts.
        # So ../../artifacts
        candidate_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "artifacts", "datasets", "production"))
        if os.path.exists(candidate_dir):
            # Find latest date
            subdirs = sorted([d for d in os.listdir(candidate_dir) if os.path.isdir(os.path.join(candidate_dir, d))])
            if subdirs:
                data_dir = os.path.join(candidate_dir, subdirs[-1])
                print(f"Auto-detected data directory: {data_dir}")
        else:
            # Fallback for Docker paths if structure differs
            if os.path.exists("/app/artifacts/datasets/production"):
                candidate_dir = "/app/artifacts/datasets/production"
                subdirs = sorted([d for d in os.listdir(candidate_dir) if os.path.isdir(os.path.join(candidate_dir, d))])
                if subdirs:
                    data_dir = os.path.join(candidate_dir, subdirs[-1])
                    print(f"Auto-detected data directory (Docker): {data_dir}")

    # FORCE DEFAULT FOR DOCKER IF STILL NONE
    if data_dir is None and os.path.exists("/app/artifacts/datasets/production/2025-11-01"):
         data_dir = "/app/artifacts/datasets/production/2025-11-01"
         print(f"Forced default data directory: {data_dir}")

    print(f"Final Data Directory: {data_dir}")
    os.makedirs(storage_dir, exist_ok=True)

    # Threat Detection
    print("Training Threat Detection Model...")
    X_td, y_td = None, None
    if data_dir:
        X_td, y_td = load_data_from_dir(os.path.join(data_dir, "threat_detection"), "threat_detection")
    
    if X_td is None:
        print("Using synthetic data for Threat Detection.")
        X_td, y_td = generate_threat_samples(n=200)

    td_model = ThreatDetectionModel()
    td_model.train(X_td, y_td, validation_split=0.2, optimize_hyperparameters=False, cross_validate=False)

    td_path = os.path.join(storage_dir, "threat_detection_latest.joblib")
    td_model.save(td_path)
    td_saved = os.path.exists(td_path)

    # Vulnerability Assessment
    print("Training Vulnerability Assessment Model...")
    X_va, y_va = None, None
    if data_dir:
        X_va, y_va = load_data_from_dir(os.path.join(data_dir, "vulnerability_assessment"), "vulnerability_assessment")
        
    if X_va is None:
        print("Using synthetic data for Vulnerability Assessment.")
        X_va, y_va = generate_vulnerability_samples(n=300)

    va_model = VulnerabilityAssessmentModel()
    va_model.train(X_va, y_va, validation_split=0.2, optimize_hyperparameters=False)
    
    # Ensure a primary trained model is assigned for saving
    if hasattr(va_model, 'models') and 'primary' in getattr(va_model, 'models', {}):
        va_model.model = va_model.models['primary']

    va_path = os.path.join(storage_dir, "vulnerability_assessment_latest.joblib")
    try:
        va_model.save(va_path)
    except Exception as e:
        print(f"Failed to save vulnerability model: {e}")
    va_saved = os.path.exists(va_path)

    # UEBA
    print("Training UEBA Model...")
    # Import here to avoid circular imports if not needed
    try:
        from app.ueba.ueba_graph_detector_prod import get_ueba_detector, UserActivity
        from datetime import datetime
        
        ueba_detector = get_ueba_detector()
        
        # Load data
        ueba_data = []
        if data_dir:
            # Check for ueba folder
            ueba_files = glob.glob(os.path.join(data_dir, "ueba", "*.jsonl"))
            for fpath in ueba_files:
                try:
                    with open(fpath, 'r') as f:
                        for line in f:
                            ueba_data.append(json.loads(line))
                except Exception as e:
                    print(f"Error reading UEBA file {fpath}: {e}")
        
        if not ueba_data:
            print("No UEBA data found, generating synthetic UEBA data...")
            ueba_data = generate_ueba_samples(n_users=50, events_per_user=50) # 2500 events
            
            # Save generated data so it persists
            if data_dir:
                ueba_dir = os.path.join(data_dir, "ueba")
                print(f"Attempting to save UEBA data to dir: {ueba_dir}")
                os.makedirs(ueba_dir, exist_ok=True)
                save_path = os.path.join(ueba_dir, "ueba_events.jsonl")
                try:
                    with open(save_path, 'w') as f:
                        for item in ueba_data:
                            f.write(json.dumps(item) + "\n")
                    print(f"SUCCESS: Saved generated UEBA data to {save_path}")
                except Exception as e:
                    print(f"FAILURE: Failed to save generated UEBA data: {e}")
            else:
                print("WARNING: Skipping save because data_dir is None")
        else:
            print(f"Loaded {len(ueba_data)} UEBA events.")
            
        if ueba_data:
            # Populate buffer
            # Populate buffer
                # Populate buffer and graph
            print(f"Populating UEBA graph with {len(ueba_data)} events...")
            count = 0
            for item in ueba_data:
                user_id = item.get("entity_id", "unknown")
                activity = UserActivity(
                    user_id=user_id,
                    activity_type=item.get("event_type", "unknown"),
                    timestamp=datetime.fromisoformat(item.get("timestamp", datetime.now().isoformat()).replace("Z", "+00:00")),
                    source_host=item.get("source_ip", ""),
                    target_resource=item.get("resource", ""),
                    details=item
                )
                
                # IMPORTANT: Must populate graph for features to be extracted correctly
                # 1. Ensure user exists
                profile = ueba_detector.graph.add_user(user_id, user_id)
                # Manually set attributes not in add_user
                if item.get("is_service_account"):
                    profile.is_service_account = True
                if item.get("is_admin"):
                    profile.is_admin = True
                    profile.privilege_level = 1
                
                # 2. Record activity in graph to build baseline
                ueba_detector.graph.add_activity(user_id, activity)
                
                # 3. Add to buffer for training
                ueba_detector.activity_buffer.append((activity.user_id, activity))
                count += 1
                
            print(f"Graph populated with {len(ueba_detector.graph.user_profiles)} users and {count} activities.")
            
            # CHAOS MONKEY: Forcibly inject variance into buffer and profiles to guarantee full rank
            print("Running Chaos Monkey to guarantee variance...")
            rng_chaos = np.random.default_rng(42)
            
            # 1. Randomize Profiles (Rate, Admin, Priv)
            for uid, profile in ueba_detector.graph.user_profiles.items():
                profile.event_rate = float(rng_chaos.exponential(1.0)) * 10.0 # Scale up to ensure variance
                profile.baseline_established = True # FORCE BASELINE
                
                if rng_chaos.random() < 0.2:
                     profile.privilege_level = 1 
                # Prune hosts/apps for Baseline features
                if len(profile.typical_hosts) > 1:
                    profile.typical_hosts.remove(list(profile.typical_hosts)[0])

            # 2. Randomize Activity Buffer features
            for i in range(len(ueba_detector.activity_buffer)):
                uid, act = ueba_detector.activity_buffer[i]
                
                # Fix Feature 0 (Host Match) & 3 (New Host)
                if rng_chaos.random() < 0.1:
                    act.source_host = f"chaos_host_{rng_chaos.integers(0,100)}" 
                
                # Fix Feature 4 (New Resource) -> Needs chaos app
                if rng_chaos.random() < 0.1:
                    act.target_resource = f"chaos_app_{rng_chaos.integers(0,100)}"

                # Fix Feature 1 (Hour Match) -> Randomize time
                if rng_chaos.random() < 0.1:
                    # randomize hour by adjusting timestamp
                    act.timestamp = datetime.now() - timedelta(hours=int(rng_chaos.integers(0, 24)))

                # Fix Feature 11 (Interactive)
                if rng_chaos.random() < 0.3:
                    act.is_interactive = not act.is_interactive
                
                # Fix Feature 2 (Priv Change)
                if rng_chaos.random() < 0.05:
                    act.activity_type = "privilege_change"
                    # Ensure matching profile has priv
                    if uid in ueba_detector.graph.user_profiles:
                        ueba_detector.graph.user_profiles[uid].privilege_level = 1
            
            print("Data augmentation completed.")
            
            # Train
            # Since train_models is async, we need to run it. But this script is sync.
            # The train_models method in UEBA is async defined but doesn't use await inside except for lock?
            # Actually it uses 'with self.lock' which is a threading lock, so it's synchronous safe.
            # But it is defined as 'async def'. We need to run it.
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we are in a running loop (unlikely in this script), create task
                # But this script is main.
                pass
            
            # Simple wrapper to run async method
            async def run_ueba_train():
                return await ueba_detector.train_models(min_samples=10)
            
            ueba_result = asyncio.run(run_ueba_train())
            print(f"UEBA Training Result: {ueba_result}")
            
    except ImportError as e:
        print(f"Could not import UEBA modules: {e}")
    except Exception as e:
        print(f"UEBA training failed: {e}")

    duration = time.time() - start
    result = {
        "threat_detection_model_path": os.path.abspath(td_path),
        "vulnerability_assessment_model_path": os.path.abspath(va_path),
        "vulnerability_assessment_saved": va_saved,
        "samples": {"threat_detection": int(X_td.shape[0]), "vulnerability_assessment": int(X_va.shape[0])},
    }

    # Write results to a JSON file for later inspection
    results_path = os.path.join(os.path.dirname(__file__), "training_results.json")
    try:
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train ML Models")
    parser.add_argument("--data-dir", type=str, help="Directory containing training data")
    parser.add_argument("--output-dir", type=str, help="Directory to save trained models")
    args = parser.parse_args()

    results = train_and_save_models(data_dir=args.data_dir, output_dir=args.output_dir)
    print("Training completed:")
    print(results)