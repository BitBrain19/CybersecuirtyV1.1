import os
import random
import time
from typing import List, Dict, Any, Tuple

import numpy as np
import pandas as pd
import sys
import json

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
    
    os.makedirs(storage_dir, exist_ok=True)

    # Threat Detection
    print("Training Threat Detection Model...")
    X_td, y_td = None, None
    if data_dir:
        X_td, y_td = load_data_from_dir(os.path.join(data_dir, "threat_detection"), "threat_detection")
    
    if X_td is None:
        print("Using synthetic data for Threat Detection.")
        X_td, y_td = generate_threat_samples(n=1200)

    td_model = ThreatDetectionModel()
    td_model.train(X_td, y_td, validation_split=0.2, optimize_hyperparameters=True, cross_validate=True)

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
    va_model.train(X_va, y_va, validation_split=0.2, optimize_hyperparameters=True)
    
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
            print("No UEBA data found, skipping UEBA training.")
        else:
            print(f"Loaded {len(ueba_data)} UEBA events.")
            # Populate buffer
            for item in ueba_data:
                activity = UserActivity(
                    user_id=item.get("entity_id", "unknown"),
                    activity_type=item.get("event_type", "unknown"),
                    timestamp=datetime.fromisoformat(item.get("timestamp", datetime.now().isoformat()).replace("Z", "+00:00")),
                    source_host=item.get("source_ip", ""),
                    target_resource=item.get("resource", ""),
                    details=item
                )
                # We access the buffer directly for batch loading in this script context
                ueba_detector.activity_buffer.append((activity.user_id, activity))
            
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