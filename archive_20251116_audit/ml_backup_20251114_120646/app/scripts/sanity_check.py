import os
import sys
import numpy as np
import pandas as pd

# Ensure internal app modules import correctly when running as module
CURRENT_DIR = os.path.dirname(__file__)
APP_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from ..models.threat_detection import ThreatDetectionModel
from ..models.vulnerability_assessment import VulnerabilityAssessmentModel


def run_threat_detection_sanity():
    print("\n=== Threat Detection Sanity Check ===")
    model = ThreatDetectionModel()
    X = np.random.rand(120, 15)
    y = np.array(["benign", "malicious", "suspicious"] * 40)[:120]
    model.train(X, y, validation_split=0.2, optimize_hyperparameters=False, cross_validate=False)
    # Predict on a small batch of synthetic features
    features = {
        'source_ip': '192.168.1.10',
        'destination_ip': '10.0.0.5',
        'source_port': 12345,
        'destination_port': 443,
        'protocol': 'TCP',
        'packet_count': 150,
        'byte_count': 20000,
        'duration': 12.5,
        'flag_syn': 1,
        'flag_ack': 1,
        'flag_fin': 0,
        'flag_rst': 0,
        'flag_psh': 0,
        'flag_urg': 0,
    }
    pred, conf, meta = model.predict(features)
    print(f"Prediction: {pred}, Confidence: {conf:.3f}, Models: {list(model.models.keys())}")


def run_vulnerability_assessment_sanity():
    print("\n=== Vulnerability Assessment Sanity Check ===")
    model = VulnerabilityAssessmentModel()
    df = pd.DataFrame({
        "age": np.random.randint(0, 365, 120),
        "version": np.random.randint(1, 10, 120),
        "patch_level": np.random.randint(0, 10, 120),
        "complexity_score": np.random.uniform(0.0, 10.0, 120),
        "os_type": np.random.choice(["Windows","Linux","macOS","NetworkOS"], 120),
        "service_type": np.random.choice(["web","database","ssh","smtp","fileserver"], 120),
        "access_vector": np.random.choice(["NETWORK","ADJACENT","LOCAL"], 120),
        "authentication_required": np.random.choice(["NONE","SINGLE","MULTIPLE"], 120),
        "confidentiality_impact": np.random.choice(["NONE","PARTIAL","COMPLETE"], 120),
        "integrity_impact": np.random.choice(["NONE","PARTIAL","COMPLETE"], 120),
        "availability_impact": np.random.choice(["NONE","PARTIAL","COMPLETE"], 120),
    })
    y = np.random.uniform(0.0, 10.0, 120)
    model.train(df, y, validation_split=0.2, optimize_hyperparameters=False)
    # Predict single sample
    sample = df.iloc[0]
    score, severity, details = model.predict(sample.to_dict())
    print(f"Score: {score:.2f}, Severity: {severity}, Details keys: {list(details.keys())[:5]}")


if __name__ == "__main__":
    run_threat_detection_sanity()
    run_vulnerability_assessment_sanity()