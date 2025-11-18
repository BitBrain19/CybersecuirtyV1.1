#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Example script demonstrating how to use the ML models directly.

This script shows how to:
1. Create and train the threat detection model
2. Make predictions with the threat detection model
3. Create and train the vulnerability assessment model
4. Make predictions with the vulnerability assessment model
"""

import pandas as pd
import numpy as np
import os
import sys

# Add the parent directory to the path so we can import the app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.threat_detection import ThreatDetectionModel
from app.models.vulnerability_assessment import VulnerabilityAssessmentModel


def demonstrate_threat_detection():
    print("\n=== Threat Detection Model Demonstration ===")
    
    # Create sample data
    print("Creating sample network traffic data...")
    sample_data = {
        'source_ip': ['192.168.1.1', '10.0.0.1', '172.16.0.1', '192.168.1.2', '10.0.0.2'],
        'destination_ip': ['10.0.0.2', '192.168.1.2', '10.0.0.3', '172.16.0.2', '192.168.1.3'],
        'source_port': [12345, 54321, 23456, 34567, 45678],
        'destination_port': [80, 443, 22, 8080, 3389],
        'protocol': ['TCP', 'UDP', 'TCP', 'TCP', 'UDP'],
        'packet_count': [100, 200, 50, 300, 150],
        'byte_count': [1500, 3000, 800, 4500, 2500],
        'duration': [5.2, 10.5, 2.1, 15.3, 7.8],
        'flag_syn': [1, 0, 1, 0, 0],
        'flag_ack': [0, 1, 0, 1, 1],
        'flag_fin': [0, 0, 0, 0, 1]
    }
    
    # Create labels (0 = benign, 1 = malicious)
    sample_labels = ['benign', 'malicious', 'benign', 'malicious', 'benign']
    
    # Convert to DataFrame
    df = pd.DataFrame(sample_data)
    
    # Initialize the model
    print("Initializing threat detection model...")
    model = ThreatDetectionModel()
    
    # Train the model
    print("Training threat detection model...")
    model.train(df, np.array(sample_labels))
    
    # Make predictions
    print("Making predictions...")
    predictions = model.predict(df)
    probabilities = model.predict_proba(df)
    
    # Display results
    print("\nResults:")
    for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
        print(f"Sample {i+1}: Prediction = {pred}, Probability = {prob:.4f}")
    
    # Save the model
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_detection_example.joblib")
    print(f"\nSaving model to {model_path}")
    model.save(model_path)
    
    # Load the model
    print("Loading model from file...")
    loaded_model = ThreatDetectionModel()
    loaded_model.load(model_path)
    
    # Make predictions with loaded model
    print("Making predictions with loaded model...")
    loaded_predictions = loaded_model.predict(df)
    
    # Verify predictions match
    print("Verifying predictions match...")
    match = all(p1 == p2 for p1, p2 in zip(predictions, loaded_predictions))
    print(f"Predictions match: {match}")
    
    return model_path


def demonstrate_vulnerability_assessment():
    print("\n=== Vulnerability Assessment Model Demonstration ===")
    
    # Create sample data
    print("Creating sample vulnerability data...")
    sample_data = {
        'cve_id': ['CVE-2021-1234', 'CVE-2022-5678', 'CVE-2020-9101', 'CVE-2023-4321', 'CVE-2022-8765'],
        'cwe_id': ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-78', 'CWE-22'],
        'cvss_base_score': [7.5, 9.1, 5.2, 8.7, 6.3],
        'access_vector': ['NETWORK', 'LOCAL', 'NETWORK', 'NETWORK', 'LOCAL'],
        'access_complexity': ['LOW', 'HIGH', 'MEDIUM', 'LOW', 'MEDIUM'],
        'authentication': ['NONE', 'SINGLE', 'NONE', 'NONE', 'MULTIPLE'],
        'confidentiality_impact': ['PARTIAL', 'COMPLETE', 'NONE', 'PARTIAL', 'COMPLETE'],
        'integrity_impact': ['PARTIAL', 'COMPLETE', 'PARTIAL', 'COMPLETE', 'PARTIAL'],
        'availability_impact': ['PARTIAL', 'COMPLETE', 'PARTIAL', 'PARTIAL', 'COMPLETE'],
        'patch_available': [1, 0, 1, 0, 1],
        'exploit_available': [0, 1, 0, 1, 0]
    }
    
    # Create risk scores (0-10 scale)
    sample_scores = [6.5, 8.9, 4.2, 7.8, 5.5]
    
    # Convert to DataFrame
    df = pd.DataFrame(sample_data)
    
    # Initialize the model
    print("Initializing vulnerability assessment model...")
    model = VulnerabilityAssessmentModel()
    
    # Train the model
    print("Training vulnerability assessment model...")
    model.train(df, np.array(sample_scores))
    
    # Make predictions
    print("Making predictions...")
    predictions = model.predict(df)
    severities = model.get_severity(predictions)
    
    # Display results
    print("\nResults:")
    for i, (score, severity) in enumerate(zip(predictions, severities)):
        print(f"Sample {i+1}: Risk Score = {score:.2f}, Severity = {severity}")
    
    # Save the model
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerability_assessment_example.joblib")
    print(f"\nSaving model to {model_path}")
    model.save(model_path)
    
    # Load the model
    print("Loading model from file...")
    loaded_model = VulnerabilityAssessmentModel()
    loaded_model.load(model_path)
    
    # Make predictions with loaded model
    print("Making predictions with loaded model...")
    loaded_predictions = loaded_model.predict(df)
    
    # Verify predictions match
    print("Verifying predictions match...")
    match = all(abs(p1 - p2) < 0.001 for p1, p2 in zip(predictions, loaded_predictions))
    print(f"Predictions match: {match}")
    
    return model_path


if __name__ == "__main__":
    print("SecurityAI ML Models Usage Example")
    print("==================================")
    
    # Run demonstrations
    threat_model_path = demonstrate_threat_detection()
    vuln_model_path = demonstrate_vulnerability_assessment()
    
    print("\n=== Demonstration Complete ===")
    print(f"Threat Detection Model saved to: {threat_model_path}")
    print(f"Vulnerability Assessment Model saved to: {vuln_model_path}")