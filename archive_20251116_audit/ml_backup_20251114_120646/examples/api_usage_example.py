#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Example script demonstrating how to use the ML service API endpoints.

This script shows how to:
1. Make a single prediction request
2. Make a batch prediction request
3. Train a model with new data
4. Evaluate a model's performance
5. List available models

Note: This assumes the ML service is running locally on port 8001.
"""

import requests
import json
import time

# Base URL for the ML service
BASE_URL = "http://localhost:8001"


def check_service_health():
    """Check if the ML service is healthy."""
    print("\n=== Checking Service Health ===")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200


def list_available_models():
    """List all available models in the service."""
    print("\n=== Listing Available Models ===")
    response = requests.get(f"{BASE_URL}/models")
    print(f"Status Code: {response.status_code}")
    print("Available Models:")
    for model in response.json()["models"]:
        print(f"  - {model['name']}: {model['description']}")
        print(f"    Versions: {', '.join(model['versions'])}")
        print(f"    Latest: {model['latest']}")
    return response.json()["models"]


def make_threat_detection_prediction():
    """Make a prediction using the threat detection model."""
    print("\n=== Making Threat Detection Prediction ===")
    
    # Sample data for threat detection
    data = {
        "features": {
            "source_ip": "192.168.1.1",
            "destination_ip": "10.0.0.2",
            "source_port": 12345,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 100,
            "byte_count": 1500,
            "duration": 5.2,
            "flag_syn": 1,
            "flag_ack": 0,
            "flag_fin": 0
        },
        "model_name": "threat_detection",
        "model_version": "latest"
    }
    
    # Make the prediction request
    response = requests.post(f"{BASE_URL}/predict", json=data)
    print(f"Status Code: {response.status_code}")
    print("Prediction Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def make_vulnerability_assessment_prediction():
    """Make a prediction using the vulnerability assessment model."""
    print("\n=== Making Vulnerability Assessment Prediction ===")
    
    # Sample data for vulnerability assessment
    data = {
        "features": {
            "cve_id": "CVE-2021-1234",
            "cwe_id": "CWE-79",
            "cvss_base_score": 7.5,
            "access_vector": "NETWORK",
            "access_complexity": "LOW",
            "authentication": "NONE",
            "confidentiality_impact": "PARTIAL",
            "integrity_impact": "PARTIAL",
            "availability_impact": "PARTIAL",
            "patch_available": 1,
            "exploit_available": 0
        },
        "model_name": "vulnerability_assessment",
        "model_version": "latest"
    }
    
    # Make the prediction request
    response = requests.post(f"{BASE_URL}/predict", json=data)
    print(f"Status Code: {response.status_code}")
    print("Prediction Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def make_batch_prediction():
    """Make a batch prediction request."""
    print("\n=== Making Batch Prediction ===")
    
    # Sample data for batch prediction
    data = {
        "items": [
            {
                "features": {
                    "source_ip": "192.168.1.1",
                    "destination_ip": "10.0.0.2",
                    "source_port": 12345,
                    "destination_port": 80,
                    "protocol": "TCP",
                    "packet_count": 100,
                    "byte_count": 1500,
                    "duration": 5.2,
                    "flag_syn": 1,
                    "flag_ack": 0,
                    "flag_fin": 0
                },
                "model_name": "threat_detection"
            },
            {
                "features": {
                    "cve_id": "CVE-2021-1234",
                    "cwe_id": "CWE-79",
                    "cvss_base_score": 7.5,
                    "access_vector": "NETWORK",
                    "access_complexity": "LOW",
                    "authentication": "NONE",
                    "confidentiality_impact": "PARTIAL",
                    "integrity_impact": "PARTIAL",
                    "availability_impact": "PARTIAL",
                    "patch_available": 1,
                    "exploit_available": 0
                },
                "model_name": "vulnerability_assessment"
            }
        ]
    }
    
    # Make the batch prediction request
    response = requests.post(f"{BASE_URL}/batch-predict", json=data)
    print(f"Status Code: {response.status_code}")
    print("Batch Prediction Results:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def train_threat_detection_model():
    """Train the threat detection model with new data."""
    print("\n=== Training Threat Detection Model ===")
    
    # Sample training data
    data = {
        "model_name": "threat_detection",
        "features": [
            {
                "source_ip": "192.168.1.1",
                "destination_ip": "10.0.0.2",
                "source_port": 12345,
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": 100,
                "byte_count": 1500,
                "duration": 5.2,
                "flag_syn": 1,
                "flag_ack": 0,
                "flag_fin": 0
            },
            {
                "source_ip": "10.0.0.1",
                "destination_ip": "192.168.1.2",
                "source_port": 54321,
                "destination_port": 443,
                "protocol": "UDP",
                "packet_count": 200,
                "byte_count": 3000,
                "duration": 10.5,
                "flag_syn": 0,
                "flag_ack": 1,
                "flag_fin": 0
            }
        ],
        "labels": ["malicious", "benign"],
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 10
        },
        "run_name": "example_training_run"
    }
    
    # Make the training request
    response = requests.post(f"{BASE_URL}/train", json=data)
    print(f"Status Code: {response.status_code}")
    print("Training Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def evaluate_vulnerability_assessment_model():
    """Evaluate the vulnerability assessment model."""
    print("\n=== Evaluating Vulnerability Assessment Model ===")
    
    # Sample evaluation data
    data = {
        "model_name": "vulnerability_assessment",
        "features": [
            {
                "cve_id": "CVE-2021-1234",
                "cwe_id": "CWE-79",
                "cvss_base_score": 7.5,
                "access_vector": "NETWORK",
                "access_complexity": "LOW",
                "authentication": "NONE",
                "confidentiality_impact": "PARTIAL",
                "integrity_impact": "PARTIAL",
                "availability_impact": "PARTIAL",
                "patch_available": 1,
                "exploit_available": 0
            },
            {
                "cve_id": "CVE-2022-5678",
                "cwe_id": "CWE-89",
                "cvss_base_score": 9.1,
                "access_vector": "LOCAL",
                "access_complexity": "HIGH",
                "authentication": "SINGLE",
                "confidentiality_impact": "COMPLETE",
                "integrity_impact": "COMPLETE",
                "availability_impact": "COMPLETE",
                "patch_available": 0,
                "exploit_available": 1
            }
        ],
        "labels": [6.5, 8.9],
        "model_version": "latest"
    }
    
    # Make the evaluation request
    response = requests.post(f"{BASE_URL}/evaluate", json=data)
    print(f"Status Code: {response.status_code}")
    print("Evaluation Result:")
    print(json.dumps(response.json(), indent=2))
    return response.json()


def run_all_examples():
    """Run all API examples."""
    print("SecurityAI ML Service API Usage Examples")
    print("=======================================")
    
    # Check if the service is running
    if not check_service_health():
        print("\nError: ML service is not running or not healthy.")
        print("Please start the service with 'uvicorn app.main:app --reload --port 8001'")
        return
    
    # Run all examples
    list_available_models()
    make_threat_detection_prediction()
    make_vulnerability_assessment_prediction()
    make_batch_prediction()
    train_threat_detection_model()
    evaluate_vulnerability_assessment_model()
    
    print("\n=== All Examples Completed ===")


if __name__ == "__main__":
    run_all_examples()