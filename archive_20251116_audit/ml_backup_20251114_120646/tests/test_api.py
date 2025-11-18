from fastapi.testclient import TestClient
import json
import pytest
from unittest.mock import patch, MagicMock

from app.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to SecurityAI ML Service"}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_models():
    response = client.get("/models")
    assert response.status_code == 200
    data = response.json()
    assert "models" in data
    assert len(data["models"]) >= 2  # At least threat_detection and vulnerability_assessment
    
    # Check that the required models exist
    model_names = [model["name"] for model in data["models"]]
    assert "threat_detection" in model_names
    assert "vulnerability_assessment" in model_names


@patch("app.models.threat_detection.ThreatDetectionModel")
def test_predict_threat_detection(mock_model):
    # Mock the model's predict and predict_proba methods
    instance = mock_model.return_value
    instance.predict.return_value = ["malicious"]
    instance.predict_proba.return_value = [0.85]
    
    # Test data
    test_data = {
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
    
    response = client.post("/predict", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "malicious"
    assert "probability" in data
    assert "model_info" in data


@patch("app.models.vulnerability_assessment.VulnerabilityAssessmentModel")
def test_predict_vulnerability_assessment(mock_model):
    # Mock the model's predict and get_severity methods
    instance = mock_model.return_value
    instance.predict.return_value = [7.5]
    instance.get_severity.return_value = ["high"]
    
    # Test data
    test_data = {
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
    
    response = client.post("/predict", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert "score" in data
    assert data["severity"] == "high"
    assert "model_info" in data


@patch("app.models.threat_detection.ThreatDetectionModel")
@patch("app.models.vulnerability_assessment.VulnerabilityAssessmentModel")
def test_batch_predict(mock_vuln_model, mock_threat_model):
    # Mock the models
    threat_instance = mock_threat_model.return_value
    threat_instance.predict.return_value = ["malicious", "benign"]
    threat_instance.predict_proba.return_value = [0.85, 0.15]
    
    vuln_instance = mock_vuln_model.return_value
    vuln_instance.predict.return_value = [7.5]
    vuln_instance.get_severity.return_value = ["high"]
    
    # Test data
    test_data = {
        "items": [
            {
                "features": {
                    "source_ip": "192.168.1.1",
                    "destination_ip": "10.0.0.2"
                },
                "model_name": "threat_detection"
            },
            {
                "features": {
                    "source_ip": "10.0.0.1",
                    "destination_ip": "192.168.1.2"
                },
                "model_name": "threat_detection"
            },
            {
                "features": {
                    "cve_id": "CVE-2021-1234",
                    "cvss_base_score": 7.5
                },
                "model_name": "vulnerability_assessment"
            }
        ]
    }
    
    response = client.post("/batch-predict", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert len(data["results"]) == 3
    assert "failed_indices" in data
    assert "errors" in data


@patch("app.models.threat_detection.ThreatDetectionModel")
def test_train_threat_detection(mock_model):
    # Mock the model
    instance = mock_model.return_value
    instance.train.return_value = None
    instance.log_to_mlflow.return_value = "abc123"
    
    # Test data
    test_data = {
        "model_name": "threat_detection",
        "features": [
            {
                "source_ip": "192.168.1.1",
                "destination_ip": "10.0.0.2"
            },
            {
                "source_ip": "10.0.0.1",
                "destination_ip": "192.168.1.2"
            }
        ],
        "labels": ["malicious", "benign"],
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 10
        },
        "run_name": "test_run"
    }
    
    response = client.post("/train", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "threat_detection"
    assert data["status"] == "success"
    assert "run_id" in data


@patch("app.models.vulnerability_assessment.VulnerabilityAssessmentModel")
def test_train_vulnerability_assessment(mock_model):
    # Mock the model
    instance = mock_model.return_value
    instance.train.return_value = None
    instance.log_to_mlflow.return_value = "def456"
    
    # Test data
    test_data = {
        "model_name": "vulnerability_assessment",
        "features": [
            {
                "cve_id": "CVE-2021-1234",
                "cvss_base_score": 7.5
            },
            {
                "cve_id": "CVE-2022-5678",
                "cvss_base_score": 9.1
            }
        ],
        "labels": [6.5, 8.9],
        "hyperparameters": {
            "n_estimators": 100,
            "learning_rate": 0.1
        },
        "run_name": "test_run"
    }
    
    response = client.post("/train", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "vulnerability_assessment"
    assert data["status"] == "success"
    assert "run_id" in data


@patch("app.models.threat_detection.ThreatDetectionModel")
def test_evaluate_threat_detection(mock_model):
    # Mock the model
    instance = mock_model.return_value
    instance.predict.return_value = ["malicious", "benign"]
    
    # Test data
    test_data = {
        "model_name": "threat_detection",
        "features": [
            {
                "source_ip": "192.168.1.1",
                "destination_ip": "10.0.0.2"
            },
            {
                "source_ip": "10.0.0.1",
                "destination_ip": "192.168.1.2"
            }
        ],
        "labels": ["malicious", "benign"],
        "model_version": "latest"
    }
    
    response = client.post("/evaluate", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "threat_detection"
    assert data["status"] == "success"
    assert "metrics" in data
    assert "confusion_matrix" in data


@patch("app.models.vulnerability_assessment.VulnerabilityAssessmentModel")
def test_evaluate_vulnerability_assessment(mock_model):
    # Mock the model
    instance = mock_model.return_value
    instance.predict.return_value = [6.5, 8.9]
    
    # Test data
    test_data = {
        "model_name": "vulnerability_assessment",
        "features": [
            {
                "cve_id": "CVE-2021-1234",
                "cvss_base_score": 7.5
            },
            {
                "cve_id": "CVE-2022-5678",
                "cvss_base_score": 9.1
            }
        ],
        "labels": [6.5, 8.9],
        "model_version": "latest"
    }
    
    response = client.post("/evaluate", json=test_data)
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "vulnerability_assessment"
    assert data["status"] == "success"
    assert "metrics" in data