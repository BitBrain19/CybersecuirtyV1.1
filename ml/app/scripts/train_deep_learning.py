"""
Training Script for Deep Learning Models
Trains CNN, LSTM, Autoencoder, and Transformer models for advanced anomaly detection
"""

import os
import sys
import json
import argparse
import glob
import time
from datetime import datetime
from typing import List, Dict, Any, Tuple
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.deep_learning.deep_learning_models_prod import (
    DeepLearningConfig,
    CNNTrafficClassifier,
    LSTMSequenceDetector,
    AutoencoderAnomalyDetector,
    TransformerLogUnderstanding
)


def generate_synthetic_traffic_data(n_samples: int = 1000, sequence_length: int = 100) -> Tuple[np.ndarray, np.ndarray]:
    """Generate synthetic network traffic data for CNN"""
    import random
    
    X = []
    y = []
    
    for i in range(n_samples):
        # Generate traffic sequence (packet sizes, inter-arrival times, etc.)
        is_anomaly = random.random() < 0.2  # 20% anomalies
        
        if is_anomaly:
            # Anomalous traffic: sudden spikes, unusual patterns
            traffic = np.random.exponential(scale=200, size=sequence_length)
            # Add spikes
            spike_positions = np.random.choice(sequence_length, size=5, replace=False)
            traffic[spike_positions] *= 10
            y.append(1)
        else:
            # Normal traffic: more uniform distribution
            traffic = np.random.normal(loc=100, scale=20, size=sequence_length)
            y.append(0)
        
        X.append(traffic)
    
    return np.array(X), np.array(y)


def generate_synthetic_sequence_data(n_samples: int = 800, sequence_length: int = 50, n_features: int = 10) -> np.ndarray:
    """Generate synthetic sequence data for LSTM (normal sequences only for unsupervised learning)"""
    X = []
    
    for i in range(n_samples):
        # Generate normal sequence with temporal patterns
        sequence = []
        for t in range(sequence_length):
            # Features with temporal correlation
            features = np.random.normal(
                loc=np.sin(t / 10) * 5,  # Temporal pattern
                scale=1.0,
                size=n_features
            )
            sequence.append(features)
        
        X.append(sequence)
    
    return np.array(X)


def generate_synthetic_autoencoder_data(n_samples: int = 1000, n_features: int = 50) -> np.ndarray:
    """Generate synthetic data for Autoencoder (normal data only)"""
    # Generate normal data with some structure
    X = np.random.multivariate_normal(
        mean=np.zeros(n_features),
        cov=np.eye(n_features) * 0.5,
        size=n_samples
    )
    
    # Add some correlation between features
    for i in range(0, n_features - 1, 2):
        X[:, i+1] = X[:, i] * 0.7 + np.random.normal(0, 0.3, n_samples)
    
    return X


def generate_synthetic_log_sequences(n_samples: int = 500, sequence_length: int = 20, vocab_size: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
    """Generate synthetic log sequences for Transformer"""
    import random
    
    X = []
    y = []
    
    # Define normal and anomalous patterns
    normal_patterns = [
        [1, 2, 3, 4, 5],  # Login sequence
        [10, 11, 12, 13],  # File access
        [20, 21, 22],      # Network activity
    ]
    
    anomalous_patterns = [
        [100, 101, 102, 103, 104],  # Suspicious activity
        [200, 201, 202],             # Attack pattern
    ]
    
    for i in range(n_samples):
        is_anomaly = random.random() < 0.25  # 25% anomalies
        
        sequence = []
        if is_anomaly:
            # Mix normal and anomalous patterns
            for _ in range(sequence_length // 5):
                if random.random() < 0.6:
                    sequence.extend(random.choice(anomalous_patterns))
                else:
                    sequence.extend(random.choice(normal_patterns))
            y.append(1)
        else:
            # Only normal patterns
            for _ in range(sequence_length // 5):
                sequence.extend(random.choice(normal_patterns))
            y.append(0)
        
        # Pad or truncate to sequence_length
        if len(sequence) < sequence_length:
            sequence.extend([0] * (sequence_length - len(sequence)))
        else:
            sequence = sequence[:sequence_length]
        
        X.append(sequence)
    
    return np.array(X), np.array(y)


def train_cnn_traffic_model(output_dir: str):
    """Train CNN for traffic classification"""
    print("\n" + "=" * 60)
    print("Training CNN Traffic Classifier")
    print("=" * 60)
    
    # Generate data
    print("Generating synthetic traffic data...")
    X, y = generate_synthetic_traffic_data(n_samples=1000, sequence_length=100)
    
    # Reshape for CNN (samples, timesteps, features)
    X = X.reshape(X.shape[0], X.shape[1], 1)
    
    print(f"Data shape: {X.shape}")
    print(f"Anomalies: {sum(y)} / {len(y)}")
    
    # Train
    config = DeepLearningConfig(epochs=20, batch_size=32, verbose=1)
    model = CNNTrafficClassifier(config=config)
    
    print("\nTraining CNN model...")
    model.train(X, y)
    
    # Save
    model_path = os.path.join(output_dir, "cnn_traffic_classifier.h5")
    model.model.save(model_path)
    print(f"Model saved to: {model_path}")
    
    return {
        "model_type": "CNN Traffic Classifier",
        "model_path": model_path,
        "samples": len(X),
        "input_shape": list(X.shape[1:])
    }


def train_lstm_sequence_model(output_dir: str):
    """Train LSTM for sequence anomaly detection"""
    print("\n" + "=" * 60)
    print("Training LSTM Sequence Detector")
    print("=" * 60)
    
    # Generate data (normal sequences only for unsupervised learning)
    print("Generating synthetic sequence data...")
    X = generate_synthetic_sequence_data(n_samples=800, sequence_length=50, n_features=10)
    
    print(f"Data shape: {X.shape}")
    
    # Train
    config = DeepLearningConfig(epochs=30, batch_size=32, verbose=1)
    model = LSTMSequenceDetector(use_gru=False, config=config)
    
    print("\nTraining LSTM model...")
    model.train(X)
    
    # Save
    model_path = os.path.join(output_dir, "lstm_sequence_detector.h5")
    model.model.save(model_path)
    print(f"Model saved to: {model_path}")
    
    return {
        "model_type": "LSTM Sequence Detector",
        "model_path": model_path,
        "samples": len(X),
        "input_shape": list(X.shape[1:])
    }


def train_autoencoder_model(output_dir: str):
    """Train Autoencoder for anomaly detection"""
    print("\n" + "=" * 60)
    print("Training Autoencoder Anomaly Detector")
    print("=" * 60)
    
    # Generate data (normal data only)
    print("Generating synthetic data...")
    X = generate_synthetic_autoencoder_data(n_samples=1000, n_features=50)
    
    print(f"Data shape: {X.shape}")
    
    # Train
    config = DeepLearningConfig(epochs=50, batch_size=32, verbose=1, autoencoder_encoding_dim=16)
    model = AutoencoderAnomalyDetector(config=config)
    
    print("\nTraining Autoencoder...")
    model.train(X)
    
    # Save
    model_path = os.path.join(output_dir, "autoencoder_anomaly_detector.h5")
    model.model.save(model_path)
    print(f"Model saved to: {model_path}")
    
    return {
        "model_type": "Autoencoder Anomaly Detector",
        "model_path": model_path,
        "samples": len(X),
        "input_shape": list(X.shape[1:]),
        "encoding_dim": config.autoencoder_encoding_dim
    }


def train_transformer_log_model(output_dir: str):
    """Train Transformer for log understanding"""
    print("\n" + "=" * 60)
    print("Training Transformer Log Understanding")
    print("=" * 60)
    
    # Generate data
    print("Generating synthetic log sequences...")
    X, y = generate_synthetic_log_sequences(n_samples=500, sequence_length=20, vocab_size=1000)
    
    print(f"Data shape: {X.shape}")
    print(f"Anomalies: {sum(y)} / {len(y)}")
    
    # Train
    config = DeepLearningConfig(epochs=25, batch_size=16, verbose=1)
    model = TransformerLogUnderstanding(vocab_size=1000, sequence_length=20, config=config)
    
    print("\nTraining Transformer model...")
    model.train(X, y)
    
    # Save
    model_path = os.path.join(output_dir, "transformer_log_understanding.h5")
    model.model.save(model_path)
    print(f"Model saved to: {model_path}")
    
    return {
        "model_type": "Transformer Log Understanding",
        "model_path": model_path,
        "samples": len(X),
        "vocab_size": 1000,
        "sequence_length": 20
    }


def train_deep_learning_models(output_dir: str = None, models: List[str] = None):
    """Train all or selected deep learning models"""
    start = time.time()
    
    # Resolve output directory
    if output_dir:
        storage_dir = output_dir
    else:
        storage_dir = os.path.join(os.path.dirname(__file__), "..", "..", "artifacts", "saved", "deep_learning")
    
    os.makedirs(storage_dir, exist_ok=True)
    
    print("=" * 60)
    print("Deep Learning Models Training")
    print("=" * 60)
    print(f"Output directory: {storage_dir}")
    
    # Default to all models if none specified
    if not models:
        models = ["cnn", "lstm", "autoencoder", "transformer"]
    
    results = {
        "trained_at": datetime.now().isoformat(),
        "models": {}
    }
    
    # Train selected models
    if "cnn" in models:
        try:
            result = train_cnn_traffic_model(storage_dir)
            results["models"]["cnn"] = result
        except Exception as e:
            print(f"Error training CNN: {e}")
            results["models"]["cnn"] = {"error": str(e)}
    
    if "lstm" in models:
        try:
            result = train_lstm_sequence_model(storage_dir)
            results["models"]["lstm"] = result
        except Exception as e:
            print(f"Error training LSTM: {e}")
            results["models"]["lstm"] = {"error": str(e)}
    
    if "autoencoder" in models:
        try:
            result = train_autoencoder_model(storage_dir)
            results["models"]["autoencoder"] = result
        except Exception as e:
            print(f"Error training Autoencoder: {e}")
            results["models"]["autoencoder"] = {"error": str(e)}
    
    if "transformer" in models:
        try:
            result = train_transformer_log_model(storage_dir)
            results["models"]["transformer"] = result
        except Exception as e:
            print(f"Error training Transformer: {e}")
            results["models"]["transformer"] = {"error": str(e)}
    
    duration = time.time() - start
    results["training_time_seconds"] = duration
    
    # Save results
    results_path = os.path.join(storage_dir, "deep_learning_training_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"All training completed in {duration:.2f}s")
    print(f"Results saved to: {results_path}")
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Deep Learning Models")
    parser.add_argument("--output-dir", type=str, help="Directory to save trained models")
    parser.add_argument("--models", type=str, nargs="+", 
                        choices=["cnn", "lstm", "autoencoder", "transformer"],
                        help="Specific models to train (default: all)")
    args = parser.parse_args()
    
    results = train_deep_learning_models(output_dir=args.output_dir, models=args.models)
    print("\nFinal Results:")
    print(json.dumps(results, indent=2))
