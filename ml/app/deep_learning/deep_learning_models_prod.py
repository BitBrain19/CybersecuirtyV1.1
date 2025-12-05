"""
Deep Learning Detection Models - Production System
Implements CNN, LSTM/GRU, Autoencoder, Transformer, and GNN for advanced anomaly detection
"""

import asyncio
import json
import logging
import pickle
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np
from collections import defaultdict, deque
import warnings

warnings.filterwarnings('ignore')

# Deep Learning frameworks
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, callbacks
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from tensorflow.keras.utils import to_categorical
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None
    keras = None

try:
    import torch
    import torch.nn as nn
    from torch_geometric.nn import GCNConv, GraphConv
    from torch_geometric.data import Data, DataLoader
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False
    torch = None
    nn = None

from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Types of anomalies detected"""
    TRAFFIC_ANOMALY = "traffic_anomaly"
    SEQUENCE_ANOMALY = "sequence_anomaly"
    RECONSTRUCTION_ERROR = "reconstruction_error"
    GRAPH_ANOMALY = "graph_anomaly"
    PATTERN_DEVIATION = "pattern_deviation"


@dataclass
class DeepLearningConfig:
    """Configuration for deep learning models"""
    cnn_filters: int = 64
    cnn_kernel_size: int = 3
    lstm_units: int = 128
    gru_units: int = 128
    autoencoder_encoding_dim: int = 32
    transformer_heads: int = 8
    transformer_dim_ff: int = 256
    gnn_hidden_dim: int = 64
    batch_size: int = 32
    epochs: int = 50
    learning_rate: float = 0.001
    dropout_rate: float = 0.2
    validation_split: float = 0.2
    early_stopping_patience: int = 5
    verbose: int = 0


@dataclass
class DetectionResult:
    """Result from deep learning anomaly detection"""
    anomaly_type: AnomalyType
    anomaly_score: float  # 0-1, higher = more anomalous
    is_anomaly: bool
    confidence: float
    model_used: str
    detection_time: datetime = field(default_factory=datetime.now)
    raw_prediction: Optional[np.ndarray] = None
    explanation: str = ""


class CNNTrafficClassifier:
    """Convolutional Neural Network for traffic pattern classification"""
    
    def __init__(self, config: DeepLearningConfig = None):
        self.config = config or DeepLearningConfig()
        self.model = None
        self.scaler = StandardScaler()
        self.input_shape = None
        self._lock = threading.RLock()
        
    def build_model(self, input_shape: Tuple[int, ...]):
        """Build CNN architecture for 1D traffic sequences"""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("TensorFlow not available, skipping CNN model build")
            return
            
        self.input_shape = input_shape
        
        self.model = models.Sequential([
            layers.Input(shape=input_shape),
            layers.Conv1D(self.config.cnn_filters, self.config.cnn_kernel_size, 
                         activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Dropout(self.config.dropout_rate),
            layers.MaxPooling1D(2),
            
            layers.Conv1D(self.config.cnn_filters * 2, self.config.cnn_kernel_size,
                         activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Dropout(self.config.dropout_rate),
            layers.MaxPooling1D(2),
            
            layers.Conv1D(self.config.cnn_filters * 4, self.config.cnn_kernel_size,
                         activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Dropout(self.config.dropout_rate),
            
            layers.GlobalAveragePooling1D(),
            layers.Dense(128, activation='relu'),
            layers.Dropout(self.config.dropout_rate),
            layers.Dense(64, activation='relu'),
            layers.Dense(2, activation='softmax')  # Binary classification
        ])
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config.learning_rate),
            loss='categorical_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
    def train(self, X: np.ndarray, y: np.ndarray):
        """Train CNN model"""
        if self.model is None:
            self.build_model((X.shape[1], X.shape[2]) if len(X.shape) > 2 else (X.shape[1],))
        
        with self._lock:
            X_scaled = self.scaler.fit_transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
            y_cat = to_categorical(y, 2)
            
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.config.early_stopping_patience,
                restore_best_weights=True
            )
            
            self.model.fit(
                X_scaled, y_cat,
                batch_size=self.config.batch_size,
                epochs=self.config.epochs,
                validation_split=self.config.validation_split,
                callbacks=[early_stop],
                verbose=self.config.verbose
            )
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict on new traffic"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        with self._lock:
            X_scaled = self.scaler.transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
            return self.model.predict(X_scaled, verbose=0)
    
    def get_anomaly_score(self, X: np.ndarray) -> float:
        """Get anomaly score - uncertainty in classification"""
        predictions = self.predict(X)
        max_prob = np.max(predictions, axis=1)
        anomaly_score = 1.0 - np.mean(max_prob)  # Higher = more uncertain = anomalous
        return float(anomaly_score)


class LSTMSequenceDetector:
    """LSTM/GRU for sequence-based anomaly detection"""
    
    def __init__(self, use_gru: bool = False, config: DeepLearningConfig = None):
        self.config = config or DeepLearningConfig()
        self.model = None
        self.scaler = StandardScaler()
        self.use_gru = use_gru
        self.sequence_length = 50
        self._lock = threading.RLock()
        
    def build_model(self, input_dim: int):
        """Build LSTM/GRU encoder-decoder for sequence anomaly detection"""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("TensorFlow not available, skipping LSTM model build")
            return
        
        rnn_layer = layers.GRU if self.use_gru else layers.LSTM
        units = self.config.gru_units if self.use_gru else self.config.lstm_units
        
        # Encoder-Decoder architecture
        self.model = models.Sequential([
            layers.Input(shape=(self.sequence_length, input_dim)),
            
            # Encoder
            rnn_layer(units, activation='relu', return_sequences=True),
            layers.Dropout(self.config.dropout_rate),
            rnn_layer(units // 2, activation='relu', return_sequences=False),
            
            # Decoder
            layers.RepeatVector(self.sequence_length),
            rnn_layer(units // 2, activation='relu', return_sequences=True),
            layers.Dropout(self.config.dropout_rate),
            rnn_layer(units, activation='relu', return_sequences=True),
            
            layers.TimeDistributed(layers.Dense(input_dim))
        ])
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config.learning_rate),
            loss='mse'
        )
    
    def train(self, X: np.ndarray):
        """Train on normal sequences to learn reconstruction"""
        if self.model is None:
            self.build_model(X.shape[2] if len(X.shape) > 2 else 1)
        
        with self._lock:
            X_scaled = self.scaler.fit_transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
            
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.config.early_stopping_patience,
                restore_best_weights=True
            )
            
            self.model.fit(
                X_scaled, X_scaled,  # Autoencoder: reconstruct input
                batch_size=self.config.batch_size,
                epochs=self.config.epochs,
                validation_split=self.config.validation_split,
                callbacks=[early_stop],
                verbose=self.config.verbose
            )
    
    def get_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Get reconstruction error for each sequence"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        with self._lock:
            X_scaled = self.scaler.transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
            X_pred = self.model.predict(X_scaled, verbose=0)
            mse = np.mean(np.square(X_scaled - X_pred), axis=(1, 2))
            return mse


class AutoencoderAnomalyDetector:
    """Autoencoder for unsupervised anomaly detection"""
    
    def __init__(self, config: DeepLearningConfig = None):
        self.config = config or DeepLearningConfig()
        self.model = None
        self.encoder = None
        self.scaler = MinMaxScaler()
        self._lock = threading.RLock()
        
    def build_model(self, input_dim: int):
        """Build autoencoder with bottleneck architecture"""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("TensorFlow not available, skipping Autoencoder model build")
            return
        
        # Encoder
        encoder_inputs = layers.Input(shape=(input_dim,))
        x = layers.Dense(256, activation='relu')(encoder_inputs)
        x = layers.Dropout(self.config.dropout_rate)(x)
        x = layers.Dense(128, activation='relu')(x)
        x = layers.Dropout(self.config.dropout_rate)(x)
        encoded = layers.Dense(self.config.autoencoder_encoding_dim, activation='relu')(x)
        
        # Decoder
        x = layers.Dense(128, activation='relu')(encoded)
        x = layers.Dropout(self.config.dropout_rate)(x)
        x = layers.Dense(256, activation='relu')(x)
        x = layers.Dropout(self.config.dropout_rate)(x)
        decoded = layers.Dense(input_dim, activation='sigmoid')(x)
        
        self.model = models.Model(encoder_inputs, decoded)
        self.encoder = models.Model(encoder_inputs, encoded)
        
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config.learning_rate),
            loss='mse',
            metrics=['mae']
        )
    
    def train(self, X: np.ndarray):
        """Train on normal data to learn reconstruction"""
        if self.model is None:
            self.build_model(X.shape[1])
        
        with self._lock:
            X_scaled = self.scaler.fit_transform(X)
            
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.config.early_stopping_patience,
                restore_best_weights=True
            )
            
            self.model.fit(
                X_scaled, X_scaled,
                batch_size=self.config.batch_size,
                epochs=self.config.epochs,
                validation_split=self.config.validation_split,
                callbacks=[early_stop],
                verbose=self.config.verbose
            )
    
    def detect_anomalies(self, X: np.ndarray, threshold: float = 0.95) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies based on reconstruction error"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        with self._lock:
            X_scaled = self.scaler.transform(X)
            X_pred = self.model.predict(X_scaled, verbose=0)
            mse = np.mean(np.square(X_scaled - X_pred), axis=1)
            
            # Normalize to 0-1 range
            anomaly_scores = (mse - np.min(mse)) / (np.max(mse) - np.min(mse) + 1e-6)
            is_anomaly = anomaly_scores > threshold
            
            return is_anomaly, anomaly_scores


class TransformerLogUnderstanding:
    """Transformer-based model for log sequence understanding and anomaly detection"""
    
    def __init__(self, vocab_size: int = 5000, sequence_length: int = 100, config: DeepLearningConfig = None):
        self.config = config or DeepLearningConfig()
        self.model = None
        self.scaler = StandardScaler()
        self.vocab_size = vocab_size
        self.sequence_length = sequence_length
        self._lock = threading.RLock()
        
    def build_model(self):
        """Build Transformer model for log understanding"""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("TensorFlow not available, skipping Transformer model build")
            return
        
        inputs = layers.Input(shape=(self.sequence_length,), dtype=tf.int32)
        
        # Embedding
        x = layers.Embedding(self.vocab_size, 128)(inputs)
        x = layers.Dropout(self.config.dropout_rate)(x)
        
        # Multi-head attention
        attn_output = layers.MultiHeadAttention(
            num_heads=self.config.transformer_heads,
            key_dim=128 // self.config.transformer_heads
        )(x, x)
        x = layers.Add()([x, attn_output])
        x = layers.LayerNormalization()(x)
        
        # Feed-forward network
        ff_output = layers.Dense(self.config.transformer_dim_ff, activation='relu')(x)
        ff_output = layers.Dense(128)(ff_output)
        x = layers.Add()([x, ff_output])
        x = layers.LayerNormalization()(x)
        
        # Output layers
        x = layers.GlobalAveragePooling1D()(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(self.config.dropout_rate)(x)
        outputs = layers.Dense(2, activation='softmax')(x)  # Normal/Anomaly
        
        self.model = models.Model(inputs, outputs)
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.config.learning_rate),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
    
    def train(self, X_seq: np.ndarray, y: np.ndarray):
        """Train on log sequences"""
        if self.model is None:
            self.build_model()
        
        with self._lock:
            # Ensure sequences are padded to correct length
            X_padded = np.zeros((len(X_seq), self.sequence_length), dtype=np.int32)
            for i, seq in enumerate(X_seq):
                seq_short = seq[-self.sequence_length:] if len(seq) > self.sequence_length else seq
                X_padded[i, -len(seq_short):] = seq_short
            
            y_cat = to_categorical(y, 2)
            
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss',
                patience=self.config.early_stopping_patience,
                restore_best_weights=True
            )
            
            self.model.fit(
                X_padded, y_cat,
                batch_size=self.config.batch_size,
                epochs=self.config.epochs,
                validation_split=self.config.validation_split,
                callbacks=[early_stop],
                verbose=self.config.verbose
            )
    
    def predict(self, X_seq: np.ndarray) -> np.ndarray:
        """Predict anomalies in log sequences"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        with self._lock:
            X_padded = np.zeros((len(X_seq), self.sequence_length), dtype=np.int32)
            for i, seq in enumerate(X_seq):
                seq_short = seq[-self.sequence_length:] if len(seq) > self.sequence_length else seq
                X_padded[i, -len(seq_short):] = seq_short
            
            return self.model.predict(X_padded, verbose=0)


class GraphNeuralNetworkDetector:
    """Graph Neural Network for complex attack graph anomaly detection"""
    
    def __init__(self, config: DeepLearningConfig = None):
        self.config = config or DeepLearningConfig()
        self.model = None
        self._lock = threading.RLock()
        
    def build_gnn_model(self, num_node_features: int, num_classes: int = 2):
        """Build GNN model using PyTorch Geometric"""
        if not PYTORCH_AVAILABLE:
            logger.warning("PyTorch not available, skipping GNN model build")
            return
        
        class GNNModel(nn.Module):
            def __init__(self, in_channels, hidden_channels, out_channels):
                super().__init__()
                self.conv1 = GCNConv(in_channels, hidden_channels)
                self.conv2 = GCNConv(hidden_channels, out_channels)
                self.dropout = nn.Dropout(self.config.dropout_rate)
                
            def forward(self, x, edge_index):
                x = self.conv1(x, edge_index)
                x = nn.functional.relu(x)
                x = self.dropout(x)
                x = self.conv2(x, edge_index)
                return x
        
        self.model = GNNModel(num_node_features, self.config.gnn_hidden_dim, num_classes)
    
    def detect_graph_anomalies(self, node_features: np.ndarray, 
                              edge_list: List[Tuple[int, int]],
                              threshold: float = 0.7) -> Tuple[List[int], List[float]]:
        """Detect anomalous nodes in attack graph"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        if not PYTORCH_AVAILABLE:
            logger.warning("PyTorch not available for GNN detection")
            return [], []
        
        with self._lock:
            # Convert to PyTorch tensors
            x = torch.FloatTensor(node_features)
            edges = torch.LongTensor(edge_list).t().contiguous()
            
            # Create graph data
            data = Data(x=x, edge_index=edges)
            
            # Forward pass
            self.model.eval()
            with torch.no_grad():
                out = self.model(data.x, data.edge_index)
                anomaly_scores = torch.softmax(out, dim=1)[:, 1].numpy()
            
            # Detect anomalies
            anomalous_nodes = [i for i, score in enumerate(anomaly_scores) if score > threshold]
            
            return anomalous_nodes, anomaly_scores.tolist()


@dataclass
class DeepLearningEnsemble:
    """Ensemble of deep learning models for robust anomaly detection"""
    cnn_classifier: Optional[CNNTrafficClassifier] = None
    lstm_detector: Optional[LSTMSequenceDetector] = None
    autoencoder: Optional[AutoencoderAnomalyDetector] = None
    transformer: Optional[TransformerLogUnderstanding] = None
    gnn_detector: Optional[GraphNeuralNetworkDetector] = None
    config: DeepLearningConfig = field(default_factory=DeepLearningConfig)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    
    def __post_init__(self):
        if self.cnn_classifier is None:
            self.cnn_classifier = CNNTrafficClassifier(self.config)
        if self.lstm_detector is None:
            self.lstm_detector = LSTMSequenceDetector(use_gru=False, config=self.config)
        if self.autoencoder is None:
            self.autoencoder = AutoencoderAnomalyDetector(self.config)
        if self.transformer is None:
            self.transformer = TransformerLogUnderstanding(self.config)
        if self.gnn_detector is None:
            self.gnn_detector = GraphNeuralNetworkDetector(self.config)
    
    def ensemble_detect(self, 
                       traffic_data: Optional[np.ndarray] = None,
                       sequence_data: Optional[np.ndarray] = None,
                       feature_data: Optional[np.ndarray] = None,
                       log_sequences: Optional[np.ndarray] = None,
                       graph_nodes: Optional[np.ndarray] = None,
                       graph_edges: Optional[List[Tuple[int, int]]] = None) -> DetectionResult:
        """Run ensemble detection across all models"""
        
        scores = []
        models_used = []
        
        try:
            with self._lock:
                # CNN Traffic Classification
                if traffic_data is not None and self.cnn_classifier.model is not None:
                    cnn_score = self.cnn_classifier.get_anomaly_score(traffic_data)
                    scores.append(cnn_score)
                    models_used.append("CNN")
                
                # LSTM Sequence Detection
                if sequence_data is not None and self.lstm_detector.model is not None:
                    lstm_error = self.lstm_detector.get_reconstruction_error(sequence_data)
                    lstm_score = np.mean(lstm_error) / (1.0 + np.max(lstm_error))
                    scores.append(lstm_score)
                    models_used.append("LSTM")
                
                # Autoencoder Detection
                if feature_data is not None and self.autoencoder.model is not None:
                    is_anom, ae_scores = self.autoencoder.detect_anomalies(feature_data)
                    ae_score = np.mean(ae_scores)
                    scores.append(ae_score)
                    models_used.append("Autoencoder")
                
                # Transformer Log Understanding
                if log_sequences is not None and self.transformer.model is not None:
                    trans_preds = self.transformer.predict(log_sequences)
                    trans_score = np.mean(trans_preds[:, 1])
                    scores.append(trans_score)
                    models_used.append("Transformer")
                
                # GNN Graph Anomaly Detection
                if graph_nodes is not None and self.gnn_detector.model is not None:
                    if graph_edges is None:
                        graph_edges = []
                    anom_nodes, gnn_scores = self.gnn_detector.detect_graph_anomalies(
                        graph_nodes, graph_edges
                    )
                    gnn_score = np.mean(gnn_scores) if gnn_scores else 0.0
                    scores.append(gnn_score)
                    models_used.append("GNN")
                
                # Ensemble voting
                ensemble_score = np.mean(scores) if scores else 0.5
                is_anomaly = ensemble_score > 0.5
                
                return DetectionResult(
                    anomaly_type=AnomalyType.PATTERN_DEVIATION,
                    anomaly_score=ensemble_score,
                    is_anomaly=is_anomaly,
                    confidence=abs(ensemble_score - 0.5) * 2,  # Distance from decision boundary
                    model_used=f"Ensemble[{','.join(models_used)}]",
                    explanation=f"Ensemble score: {ensemble_score:.3f} across {len(models_used)} models"
                )
        except Exception as e:
            logger.error(f"Ensemble detection error: {e}")
            return DetectionResult(
                anomaly_type=AnomalyType.PATTERN_DEVIATION,
                anomaly_score=0.5,
                is_anomaly=False,
                confidence=0.0,
                model_used="Ensemble[Error]",
                explanation=f"Error in ensemble: {str(e)}"
            )
    
    def save_models(self, path: Union[str, Path]):
        """Save all trained models"""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            if self.cnn_classifier.model:
                self.cnn_classifier.model.save(str(path / "cnn_model.h5"))
                with open(str(path / "cnn_scaler.pkl"), 'wb') as f:
                    pickle.dump(self.cnn_classifier.scaler, f)
            
            if self.lstm_detector.model:
                self.lstm_detector.model.save(str(path / "lstm_model.h5"))
                with open(str(path / "lstm_scaler.pkl"), 'wb') as f:
                    pickle.dump(self.lstm_detector.scaler, f)
            
            if self.autoencoder.model:
                self.autoencoder.model.save(str(path / "ae_model.h5"))
                with open(str(path / "ae_scaler.pkl"), 'wb') as f:
                    pickle.dump(self.autoencoder.scaler, f)
            
            if self.transformer.model:
                self.transformer.model.save(str(path / "transformer_model.h5"))
            
            logger.info(f"Models saved to {path}")
    
    def load_models(self, path: Union[str, Path]):
        """Load previously trained models"""
        path = Path(path)
        
        with self._lock:
            if (path / "cnn_model.h5").exists() and TENSORFLOW_AVAILABLE:
                self.cnn_classifier.model = keras.models.load_model(str(path / "cnn_model.h5"))
                with open(str(path / "cnn_scaler.pkl"), 'rb') as f:
                    self.cnn_classifier.scaler = pickle.load(f)
            
            if (path / "lstm_model.h5").exists() and TENSORFLOW_AVAILABLE:
                self.lstm_detector.model = keras.models.load_model(str(path / "lstm_model.h5"))
                with open(str(path / "lstm_scaler.pkl"), 'rb') as f:
                    self.lstm_detector.scaler = pickle.load(f)
            
            if (path / "ae_model.h5").exists() and TENSORFLOW_AVAILABLE:
                self.autoencoder.model = keras.models.load_model(str(path / "ae_model.h5"))
                with open(str(path / "ae_scaler.pkl"), 'rb') as f:
                    self.autoencoder.scaler = pickle.load(f)
            
            if (path / "transformer_model.h5").exists() and TENSORFLOW_AVAILABLE:
                self.transformer.model = keras.models.load_model(str(path / "transformer_model.h5"))
            
            logger.info(f"Models loaded from {path}")


# Global instance
_deep_learning_ensemble: Optional[DeepLearningEnsemble] = None


def get_deep_learning_ensemble() -> DeepLearningEnsemble:
    """Get or create global deep learning ensemble"""
    global _deep_learning_ensemble
    if _deep_learning_ensemble is None:
        _deep_learning_ensemble = DeepLearningEnsemble()
    return _deep_learning_ensemble


if __name__ == "__main__":
    # Demo: Create and test deep learning ensemble
    ensemble = get_deep_learning_ensemble()
    
    # Test data
    traffic_data = np.random.rand(10, 100, 32)  # (batch, timesteps, features)
    sequence_data = np.random.rand(10, 50, 16)
    feature_data = np.random.rand(10, 64)
    
    logger.info("Deep Learning Detection Models initialized")
