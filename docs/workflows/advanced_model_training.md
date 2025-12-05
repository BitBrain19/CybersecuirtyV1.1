# Advanced ML Model Training Guide

This guide covers training for **Malware Detection**, **Threat Classification**, and **Deep Learning** models.

---

## 📋 Overview

### Available Training Scripts

| Script | Model Type | Purpose | Data Required |
|--------|-----------|---------|---------------|
| `train_malware_detection.py` | Malware Detection | Detect malicious processes | Process events with malware labels |
| `train_threat_classifier.py` | Threat Classification | Classify threats into categories | Security events with threat categories |
| `train_deep_learning.py` | Deep Learning (CNN, LSTM, Autoencoder, Transformer) | Advanced anomaly detection | Traffic data, sequences, logs |

---

## 🚀 Quick Start

### 1. Malware Detection Training

**With Synthetic Data:**
```bash
docker-compose exec ml_service python -m app.scripts.train_malware_detection
```

**With Your Own Data:**
```bash
docker-compose exec ml_service python -m app.scripts.train_malware_detection \
  --data-dir artifacts/datasets/malware/ \
  --output-dir artifacts/saved/
```

**Expected Output:**
```
Training Malware Detection Model
Total events: 500
Malware samples: 150
Benign samples: 350
Training completed in 12.34s
Model saved to: artifacts/saved/malware_detection_latest.pkl
```

---

### 2. Threat Classification Training

**With Synthetic Data:**
```bash
docker-compose exec ml_service python -m app.scripts.train_threat_classifier
```

**With Your Own Data:**
```bash
docker-compose exec ml_service python -m app.scripts.train_threat_classifier \
  --data-dir artifacts/datasets/threats/ \
  --output-dir artifacts/saved/
```

**Expected Output:**
```
Training Threat Classification Model
Total events: 1000
Threat events: 700
Benign events: 300

Threat Category Distribution:
  malware: 120
  exploit: 95
  lateral_movement: 88
  ...

Training Results:
  Accuracy:  87.50%
  Precision: 85.23%
  Recall:    86.71%
  F1 Score:  85.96%
```

---

### 3. Deep Learning Models Training

**Train All Models:**
```bash
docker-compose exec ml_service python -m app.scripts.train_deep_learning
```

**Train Specific Models:**
```bash
# Train only CNN and LSTM
docker-compose exec ml_service python -m app.scripts.train_deep_learning \
  --models cnn lstm

# Train only Transformer
docker-compose exec ml_service python -m app.scripts.train_deep_learning \
  --models transformer \
  --output-dir artifacts/saved/deep_learning/
```

**Available Models:**
- `cnn` - CNN Traffic Classifier
- `lstm` - LSTM Sequence Detector
- `autoencoder` - Autoencoder Anomaly Detector
- `transformer` - Transformer Log Understanding

---

## 📊 Data Format Requirements

### Malware Detection Data Format

**File:** `process_events.jsonl`

```json
{
  "process_name": "powershell.exe",
  "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "command_line": "powershell -nop -w hidden -encodedcommand ...",
  "parent_process": "explorer.exe",
  "md5_hash": "abc123...",
  "sha256_hash": "def456...",
  "file_size": 524288,
  "is_signed": false,
  "registry_accesses": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
  "file_operations": [{"type": "create", "path": "C:\\Temp\\malware.exe"}],
  "network_connections": [{"ip": "192.168.1.100", "port": "4444", "protocol": "tcp"}],
  "memory_injections": 2,
  "privilege_escalations": 1,
  "is_malware": true,
  "malware_type": "trojan"
}
```

**Malware Types:**
- `ransomware`
- `trojan`
- `worm`
- `rootkit`
- `spyware`
- `adware`

---

### Threat Classification Data Format

**File:** `security_events.jsonl`

```json
{
  "source_type": "endpoint",
  "source_id": "sensor_001",
  "event_type": "process_creation",
  "severity": "high",
  "event_data": {
    "indicator": "suspicious_process",
    "process": "cmd.exe",
    "user": "admin",
    "ip": "192.168.1.50",
    "port": 4444,
    "protocol": "tcp"
  },
  "raw_log": "[MALWARE] Detected suspicious process execution",
  "threat_category": "malware",
  "is_threat": true,
  "confidence": 0.95,
  "host_id": "host_001",
  "user_id": "user_123",
  "context": {
    "mitre_technique": "T1059",
    "kill_chain_phase": "execution"
  }
}
```

**Threat Categories:**
- `malware`
- `exploit`
- `lateral_movement`
- `privilege_escalation`
- `credential_access`
- `data_exfiltration`
- `persistence`
- `defense_evasion`
- `reconnaissance`
- `command_control`
- `initial_access`
- `execution`
- `impact`
- `collection`

---

## 📁 Directory Structure

```
ml/
├── artifacts/
│   ├── datasets/
│   │   ├── malware/
│   │   │   └── process_events.jsonl
│   │   ├── threats/
│   │   │   └── security_events.jsonl
│   │   └── deep_learning/
│   │       ├── traffic_data.jsonl
│   │       └── log_sequences.jsonl
│   └── saved/
│       ├── malware_detection_latest.pkl
│       ├── threat_classifier_latest.pkl
│       └── deep_learning/
│           ├── cnn_traffic_classifier.h5
│           ├── lstm_sequence_detector.h5
│           ├── autoencoder_anomaly_detector.h5
│           └── transformer_log_understanding.h5
└── app/
    └── scripts/
        ├── train_malware_detection.py
        ├── train_threat_classifier.py
        └── train_deep_learning.py
```

---

## 🎯 Training Results

After training, you'll find:

1. **Trained Models:**
   - Malware: `artifacts/saved/malware_detection_latest.pkl`
   - Threat Classifier: `artifacts/saved/threat_classifier_latest.pkl`
   - Deep Learning: `artifacts/saved/deep_learning/*.h5`

2. **Training Results (JSON):**
   - `malware_training_results.json`
   - `threat_classifier_training_results.json`
   - `deep_learning_training_results.json`

**Example Results File:**
```json
{
  "model_path": "/app/artifacts/saved/malware_detection_latest.pkl",
  "training_time_seconds": 12.34,
  "samples": {
    "total": 500,
    "malware": 150,
    "benign": 350
  },
  "trained_at": "2025-12-05T13:30:00"
}
```

---

## 🔧 Advanced Usage

### Custom Configuration

You can modify training parameters by editing the scripts:

**Malware Detection:**
```python
# In train_malware_detection.py
events = generate_synthetic_malware_samples(n=1000)  # Increase samples
```

**Threat Classifier:**
```python
# In train_threat_classifier.py
events = generate_synthetic_security_events(n=2000)  # More diverse data
```

**Deep Learning:**
```python
# In train_deep_learning.py
config = DeepLearningConfig(
    epochs=100,        # More epochs
    batch_size=64,     # Larger batches
    learning_rate=0.0001  # Lower learning rate
)
```

---

## 📈 Performance Expectations

### Malware Detection
- **Training Time:** ~10-20 seconds (500 samples)
- **Expected Accuracy:** 85-95%
- **Model Size:** ~5-10 MB

### Threat Classification
- **Training Time:** ~15-30 seconds (1000 samples)
- **Expected Accuracy:** 80-90%
- **Model Size:** ~3-8 MB

### Deep Learning Models
- **CNN:** ~2-5 minutes (1000 samples, 20 epochs)
- **LSTM:** ~3-7 minutes (800 samples, 30 epochs)
- **Autoencoder:** ~5-10 minutes (1000 samples, 50 epochs)
- **Transformer:** ~4-8 minutes (500 samples, 25 epochs)

---

## 🐛 Troubleshooting

### Issue: "No module named 'tensorflow'"
**Solution:** Ensure TensorFlow is installed in the container:
```bash
docker-compose exec ml_service pip install tensorflow
```

### Issue: "Out of memory"
**Solution:** Reduce batch size or number of samples:
```bash
# Edit the script and reduce:
config = DeepLearningConfig(batch_size=16)  # Instead of 32
```

### Issue: "Model not converging"
**Solution:** 
- Increase epochs
- Adjust learning rate
- Check data quality
- Ensure balanced classes

---

## ✅ Verification

After training, verify models are working:

```bash
# Check if model files exist
docker-compose exec ml_service ls -lh artifacts/saved/

# Load and test a model (Python)
docker-compose exec ml_service python -c "
from app.malware_detection.malware_detector_prod import MalwareDetectionModel
model = MalwareDetectionModel()
model.load_model('artifacts/saved/malware_detection_latest.pkl')
print('Model loaded successfully!')
"
```

---

## 🔄 Retraining

Models should be retrained periodically with new data:

1. **Collect new labeled data**
2. **Add to datasets directory**
3. **Run training script**
4. **Evaluate performance**
5. **Deploy if improved**

**Recommended Schedule:**
- Malware Detection: Weekly
- Threat Classifier: Bi-weekly
- Deep Learning: Monthly

---

## 📚 Next Steps

1. ✅ Train all models with synthetic data
2. 📊 Collect real data from your environment
3. 🔄 Retrain with real data
4. 📈 Monitor performance metrics
5. 🚀 Deploy to production

For more information, see:
- [ML Training Documentation](../ML_TRAINING_DOCUMENTATION.md)
- [Model Architecture Guide](../docs/components/ml_components.md)
