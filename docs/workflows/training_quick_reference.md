# ML Model Training - Quick Reference

## 🎯 One-Command Training

### Train Everything (Except Deep Learning)
```bash
docker-compose exec ml_service python -m app.scripts.train_all_models
```

### Train Everything (Including Deep Learning - 15-30 min)
```bash
docker-compose exec ml_service python -m app.scripts.train_all_models --include-deep-learning
```

---

## 📦 Individual Model Training

### Core Models (Threat Detection + Vulnerability Assessment)
```bash
docker-compose exec ml_service python -m app.scripts.train_models
```

### Malware Detection
```bash
docker-compose exec ml_service python -m app.scripts.train_malware_detection
```

### Threat Classification
```bash
docker-compose exec ml_service python -m app.scripts.train_threat_classifier
```

### Deep Learning (All)
```bash
docker-compose exec ml_service python -m app.scripts.train_deep_learning
```

### Deep Learning (Specific Models)
```bash
# Train only CNN
docker-compose exec ml_service python -m app.scripts.train_deep_learning --models cnn

# Train CNN and LSTM
docker-compose exec ml_service python -m app.scripts.train_deep_learning --models cnn lstm

# Train all except Transformer
docker-compose exec ml_service python -m app.scripts.train_deep_learning --models cnn lstm autoencoder
```

---

## 📊 Training Status

### Check What's Trained
```bash
docker-compose exec ml_service ls -lh artifacts/saved/
```

### View Training Results
```bash
docker-compose exec ml_service cat artifacts/saved/master_training_results.json
```

---

## ⏱️ Expected Training Times

| Model | Samples | Time | GPU Recommended |
|-------|---------|------|-----------------|
| Threat Detection | 1,200 | ~2 min | No |
| Vulnerability Assessment | 300 | ~10 sec | No |
| Malware Detection | 500 | ~15 sec | No |
| Threat Classifier | 1,000 | ~20 sec | No |
| CNN | 1,000 | ~3 min | Yes |
| LSTM | 800 | ~5 min | Yes |
| Autoencoder | 1,000 | ~8 min | Yes |
| Transformer | 500 | ~6 min | Yes |

**Total (All Models):** ~25-35 minutes

---

## 🎓 Training Modes

### Synthetic Data (Default)
No data files needed - generates realistic synthetic data automatically.

```bash
docker-compose exec ml_service python -m app.scripts.train_all_models
```

### Real Data
Provide your own labeled data in JSONL format.

```bash
docker-compose exec ml_service python -m app.scripts.train_all_models \
  --data-dir artifacts/datasets/production/
```

**Expected Directory Structure:**
```
artifacts/datasets/production/
├── core/
│   ├── threat_detection/
│   │   └── network_events.jsonl
│   └── vulnerability_assessment/
│       └── vulnerabilities.jsonl
├── malware/
│   └── process_events.jsonl
└── threats/
    └── security_events.jsonl
```

---

## 🔍 Verification

### Test Trained Models
```bash
# Test Malware Detection
docker-compose exec ml_service python -c "
from app.malware_detection.malware_detector_prod import MalwareDetectionModel
model = MalwareDetectionModel()
model.load_model('artifacts/saved/malware_detection_latest.pkl')
print('✅ Malware Detection model loaded')
"

# Test Threat Classifier
docker-compose exec ml_service python -c "
from app.threat_classification.threat_classifier_prod import ThreatClassifierModel
model = ThreatClassifierModel()
model.load_model('artifacts/saved/threat_classifier_latest.pkl')
print('✅ Threat Classifier model loaded')
"
```

---

## 🐛 Common Issues

### Issue: TensorFlow not found
```bash
docker-compose exec ml_service pip install tensorflow
```

### Issue: Out of memory
Reduce batch size in the training script or train models individually.

### Issue: Models not saving
Check permissions on `artifacts/saved/` directory.

---

## 📚 Full Documentation

For detailed information, see:
- [Advanced Model Training Guide](./advanced_model_training.md)
- [Model Training Workflow](./model_training.md)
- [ML Training Documentation](../ML_TRAINING_DOCUMENTATION.md)
