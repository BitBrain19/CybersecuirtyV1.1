---
description: How to train and retrain ML models
---

# Model Training Workflow

This guide explains how to train the Machine Learning models in the SecurityAI platform.

## 1. Dataset Preparation

Data should be placed in the `ml/artifacts/datasets/` directory.

### Directory Structure
```
ml/artifacts/datasets/
├── production/          # Raw production logs
│   └── 2025-11-01/
├── labeled/            # Labeled training data
│   ├── malware/
│   ├── benign/
│   └── anomalies/
└── validation/         # Test sets
```

### Data Formats

#### Threat Detection
**File:** `network_events.jsonl`
```json
{
  "protocol": "TCP",
  "source_port": 54321,
  "dest_port": 443,
  "bytes_sent": 50000,
  "packet_count": 150,
  "duration_seconds": 30,
  "is_encrypted": true
}
```

#### UEBA (User Behavior)
**File:** `ueba_events.jsonl`
```json
{
  "entity_id": "user_001",
  "event_type": "login",
  "timestamp": "2025-11-16T10:30:00Z",
  "action": "read",
  "resource": "file_server"
}
```

## 2. Running Training

You can train models using the provided scripts inside the ML container.

### Option A: Quick Start (Synthetic Data)
To verify the training pipeline works without needing real data:

```bash
# Enter the ML container
docker-compose exec ml_service bash

# Run training with synthetic data
python app/scripts/train_models.py
```

### Option B: Production Training (Real Data)
To train with your uploaded datasets:

```bash
# Enter the ML container
docker-compose exec ml_service bash

# Run training pointing to your data
python app/scripts/train_models.py \
  --data-dir artifacts/datasets/production/2025-11-01/ \
  --output-dir artifacts/saved/
```

## 3. Verification

After training, verify the new models are loaded:

1. Check the logs: `docker-compose logs ml_service`
2. Query the API: `GET /api/v1/ml/models`
3. Check performance metrics in `ml/training_results.json`
