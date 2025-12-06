
import asyncio
import numpy as np
import os
import json
from dataclasses import asdict
from datetime import datetime
from app.ueba.ueba_graph_detector_prod import UEBAGraphAnomalyDetector, UserActivity

async def check_variance():
    print("Initializing UEBA Detector...")
    detector = UEBAGraphAnomalyDetector()
    
    # Load activities from file locally
    data_path = "/app/artifacts/datasets/production/2025-11-01/ueba/ueba_events.jsonl"
    print(f"Loading data from {data_path}...")
    
    activities = []
    with open(data_path, "r") as f:
        for line in f:
            data = json.loads(line)
            # Map JSON to UserActivity
            # 'feature_1' etc in JSON are likely ignored by the graph loader unless mapped
            # The JSON might not match UserActivity exactly, let's see how train_models does it.
            # train_models.py (lines 336-343): 
            # activity = UserActivity(user_id=row['entity_id'], timestamp=..., activity_type=row['event_type'], ...)
            
            ts = datetime.fromisoformat(data.get("timestamp", datetime.now().isoformat()))
            user_id = data.get("entity_id", "unknown")
            
            activity = UserActivity(
                user_id=user_id,
                activity_type=data.get("event_type", "unknown"),
                timestamp=ts,
                source_host=data.get("resource", "unknown"), # Mapping 'resource' to source/target roughly
                target_resource=data.get("resource", "unknown"),
                details=data # Pass all other fields as details
            )
            activities.append((user_id, activity))

    print(f"Loaded {len(activities)} activities.")
    
    # Populate graph
    print("Populating graph...")
    for user_id, act in activities:
        detector.graph.add_user(user_id, user_id)
        detector.graph.add_activity(user_id, act)
        detector.activity_buffer.append((user_id, act))
        
    print(f"Graph populated: Users={len(detector.graph.user_profiles)}")
    
    # Extract features
    print("Extracting features...")
    features_list = []
    for user_id, act in detector.activity_buffer:
        feats = detector.feature_extractor.extract_features(user_id, act)
        features_list.append(feats)
        
    X = np.array(features_list)
    print(f"Feature Matrix Shape: {X.shape}")
    
    # Check variance
    variances = np.var(X, axis=0)
    print("\nFeature Variances:")
    for i, v in enumerate(variances):
        print(f"Feature {i}: {v:.6f} {'[ZERO VAR]' if v < 1e-9 else ''}")
        
    non_zero_cols = np.where(variances > 1e-9)[0]
    print(f"\nNon-zero variance columns: {len(non_zero_cols)} / {X.shape[1]}")
    
    if len(non_zero_cols) < X.shape[1]:
        print("\n⚠️ WARNING: Dataset has zero-variance features. This causes EllipticEnvelope failure.")
    else:
        print("\n✅ Dataset seems to have full rank (variance-wise). checking correlation...")
        
    # Check collinearity via rank
    rank = np.linalg.matrix_rank(X)
    print(f"Matrix Rank: {rank} (Expected {min(X.shape)})")

if __name__ == "__main__":
    import sys
    # Mocking app module for standalone run
    # Since we run via docker exec, we just need to ensure imports work. 
    # The file path logic handles the rest.
    asyncio.run(check_variance())
