"""
Master Training Script - Train All ML Models
Trains all available ML models in the system
"""

import os
import sys
import json
import argparse
import time
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

# Import training functions
from app.scripts.train_models import train_and_save_models
from app.scripts.train_malware_detection import train_malware_model
from app.scripts.train_threat_classifier import train_threat_classifier
from app.scripts.train_deep_learning import train_deep_learning_models


def train_all_models(data_dir: str = None, output_dir: str = None, skip_deep_learning: bool = False):
    """Train all ML models in the system"""
    start_time = time.time()
    
    # Resolve output directory
    if output_dir:
        storage_dir = output_dir
    else:
        storage_dir = os.path.join(os.path.dirname(__file__), "..", "..", "artifacts", "saved")
    
    os.makedirs(storage_dir, exist_ok=True)
    
    print("=" * 80)
    print(" " * 25 + "MASTER TRAINING SCRIPT")
    print("=" * 80)
    print(f"Output Directory: {storage_dir}")
    print(f"Data Directory: {data_dir if data_dir else 'Using synthetic data'}")
    print("=" * 80)
    
    results = {
        "started_at": datetime.now().isoformat(),
        "models": {},
        "errors": []
    }
    
    # 1. Core Models (Threat Detection + Vulnerability Assessment)
    print("\n[1/5] Training Core Models (Threat Detection + Vulnerability Assessment)...")
    try:
        core_data_dir = os.path.join(data_dir, "core") if data_dir else None
        core_results = train_and_save_models(data_dir=core_data_dir, output_dir=storage_dir)
        results["models"]["core"] = {
            "threat_detection": core_results.get("threat_detection_model_path"),
            "vulnerability_assessment": core_results.get("vulnerability_assessment_model_path"),
            "status": "success"
        }
        print("✅ Core models trained successfully")
    except Exception as e:
        error_msg = f"Core models training failed: {str(e)}"
        print(f"❌ {error_msg}")
        results["errors"].append(error_msg)
        results["models"]["core"] = {"status": "failed", "error": str(e)}
    
    # 2. Malware Detection
    print("\n[2/5] Training Malware Detection Model...")
    try:
        malware_data_dir = os.path.join(data_dir, "malware") if data_dir else None
        malware_results = train_malware_model(data_dir=malware_data_dir, output_dir=storage_dir)
        results["models"]["malware_detection"] = {
            "model_path": malware_results.get("model_path"),
            "samples": malware_results.get("samples"),
            "status": "success"
        }
        print("✅ Malware detection model trained successfully")
    except Exception as e:
        error_msg = f"Malware detection training failed: {str(e)}"
        print(f"❌ {error_msg}")
        results["errors"].append(error_msg)
        results["models"]["malware_detection"] = {"status": "failed", "error": str(e)}
    
    # 3. Threat Classification
    print("\n[3/5] Training Threat Classification Model...")
    try:
        threat_data_dir = os.path.join(data_dir, "threats") if data_dir else None
        threat_results = train_threat_classifier(data_dir=threat_data_dir, output_dir=storage_dir)
        results["models"]["threat_classification"] = {
            "model_path": threat_results.get("model_path"),
            "metrics": threat_results.get("metrics"),
            "samples": threat_results.get("samples"),
            "status": "success"
        }
        print("✅ Threat classification model trained successfully")
    except Exception as e:
        error_msg = f"Threat classification training failed: {str(e)}"
        print(f"❌ {error_msg}")
        results["errors"].append(error_msg)
        results["models"]["threat_classification"] = {"status": "failed", "error": str(e)}
    
    # 4. Deep Learning Models (Optional - can be slow)
    if not skip_deep_learning:
        print("\n[4/5] Training Deep Learning Models (CNN, LSTM, Autoencoder, Transformer)...")
        print("⚠️  This may take 15-30 minutes...")
        try:
            dl_output_dir = os.path.join(storage_dir, "deep_learning")
            dl_results = train_deep_learning_models(output_dir=dl_output_dir)
            results["models"]["deep_learning"] = {
                "models": dl_results.get("models"),
                "training_time": dl_results.get("training_time_seconds"),
                "status": "success"
            }
            print("✅ Deep learning models trained successfully")
        except Exception as e:
            error_msg = f"Deep learning training failed: {str(e)}"
            print(f"❌ {error_msg}")
            results["errors"].append(error_msg)
            results["models"]["deep_learning"] = {"status": "failed", "error": str(e)}
    else:
        print("\n[4/5] Skipping Deep Learning Models (use --include-deep-learning to train)")
        results["models"]["deep_learning"] = {"status": "skipped"}
    
    # 5. Summary
    print("\n[5/5] Generating Summary...")
    
    total_time = time.time() - start_time
    results["completed_at"] = datetime.now().isoformat()
    results["total_training_time_seconds"] = total_time
    
    # Count successes and failures
    successful = sum(1 for m in results["models"].values() if m.get("status") == "success")
    failed = sum(1 for m in results["models"].values() if m.get("status") == "failed")
    skipped = sum(1 for m in results["models"].values() if m.get("status") == "skipped")
    
    results["summary"] = {
        "total_models": len(results["models"]),
        "successful": successful,
        "failed": failed,
        "skipped": skipped
    }
    
    # Save results
    results_path = os.path.join(storage_dir, "master_training_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 80)
    print(" " * 30 + "TRAINING SUMMARY")
    print("=" * 80)
    print(f"Total Time: {total_time:.2f}s ({total_time/60:.1f} minutes)")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    
    if results["errors"]:
        print("\n⚠️  Errors encountered:")
        for error in results["errors"]:
            print(f"  - {error}")
    
    print(f"\nResults saved to: {results_path}")
    print("=" * 80)
    
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train All ML Models")
    parser.add_argument("--data-dir", type=str, 
                        help="Base directory containing training data subdirectories")
    parser.add_argument("--output-dir", type=str, 
                        help="Directory to save all trained models")
    parser.add_argument("--include-deep-learning", action="store_true",
                        help="Include deep learning models (slower, 15-30 min)")
    args = parser.parse_args()
    
    results = train_all_models(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        skip_deep_learning=not args.include_deep_learning
    )
    
    # Exit with error code if any training failed
    if results["summary"]["failed"] > 0:
        sys.exit(1)
