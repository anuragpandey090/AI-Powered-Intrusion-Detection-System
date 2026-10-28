"""Exports trained model bundle to standard .pkl format."""

import sys
from pathlib import Path
import joblib
import pickle

# Ensure src is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_ids.config import MODEL_BUNDLE_PATH, MODELS_DIR

def main():
    print(f"Loading {MODEL_BUNDLE_PATH}...")
    bundle = joblib.load(MODEL_BUNDLE_PATH)

    # 1. Save full bundle as .pkl
    bundle_pkl_path = MODELS_DIR / "ids_random_forest_bundle.pkl"
    with open(bundle_pkl_path, "wb") as f:
        pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"Saved: {bundle_pkl_path} ({bundle_pkl_path.stat().st_size / (1024*1024):.2f} MB)")

    # 2. Save standalone scikit-learn model as model.pkl
    model_pkl_path = MODELS_DIR / "model.pkl"
    with open(model_pkl_path, "wb") as f:
        pickle.dump(bundle["model"], f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"Saved: {model_pkl_path} ({model_pkl_path.stat().st_size / (1024*1024):.2f} MB)")

if __name__ == "__main__":
    main()
