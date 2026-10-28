"""Model Training CLI script.

Executes baseline training on real CIC-IDS2017 dataset, runs evaluations,
and exports model artifacts and performance summaries.
"""

import sys
from pathlib import Path
import logging

# Ensure project src is in Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_ids.models.trainer import train_ids_model
from ai_ids.config import DATASET_DIR, MODEL_BUNDLE_PATH

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)

def main():
    print("=" * 70)
    print("   AI-IDS: MODEL TRAINING & RIGOROUS EVALUATION")
    print("=" * 70)
    print(f"Dataset path: {DATASET_DIR}")
    print(f"Model output bundle: {MODEL_BUNDLE_PATH}")
    print("Beginning balanced sub-sampling and training...")

    try:
        results = train_ids_model(
            dataset_dir=DATASET_DIR,
            n_estimators=100,
            max_depth=16,
            samples_per_attack=15_000,
            samples_benign=50_000,
            test_size=0.2,
            holdout_file_name="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        )
        print("\n" + "=" * 70)
        print(" TRAINING & EVALUATION COMPLETE!")
        print("=" * 70)
        rand_m = results["random_split_evaluation"]["metrics"]
        print("\nRandom-Split Test Set Metrics:")
        print(f"  - Accuracy:              {rand_m['accuracy'] * 100:.2f}%")
        print(f"  - Precision:             {rand_m['precision'] * 100:.2f}%")
        print(f"  - Recall:                {rand_m['recall'] * 100:.2f}%")
        print(f"  - F1-Score:              {rand_m['f1_score'] * 100:.2f}%")
        print(f"  - False Positive Rate:   {rand_m['false_positive_rate'] * 100:.3f}%")
        print(f"  - False Negative Rate:   {rand_m['false_negative_rate'] * 100:.3f}%")

        if results.get("whole_file_holdout_evaluation"):
            h_m = results["whole_file_holdout_evaluation"]["metrics"]
            print("\nWhole-File Holdout Evaluation Metrics (PortScan CSV):")
            print(f"  - Accuracy:              {h_m['accuracy'] * 100:.2f}%")
            print(f"  - Precision:             {h_m['precision'] * 100:.2f}%")
            print(f"  - Recall:                {h_m['recall'] * 100:.2f}%")
            print(f"  - F1-Score:              {h_m['f1_score'] * 100:.2f}%")
            print(f"  - False Positive Rate:   {h_m['false_positive_rate'] * 100:.3f}%")

        lat = results["random_split_evaluation"]["latency_ms"]
        print("\nLatency Profiling:")
        print(f"  - Single Flow:           {lat['single_record_mean_ms']:.4f} ms")
        print(f"  - Batch Per Record:      {lat['per_record_in_batch_ms']:.5f} ms")

        print("\nArtifacts Saved:")
        print(f"  - Model bundle: {MODEL_BUNDLE_PATH}")
        print("  - Evaluation report: reports/evaluation_report.json")
        print("  - Academic summary:  reports/evaluation_summary.md")
        print("=" * 70)

    except Exception as e:
        print(f"ERROR during training: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
