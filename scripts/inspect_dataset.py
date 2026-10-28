"""Dataset Inspection CLI script.

Executes a complete, auditable verification of the raw CIC-IDS2017 dataset.
"""

import sys
from pathlib import Path
import logging

# Ensure project src is in Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_ids.config import DATASET_DIR, DATASET_AUDIT_REPORT_PATH
from ai_ids.datasets.inspection import audit_cic_ids_dataset

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)

def main():
    print("=" * 70)
    print("   AI-IDS DATASET INSPECTION & INTEGRITY AUDIT")
    print("=" * 70)
    print(f"Dataset path: {DATASET_DIR}")
    print(f"Output audit manifest: {DATASET_AUDIT_REPORT_PATH}")
    print("Scanning and verifying SHA-256 hashes & chunked statistics...")
    
    try:
        report = audit_cic_ids_dataset(DATASET_DIR, DATASET_AUDIT_REPORT_PATH)
        print("\nAudit Summary:")
        print(f"- Total CSV Files: {report['total_csv_files']}")
        print(f"- Total Rows Scanned: {report['total_records']:,}")
        print(f"- Feature Schema Uniform: {report['schema_consistent_across_all_files']}")
        print(f"- Total Canonical Features: {report['canonical_feature_count']}")
        print("\nLabel Distribution Across All Files:")
        for label, count in sorted(report['aggregated_label_distribution'].items(), key=lambda x: -x[1]):
            pct = (count / report['total_records']) * 100
            safe_label = label.encode("ascii", "replace").decode("ascii")
            print(f"  * {safe_label:32s}: {count:10,d} ({pct:6.2f}%)")
        print("\nPer-File Overview:")
        for f in report['files']:
            safe_name = f['file_name'].encode("ascii", "replace").decode("ascii")
            print(f"  - {safe_name}")
            print(f"    Size: {f['file_size_bytes'] / (1024*1024):.2f} MB | Rows: {f['total_rows']:,}")
            print(f"    NaNs: {f['total_nan_count']:,} | Infs: {f['total_inf_count']:,}")
            print(f"    SHA-256: {f['sha256'][:16]}...")
        print("=" * 70)
        print(f"SUCCESS: Audit saved to {DATASET_AUDIT_REPORT_PATH}")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
