"""Dataset Inspection and Auditing Module for CIC-IDS2017.

Performs schema verification, SHA-256 checksumming, chunked record counting,
label distribution analysis, missing/infinite value detection, and audit recording.
"""

from pathlib import Path
import hashlib
import json
import logging
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd

from ai_ids.config import (
    DATASET_DIR,
    DEFAULT_CHUNK_SIZE,
    MANIFEST_DIR,
    DATASET_AUDIT_REPORT_PATH,
)

logger = logging.getLogger(__name__)


def compute_file_sha256(file_path: Path, block_size: int = 65536) -> str:
    """Computes SHA-256 hash of a file efficiently without loading it into RAM."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def inspect_single_csv(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, Any]:
    """Inspects a single CIC-IDS2017 CSV file in chunked streaming mode.
    
    Returns detailed schema, record counts, label distribution,
    missing values, and infinity occurrences.
    """
    logger.info("Inspecting: %s", file_path.name)
    file_size = file_path.stat().st_size
    sha256_hash = compute_file_sha256(file_path)

    # Read header only to check columns and whitespace issues
    sample_df = pd.read_csv(file_path, nrows=5)
    raw_columns = list(sample_df.columns)
    stripped_columns = [c.strip() for c in raw_columns]
    
    # Identify label column (often has leading/trailing space in CIC-IDS2017 e.g. ' Label')
    label_col_raw = None
    for c in raw_columns:
        if c.strip().lower() == "label":
            label_col_raw = c
            break

    if not label_col_raw:
        raise ValueError(f"No 'Label' column found in {file_path.name}")

    total_rows = 0
    label_counts: Dict[str, int] = {}
    total_nan_count = 0
    total_inf_count = 0
    columns_with_nan: Dict[str, int] = {}
    columns_with_inf: Dict[str, int] = {}

    # Stream file in chunks to respect the 12GB RAM boundary
    reader = pd.read_csv(
        file_path,
        chunksize=chunk_size,
        low_memory=False,
        encoding="utf-8",
    )

    for chunk in reader:
        chunk_len = len(chunk)
        total_rows += chunk_len

        # Count labels
        raw_labels = chunk[label_col_raw].astype(str).str.strip().value_counts()
        for lbl, count in raw_labels.items():
            label_counts[lbl] = label_counts.get(lbl, 0) + int(count)

        # Drop label column for numeric checks
        feature_cols = [c for c in chunk.columns if c != label_col_raw]
        numeric_chunk = chunk[feature_cols]

        # Check NaNs
        nan_counts = numeric_chunk.isna().sum()
        for col, count in nan_counts[nan_counts > 0].items():
            stripped_col = col.strip()
            columns_with_nan[stripped_col] = columns_with_nan.get(stripped_col, 0) + int(count)
            total_nan_count += int(count)

        # Check Infinities
        for col in feature_cols:
            series = pd.to_numeric(chunk[col], errors="coerce")
            inf_mask = np.isinf(series)
            inf_count = int(inf_mask.sum())
            if inf_count > 0:
                stripped_col = col.strip()
                columns_with_inf[stripped_col] = columns_with_inf.get(stripped_col, 0) + inf_count
                total_inf_count += inf_count

    return {
        "file_name": file_path.name,
        "file_size_bytes": file_size,
        "sha256": sha256_hash,
        "total_rows": total_rows,
        "raw_column_count": len(raw_columns),
        "raw_columns": raw_columns,
        "stripped_columns": stripped_columns,
        "label_column_raw": label_col_raw,
        "label_counts": label_counts,
        "total_nan_count": total_nan_count,
        "total_inf_count": total_inf_count,
        "columns_with_nan": columns_with_nan,
        "columns_with_inf": columns_with_inf,
    }


def audit_cic_ids_dataset(
    dataset_dir: Path = DATASET_DIR,
    output_manifest: Path = DATASET_AUDIT_REPORT_PATH,
) -> Dict[str, Any]:
    """Scans all CSVs in dataset_dir, verifies schema alignment,
    generates an audit report, and writes JSON to output_manifest.
    """
    if not dataset_dir.exists():
        raise FileNotFoundError(
            f"Dataset directory does not exist: {dataset_dir}. "
            "Please verify the dataset path."
        )

    csv_files = sorted(list(dataset_dir.glob("*.csv")))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in dataset directory: {dataset_dir}."
        )

    logger.info("Found %d CSV files to audit.", len(csv_files))

    files_audit = []
    total_records = 0
    aggregated_labels: Dict[str, int] = {}
    reference_columns: List[str] = []
    schema_mismatches = []

    for idx, csv_file in enumerate(csv_files):
        audit = inspect_single_csv(csv_file)
        files_audit.append(audit)
        total_records += audit["total_rows"]

        for lbl, count in audit["label_counts"].items():
            aggregated_labels[lbl] = aggregated_labels.get(lbl, 0) + count

        if idx == 0:
            reference_columns = audit["stripped_columns"]
        else:
            if audit["stripped_columns"] != reference_columns:
                diff = set(audit["stripped_columns"]).symmetric_difference(set(reference_columns))
                schema_mismatches.append({
                    "file": csv_file.name,
                    "differing_columns": list(diff)
                })

    report = {
        "dataset_directory": str(dataset_dir),
        "total_csv_files": len(csv_files),
        "total_records": total_records,
        "schema_consistent_across_all_files": len(schema_mismatches) == 0,
        "schema_mismatches": schema_mismatches,
        "canonical_feature_count": len(reference_columns) - 1,  # minus label
        "canonical_columns": reference_columns,
        "aggregated_label_distribution": aggregated_labels,
        "files": files_audit,
    }

    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    with open(output_manifest, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(
        "Dataset audit complete. Total rows: %d. Report saved to: %s",
        total_records,
        output_manifest,
    )
    return report
