"""CSV Ingestion and Validation Module.

Validates uploaded flow CSV files for schema compatibility, memory safety,
and data integrity before passing to the inference engine.
"""

from pathlib import Path
from typing import Dict, Any, List, Tuple
import pandas as pd
from ai_ids.preprocessing.cleaner import clean_dataframe_columns


def validate_csv_schema(
    df: pd.DataFrame,
    required_feature_names: List[str],
    min_matching_ratio: float = 0.5,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Validates whether an uploaded DataFrame aligns with the trained model's feature schema.
    
    Returns:
        (is_valid, message, details)
    """
    df_clean = clean_dataframe_columns(df)
    uploaded_cols = set(df_clean.columns)
    required_set = set(required_feature_names)

    matching_cols = uploaded_cols.intersection(required_set)
    missing_cols = required_set - uploaded_cols
    extra_cols = uploaded_cols - required_set

    match_ratio = len(matching_cols) / len(required_set) if required_set else 0.0

    details = {
        "total_required_features": len(required_set),
        "total_uploaded_columns": len(uploaded_cols),
        "matching_columns_count": len(matching_cols),
        "missing_columns_count": len(missing_cols),
        "matching_ratio": round(match_ratio, 4),
        "missing_features_sample": sorted(list(missing_cols))[:10],
        "extra_columns_sample": sorted(list(extra_cols))[:10],
    }

    if match_ratio < min_matching_ratio:
        return (
            False,
            f"Schema mismatch: Only {len(matching_cols)} of {len(required_set)} "
            f"({match_ratio * 100:.1f}%) required flow features are present in the uploaded file.",
            details,
        )

    return (
        True,
        f"Schema validation passed: {len(matching_cols)}/{len(required_set)} features matched.",
        details,
    )


def load_and_validate_csv_file(
    file_path: Path,
    required_features: List[str],
    max_records: int = 100_000,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Reads a CSV file up to max_records, validates schema, and returns cleaned DataFrame."""
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Read bounded slice to ensure memory safety
    df = pd.read_csv(file_path, nrows=max_records, low_memory=False)
    is_valid, msg, details = validate_csv_schema(df, required_features)
    
    if not is_valid:
        raise ValueError(msg)

    return df, details
