"""Data Cleaning and Normalization Module.

Implements explicit, auditable data-cleaning transformations:
- Whitespace stripping on column headers and labels.
- Standardized label mapping (Binary and Multi-class).
- Invalidation / handling of infinities and missing numbers.
"""

from typing import Tuple, List, Optional
import numpy as np
import pandas as pd
from ai_ids.config import ATTACK_CATEGORIES, BENIGN_LABEL, TARGET_COLUMN


def normalize_column_names(columns: List[str]) -> List[str]:
    """Strips leading and trailing whitespace from column names."""
    return [col.strip() for col in columns]


def clean_dataframe_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Returns a DataFrame copy with normalized column names."""
    df_clean = df.copy()
    df_clean.columns = normalize_column_names(list(df.columns))
    return df_clean


def standardize_label_series(label_series: pd.Series) -> pd.Series:
    """Normalizes label text: strips spaces, normalizes encodings."""
    return label_series.astype(str).str.strip()


def map_to_binary(label_series: pd.Series) -> pd.Series:
    """Maps raw labels to binary classification: 0 for BENIGN, 1 for ATTACK."""
    cleaned = standardize_label_series(label_series)
    return (cleaned != BENIGN_LABEL).astype(int)


def map_to_attack_category(label_series: pd.Series) -> pd.Series:
    """Maps raw labels to canonical attack categories using configuration dictionary and heuristics."""
    cleaned = standardize_label_series(label_series)
    
    def resolve_label(val: str) -> str:
        if val in ATTACK_CATEGORIES:
            return ATTACK_CATEGORIES[val]
        # Heuristic fallback for minor encoding variations
        lower_val = val.lower()
        if "benign" in lower_val:
            return "BENIGN"
        if "ddos" in lower_val:
            return "DDoS"
        if "portscan" in lower_val:
            return "PortScan"
        if "web attack" in lower_val or "brute force" in lower_val or "xss" in lower_val or "sql" in lower_val:
            return "Web_Attack"
        if "patator" in lower_val or "ssh" in lower_val or "ftp" in lower_val:
            return "Brute_Force"
        if "slowloris" in lower_val or "slowhttptest" in lower_val or "hulk" in lower_val or "goldeneye" in lower_val:
            return "DoS"
        if "bot" in lower_val:
            return "Botnet"
        if "infil" in lower_val:
            return "Infiltration"
        if "heartbleed" in lower_val:
            return "Heartbleed"
        return "UNKNOWN_ATTACK"

    return cleaned.map(resolve_label)


def sanitize_numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    """Replaces positive/negative infinities with NaN and ensures float64 conversion."""
    df_sanitized = df.copy()
    for col in df_sanitized.columns:
        if col.lower() == "label":
            continue
        df_sanitized[col] = pd.to_numeric(df_sanitized[col], errors="coerce")
        df_sanitized[col] = df_sanitized[col].replace([np.inf, -np.inf], np.nan)
    return df_sanitized
