"""Feature Preprocessing Pipeline for AI-IDS.

Guarantees:
- Strict feature ordering preservation.
- Learned imputation values derived ONLY from training sets (prevents data leakage).
- Robust handling of infinities, NaNs, missing columns, and data type coercion.
"""

from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from ai_ids.preprocessing.cleaner import clean_dataframe_columns, sanitize_numeric_features


class IDSPreprocessor:
    """Production-grade preprocessor fitted on network flow features."""

    def __init__(self, feature_names: Optional[List[str]] = None, version: str = "1.0.0"):
        self.version = version
        self.feature_names: List[str] = feature_names or []
        self.medians: Dict[str, float] = {}
        self.is_fitted: bool = False

    def fit(self, df: pd.DataFrame, target_col: Optional[str] = "label") -> "IDSPreprocessor":
        """Learns feature ordering and median replacement values from the training split."""
        df_clean = clean_dataframe_columns(df)
        
        # Exclude label column if present
        cols = [c for c in df_clean.columns if target_col is None or c.lower() != target_col.lower()]
        self.feature_names = cols

        sanitized = sanitize_numeric_features(df_clean[self.feature_names])
        self.medians = {}
        for col in self.feature_names:
            med = sanitized[col].median()
            # If all values in a column are NaN/Inf, fallback to 0.0
            self.medians[col] = float(0.0 if np.isnan(med) else med)

        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transforms raw incoming DataFrame into ordered, clean numpy matrix."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor has not been fitted yet.")

        df_clean = clean_dataframe_columns(df)
        
        # Re-index/align columns to expected feature schema
        aligned = pd.DataFrame(index=df_clean.index)
        for col in self.feature_names:
            if col in df_clean.columns:
                aligned[col] = pd.to_numeric(df_clean[col], errors="coerce")
            else:
                # Column missing in input: impute with learned median
                aligned[col] = self.medians.get(col, 0.0)

        # Replace infinities with NaN
        aligned = aligned.replace([np.inf, -np.inf], np.nan)

        # Impute missing with learned medians
        for col in self.feature_names:
            aligned[col] = aligned[col].fillna(self.medians.get(col, 0.0))

        # Return strictly ordered float32 matrix
        return aligned[self.feature_names].to_numpy(dtype=np.float32)

    def fit_transform(self, df: pd.DataFrame, target_col: Optional[str] = "label") -> np.ndarray:
        """Convenience method to fit and transform training data."""
        self.fit(df, target_col=target_col)
        return self.transform(df)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes preprocessor state to dictionary."""
        return {
            "version": self.version,
            "feature_names": self.feature_names,
            "medians": self.medians,
            "is_fitted": self.is_fitted,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IDSPreprocessor":
        """Reconstructs preprocessor from serialized state."""
        instance = cls(feature_names=data.get("feature_names", []), version=data.get("version", "1.0.0"))
        instance.medians = data.get("medians", {})
        instance.is_fitted = data.get("is_fitted", False)
        return instance
