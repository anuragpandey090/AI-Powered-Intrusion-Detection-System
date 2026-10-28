"""Dataset Loading and Sampling Module for CIC-IDS2017.

Handles bounded chunked streaming, balanced sub-sampling across attack categories,
and file-level train/test/holdout partitioning without exhausting memory.
"""

from pathlib import Path
from typing import List, Dict, Tuple, Optional
import logging
import numpy as np
import pandas as pd

from ai_ids.config import (
    DATASET_DIR,
    DEFAULT_CHUNK_SIZE,
    RANDOM_SEED,
    BENIGN_LABEL,
)
from ai_ids.preprocessing.cleaner import clean_dataframe_columns, map_to_attack_category, map_to_binary

logger = logging.getLogger(__name__)


def load_dataset_sample(
    dataset_dir: Path = DATASET_DIR,
    files_to_include: Optional[List[str]] = None,
    samples_per_attack: int = 20_000,
    samples_benign: int = 60_000,
    random_state: int = RANDOM_SEED,
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Streams CSV files and gathers a balanced, memory-conscious sample across all classes.
    
    Returns:
        (X_raw, y_binary, y_category)
    """
    if not dataset_dir.exists():
        raise FileNotFoundError(f"Dataset directory not found: {dataset_dir}")

    all_csvs = sorted(list(dataset_dir.glob("*.csv")))
    if files_to_include:
        target_csvs = [f for f in all_csvs if f.name in files_to_include]
    else:
        target_csvs = all_csvs

    rng = np.random.RandomState(random_state)
    collected_dfs: List[pd.DataFrame] = []

    logger.info("Sampling across %d CSV files (Seed=%d)...", len(target_csvs), random_state)

    for csv_file in target_csvs:
        logger.info("Reading chunks from: %s", csv_file.name)
        reader = pd.read_csv(
            csv_file,
            chunksize=DEFAULT_CHUNK_SIZE,
            low_memory=False,
            encoding="utf-8",
        )

        for chunk in reader:
            chunk = clean_dataframe_columns(chunk)
            
            # Find label column
            lbl_col = None
            for c in chunk.columns:
                if c.lower() == "label":
                    lbl_col = c
                    break
            if not lbl_col:
                continue

            chunk["attack_cat"] = map_to_attack_category(chunk[lbl_col])
            
            # Subsample within chunk to ensure diverse temporal coverage
            sampled_chunk_parts = []
            for cat, group in chunk.groupby("attack_cat"):
                quota = samples_benign if cat == BENIGN_LABEL else samples_per_attack
                # Sample a small fraction from each chunk
                n_take = min(len(group), max(200, int(quota / 20)))
                if n_take > 0:
                    sampled_chunk_parts.append(group.sample(n=n_take, random_state=rng))

            if sampled_chunk_parts:
                collected_dfs.append(pd.concat(sampled_chunk_parts, ignore_index=True))

    if not collected_dfs:
        raise ValueError("No data could be collected from the dataset.")

    combined = pd.concat(collected_dfs, ignore_index=True)
    logger.info("Total sampled rows before balancing: %d", len(combined))

    # Final balanced quota enforcement
    final_parts = []
    for cat, group in combined.groupby("attack_cat"):
        target_quota = samples_benign if cat == BENIGN_LABEL else samples_per_attack
        n_final = min(len(group), target_quota)
        final_parts.append(group.sample(n=n_final, random_state=rng))

    final_df = pd.concat(final_parts, ignore_index=True).sample(frac=1.0, random_state=rng).reset_index(drop=True)
    logger.info("Final balanced dataset shape: %s", final_df.shape)

    # Separate features and targets
    label_col = [c for c in final_df.columns if c.lower() == "label"][0]
    y_raw = final_df[label_col]
    y_binary = map_to_binary(y_raw)
    y_category = final_df["attack_cat"]

    feature_cols = [c for c in final_df.columns if c.lower() != "label" and c != "attack_cat"]
    X_raw = final_df[feature_cols]

    return X_raw, y_binary, y_category


def load_single_file_for_holdout(
    file_path: Path,
    max_records: int = 50_000,
    random_state: int = RANDOM_SEED,
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Loads a bounded slice of an entire CSV file for holdout testing."""
    df = pd.read_csv(file_path, nrows=max_records, low_memory=False, encoding="utf-8")
    df = clean_dataframe_columns(df)
    
    label_col = [c for c in df.columns if c.lower() == "label"][0]
    y_raw = df[label_col]
    y_binary = map_to_binary(y_raw)
    y_category = map_to_attack_category(y_raw)

    feature_cols = [c for c in df.columns if c.lower() != "label"]
    X_raw = df[feature_cols]

    return X_raw, y_binary, y_category
