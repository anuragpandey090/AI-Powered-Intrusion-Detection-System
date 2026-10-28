"""AI-Powered Intrusion Detection System (AI-IDS) Configuration Module.

Central configuration for paths, datasets, preprocessing, training,
inference, alerts, and runtime boundaries.
"""

from pathlib import Path
import os

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MANIFEST_DIR = DATA_DIR / "manifests"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
ALERTS_DB_PATH = DATA_DIR / "alerts.db"

# CIC-IDS2017 Dataset path
DEFAULT_DATASET_DIR = Path(r"E:\IILM\Major Project\raw\MachineLearningCVE")
DATASET_DIR = Path(os.environ.get("CIC_IDS_DATASET_DIR", DEFAULT_DATASET_DIR))

# Chunking and memory controls
DEFAULT_CHUNK_SIZE = 50_000
MAX_TRAIN_SAMPLES_PER_CLASS = 150_000
RANDOM_SEED = 42

# Label definitions
BENIGN_LABEL = "BENIGN"
TARGET_COLUMN = "label"

# Attack categorization mapping for CIC-IDS2017
ATTACK_CATEGORIES = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Web Attack  Brute Force": "Web_Attack",
    "Web Attack \ufffd Brute Force": "Web_Attack",
    "Web Attack  XSS": "Web_Attack",
    "Web Attack \ufffd XSS": "Web_Attack",
    "Web Attack  Sql Injection": "Web_Attack",
    "Web Attack \ufffd Sql Injection": "Web_Attack",
    "FTP-Patator": "Brute_Force",
    "SSH-Patator": "Brute_Force",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "Heartbleed": "Heartbleed",
}

# Model and inference artifact names
MODEL_BUNDLE_FILENAME = "ids_random_forest_bundle.joblib"
MODEL_BUNDLE_PATH = MODELS_DIR / MODEL_BUNDLE_FILENAME
TRAINING_METADATA_PATH = MODELS_DIR / "training_metadata.json"
DATASET_AUDIT_REPORT_PATH = MANIFEST_DIR / "dataset_audit_manifest.json"

# Severity mapping for alerts based on attack type and score
SEVERITY_LEVELS = {
    "BENIGN": "INFO",
    "PortScan": "MEDIUM",
    "Brute_Force": "HIGH",
    "Web_Attack": "HIGH",
    "Botnet": "HIGH",
    "DoS": "HIGH",
    "DDoS": "CRITICAL",
    "Infiltration": "CRITICAL",
    "Heartbleed": "CRITICAL",
    "UNKNOWN_ATTACK": "HIGH",
}

# Safety boundary affirmation
STRICT_SAFETY_MODE = True  # Detection and alerting ONLY. No automated blocking.
