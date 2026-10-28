"""Security Alert Generation Module.

Constructs structured SIEM alerts from model predictions and associates
appropriate severity levels based on cybersecurity taxonomy.
"""

from typing import Dict, Any, Optional
import pandas as pd
from ai_ids.config import SEVERITY_LEVELS, BENIGN_LABEL
from ai_ids.alerts.schema import SecurityAlert

# Notable features to capture in the event snapshot
KEY_SNAPSHOT_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
    "SYN Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
]


def create_security_alert(
    source: str,
    flow_index: int,
    prediction: str,
    confidence_score: float,
    raw_features: Dict[str, Any],
    model_version: str = "1.0.0",
) -> SecurityAlert:
    """Creates a validated SecurityAlert object.
    
    Note: Feature snapshot values represent observed flow metrics at time of detection,
    and are recorded for SIEM investigation context.
    """
    is_attack = (prediction != BENIGN_LABEL)
    
    if not is_attack:
        severity = "INFO"
        attack_type = "BENIGN"
    else:
        attack_type = prediction
        severity = SEVERITY_LEVELS.get(attack_type, "HIGH")
        # Elevate severity if model confidence is extraordinarily high
        if confidence_score > 0.95 and severity == "MEDIUM":
            severity = "HIGH"

    # Capture key feature values safely
    snapshot = {}
    for feat in KEY_SNAPSHOT_FEATURES:
        if feat in raw_features:
            val = raw_features[feat]
            # Convert numpy types to pure Python for JSON serialization
            snapshot[feat] = float(val) if pd.notna(val) else None

    return SecurityAlert(
        source=source,
        flow_index=flow_index,
        prediction="ATTACK" if is_attack else "BENIGN",
        attack_type=attack_type,
        confidence_score=round(float(confidence_score), 4),
        severity=severity,
        model_version=model_version,
        features_snapshot=snapshot,
        is_mitigated=False,  # Strict IDS boundary: alerts only
    )
