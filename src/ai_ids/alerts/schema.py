"""Alert Data Structures and SIEM Event Schema.

Defines the structured intrusion detection event models.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid


class SecurityAlert(BaseModel):
    """Structured SIEM-compatible intrusion detection alert."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = Field(..., description="Ingestion source (e.g., CSV file name or live capture adapter)")
    flow_index: int = Field(default=-1, description="Sequential row/packet index within source")
    prediction: str = Field(..., description="Model classification result: BENIGN or attack category")
    attack_type: str = Field(..., description="Canonical category: DDoS, PortScan, DoS, Web_Attack, etc.")
    confidence_score: float = Field(..., description="Model confidence/probability [0.0 - 1.0]")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    model_version: str = Field(default="1.0.0", description="Version of model producing alert")
    features_snapshot: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key flow features observed at inference time",
    )
    is_mitigated: bool = Field(
        default=False,
        description="Safety boundary flag. IDS does not disrupt traffic.",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to standard dictionary."""
        return self.model_dump()
