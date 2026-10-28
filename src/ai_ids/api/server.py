"""FastAPI REST API Server for AI-IDS.

Provides structured endpoints for:
- CSV file upload and batch intrusion detection.
- Single network flow inference.
- SIEM alert retrieval and filtering from SQLite.
- Live traffic capture diagnostic status.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import io
import pandas as pd
from fastapi import FastAPI, File, UploadFile, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai_ids.config import (
    MODEL_BUNDLE_PATH,
    STRICT_SAFETY_MODE,
)
from ai_ids.inference.engine import InferenceEngine
from ai_ids.ingestion.csv_ingest import validate_csv_schema
from ai_ids.storage.db import query_alerts, get_alert_statistics
from ai_ids.ingestion.live_capture import check_capture_capabilities

app = FastAPI(
    title="AI-Powered Intrusion Detection System API",
    description="SIEM-integrated ML Intrusion Detection Engine (Evaluation & Alerting)",
    version="1.0.0",
)

# Enable CORS for web dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lazy inference engine instance
_engine: Optional[InferenceEngine] = None


def get_engine() -> InferenceEngine:
    global _engine
    if _engine is None:
        if not MODEL_BUNDLE_PATH.exists():
            raise HTTPException(
                status_code=503,
                detail="Model bundle is not yet trained. Run training first.",
            )
        _engine = InferenceEngine(MODEL_BUNDLE_PATH)
    return _engine


@app.get("/")
def root_status() -> Dict[str, Any]:
    """Returns system status, active version, and safety boundaries."""
    engine = get_engine()
    return {
        "system": "AI-Powered Intrusion Detection System",
        "status": "OPERATIONAL",
        "model_version": engine.metadata.get("version", "1.0.0"),
        "model_type": engine.metadata.get("model_type", "RandomForestClassifier"),
        "features_count": len(engine.feature_names),
        "supported_classes": engine.classes,
        "safety_boundary": {
            "strict_ids_mode": STRICT_SAFETY_MODE,
            "automated_prevention_enabled": False,
            "disruption_allowed": False,
            "action_policy": "Detection and Alerting ONLY",
        },
    }


@app.post("/predict/csv")
async def predict_csv_endpoint(
    file: UploadFile = File(...),
    save_alerts: bool = True,
) -> Dict[str, Any]:
    """Processes an uploaded flow CSV file, runs model inference, and persists alerts."""
    engine = get_engine()

    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents), low_memory=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse uploaded CSV: {e}")

    # Validate schema
    is_valid, msg, details = validate_csv_schema(df, engine.feature_names)
    if not is_valid:
        raise HTTPException(status_code=422, detail=f"Schema Validation Failed: {msg}")

    # Execute inference
    result = engine.predict_dataframe(
        df=df,
        source_name=f"CSV_UPLOAD:{file.filename}",
        save_alerts=save_alerts,
    )

    # Convert alert models to dicts for JSON response
    serialized_alerts = [a.to_dict() for a in result["alerts"][:50]]

    return {
        "filename": file.filename,
        "total_records": result["total_records"],
        "benign_count": result["benign_count"],
        "attack_count": result["attack_count"],
        "attacks_by_type": result["attacks_by_type"],
        "alerts_generated_count": len(result["alerts"]),
        "recent_alerts_sample": serialized_alerts,
        "schema_details": details,
    }


class SingleFlowPayload(BaseModel):
    source: Optional[str] = "REST_API_FLOW"
    features: Dict[str, Any]


@app.post("/predict/flow")
def predict_single_flow_endpoint(payload: SingleFlowPayload) -> Dict[str, Any]:
    """Runs low-latency inference on a single network flow."""
    engine = get_engine()
    return engine.predict_single_flow(
        flow_features=payload.features,
        source_name=payload.source or "REST_API_FLOW",
        save_alert=True,
    )


@app.get("/alerts")
def get_alerts_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves SIEM intrusion alerts with filtering."""
    return query_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        attack_type=attack_type,
        source=source,
    )


@app.get("/alerts/stats")
def get_alerts_stats_endpoint() -> Dict[str, Any]:
    """Returns aggregated SIEM alert statistics."""
    return get_alert_statistics()


@app.get("/status/capture")
def capture_status_endpoint() -> Dict[str, Any]:
    """Returns diagnostic status of live packet capture capabilities."""
    status = check_capture_capabilities()
    return {
        "is_available": status.is_available,
        "has_admin_rights": status.has_admin_rights,
        "driver_detected": status.driver_detected,
        "platform": status.platform,
        "message": status.message,
    }
