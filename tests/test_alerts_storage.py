"""Tests for Security Alert Generation and SQLite Storage."""

from pathlib import Path
import pytest
from ai_ids.alerts.schema import SecurityAlert
from ai_ids.alerts.generator import create_security_alert
from ai_ids.storage.db import (
    init_db,
    insert_alert,
    insert_alerts_batch,
    query_alerts,
    get_alert_statistics,
    clear_alerts,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "test_alerts.db"
    init_db(db_file)
    return db_file


def test_create_security_alert():
    features = {"Destination Port": 80, "Flow Duration": 12000, "Flow Bytes/s": 4500.0}
    alert = create_security_alert(
        source="TEST_SOURCE",
        flow_index=1,
        prediction="DDoS",
        confidence_score=0.97,
        raw_features=features,
    )

    assert alert.prediction == "ATTACK"
    assert alert.attack_type == "DDoS"
    assert alert.severity == "CRITICAL"
    assert alert.is_mitigated is False
    assert alert.features_snapshot["Destination Port"] == 80.0


def test_sqlite_insert_and_query(temp_db: Path):
    alert1 = create_security_alert("SRC_A", 1, "DDoS", 0.99, {"Destination Port": 80})
    alert2 = create_security_alert("SRC_B", 2, "PortScan", 0.88, {"Destination Port": 22})

    insert_alerts_batch([alert1, alert2], db_path=temp_db)

    # Query all
    results = query_alerts(limit=10, db_path=temp_db)
    assert len(results) == 2

    # Query by severity
    crit_results = query_alerts(severity="CRITICAL", db_path=temp_db)
    assert len(crit_results) == 1
    assert crit_results[0]["attack_type"] == "DDoS"

    # Statistics
    stats = get_alert_statistics(db_path=temp_db)
    assert stats["total_alerts"] == 2
    assert "DDoS" in stats["by_attack_type"]
    assert "PortScan" in stats["by_attack_type"]

    # Clear
    clear_alerts(db_path=temp_db)
    assert len(query_alerts(db_path=temp_db)) == 0
