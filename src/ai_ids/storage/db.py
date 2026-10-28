"""Persistent Storage Module for SIEM Alerts.

Provides SQLite persistence, indexing, and structured querying for intrusion alerts.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import sqlite3
import json
import logging
from ai_ids.config import ALERTS_DB_PATH
from ai_ids.alerts.schema import SecurityAlert

logger = logging.getLogger(__name__)


def get_db_connection(db_path: Path = ALERTS_DB_PATH) -> sqlite3.Connection:
    """Returns a SQLite connection with row factory configured."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = ALERTS_DB_PATH) -> None:
    """Initializes the SQLite schema and indexes for security alerts."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                flow_index INTEGER NOT NULL,
                prediction TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                severity TEXT NOT NULL,
                model_version TEXT NOT NULL,
                features_snapshot_json TEXT NOT NULL,
                is_mitigated INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON security_alerts(attack_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON security_alerts(source)")
        conn.commit()


def insert_alert(alert: SecurityAlert, db_path: Path = ALERTS_DB_PATH) -> None:
    """Persists a single SecurityAlert into SQLite."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_alerts (
                alert_id, timestamp, source, flow_index, prediction,
                attack_type, confidence_score, severity, model_version,
                features_snapshot_json, is_mitigated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.timestamp,
                alert.source,
                alert.flow_index,
                alert.prediction,
                alert.attack_type,
                alert.confidence_score,
                alert.severity,
                alert.model_version,
                json.dumps(alert.features_snapshot),
                1 if alert.is_mitigated else 0,
            ),
        )
        conn.commit()


def insert_alerts_batch(alerts: List[SecurityAlert], db_path: Path = ALERTS_DB_PATH) -> int:
    """Persists a batch of SecurityAlert objects atomically."""
    if not alerts:
        return 0
    init_db(db_path)
    records = [
        (
            a.alert_id,
            a.timestamp,
            a.source,
            a.flow_index,
            a.prediction,
            a.attack_type,
            a.confidence_score,
            a.severity,
            a.model_version,
            json.dumps(a.features_snapshot),
            1 if a.is_mitigated else 0,
        )
        for a in alerts
    ]
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.executemany(
            """
            INSERT OR IGNORE INTO security_alerts (
                alert_id, timestamp, source, flow_index, prediction,
                attack_type, confidence_score, severity, model_version,
                features_snapshot_json, is_mitigated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            records,
        )
        conn.commit()
    return len(records)


def query_alerts(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    source: Optional[str] = None,
    db_path: Path = ALERTS_DB_PATH,
) -> List[Dict[str, Any]]:
    """Retrieves filtered alerts sorted by timestamp descending."""
    init_db(db_path)
    clauses = []
    params = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity.upper())
    if attack_type:
        clauses.append("attack_type = ?")
        params.append(attack_type)
    if source:
        clauses.append("source LIKE ?")
        params.append(f"%{source}%")

    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"""
        SELECT * FROM security_alerts
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        results = []
        for r in rows:
            d = dict(r)
            d["features_snapshot"] = json.loads(d.pop("features_snapshot_json"))
            results.append(d)
        return results


def get_alert_statistics(db_path: Path = ALERTS_DB_PATH) -> Dict[str, Any]:
    """Computes summary statistics for dashboard and SIEM overviews."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_alerts")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM security_alerts GROUP BY severity")
        by_severity = dict(cursor.fetchall())

        cursor.execute("SELECT attack_type, COUNT(*) FROM security_alerts GROUP BY attack_type")
        by_attack_type = dict(cursor.fetchall())

        cursor.execute("SELECT source, COUNT(*) FROM security_alerts GROUP BY source")
        by_source = dict(cursor.fetchall())

    return {
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "by_attack_type": by_attack_type,
        "by_source": by_source,
    }


def clear_alerts(db_path: Path = ALERTS_DB_PATH) -> None:
    """Clears all stored alerts (useful for test resets)."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        conn.cursor().execute("DELETE FROM security_alerts")
        conn.commit()
