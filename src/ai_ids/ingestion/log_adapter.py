"""System Log Adapter Module.

Provides a dedicated adapter for system and authentication logs (e.g., auth.log, syslog).
Architectural boundary note:
Textual system logs are parsed into structured security events. They are NOT
conflated or force-fed into network-flow ML models as incompatible feature arrays.
"""

from typing import Dict, Any, List, Optional
import re
from datetime import datetime, timezone
import uuid

from ai_ids.alerts.schema import SecurityAlert
from ai_ids.storage.db import insert_alerts_batch


class SystemLogAdapter:
    """Parses and correlates system log events (e.g., SSH authentication attempts)."""

    # Regex patterns for common Linux/Unix authentication logs
    SSH_FAILED_PATTERN = re.compile(
        r"(?P<date>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )
    SSH_ACCEPTED_PATTERN = re.compile(
        r"(?P<date>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    )

    def __init__(self, failure_threshold: int = 5):
        self.failure_threshold = failure_threshold
        self.ip_failure_counts: Dict[str, int] = {}

    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parses a single system log line into a structured event."""
        line = line.strip()
        if not line:
            return None

        failed_match = self.SSH_FAILED_PATTERN.search(line)
        if failed_match:
            d = failed_match.groupdict()
            return {
                "event_type": "AUTH_FAILURE",
                "service": "ssh",
                "source_ip": d["ip"],
                "port": int(d["port"]),
                "username": d["user"],
                "raw_date": d["date"],
                "status": "failed",
            }

        accepted_match = self.SSH_ACCEPTED_PATTERN.search(line)
        if accepted_match:
            d = accepted_match.groupdict()
            return {
                "event_type": "AUTH_SUCCESS",
                "service": "ssh",
                "source_ip": d["ip"],
                "port": int(d["port"]),
                "username": d["user"],
                "raw_date": d["date"],
                "status": "success",
            }

        # Generic log line fallback
        return {
            "event_type": "GENERIC_SYSTEM_EVENT",
            "service": "system",
            "raw_line": line,
            "status": "info",
        }

    def process_log_stream(
        self,
        log_lines: List[str],
        source_name: str = "SYSTEM_LOG",
        persist: bool = True,
    ) -> List[SecurityAlert]:
        """Parses lines and correlates repeated authentication failures into alerts."""
        alerts = []

        for idx, line in enumerate(log_lines):
            event = self.parse_log_line(line)
            if not event:
                continue

            if event.get("event_type") == "AUTH_FAILURE":
                src_ip = event["source_ip"]
                self.ip_failure_counts[src_ip] = self.ip_failure_counts.get(src_ip, 0) + 1

                # If threshold exceeded, generate a SIEM Brute-Force alert
                if self.ip_failure_counts[src_ip] >= self.failure_threshold:
                    alert = SecurityAlert(
                        source=f"{source_name}:{src_ip}",
                        flow_index=idx,
                        prediction="ATTACK",
                        attack_type="Brute_Force",
                        confidence_score=0.98,
                        severity="HIGH",
                        model_version="rule-correlation-1.0.0",
                        features_snapshot={
                            "service": "ssh",
                            "source_ip": src_ip,
                            "failed_attempts": self.ip_failure_counts[src_ip],
                            "targeted_user": event.get("username", "unknown"),
                        },
                    )
                    alerts.append(alert)

        if persist and alerts:
            insert_alerts_batch(alerts)

        return alerts
