"""Tests for System Log Ingestion Adapter."""

import pytest
from ai_ids.ingestion.log_adapter import SystemLogAdapter


def test_ssh_log_parsing():
    adapter = SystemLogAdapter(failure_threshold=3)

    log_line_failed = "Oct 28 14:10:05 srv-edge sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    event_failed = adapter.parse_log_line(log_line_failed)

    assert event_failed is not None
    assert event_failed["event_type"] == "AUTH_FAILURE"
    assert event_failed["source_ip"] == "192.168.1.100"
    assert event_failed["username"] == "admin"

    log_line_ok = "Oct 28 14:12:00 srv-edge sshd[1235]: Accepted password for root from 192.168.1.100 port 54322 ssh2"
    event_ok = adapter.parse_log_line(log_line_ok)
    assert event_ok is not None
    assert event_ok["event_type"] == "AUTH_SUCCESS"


def test_brute_force_correlation():
    adapter = SystemLogAdapter(failure_threshold=3)
    lines = [
        "Oct 28 14:10:01 srv sshd[1]: Failed password for invalid user root from 10.0.0.5 port 1111 ssh2",
        "Oct 28 14:10:02 srv sshd[2]: Failed password for invalid user root from 10.0.0.5 port 1112 ssh2",
        "Oct 28 14:10:03 srv sshd[3]: Failed password for invalid user root from 10.0.0.5 port 1113 ssh2",
    ]

    alerts = adapter.process_log_stream(lines, persist=False)
    assert len(alerts) == 1
    assert alerts[0].attack_type == "Brute_Force"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].features_snapshot["failed_attempts"] == 3
